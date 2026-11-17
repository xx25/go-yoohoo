package yoohoo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

// Config parameterises one handshake. Zero durations and counts take
// the FTS-0006 defaults named on each field.
type Config struct {
	// Local is our hello. Its Capabilities are what we can do (methods
	// plus CapFreq when we accept .REQ files); CapDomain is set by the
	// encoder whenever Local.Domain is non-empty. Password is ignored:
	// the caller sends WirePassword(Password), the answerer echoes what
	// Authorize returns.
	Local Hello
	// Password is the caller's configured session secret for this peer
	// ("" or "-" = none). Caller only.
	Password string
	// Authorize judges the caller's hello (answerer only). It returns
	// the password our hello echoes and whether the session may go on.
	// ok == false narrows our capabilities to no method at all — the
	// FTS-0006 way of refusing — and Answer still completes the exchange so the
	// caller learns it, then returns ErrRefused. nil accepts everyone
	// and echoes nothing.
	Authorize func(remote *Hello) (echo string, ok bool)
	// Logger receives Debug lines for every state transition; nil = none.
	Logger *slog.Logger

	// SyncTimeout is how long the caller waits for ENQ after each
	// YOOHOO before sending another (SS1: 3 s).
	SyncTimeout time.Duration
	// MasterTimeout bounds the caller's whole synchronisation phase
	// (SS1: 60 s).
	MasterTimeout time.Duration
	// HelloAckTimeout is how long a sent hello waits for ACK (SH3: 40 s).
	HelloAckTimeout time.Duration
	// HelloWait is how long the caller waits for the answerer's YOOHOO
	// after its own hello was ACKed (YS2: 30 s).
	HelloWait time.Duration
	// ENQWait is how long the answerer waits for ENQ after its YOOHOO
	// (YR2: 20 s).
	ENQWait time.Duration
	// HeaderWait is how long an ENQ waits for the hello's 0x1F before
	// the ENQ is repeated (10 s; the spec's RH3 junk timer).
	HeaderWait time.Duration
	// BodyTimeout bounds the read of the 130 hello bytes (RH5: 30 s).
	BodyTimeout time.Duration
	// MaxRetries caps every retried step (10 by default).
	MaxRetries int
}

func (c *Config) defaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&c.SyncTimeout, 3*time.Second)
	def(&c.MasterTimeout, 60*time.Second)
	def(&c.HelloAckTimeout, 40*time.Second)
	def(&c.HelloWait, 30*time.Second)
	def(&c.ENQWait, 20*time.Second)
	def(&c.HeaderWait, 10*time.Second)
	def(&c.BodyTimeout, 30*time.Second)
	if c.MaxRetries <= 0 {
		c.MaxRetries = 10
	}
}

// Result is a completed exchange.
type Result struct {
	// Remote is the peer's hello.
	Remote *Hello
	// Method is the single method bit both sides settled on, or 0 when
	// the peer shares no method with us (the caller's ErrNoMethod).
	Method uint16
	// Conn is the connection to hand the transfer phase. Bytes the
	// handshake read past its last consumed byte — a caller that
	// pipelines its ZRQINIT behind the ACK — are replayed ahead of the
	// live connection.
	Conn net.Conn
	// Elapsed is the handshake's wall-clock duration.
	Elapsed time.Duration
}

// Errors. Every failure of Call and Answer wraps one of these;
// errors.Is works on them.
var (
	ErrCarrierLost = errors.New("yoohoo: carrier lost")
	ErrNoENQ       = errors.New("yoohoo: no ENQ for our YOOHOO")
	ErrNoACK       = errors.New("yoohoo: our hello was not acknowledged")
	ErrNoYooHoo    = errors.New("yoohoo: peer sent no YOOHOO of its own")
	ErrNoHello     = errors.New("yoohoo: no hello from the peer")
	ErrNoMethod    = errors.New("yoohoo: no session method in common")
	ErrRefused     = errors.New("yoohoo: session refused (password or capabilities)")
)

// Call runs the calling side on an established connection: YOOHOO
// until ENQ, our hello until ACK, the peer's YOOHOO, ENQ, its hello,
// ACK. On success Result.Method is the chosen method (0 is reported as
// ErrNoMethod with the Result still returned, so the caller can log the
// peer's identity).
func Call(conn net.Conn, cfg Config) (*Result, error) {
	cfg.defaults()
	start := time.Now()
	s := newSession(conn, &cfg)
	defer s.clearDeadlines()

	// SS1: clear the inbound buffer, then YOOHOO until ENQ.
	master := time.Now().Add(cfg.MasterTimeout)
	s.drain(500 * time.Millisecond)
	gotENQ := false
	for try := 0; try < cfg.MaxRetries && time.Now().Before(master); try++ {
		s.dbg("send YOOHOO (try %d)", try+1)
		if err := s.write([]byte{YooHoo}); err != nil {
			return nil, err
		}
		b, err := s.waitFor(cfg.SyncTimeout, master, func(b byte) bool { return b == ENQ })
		if err != nil {
			if errors.Is(err, errTimeout) {
				continue
			}
			return nil, err
		}
		_ = b
		gotENQ = true
		break
	}
	if !gotENQ {
		return nil, ErrNoENQ
	}

	// SH: our hello until ACK.
	local := cfg.Local
	local.Password = WirePassword(cfg.Password)
	if err := s.sendHello(&local); err != nil {
		return nil, err
	}

	// YS2: the peer's YOOHOO, then its hello.
	if _, err := s.waitFor(cfg.HelloWait, time.Time{}, func(b byte) bool { return b == YooHoo }); err != nil {
		if errors.Is(err, errTimeout) {
			return nil, ErrNoYooHoo
		}
		return nil, err
	}
	remote, err := s.recvHello()
	if err != nil {
		return nil, err
	}
	res := &Result{
		Remote:  remote,
		Method:  ChooseMethod(cfg.Local.Capabilities, remote.Capabilities),
		Conn:    s.handoff(),
		Elapsed: time.Since(start),
	}
	s.dbg("exchange complete: remote %s caps 0x%04x -> method %s",
		remote.Address(), remote.Capabilities, MethodName(res.Method))
	if res.Method == 0 {
		return res, ErrNoMethod
	}
	return res, nil
}

// Answer runs the called side once the caller's YOOHOO has been seen.
// The YOOHOO byte itself has normally been consumed by whoever
// recognised the handshake (an EMSI answerer sniffing its first bytes);
// pass yoohooPending = true when it is still unread on conn.
//
// Flow: ENQ, the caller's hello, ACK; Authorize; our YOOHOO, its ENQ,
// our hello, its ACK. Result.Method is the method we narrowed our reply
// to — the called system chooses (FTS-0006 "Choosing WaZOO Methods").
// A refused caller still gets the whole exchange (with no method bit)
// and Answer returns ErrRefused with the Result.
func Answer(conn net.Conn, cfg Config, yoohooPending bool) (*Result, error) {
	cfg.defaults()
	start := time.Now()
	s := newSession(conn, &cfg)
	defer s.clearDeadlines()

	if yoohooPending {
		// RS5: the caller has up to the "not a mail session" window to
		// show its YOOHOO; ENQWait (20 s) is that window.
		if _, err := s.waitFor(cfg.ENQWait, time.Time{}, func(b byte) bool { return b == YooHoo }); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNoHello, err)
		}
	}

	remote, err := s.recvHello()
	if err != nil {
		return nil, err
	}

	echo, ok := "", true
	if cfg.Authorize != nil {
		echo, ok = cfg.Authorize(remote)
	}
	local := cfg.Local
	local.Password = echo
	method := uint16(0)
	if ok {
		method = ChooseMethod(cfg.Local.Capabilities, remote.Capabilities)
		// Reply with the one method bit plus our options.
		local.Capabilities = method | (cfg.Local.Capabilities & (CapFreq | CapDomain))
	} else {
		local.Capabilities = 0
	}
	s.dbg("caller %s caps 0x%04x, authorized=%v -> reply caps 0x%04x (%s)",
		remote.Address(), remote.Capabilities, ok, local.Capabilities, MethodName(method))

	// YR1..YR3: our YOOHOO until the caller's ENQ.
	gotENQ := false
	for try := 0; try < 3; try++ {
		if try > 0 {
			s.drain(0)
		}
		if err := s.write([]byte{YooHoo}); err != nil {
			return nil, err
		}
		if _, err := s.waitFor(cfg.ENQWait, time.Time{}, func(b byte) bool { return b == ENQ }); err != nil {
			if errors.Is(err, errTimeout) {
				continue
			}
			return nil, err
		}
		gotENQ = true
		break
	}
	if !gotENQ {
		return nil, ErrNoENQ
	}
	// YR4: our hello until ACK.
	if err := s.sendHello(&local); err != nil {
		return nil, err
	}

	res := &Result{
		Remote:  remote,
		Method:  method,
		Conn:    s.handoff(),
		Elapsed: time.Since(start),
	}
	if !ok {
		return res, ErrRefused
	}
	if method == 0 {
		return res, ErrNoMethod
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// The byte-level session
// ---------------------------------------------------------------------------

var errTimeout = errors.New("yoohoo: timeout")

type session struct {
	conn   net.Conn
	reader *bufio.Reader
	cfg    *Config
}

func newSession(conn net.Conn, cfg *Config) *session {
	return &session{conn: conn, reader: bufio.NewReaderSize(conn, 4096), cfg: cfg}
}

func (s *session) dbg(format string, args ...any) {
	if s.cfg.Logger != nil {
		s.cfg.Logger.Debug("yoohoo: " + fmt.Sprintf(format, args...))
	}
}

// clearDeadlines removes the per-step read deadlines so the transfer
// phase does not inherit an expired one: an expired deadline makes
// every read of the transfer protocol fail at once.
func (s *session) clearDeadlines() { _ = s.conn.SetDeadline(time.Time{}) }

func (s *session) write(b []byte) error {
	_ = s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer func() { _ = s.conn.SetWriteDeadline(time.Time{}) }()
	if _, err := s.conn.Write(b); err != nil {
		return fmt.Errorf("%w: write: %v", ErrCarrierLost, err)
	}
	return nil
}

// getc reads one byte within timeout. XON/XOFF/NUL are stripped:
// they are flow control, never protocol.
func (s *session) getc(timeout time.Duration) (byte, error) {
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, errTimeout
		}
		_ = s.conn.SetReadDeadline(deadline)
		b, err := s.reader.ReadByte()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return 0, errTimeout
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, ErrCarrierLost
			}
			return 0, fmt.Errorf("%w: %v", ErrCarrierLost, err)
		}
		if b == 0x00 || b == 0x11 || b == 0x13 {
			continue
		}
		return b, nil
	}
}

// waitFor reads bytes until one satisfies want, the step timeout
// elapses, or the (optional) master deadline passes. Debris is logged
// and dropped.
func (s *session) waitFor(step time.Duration, master time.Time, want func(byte) bool) (byte, error) {
	deadline := time.Now().Add(step)
	if !master.IsZero() && master.Before(deadline) {
		deadline = master
	}
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, errTimeout
		}
		b, err := s.getc(remaining)
		if err != nil {
			return 0, err
		}
		if want(b) {
			return b, nil
		}
		s.dbg("debris 0x%02x", b)
	}
}

// drain discards whatever is buffered and whatever arrives within d
// ("Clear Input Buffer"). d == 0 drains only what is already there.
func (s *session) drain(d time.Duration) {
	if n := s.reader.Buffered(); n > 0 {
		_, _ = s.reader.Discard(n)
	}
	if d <= 0 {
		d = 50 * time.Millisecond
	}
	deadline := time.Now().Add(d)
	n := 0
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		if _, err := s.getc(remaining); err != nil {
			break
		}
		n++
	}
	if n > 0 {
		s.dbg("drained %d stale byte(s)", n)
	}
}

// sendHello runs SH1-SH4: the frame until ACK. '?' and ENQ ask for a
// resend; anything else is debris.
func (s *session) sendHello(h *Hello) error {
	frame := Frame(h)
	for try := 0; try < s.cfg.MaxRetries; try++ {
		// SH3 "Clear Input Buffer": stale ENQs an answerer emitted for
		// bytes it read before our YOOHOO (Opus answers every non-0x1F
		// byte with ENQ) must not be read as resend requests.
		s.drain(0)
		s.dbg("send hello (try %d) caps 0x%04x", try+1, h.Capabilities|boolDomain(h.Domain))
		if err := s.write(frame); err != nil {
			return err
		}
		b, err := s.waitFor(s.cfg.HelloAckTimeout, time.Time{}, func(b byte) bool {
			return b == ACK || b == HelloRefuse || b == ENQ
		})
		if err != nil {
			if errors.Is(err, errTimeout) {
				return ErrNoACK
			}
			return err
		}
		switch b {
		case ACK:
			s.dbg("hello acknowledged")
			return nil
		case HelloRefuse:
			s.dbg("hello refused with '?', resending")
		case ENQ:
			s.dbg("ENQ after hello (out of sync), resending")
		}
	}
	return ErrNoACK
}

func boolDomain(domain string) uint16 {
	if domain != "" {
		return CapDomain
	}
	return 0
}

// recvHello runs RH1-RH10: ENQ, the frame, CRC check, ACK (or '?' and
// another go). A further YOOHOO while we wait for the header is
// ignored rather than re-ENQed: Opus sends two YOOHOOs before its
// hello, and answering each produced duplicate hellos (measured
// against a real Opus).
func (s *session) recvHello() (*Hello, error) {
	needENQ := true
	for try := 0; try < s.cfg.MaxRetries; try++ {
		if needENQ {
			s.dbg("send ENQ (try %d)", try+1)
			if err := s.write([]byte{ENQ}); err != nil {
				return nil, err
			}
		}
		needENQ = true
		if _, err := s.waitFor(s.cfg.HeaderWait, time.Time{}, func(b byte) bool { return b == HelloStart }); err != nil {
			if errors.Is(err, errTimeout) {
				continue // RH4: resynch with another ENQ
			}
			return nil, err
		}
		body := make([]byte, HelloSize+2)
		if err := s.readFull(body, s.cfg.BodyTimeout); err != nil {
			if errors.Is(err, errTimeout) {
				s.dbg("hello body timed out, '?'")
				_ = s.write([]byte{HelloRefuse})
				needENQ = false
				continue
			}
			return nil, err
		}
		h, err := CheckFrame(body)
		if err != nil {
			s.dbg("%v, '?'", err)
			if werr := s.write([]byte{HelloRefuse}); werr != nil {
				return nil, werr
			}
			needENQ = false
			continue
		}
		if !h.SignatureOK() {
			s.dbg("hello signature %04x/%04x is not 'o'/1 — accepted anyway", h.Signal, h.HelloVersion)
		}
		// RH10: clear the inbound buffer, ACK.
		s.drain(0)
		if err := s.write([]byte{ACK}); err != nil {
			return nil, err
		}
		s.dbg("hello received from %s (%q, product 0x%04x %d.%d, caps 0x%04x)",
			h.Address(), h.SystemName, h.Product, h.ProductMajor, h.ProductMinor, h.Capabilities)
		return h, nil
	}
	return nil, ErrNoHello
}

// readFull reads exactly len(buf) bytes within timeout, NUL/XON/XOFF
// included — the hello is binary.
func (s *session) readFull(buf []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	_ = s.conn.SetReadDeadline(deadline)
	_, err := io.ReadFull(s.reader, buf)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return errTimeout
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrCarrierLost
		}
		return fmt.Errorf("%w: %v", ErrCarrierLost, err)
	}
	return nil
}

// handoff returns the connection for the transfer phase with any bytes
// still buffered in our reader replayed first.
func (s *session) handoff() net.Conn {
	n := s.reader.Buffered()
	if n == 0 {
		return s.conn
	}
	peeked, err := s.reader.Peek(n)
	if err != nil {
		return s.conn
	}
	prefix := make([]byte, len(peeked))
	copy(prefix, peeked)
	return &prefixConn{Conn: s.conn, prefix: prefix}
}

// prefixConn replays a byte prefix ahead of the live connection. It
// embeds net.Conn so deadlines and addresses promote through.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
