package yoohoo

import (
	"bufio"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func fastConfig(local Hello) Config {
	return Config{
		Local:           local,
		SyncTimeout:     300 * time.Millisecond,
		MasterTimeout:   5 * time.Second,
		HelloAckTimeout: 2 * time.Second,
		HelloWait:       2 * time.Second,
		ENQWait:         2 * time.Second,
		HeaderWait:      500 * time.Millisecond,
		BodyTimeout:     2 * time.Second,
		MaxRetries:      4,
	}
}

var (
	callerHello   = Hello{Product: 0xFE, SystemName: "Point", Sysop: "Op", Zone: 999, Net: 2, Node: 4, Point: 1, Domain: "testzone", Capabilities: CapZedZap | CapZedZip | CapFreq}
	answererHello = Hello{Product: 0xFE, SystemName: "Node", Sysop: "Sysop", Zone: 999, Net: 2, Node: 4, Capabilities: CapZedZap | CapZedZip | CapDietIFNA | CapFreq}
)

// run drives Call on one end of a pipe and Answer on the other.
func run(t *testing.T, callerCfg, answererCfg Config, pending bool) (cres *Result, cerr error, ares *Result, aerr error) {
	t.Helper()
	c, a := net.Pipe()
	defer c.Close()
	defer a.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if pending {
			ares, aerr = Answer(a, answererCfg, true)
			return
		}
		// The adapter has consumed the YOOHOO: emulate that.
		var one [1]byte
		_ = a.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := io.ReadFull(a, one[:])
		if err != nil || one[0] != YooHoo {
			aerr = errors.New("expected YOOHOO first")
			return
		}
		ares, aerr = Answer(a, answererCfg, false)
	}()
	cres, cerr = Call(c, callerCfg)
	<-done
	return
}

func TestCallAnswerExchange(t *testing.T) {
	ccfg := fastConfig(callerHello)
	ccfg.Password = "pt1secrt-longer"
	acfg := fastConfig(answererHello)
	var seen *Hello
	acfg.Authorize = func(remote *Hello) (string, bool) {
		seen = remote
		return "PT1SECRT", PasswordMatch(remote.Password, "pt1secrt")
	}

	cres, cerr, ares, aerr := run(t, ccfg, acfg, false)
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	require.NotNil(t, seen)
	assert.Equal(t, "pt1secrt", seen.Password, "the caller sent its first eight bytes")
	assert.Equal(t, "999:2/4.1@testzone", seen.Address())

	assert.Equal(t, CapZedZap, ares.Method, "the answerer narrows to the best common method")
	assert.Equal(t, CapZedZap, cres.Method, "and the caller reads the one bit back")
	assert.Equal(t, CapZedZap|CapFreq, cres.Remote.Capabilities, "options ride along, no second method")
	assert.Equal(t, "PT1SECRT", cres.Remote.Password, "the echo is what Authorize returned")
	assert.Equal(t, "999:2/4", cres.Remote.Address())
	assert.Equal(t, "Node", cres.Remote.SystemName)
}

func TestAnswerYooHooPending(t *testing.T) {
	ccfg := fastConfig(callerHello)
	acfg := fastConfig(answererHello)
	cres, cerr, ares, aerr := run(t, ccfg, acfg, true)
	require.NoError(t, cerr)
	require.NoError(t, aerr)
	assert.Equal(t, CapZedZap, cres.Method)
	assert.Equal(t, CapZedZap, ares.Method)
}

func TestAnswerRefusesWithNoMethod(t *testing.T) {
	ccfg := fastConfig(callerHello)
	acfg := fastConfig(answererHello)
	acfg.Authorize = func(*Hello) (string, bool) { return "BAD_PASS", false }
	cres, cerr, ares, aerr := run(t, ccfg, acfg, false)
	assert.ErrorIs(t, aerr, ErrRefused)
	require.NotNil(t, ares, "the refused exchange still reports who called")
	assert.Equal(t, uint16(0), ares.Method)
	assert.ErrorIs(t, cerr, ErrNoMethod)
	require.NotNil(t, cres)
	assert.Equal(t, uint16(0), cres.Remote.Capabilities&MethodMask)
}

func TestNoCommonMethod(t *testing.T) {
	ccfg := fastConfig(callerHello)
	ccfg.Local.Capabilities = CapZedZap
	acfg := fastConfig(answererHello)
	acfg.Local.Capabilities = CapDietIFNA
	cres, cerr, _, aerr := run(t, ccfg, acfg, false)
	assert.ErrorIs(t, cerr, ErrNoMethod)
	assert.ErrorIs(t, aerr, ErrNoMethod)
	assert.Equal(t, "999:2/4", cres.Remote.Address())
}

// opusLikeAnswerer scripts the called side the way Opus-CBCS 1.79 was
// measured to behave: it answers every byte that is not a hello start
// with ENQ while it waits for the hello, it sends its own YOOHOO twice,
// and (here) its first hello carries a bad CRC so the caller must '?'
// it once. It pipelines a ZRQINIT-like preamble right behind its final
// ACK so the handoff replay is exercised too.
func opusLikeAnswerer(t *testing.T, conn net.Conn, bannerFirst bool, done chan<- error) {
	defer close(done)
	r := bufio.NewReader(conn)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fail := func(err error) { done <- err }
	if bannerFirst {
		if _, err := conn.Write([]byte("OPUS-CBCS v1.79 Mail only\r\n")); err != nil {
			fail(err)
			return
		}
	}
	// Wait for YOOHOO; ENQ every stray byte.
	for {
		b, err := r.ReadByte()
		if err != nil {
			fail(err)
			return
		}
		if b == YooHoo {
			break
		}
		_, _ = conn.Write([]byte{ENQ})
	}
	// ENQ once, then ENQ for a couple of stale bytes the "line" had.
	_, _ = conn.Write([]byte{ENQ, ENQ, ENQ})
	// Read the hello frame; any non-0x1F byte in front gets an ENQ.
	for {
		b, err := r.ReadByte()
		if err != nil {
			fail(err)
			return
		}
		if b == HelloStart {
			break
		}
		_, _ = conn.Write([]byte{ENQ})
	}
	body := make([]byte, HelloSize+2)
	if _, err := io.ReadFull(r, body); err != nil {
		fail(err)
		return
	}
	if _, err := CheckFrame(body); err != nil {
		fail(err)
		return
	}
	_, _ = conn.Write([]byte{ACK})
	// Our side: two YOOHOOs (measured), then wait for ENQ.
	_, _ = conn.Write([]byte{YooHoo, YooHoo})
	for {
		b, err := r.ReadByte()
		if err != nil {
			fail(err)
			return
		}
		if b == ENQ {
			break
		}
	}
	ours := answererHello
	ours.Capabilities = CapZedZap | CapFreq
	ours.Password = "pt1secrt"
	good := Frame(&ours)
	bad := append([]byte(nil), good...)
	bad[40] ^= 0x55 // corrupt the structure, keep the CRC
	if _, err := conn.Write(bad); err != nil {
		fail(err)
		return
	}
	b, err := r.ReadByte()
	if err != nil || b != HelloRefuse {
		fail(errors.New("expected '?' for the bad hello"))
		return
	}
	// Good hello, then pipeline a data-phase preamble behind the ACK read.
	if _, err := conn.Write(good); err != nil {
		fail(err)
		return
	}
	b, err = r.ReadByte()
	if err != nil || b != ACK {
		fail(errors.New("expected ACK for the good hello"))
		return
	}
	_, _ = conn.Write([]byte("rz\r**\x18B00"))
}

func TestCallerAgainstOpusQuirks(t *testing.T) {
	c, a := net.Pipe()
	defer c.Close()
	defer a.Close()
	done := make(chan error, 1)
	go opusLikeAnswerer(t, a, true, done)

	cfg := fastConfig(callerHello)
	cfg.Password = "pt1secrt"
	res, err := Call(c, cfg)
	require.NoError(t, err)
	assert.Equal(t, CapZedZap, res.Method)
	assert.Equal(t, "pt1secrt", res.Remote.Password)

	// The pipelined preamble must come out of the handoff conn.
	buf := make([]byte, 64)
	_ = res.Conn.SetReadDeadline(time.Now().Add(time.Second))
	n, rerr := res.Conn.Read(buf)
	require.NoError(t, rerr)
	assert.Equal(t, "rz\r", string(buf[:min(n, 3)]))

	if aerr := <-done; aerr != nil {
		t.Fatalf("scripted answerer: %v", aerr)
	}
}

func TestCallNoENQ(t *testing.T) {
	c, a := net.Pipe()
	defer c.Close()
	go func() {
		// Swallow everything, never answer.
		_, _ = io.Copy(io.Discard, a)
	}()
	cfg := fastConfig(callerHello)
	cfg.MasterTimeout = 1500 * time.Millisecond
	_, err := Call(c, cfg)
	assert.ErrorIs(t, err, ErrNoENQ)
	a.Close()
}

func TestCallCarrierLost(t *testing.T) {
	c, a := net.Pipe()
	defer c.Close()
	go func() {
		var one [1]byte
		_, _ = io.ReadFull(a, one[:])
		a.Close()
	}()
	cfg := fastConfig(callerHello)
	_, err := Call(c, cfg)
	assert.ErrorIs(t, err, ErrCarrierLost)
}
