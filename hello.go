// Package yoohoo implements the FTS-0006 YooHoo/2U2 handshake — the
// netmail handshake Opus-CBCS introduced and WaZOO-capable mailers still
// answer. It replaces FTS-0001's TSYNC synchronisation with a 128-byte
// "hello" packet exchanged in each direction, carrying the system's
// address, name, sysop, an 8-byte session password and a capability
// mask from which the session method is chosen: ZedZap, ZedZip
// (plain ZMODEM), DietIFNA (FTS-0001 transfers), Janus or Hydra.
//
// This package is the handshake only. The transfer phase is whatever
// the chosen capability bit names (Result.Method); running it is the
// caller's job.
//
// The package depends on the standard library only.
//
// Wire reference: FTS-0006.002, plus the Opus quirks measured against
// a real Opus.
package yoohoo

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Wire bytes (FTS-0006 "STRUCTURES AND DECLARATIONS").
const (
	// YooHoo is the synchronisation byte a WaZOO caller sends; the
	// answerer replies ENQ to ask for the hello.
	YooHoo byte = 0xF1
	// TSync is the FTS-0001 synchronisation byte. FTS-0006 SS1 has a
	// caller send it right after YooHoo so an FTS-0001-only answerer
	// still recognises the call; Call sends YooHoo alone, and the
	// constant is here for a caller that wants to add it. An answerer
	// that sees TSync first is in an FTS-0001 session, not a WaZOO one.
	TSync byte = 0xAE
	// ENQ asks the peer to send its hello.
	ENQ byte = 0x05
	// ACK acknowledges a hello whose CRC matched.
	ACK byte = 0x06
	// NAK is defined by FTS-0006 but the hello flow refuses with '?'.
	NAK byte = 0x15
	// HelloStart opens a hello frame: 0x1F, 128 bytes, CRC hi, CRC lo.
	HelloStart byte = 0x1F
	// HelloRefuse ('?') asks for the hello again after a CRC mismatch.
	HelloRefuse byte = '?'
	// HelloSize is the fixed size of the hello structure.
	HelloSize = 128
	// FrameSize is HelloStart + HelloSize + the 2-byte CRC.
	FrameSize = 1 + HelloSize + 2
	// PasswordSize is the width of the hello's password field. It is
	// "not necessarily null-terminated": eight significant bytes.
	PasswordSize = 8
)

// Capability bits (FTS-0006 "YOOHOO CAPABILITY VALUES"). CapHydra is
// the 0x0020 bit mailers in the field use for Hydra; FTS-0006.002 lists
// it as reserved.
const (
	CapDietIFNA uint16 = 0x0001 // fast FTS-0001 (packets + SEAlink/Telink)
	CapFTBUser  uint16 = 0x0002 // reserved by Opus (Full-Tilt Boogie)
	CapZedZip   uint16 = 0x0004 // ZMODEM, 1 KiB blocks
	CapZedZap   uint16 = 0x0008 // ZMODEM, 8 KiB blocks
	CapJanus    uint16 = 0x0010
	CapHydra    uint16 = 0x0020 // a field extension, not FTS-0006
	CapDomain   uint16 = 0x4000 // my_name carries a domain after its NUL
	CapFreq     uint16 = 0x8000 // WaZOO .REQ file requests accepted
)

// Methods are the capability bits that name a session method, in the
// FTS-0006 "How to decide which WaZOO method to use" preference order:
// Janus, ZedZap, ZedZip, DietIFNA. Hydra is placed first — it is
// strictly better than Janus and a peer that sets the bit means it. CapFreq and CapDomain are options, never methods.
var Methods = []uint16{CapHydra, CapJanus, CapZedZap, CapZedZip, CapDietIFNA}

// MethodMask is the union of every method bit.
const MethodMask = CapHydra | CapJanus | CapZedZap | CapZedZip | CapDietIFNA | CapFTBUser

// ChooseMethod returns the single highest-preference method bit set in
// both masks, or 0 when the two sides share none. The called system
// applies it to narrow its reply to one bit; the caller applies it to
// a reply that (against the spec) still carries several.
func ChooseMethod(local, remote uint16) uint16 {
	common := local & remote
	for _, m := range Methods {
		if common&m != 0 {
			return m
		}
	}
	return 0
}

// MethodName is the log token for a method bit.
func MethodName(m uint16) string {
	switch m {
	case CapHydra:
		return "Hydra"
	case CapJanus:
		return "Janus"
	case CapZedZap:
		return "ZedZap"
	case CapZedZip:
		return "ZedZip"
	case CapDietIFNA:
		return "DietIFNA"
	case CapFTBUser:
		return "FTB"
	case 0:
		return "none"
	}
	return fmt.Sprintf("0x%04x", m)
}

// Hello is the decoded 128-byte hello structure.
type Hello struct {
	Signal       uint16 // 'o' (0x6F) on every compliant implementation
	HelloVersion uint16 // 1
	Product      uint16 // FTSC product code
	ProductMajor uint16
	ProductMinor uint16
	SystemName   string // my_name up to its first NUL (CP437 bytes as-is)
	Domain       string // the text after that NUL, when CapDomain is set
	Sysop        string
	Zone         uint16
	Net          uint16
	Node         uint16
	Point        uint16
	Password     string // the 8-byte field with trailing NULs removed
	Capabilities uint16
}

// Field offsets inside the structure.
const (
	offSignal   = 0
	offVersion  = 2
	offProduct  = 4
	offMajor    = 6
	offMinor    = 8
	offName     = 10
	nameSize    = 60
	offSysop    = 70
	sysopSize   = 20
	offZone     = 90
	offNet      = 92
	offNode     = 94
	offPoint    = 96
	offPassword = 98
	offCaps     = 114
)

// SignatureOK reports whether the signal and version fields carry the
// values every known implementation writes. A mismatch is logged, never
// refused: mailers in the field carry on past one.
func (h *Hello) SignatureOK() bool {
	return h.Signal == 'o' && h.HelloVersion == 1
}

// Address renders the hello's address as "zone:net/node", with ".point"
// when the point is non-zero and "@domain" when a domain was carried.
// A zero zone is rendered as-is: FTS-0006 says 0 means "not supported",
// and the consumer decides which zone that implies.
func (h *Hello) Address() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d:%d/%d", h.Zone, h.Net, h.Node)
	if h.Point != 0 {
		fmt.Fprintf(&sb, ".%d", h.Point)
	}
	if h.Domain != "" {
		sb.WriteByte('@')
		sb.WriteString(h.Domain)
	}
	return sb.String()
}

// Marshal encodes the structure into its 128 wire bytes. Strings are
// cut to their field widths; when the system name and the domain do not
// both fit in my_name the name is shortened from the right (FTS-0006
// "Domain addressing in Hello Packet"). CapDomain is set in the encoded
// capabilities whenever a domain is written, whatever h.Capabilities
// says, so a reader always finds a domain it is told to look for.
func (h *Hello) Marshal() []byte {
	b := make([]byte, HelloSize)
	le := binary.LittleEndian
	signal := h.Signal
	if signal == 0 {
		signal = 'o'
	}
	version := h.HelloVersion
	if version == 0 {
		version = 1
	}
	le.PutUint16(b[offSignal:], signal)
	le.PutUint16(b[offVersion:], version)
	le.PutUint16(b[offProduct:], h.Product)
	le.PutUint16(b[offMajor:], h.ProductMajor)
	le.PutUint16(b[offMinor:], h.ProductMinor)

	caps := h.Capabilities
	name := h.SystemName
	domain := h.Domain
	if domain != "" {
		// name NUL domain NUL must fit in 60 bytes.
		room := nameSize - 2 - len(domain)
		if room < 0 {
			// A domain alone that does not fit is cut; nobody does this.
			domain = domain[:nameSize-2]
			room = 0
		}
		if len(name) > room {
			name = name[:room]
		}
		copy(b[offName:], name)
		copy(b[offName+len(name)+1:], domain)
		caps |= CapDomain
	} else {
		if len(name) > nameSize-1 {
			name = name[:nameSize-1]
		}
		copy(b[offName:], name)
	}
	sysop := h.Sysop
	if len(sysop) > sysopSize-1 {
		sysop = sysop[:sysopSize-1]
	}
	copy(b[offSysop:], sysop)

	le.PutUint16(b[offZone:], h.Zone)
	le.PutUint16(b[offNet:], h.Net)
	le.PutUint16(b[offNode:], h.Node)
	le.PutUint16(b[offPoint:], h.Point)
	pw := h.Password
	if len(pw) > PasswordSize {
		pw = pw[:PasswordSize]
	}
	copy(b[offPassword:], pw)
	le.PutUint16(b[offCaps:], caps)
	return b
}

// ErrShortHello reports a buffer smaller than HelloSize.
var ErrShortHello = errors.New("yoohoo: hello shorter than 128 bytes")

// ParseHello decodes the first 128 bytes of b. Any bytes are accepted
// (see SignatureOK for the sanity check); the only error is a short
// buffer. The domain is read only when CapDomain is set, as the spec
// directs — the bytes after the name's NUL are otherwise padding.
func ParseHello(b []byte) (*Hello, error) {
	if len(b) < HelloSize {
		return nil, ErrShortHello
	}
	le := binary.LittleEndian
	h := &Hello{
		Signal:       le.Uint16(b[offSignal:]),
		HelloVersion: le.Uint16(b[offVersion:]),
		Product:      le.Uint16(b[offProduct:]),
		ProductMajor: le.Uint16(b[offMajor:]),
		ProductMinor: le.Uint16(b[offMinor:]),
		Zone:         le.Uint16(b[offZone:]),
		Net:          le.Uint16(b[offNet:]),
		Node:         le.Uint16(b[offNode:]),
		Point:        le.Uint16(b[offPoint:]),
		Capabilities: le.Uint16(b[offCaps:]),
	}
	nameField := b[offName : offName+nameSize]
	h.SystemName = cString(nameField)
	if h.Capabilities&CapDomain != 0 && len(h.SystemName)+1 < nameSize {
		h.Domain = cString(nameField[len(h.SystemName)+1:])
		// ifmail cuts the domain at its first '.' ("fidonet.org" →
		// "fidonet"); we keep it whole and let the consumer decide.
	}
	h.Sysop = cString(b[offSysop : offSysop+sysopSize])
	h.Password = string(bytes.TrimRight(b[offPassword:offPassword+PasswordSize], "\x00"))
	return h, nil
}

// cString returns the bytes before the first NUL (or the whole field).
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// CRC computes the hello CRC: CRC-16/XMODEM over the 128 structure
// bytes, sent MSB first (FTS-0006 SH3).
func CRC(structure []byte) uint16 {
	return crc16(structure)
}

// Frame returns the full wire frame for h: HelloStart, the 128 bytes,
// CRC high byte, CRC low byte.
func Frame(h *Hello) []byte {
	s := h.Marshal()
	c := CRC(s)
	out := make([]byte, 0, FrameSize)
	out = append(out, HelloStart)
	out = append(out, s...)
	out = append(out, byte(c>>8), byte(c))
	return out
}

// CheckFrame verifies the CRC of a 130-byte body (structure + CRC, the
// bytes after HelloStart) and returns the parsed hello.
func CheckFrame(body []byte) (*Hello, error) {
	if len(body) < HelloSize+2 {
		return nil, ErrShortHello
	}
	want := uint16(body[HelloSize])<<8 | uint16(body[HelloSize+1])
	if got := CRC(body[:HelloSize]); got != want {
		return nil, fmt.Errorf("yoohoo: hello CRC mismatch: got %04x want %04x", got, want)
	}
	return ParseHello(body[:HelloSize])
}

// PasswordMatch compares a presented hello password with a configured
// secret the way mailers in the field do: case-insensitively on the
// first eight bytes — the field is eight bytes wide, so a longer
// configured secret can only ever match by its prefix.
// A configured secret that is empty or "-" means "no password expected"
// and matches anything.
func PasswordMatch(presented, configured string) bool {
	c := strings.TrimSpace(configured)
	if c == "" || c == "-" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(strings.ToLower(cap8(presented))), []byte(strings.ToLower(cap8(c)))) == 1
}

// WirePassword returns the bytes of a configured secret that fit the
// hello field, for sending: the first eight bytes, or "" for the
// "no password" sentinels.
func WirePassword(configured string) string {
	c := strings.TrimSpace(configured)
	if c == "" || c == "-" {
		return ""
	}
	return cap8(c)
}

func cap8(s string) string {
	if len(s) > PasswordSize {
		return s[:PasswordSize]
	}
	return s
}
