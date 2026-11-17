package yoohoo

import (
	"encoding/hex"
	"testing"
)

// goldenHello is a 128-byte hello built independently of this package,
// for 999:2/4.1@testzone with password pt1secrt and capabilities
// ZedZap, CapFreq and CapDomain; its CRC-16 is 0x1efd. Pinning both
// proves the layout and the CRC agree with a hello Opus has accepted.
const goldenHello = "6f000100fe00010000005465737420506f696e7400746573747a6f6e65000000000000000000000000000000000000000000000000000000000000000000000000000000000054657374205379736f7000000000000000000000e7030200040001007074317365637274000000000000000008c0000000000000000000000000"

func TestHelloMarshalMatchesAnIndependentEncoder(t *testing.T) {
	h := &Hello{
		Product:      0xFE,
		ProductMajor: 1,
		SystemName:   "Test Point",
		Domain:       "testzone",
		Sysop:        "Test Sysop",
		Zone:         999, Net: 2, Node: 4, Point: 1,
		Password:     "pt1secrt",
		Capabilities: CapZedZap | CapFreq, // CapDomain is added by Marshal
	}
	got := h.Marshal()
	want, err := hex.DecodeString(goldenHello)
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Equal(t, uint16(0x1efd), CRC(got))

	frame := Frame(h)
	assert.Len(t, frame, FrameSize)
	assert.Equal(t, HelloStart, frame[0])
	assert.Equal(t, []byte{0x1e, 0xfd}, frame[129:131], "CRC is sent MSB first")
}

func TestHelloParseRoundTrip(t *testing.T) {
	want, err := hex.DecodeString(goldenHello)
	require.NoError(t, err)
	h, err := ParseHello(want)
	require.NoError(t, err)
	assert.True(t, h.SignatureOK())
	assert.Equal(t, "999:2/4.1@testzone", h.Address())
	assert.Equal(t, "Test Point", h.SystemName)
	assert.Equal(t, "Test Sysop", h.Sysop)
	assert.Equal(t, "pt1secrt", h.Password)
	assert.Equal(t, uint16(0xFE), h.Product)
	assert.Equal(t, CapZedZap|CapFreq|CapDomain, h.Capabilities)

	parsed, err := CheckFrame(Frame(h)[1:])
	require.NoError(t, err)
	assert.Equal(t, h, parsed)
}

func TestHelloDomainOnlyWhenFlagged(t *testing.T) {
	// A system name followed by NUL and text, but no DO_DOMAIN: the
	// text is padding, not a domain (FTS-0006 says to look past the NUL
	// only when the bit is set).
	h := &Hello{SystemName: "Node", Domain: "fidonet", Zone: 999, Net: 1, Node: 2021}
	b := h.Marshal()
	b[offCaps+1] &^= byte(CapDomain >> 8)
	p, err := ParseHello(b)
	require.NoError(t, err)
	assert.Equal(t, "", p.Domain)
	assert.Equal(t, "999:1/2021", p.Address())
}

func TestHelloNameShortenedForDomain(t *testing.T) {
	h := &Hello{
		SystemName: "A very long system name that fills the whole sixty byte field",
		Domain:     "fidonet.org",
	}
	p, err := ParseHello(h.Marshal())
	require.NoError(t, err)
	assert.Equal(t, "fidonet.org", p.Domain, "the domain is kept whole")
	assert.Equal(t, nameSize-2-len("fidonet.org"), len(p.SystemName), "the name gives way")
}

func TestCheckFrameRejectsBadCRC(t *testing.T) {
	body := Frame(&Hello{Zone: 999, Net: 1, Node: 1})[1:]
	body[5] ^= 0xFF
	_, err := CheckFrame(body)
	assert.Error(t, err)
}

func TestChooseMethod(t *testing.T) {
	assert.Equal(t, CapZedZap, ChooseMethod(CapZedZap|CapZedZip|CapFreq, CapZedZip|CapZedZap|CapDietIFNA))
	assert.Equal(t, CapZedZip, ChooseMethod(CapZedZap|CapZedZip, CapZedZip|CapDietIFNA))
	assert.Equal(t, CapDietIFNA, ChooseMethod(CapZedZap|CapDietIFNA, CapDietIFNA))
	assert.Equal(t, uint16(0), ChooseMethod(CapZedZap, CapDietIFNA))
	assert.Equal(t, uint16(0), ChooseMethod(CapZedZap|CapFreq, CapFreq), "options are not methods")
}

func TestPasswordMatchEightBytesInsensitive(t *testing.T) {
	assert.True(t, PasswordMatch("pt1secrt", "PT1SECRT"))
	assert.True(t, PasswordMatch("pt1secrt", "pt1secrtLONGER"), "a long configured secret matches by its first 8 bytes")
	assert.True(t, PasswordMatch("anything", ""), "no password configured")
	assert.True(t, PasswordMatch("anything", "-"))
	assert.False(t, PasswordMatch("pt1secrt", "pt1secrx"))
	assert.False(t, PasswordMatch("", "secret"))
	assert.Equal(t, "pt1secrt", WirePassword("pt1secrtLONGER"))
	assert.Equal(t, "", WirePassword("-"))
}
