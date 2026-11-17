package yoohoo

import "testing"

// The session tests run the same constants on both ends, so they cannot
// notice a wrong one. These pin the wire in literal values.

func TestWireBytes(t *testing.T) {
	for name, pair := range map[string][2]byte{
		"YooHoo": {YooHoo, 0xf1}, "TSync": {TSync, 0xae}, "ENQ": {ENQ, 0x05}, "ACK": {ACK, 0x06},
		"NAK": {NAK, 0x15}, "HelloStart": {HelloStart, 0x1f}, "HelloRefuse": {HelloRefuse, 0x3f},
	} {
		assert.Equal(t, pair[1], pair[0], name)
	}
	assert.Equal(t, 128, HelloSize)
	assert.Equal(t, 131, FrameSize)
	assert.Equal(t, 8, PasswordSize)
}

func TestCapabilityBits(t *testing.T) {
	for name, pair := range map[string][2]uint16{
		"DietIFNA": {CapDietIFNA, 0x0001}, "FTBUser": {CapFTBUser, 0x0002}, "ZedZip": {CapZedZip, 0x0004},
		"ZedZap": {CapZedZap, 0x0008}, "Janus": {CapJanus, 0x0010}, "Hydra": {CapHydra, 0x0020},
		"Domain": {CapDomain, 0x4000}, "Freq": {CapFreq, 0x8000},
	} {
		assert.Equal(t, pair[1], pair[0], name)
	}
	// Preference order: Hydra, then the FTS-0006 order.
	assert.Equal(t, []uint16{0x0020, 0x0010, 0x0008, 0x0004, 0x0001}, Methods)
	assert.Equal(t, CapHydra, ChooseMethod(CapHydra|CapJanus|CapZedZap, CapHydra|CapJanus))
	assert.Equal(t, CapJanus, ChooseMethod(CapJanus|CapZedZap, CapHydra|CapJanus|CapZedZap))
}

func TestCRCKnownVector(t *testing.T) {
	// CRC-16/XMODEM check value.
	assert.Equal(t, uint16(0x31c3), CRC([]byte("123456789")))
}

func TestPasswordMatchFoldsBothSides(t *testing.T) {
	assert.True(t, PasswordMatch("SECRET", "secret"))
	assert.True(t, PasswordMatch("secret", "SECRET"))
	assert.True(t, PasswordMatch("secretXX", "secretXXtail"), "only eight bytes count")
	assert.False(t, PasswordMatch("secretXY", "secretXXtail"))
	assert.False(t, PasswordMatch("other", "secret"))
	assert.True(t, PasswordMatch("anything", "-"), "no password configured")
}
