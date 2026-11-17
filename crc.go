package yoohoo

// CRC-16/XMODEM: polynomial 0x1021, initial value 0, MSB first, no
// reflection, no final XOR.

var crcTable = func() (t [256]uint16) {
	for i := range t {
		c := uint16(i) << 8
		for j := 0; j < 8; j++ {
			if c&0x8000 != 0 {
				c = (c << 1) ^ 0x1021
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return t
}()

func crc16(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc = crcTable[byte(crc>>8)^b] ^ (crc << 8)
	}
	return crc
}
