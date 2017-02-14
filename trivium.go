/*
Package trivium is a simple implementation of the light weight stream cipher trivium.

DISCLAIMER: This package is purely for fun and makes no claim or waranty of security.
Do not use this package to encrypt any sensitive information.

Trivium is a light weight stream cipher developed to be particularly efficient in hardware.
*/
package trivium

import "strconv"

// Trivium represents the 288-bit state of the Trivium cipher.
type Trivium struct {
	state [9]uint32
}

const (
	keyIvLengthBytes = 10 // bytes in the key and IV 10 bytes = 80 bits
	bits             = 5  // 32 = 2^5

	// the indices in the array for the given cells
	i66  = 65 >> bits
	i93  = 92 >> bits
	i162 = 161 >> bits
	i177 = 176 >> bits
	i243 = 242 >> bits
	i288 = 287 >> bits
	i91  = 90 >> bits
	i92  = 91 >> bits
	i171 = 170 >> bits
	i175 = 174 >> bits
	i176 = 175 >> bits
	i264 = 263 >> bits
	i286 = 285 >> bits
	i287 = 286 >> bits
	i69  = 68 >> bits
	i94  = 93 >> bits
	i178 = 177 >> bits
	// the position within the word, shift
	mask = (1 << bits) - 1
	s66  = 65 & mask
	s93  = 92 & mask
	s162 = 161 & mask
	s177 = 176 & mask
	s243 = 242 & mask
	s288 = 287 & mask
	s91  = 90 & mask
	s92  = 91 & mask
	s171 = 170 & mask
	s175 = 174 & mask
	s176 = 175 & mask
	s264 = 263 & mask
	s286 = 285 & mask
	s287 = 286 & mask
	s69  = 68 & mask
	s94  = 93 & mask
	s178 = 177 & mask
)

// NewTrivium returns a Trivium cipher initialized with key and initialization value (IV).
// Both the key and IV are 80-bits (10 bytes).  The initialization processes the cipher for
// 4*288 cycles to "warm-up" and attempt to eliminate and usable dependency on key and IV.
func NewTrivium(key, iv [keyIvLengthBytes]byte) *Trivium {
	var state [9]uint32

	state[0] = (uint32(key[3]) << 24) | (uint32(key[2]) << 16) | (uint32(key[1]) << 8) | uint32(key[0])
	state[1] = (uint32(key[7]) << 24) | (uint32(key[6]) << 16) | (uint32(key[5]) << 8) | uint32(key[4])
	state[2] = (uint32(iv[0]) << 29) | (uint32(key[9]) << 8) | uint32(key[8])
	state[3] = (uint32(iv[4]) << 29) | (uint32(iv[3]) << 21) | (uint32(iv[2]) << 13) | (uint32(iv[1]) << 5) | (uint32(iv[0]) >> 3)
	state[4] = (uint32(iv[8]) << 29) | (uint32(iv[7]) << 21) | (uint32(iv[6]) << 13) | (uint32(iv[5]) << 5) | (uint32(iv[4]) >> 3)
	state[5] = (uint32(iv[9]) << 5) | (uint32(iv[8]) >> 3)
	// state[6] and state[7] are initialized with all zeros
	state[8] = uint32(7) << 29
	trivium := Trivium{state: state}
	for i := 0; i < 4*288; i++ {
		trivium.NextBit()
	}
	return &trivium
}

// NextBit gets the next bit from the Trivium stream
func (t *Trivium) NextBit() uint32 {
	// get the taps
	t1 := (t.state[i66] >> s66) ^ (t.state[i93] >> s93)
	t2 := (t.state[i162] >> s162) ^ (t.state[i177] >> s177)
	t3 := (t.state[i243] >> s243) ^ (t.state[i288] >> s288)
	// store the output
	z := (t1 ^ t2 ^ t3) & 1
	// process the taps
	t1 ^= (t.state[i91]>>s91)&(t.state[i92]>>s92) ^ (t.state[i171] >> s171)
	t2 ^= (t.state[i175]>>s175)&(t.state[i176]>>s176) ^ (t.state[i264] >> s264)
	t3 ^= (t.state[i286]>>s286)&(t.state[i287]>>s287) ^ (t.state[i69] >> s69)

	// rotate the state
	t.state[8] = (t.state[8] << 1) | (t.state[7] >> 31)
	t.state[7] = (t.state[7] << 1) | (t.state[6] >> 31)
	t.state[6] = (t.state[6] << 1) | (t.state[5] >> 31)
	t.state[5] = (t.state[5] << 1) | (t.state[4] >> 31)
	t.state[4] = (t.state[4] << 1) | (t.state[3] >> 31)
	t.state[3] = (t.state[3] << 1) | (t.state[2] >> 31)
	t.state[2] = (t.state[2] << 1) | (t.state[1] >> 31)
	t.state[1] = (t.state[1] << 1) | (t.state[0] >> 31)
	t.state[0] = (t.state[0] << 1) | (t3 & 1)
	// update the final values
	t.state[i94] = t.state[i94] &^ (1 << s94)
	t.state[i94] |= (t1 & 1) << s94
	t.state[i178] = t.state[i178] &^ (1 << s178)
	t.state[i178] |= (t2 & 1) << s178
	return z
}

// NextByte returns the next byte of key stream with the MSB as the last bit produced
func (t *Trivium) NextByte() byte {
	var keyStreamByte uint32
	for j := 0; j < 8; j++ {
		keyStreamByte = (keyStreamByte >> 1) | (t.NextBit() << 7)
	}
	return byte(keyStreamByte)
}

// String outputs a '0' and '1' representation of the binary string with the first bit at the left.
func (t Trivium) String() string {
	buff := make([]byte, 0, 32*len(t.state))
	for _, word := range t.state {
		bits := []byte(strconv.FormatUint(uint64(word), 2))
		for i := len(bits) - 1; i >= 0; i-- {
			buff = append(buff, bits[i]) // append the bits in reverse order
		}
		for j := len(bits); j < 32; j++ {
			buff = append(buff, '0') // add any leading zeros
		}
	}
	return string(buff)
}
