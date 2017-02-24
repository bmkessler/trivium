/*
Package trivium is a simple implementation of the light weight stream cipher trivium.

DISCLAIMER: This package is purely for fun and makes no claim or waranty of security.
Do not use this package to encrypt any sensitive information.

Trivium is a light weight stream cipher developed to be particularly efficient in hardware.

The trivium specification is http://www.ecrypt.eu.org/stream/p3ciphers/trivium/trivium_p3.pdf

This is a straighforward implementation based on the specification

*/
package trivium

import "strconv"

// Trivium represents the 288-bit state of the Trivium cipher.
type Trivium struct {
	state [5]uint64
}

const (
	// KeyLength bytes in the key and IV, 10 bytes = 80 bits
	KeyLength  = 10
	lgWordSize = 6 // using uint64 = 2^6 as the backing array
	bitsInWord = 1 << lgWordSize

	// the indices in the array for the given cells that are tapped for processing
	i66  = 65 >> lgWordSize
	i93  = 92 >> lgWordSize
	i162 = 161 >> lgWordSize
	i177 = 176 >> lgWordSize
	i243 = 242 >> lgWordSize
	i288 = 287 >> lgWordSize
	i91  = 90 >> lgWordSize
	i92  = 91 >> lgWordSize
	i171 = 170 >> lgWordSize
	i175 = 174 >> lgWordSize
	i176 = 175 >> lgWordSize
	i264 = 263 >> lgWordSize
	i286 = 285 >> lgWordSize
	i287 = 286 >> lgWordSize
	i69  = 68 >> lgWordSize
	i94  = 93 >> lgWordSize
	i178 = 177 >> lgWordSize
	// the position within the word, shift
	mask  = (1 << lgWordSize) - 1
	sh66  = 65 & mask
	sh93  = 92 & mask
	sh162 = 161 & mask
	sh177 = 176 & mask
	sh243 = 242 & mask
	sh288 = 287 & mask
	sh91  = 90 & mask
	sh92  = 91 & mask
	sh171 = 170 & mask
	sh175 = 174 & mask
	sh176 = 175 & mask
	sh264 = 263 & mask
	sh286 = 285 & mask
	sh287 = 286 & mask
	sh69  = 68 & mask
	sh94  = 93 & mask
	sh178 = 177 & mask
)

// NewTrivium returns a Trivium cipher initialized with key and initialization value (IV).
// Both the key and IV are 80-bits (10 bytes).  The initialization processes the cipher for
// 4*288 cycles to "warm-up" and attempt to eliminate and usable dependency on key and IV.
func NewTrivium(key, iv [KeyLength]byte) *Trivium {
	var state [5]uint64

	state[0] |= (uint64(key[3]) << 24) | (uint64(key[2]) << 16) | (uint64(key[1]) << 8) | uint64(key[0])
	state[0] |= (uint64(key[7]) << 56) | (uint64(key[6]) << 48) | (uint64(key[5]) << 40) | (uint64(key[4]) << 32)
	state[1] |= (uint64(iv[0]) << 29) | (uint64(key[9]) << 8) | uint64(key[8])
	state[1] |= (uint64(iv[4]) << 61) | (uint64(iv[3]) << 53) | (uint64(iv[2]) << 45) | (uint64(iv[1]) << 37)
	state[2] |= (uint64(iv[8]) << 29) | (uint64(iv[7]) << 21) | (uint64(iv[6]) << 13) | (uint64(iv[5]) << 5) | (uint64(iv[4]) >> 3)
	state[2] |= (uint64(iv[9]) << 37)
	// state[3] is initialized with all zeros
	state[4] |= uint64(7) << 29
	trivium := Trivium{state: state}
	for i := 0; i < 4*288; i++ {
		trivium.NextBit()
	}
	return &trivium
}

// NextBit gets the next bit from the Trivium stream.
func (t *Trivium) NextBit() uint64 {
	// get the taps
	t1 := (t.state[i66] >> sh66) ^ (t.state[i93] >> sh93)
	t2 := (t.state[i162] >> sh162) ^ (t.state[i177] >> sh177)
	t3 := (t.state[i243] >> sh243) ^ (t.state[i288] >> sh288)
	// store the output
	z := (t1 ^ t2 ^ t3) & 1
	// process the taps
	t1 ^= (t.state[i91]>>sh91)&(t.state[i92]>>sh92) ^ (t.state[i171] >> sh171)
	t2 ^= (t.state[i175]>>sh175)&(t.state[i176]>>sh176) ^ (t.state[i264] >> sh264)
	t3 ^= (t.state[i286]>>sh286)&(t.state[i287]>>sh287) ^ (t.state[i69] >> sh69)

	// rotate the state
	t.state[4] = (t.state[4] << 1) | (t.state[3] >> mask)
	t.state[3] = (t.state[3] << 1) | (t.state[2] >> mask)
	t.state[2] = (t.state[2] << 1) | (t.state[1] >> mask)
	t.state[1] = (t.state[1] << 1) | (t.state[0] >> mask)
	t.state[0] = (t.state[0] << 1) | (t3 & 1)
	// update the final values
	t.state[i94] = t.state[i94] &^ (1 << sh94)
	t.state[i94] |= (t1 & 1) << sh94
	t.state[i178] = t.state[i178] &^ (1 << sh178)
	t.state[i178] |= (t2 & 1) << sh178
	return z

}

// NextByte returns the next byte of key stream with the MSB as the last bit produced.
// the first byte produced will have bits [76543210] of the keystream
func (t *Trivium) NextByte() byte {
	var keyStreamByte uint64
	for j := 0; j < 8; j++ {
		keyStreamByte = (keyStreamByte >> 1) | (t.NextBit() << 7)
	}
	return byte(keyStreamByte)
}

// String outputs a '0' and '1' representation of the trivium internal state
// as a binary string with the first bit at the left.
func (t Trivium) String() string {

	buff := make([]byte, 0, bitsInWord*len(t.state))
	for _, word := range t.state {
		bits := []byte(strconv.FormatUint(uint64(word), 2))
		for i := len(bits) - 1; i >= 0; i-- {
			buff = append(buff, bits[i]) // append the bits in reverse order
		}
		for j := len(bits); j < bitsInWord; j++ {
			buff = append(buff, '0') // add any leading zeros
		}
	}
	return string(buff)
}
