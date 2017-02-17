/*
Package trivium is a simple implementation of the light weight stream cipher trivium.

DISCLAIMER: This package is purely for fun and makes no claim or waranty of security.
Do not use this package to encrypt any sensitive information.

Trivium is a light weight stream cipher developed to be particularly efficient in hardware.

The trivium specification is http://www.ecrypt.eu.org/stream/p3ciphers/trivium/trivium_p3.pdf

This is a straighforward implementation based on the specification using SWAR calculations
to calculate up to 32 bits at a time.

*/
package trivium

import "strconv"
import "fmt"

// Trivium represents the 288-bit state of the Trivium cipher.
type Trivium struct {
	state [9]uint32
}

const (
	// KeyLength bytes in the key and IV, 10 bytes = 80 bits
	KeyLength  = 10
	bitsInWord = 5 // using uint32 = 2^5 as the backing array

	// the indices in the array for the given cells that are tapped for processing
	i66  = 65 >> bitsInWord
	i93  = 92 >> bitsInWord
	i162 = 161 >> bitsInWord
	i177 = 176 >> bitsInWord
	i243 = 242 >> bitsInWord
	i288 = 287 >> bitsInWord
	i91  = 90 >> bitsInWord
	i92  = 91 >> bitsInWord
	i171 = 170 >> bitsInWord
	i175 = 174 >> bitsInWord
	i176 = 175 >> bitsInWord
	i264 = 263 >> bitsInWord
	i286 = 285 >> bitsInWord
	i287 = 286 >> bitsInWord
	i69  = 68 >> bitsInWord
	i94  = 93 >> bitsInWord
	i178 = 177 >> bitsInWord
	// the position within the word, shift within the word starting from the left
	fullshift = 1 << bitsInWord
	mask      = fullshift - 1
	sh66      = mask - (65 & mask)
	sh93      = mask - (92 & mask)
	sh162     = mask - (161 & mask)
	sh177     = mask - (176 & mask)
	sh243     = mask - (242 & mask)
	sh288     = mask - (287 & mask)
	sh91      = mask - (90 & mask)
	sh92      = mask - (91 & mask)
	sh171     = mask - (170 & mask)
	sh175     = mask - (174 & mask)
	sh176     = mask - (175 & mask)
	sh264     = mask - (263 & mask)
	sh286     = mask - (285 & mask)
	sh287     = mask - (286 & mask)
	sh69      = mask - (68 & mask)
	sh94      = mask - (93 & mask)
	sh178     = mask - (177 & mask)
)

// NewTrivium returns a Trivium cipher initialized with key and initialization value (IV).
// Both the key and IV are 80-bits (10 bytes).  The initialization processes the cipher for
// 4*288 cycles to "warm-up" and attempt to eliminate and usable dependency on key and IV.
func NewTrivium(key, iv [KeyLength]byte) *Trivium {
	var state [9]uint32

	state[0] = (uint32(reverseByte(key[0])) << 24) | (uint32(reverseByte(key[1])) << 16) | (uint32(reverseByte(key[2])) << 8) | uint32(reverseByte(key[3]))
	state[1] = (uint32(reverseByte(key[4])) << 24) | (uint32(reverseByte(key[5])) << 16) | (uint32(reverseByte(key[6])) << 8) | uint32(reverseByte(key[7]))
	state[2] = (uint32(reverseByte(iv[0])) >> 5) | (uint32(reverseByte(key[8])) << 24) | (uint32(reverseByte(key[9])) << 16)
	state[3] = (uint32(reverseByte(iv[4])) >> 5) | (uint32(reverseByte(iv[3])) << 3) | (uint32(reverseByte(iv[2])) << 11) | (uint32(reverseByte(iv[1])) << 19) | (uint32(reverseByte(iv[0])) << 27)
	state[4] = (uint32(reverseByte(iv[8])) >> 5) | (uint32(reverseByte(iv[7])) << 3) | (uint32(reverseByte(iv[6])) << 11) | (uint32(reverseByte(iv[5])) << 19) | (uint32(reverseByte(iv[4])) << 27)
	state[5] = (uint32(reverseByte(iv[9])) << 19) | (uint32(reverseByte(iv[8])) << 27)
	// state[6] and state[7] are initialized with all zeros
	state[8] = uint32(7)

	trivium := Trivium{state: state}
	for i := 0; i < 4*288; i++ {
		trivium.NextBit()
	}

	return &trivium
}

// NextBit gets the next bit from the Trivium stream.
func (t *Trivium) NextBit() uint32 {
	return t.NextBits(1)
}

// NextBits gets the next 1 to 63 bits from the Trivium stream.
func (t *Trivium) NextBits(n uint) uint32 {
	var bitmask uint32 = (1 << n) - 1
	// get the taps
	s66 := (t.state[i66] >> sh66) | (t.state[i66-1] << (fullshift - sh66))
	s93 := (t.state[i93] >> sh93) | (t.state[i93-1] << (fullshift - sh93))
	s162 := (t.state[i162] >> sh162) | (t.state[i162-1] << (fullshift - sh162))
	s177 := (t.state[i177] >> sh177) | (t.state[i177-1] << (fullshift - sh177))
	s243 := (t.state[i243] >> sh243) | (t.state[i243-1] << (fullshift - sh243))
	s288 := (t.state[i288] >> sh288) | (t.state[i288-1] << (fullshift - sh288))

	t1 := s66 ^ s93
	t2 := s162 ^ s177
	t3 := s243 ^ s288
	// store the output
	z := (t1 ^ t2 ^ t3) & bitmask
	// process the taps
	s91 := (t.state[i91] >> sh91) | (t.state[i91-1] << (fullshift - sh91))
	s92 := (t.state[i92] >> sh92) | (t.state[i92-1] << (fullshift - sh92))
	s171 := (t.state[i171] >> sh171) | (t.state[i171-1] << (fullshift - sh171))
	s175 := (t.state[i175] >> sh175) | (t.state[i175-1] << (fullshift - sh175))
	s176 := (t.state[i176] >> sh176) | (t.state[i176-1] << (fullshift - sh176))
	s264 := (t.state[i264] >> sh264) | (t.state[i264-1] << (fullshift - sh264))
	s286 := (t.state[i286] >> sh286) | (t.state[i286-1] << (fullshift - sh286))
	s287 := (t.state[i287] >> sh287) | (t.state[i287-1] << (fullshift - sh287))
	s69 := (t.state[i69] >> sh69) | (t.state[i69-1] << (fullshift - sh69))

	t1 ^= ((s91 & s92) ^ s171)
	t2 ^= ((s175 & s176) ^ s264)
	t3 ^= ((s286 & s287) ^ s69)
	t1 &= bitmask
	t2 &= bitmask
	t3 &= bitmask

	// rotate the state
	t.state[8] = (t.state[8] >> n) | (t.state[7] << (fullshift - n))
	t.state[7] = (t.state[7] >> n) | (t.state[6] << (fullshift - n))
	t.state[6] = (t.state[6] >> n) | (t.state[5] << (fullshift - n))
	t.state[5] = (t.state[5] >> n) | (t.state[4] << (fullshift - n))
	t.state[4] = (t.state[4] >> n) | (t.state[3] << (fullshift - n))
	t.state[3] = (t.state[3] >> n) | (t.state[2] << (fullshift - n))
	t.state[2] = (t.state[2] >> n) | (t.state[1] << (fullshift - n))
	t.state[1] = (t.state[1] >> n) | (t.state[0] << (fullshift - n))
	t.state[0] = (t.state[0] >> n) | (t3 << (fullshift - n))
	// update the final values

	n94 := 92 + n
	n178 := 176 + n
	ni94 := n94 >> bitsInWord
	nsh94 := mask - (n94 & mask)
	ni178 := n178 >> bitsInWord
	nsh178 := mask - (n178 & mask)

	t.state[ni94] = t.state[ni94] &^ (bitmask << nsh94)
	t.state[ni94] |= t1 << nsh94
	// need to handle overlap across word boundaries
	t.state[i94] = t.state[i94] &^ (bitmask >> (fullshift - nsh94))
	t.state[i94] |= t1 >> (fullshift - nsh94)

	t.state[ni178] = t.state[ni178] &^ (bitmask << nsh178)
	t.state[ni178] |= t2 << nsh178
	// need to handle overlap across word boundaries
	t.state[i178] = t.state[i178] &^ (bitmask >> (fullshift - nsh178))
	t.state[i178] |= t2 >> (fullshift - nsh178)

	return z
}

func printWord(word uint32) {
	buff := make([]byte, 0, fullshift)
	bits := []byte(strconv.FormatUint(uint64(word), 2))
	for j := len(bits); j < fullshift; j++ {
		buff = append(buff, '0') // add any leading zeros
	}
	buff = append(buff, bits...) // append the bits
	fmt.Println(string(buff))
}

// NextByte returns the next byte of key stream with the MSB as the last bit produced.
// the first byte produced will have bits [76543210] of the keystream
func (t *Trivium) NextByte() byte {
	return byte(t.NextBits(8))
}

// NextBytes returns the next 1 to 4 bytes of key stream with the MSB as the last bit produced.
// the first byte produced will have bits [76543210] of the keystream
func (t *Trivium) NextBytes(n uint) []byte {
	output := make([]byte, n)
	word := t.NextBits(n << 3)
	for i := uint(0); i < n; i++ {
		output[i] = byte(word >> (i << 3))
	}

	return output
}

// String outputs a '0' and '1' representation of the trivium internal state
// as a binary string with the first bit at the left.
func (t Trivium) String() string {
	buff := make([]byte, 0, fullshift*len(t.state))
	for _, word := range t.state {
		bits := []byte(strconv.FormatUint(uint64(word), 2))
		for j := len(bits); j < fullshift; j++ {
			buff = append(buff, '0') // add any leading zeros
		}
		buff = append(buff, bits...) // append the bits
	}
	return string(buff)
}

// reverseByte reverses the bits in byte
func reverseByte(b byte) byte {
	return ((b & 0x1) << 7) | ((b & 0x80) >> 7) |
		((b & 0x2) << 5) | ((b & 0x40) >> 5) |
		((b & 0x4) << 3) | ((b & 0x20) >> 3) |
		((b & 0x8) << 1) | ((b & 0x10) >> 1)
}
