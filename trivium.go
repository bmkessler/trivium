/*
Package trivium is a simple implementation of the light weight stream cipher trivium.

DISCLAIMER: This package is purely for fun and makes no claim or waranty of security.
Do not use this package to encrypt any sensitive information.

Trivium is a light weight stream cipher developed to be particularly efficient in hardware.

The trivium specification is http://www.ecrypt.eu.org/stream/p3ciphers/trivium/trivium_p3.pdf

This is a straighforward implementation based on the specification using SWAR calculations
to calculate up to 64 bits at a time.

*/
package trivium

// Trivium represents the 288-bit state of the Trivium cipher.
type Trivium struct {
	state [5]uint64
}

const (
	// KeyLength bytes in the key and IV, 10 bytes = 80 bits
	KeyLength  = 10
	lgWordSize = 6 // using uint64 = 2^6 as the backing array

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
	// the position within the word, shift within the word starting from the left
	wordSize = 1 << lgWordSize
	mask     = wordSize - 1
	sh66     = mask - (65 & mask)
	sh93     = mask - (92 & mask)
	sh162    = mask - (161 & mask)
	sh177    = mask - (176 & mask)
	sh243    = mask - (242 & mask)
	sh288    = mask - (287 & mask)
	sh91     = mask - (90 & mask)
	sh92     = mask - (91 & mask)
	sh171    = mask - (170 & mask)
	sh175    = mask - (174 & mask)
	sh176    = mask - (175 & mask)
	sh264    = mask - (263 & mask)
	sh286    = mask - (285 & mask)
	sh287    = mask - (286 & mask)
	sh69     = mask - (68 & mask)
	sh94     = mask - (93 & mask)
	sh178    = mask - (177 & mask)
)

// NewTrivium returns a Trivium cipher initialized with key and initialization value (IV).
// Both the key and IV are 80-bits (10 bytes).  The initialization processes the cipher for
// 4*288 cycles to "warm-up" and attempt to eliminate and usable dependency on key and IV.
func NewTrivium(key, iv [KeyLength]byte) *Trivium {
	var state [5]uint64

	state[0] |= (uint64(reverseByte(key[0])) << 56) | (uint64(reverseByte(key[1])) << 48) | (uint64(reverseByte(key[2])) << 40) | (uint64(reverseByte(key[3])) << 32)
	state[0] |= (uint64(reverseByte(key[4])) << 24) | (uint64(reverseByte(key[5])) << 16) | (uint64(reverseByte(key[6])) << 8) | uint64(reverseByte(key[7]))
	state[1] |= (uint64(reverseByte(key[8])) << 56) | (uint64(reverseByte(key[9])) << 48)
	state[1] |= (uint64(reverseByte(iv[4])) >> 5) | (uint64(reverseByte(iv[3])) << 3) | (uint64(reverseByte(iv[2])) << 11) | (uint64(reverseByte(iv[1])) << 19) | (uint64(reverseByte(iv[0])) << 27)
	state[2] |= (uint64(reverseByte(iv[7])) << 35) | (uint64(reverseByte(iv[6])) << 43) | (uint64(reverseByte(iv[5])) << 51) | (uint64(reverseByte(iv[4])) << 59)
	state[2] |= (uint64(reverseByte(iv[9])) << 19) | (uint64(reverseByte(iv[8])) << 27)
	// state[3] is initialized with all zeros
	state[4] |= uint64(7) << 32

	trivium := Trivium{state: state}
	for i := 0; i < 4*288; i++ {
		trivium.NextBit()
	}

	return &trivium
}

// NextBit gets the next bit from the Trivium stream.
func (t *Trivium) NextBit() uint64 {
	return t.NextBits(1)
}

// NextBits gets the next 1 to 63 bits from the Trivium stream.
func (t *Trivium) NextBits(n uint) uint64 {
	var bitmask uint64 = (1 << n) - 1
	// get the taps
	s66 := (t.state[i66] >> sh66) | (t.state[i66-1] << (wordSize - sh66))
	s93 := (t.state[i93] >> sh93) | (t.state[i93-1] << (wordSize - sh93))
	s162 := (t.state[i162] >> sh162) | (t.state[i162-1] << (wordSize - sh162))
	s177 := (t.state[i177] >> sh177) | (t.state[i177-1] << (wordSize - sh177))
	s243 := (t.state[i243] >> sh243) | (t.state[i243-1] << (wordSize - sh243))
	s288 := (t.state[i288] >> sh288) | (t.state[i288-1] << (wordSize - sh288))

	t1 := s66 ^ s93
	t2 := s162 ^ s177
	t3 := s243 ^ s288
	// store the output
	z := (t1 ^ t2 ^ t3) & bitmask
	// process the taps
	s91 := (t.state[i91] >> sh91) | (t.state[i91-1] << (wordSize - sh91))
	s92 := (t.state[i92] >> sh92) | (t.state[i92-1] << (wordSize - sh92))
	s171 := (t.state[i171] >> sh171) | (t.state[i171-1] << (wordSize - sh171))
	s175 := (t.state[i175] >> sh175) | (t.state[i175-1] << (wordSize - sh175))
	s176 := (t.state[i176] >> sh176) | (t.state[i176-1] << (wordSize - sh176))
	s264 := (t.state[i264] >> sh264) | (t.state[i264-1] << (wordSize - sh264))
	s286 := (t.state[i286] >> sh286) | (t.state[i286-1] << (wordSize - sh286))
	s287 := (t.state[i287] >> sh287) | (t.state[i287-1] << (wordSize - sh287))
	s69 := (t.state[i69] >> sh69) | (t.state[i69-1] << (wordSize - sh69))

	t1 ^= ((s91 & s92) ^ s171)
	t2 ^= ((s175 & s176) ^ s264)
	t3 ^= ((s286 & s287) ^ s69)
	t1 &= bitmask
	t2 &= bitmask
	t3 &= bitmask

	// rotate the state
	t.state[4] = (t.state[4] >> n) | (t.state[3] << (wordSize - n))
	t.state[3] = (t.state[3] >> n) | (t.state[2] << (wordSize - n))
	t.state[2] = (t.state[2] >> n) | (t.state[1] << (wordSize - n))
	t.state[1] = (t.state[1] >> n) | (t.state[0] << (wordSize - n))
	t.state[0] = (t.state[0] >> n) | (t3 << (wordSize - n))
	// update the final values

	n94 := 92 + n
	n178 := 176 + n
	ni94 := n94 >> lgWordSize
	nsh94 := mask - (n94 & mask)
	ni178 := n178 >> lgWordSize
	nsh178 := mask - (n178 & mask)

	t.state[ni94] = t.state[ni94] &^ (bitmask << nsh94)
	t.state[ni94] |= t1 << nsh94
	// need to handle overlap across word boundaries
	t.state[i94] = t.state[i94] &^ (bitmask >> (wordSize - nsh94))
	t.state[i94] |= t1 >> (wordSize - nsh94)

	t.state[ni178] = t.state[ni178] &^ (bitmask << nsh178)
	t.state[ni178] |= t2 << nsh178
	// need to handle overlap across word boundaries
	t.state[i178] = t.state[i178] &^ (bitmask >> (wordSize - nsh178))
	t.state[i178] |= t2 >> (wordSize - nsh178)

	return z
}

// NextByte returns the next byte of key stream with the MSB as the last bit produced.
// the first byte produced will have bits [76543210] of the keystream
func (t *Trivium) NextByte() byte {
	return byte(t.NextBits(8))
}

// NextBytes returns the next 1 to 8 bytes of key stream with the MSB as the last bit produced.
// the first byte produced will have bits [76543210] of the keystream
func (t *Trivium) NextBytes(n uint) []byte {
	output := make([]byte, n)
	word := t.NextBits(n << 3)
	for i := uint(0); i < n; i++ {
		output[i] = byte(word >> (i << 3))
	}

	return output
}

// reverseByte reverses the bits in byte
func reverseByte(b byte) byte {
	return ((b & 0x1) << 7) | ((b & 0x80) >> 7) |
		((b & 0x2) << 5) | ((b & 0x40) >> 5) |
		((b & 0x4) << 3) | ((b & 0x20) >> 3) |
		((b & 0x8) << 1) | ((b & 0x10) >> 1)
}
