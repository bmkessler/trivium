package trivium

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"testing"
)

func ExampleNewTrivium() {

	var key = [10]byte{0x5F, 0xE5, 0x2A, 0x80, 0x75, 0xDA, 0x10, 0xAD, 0x46, 0xF0}
	var iv = [10]byte{0xE3, 0x06, 0x9F, 0x49, 0xD4, 0x23, 0xBA, 0x6F, 0xF1, 0x14}
	var trivium = NewTrivium(key, iv)
	// note the key and iv are printed big-endian
	fmt.Printf("key: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", key[9], key[8], key[7], key[6], key[5], key[4], key[3], key[2], key[1], key[0])
	fmt.Printf("iv:  %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", iv[9], iv[8], iv[7], iv[6], iv[5], iv[4], iv[3], iv[2], iv[1], iv[0])
	fmt.Println("first 64 bytes of key stream:")
	for j := 0; j < 4; j++ {
		for i := 0; i < 16; i++ {
			fmt.Printf("%02X", trivium.NextByte())
		}
		fmt.Println()
	}
	// Output:
	// key: F046AD10DA75802AE55F
	// iv:  14F16FBA23D4499F06E3
	// first 64 bytes of key stream:
	// A4386C6D7624983FEA8DBE7314E5FE1F
	// 9D102004C2CEC99AC3BFBF003A66433F
	// 3089A98FAD8512C49D7AABC0639F90C5
	// FFED06F9D35AA8C86630E76A838E26D7

}

// the "official" test vectors for 80-bit key and 80-bit IV
// http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/checkout/ecrypt/trunk/submissions/trivium/unverified.test-vectors?rev=210
// https://trac.cryptolib.org/avr-crypto-lib/browser/testvectors/trivium-80.80.test-vectors
// these appear to load the key and iv incorrectly according to the spec
// the vectors are big-endian, i.e. most significant byte of key and iv is on the left [9][8]...[1][0]
// but the bit order is flipped, i.e. 0x80 should be loaded as 0x01 etc.
// [72,73,74,75,76,77,78,79][64,65,66,67,68,69,70,71]...[8,9,10,11,12,13,14,15][0,1,2,3,4,5,6,7]

const TestVectorFile8080 = "trivium-80.80.test-vectors"

const (
	testvectorLineLength  = 16 // 16 bytes per line in the test vectors
	testvectorTotalLength = 64 // 64 bytes per block of test vector
)

var (
	keyRe    = regexp.MustCompile(`key = ([0-9A-F]{20})`)
	ivRe     = regexp.MustCompile(`IV = ([0-9A-F]{20})`)
	streamRe = regexp.MustCompile(`stream\[([0-9]+)..[0-9]+\] = ([0-9A-F]{32})`)
	dataRe   = regexp.MustCompile(`([0-9A-F]{32})`)
	digestRe = regexp.MustCompile(`digest = ([0-9A-F]{20})`)
)

func TestTriviumTestVectors(t *testing.T) {
	file, err := os.Open(TestVectorFile8080)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var key, iv [KeyLength]byte
	var startingByte uint64
	var tv []byte

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if keyRe.MatchString(text) {
			key = [KeyLength]byte{}
			matches := keyRe.FindStringSubmatch(text)
			for i := 0; i < KeyLength; i++ {
				val, err := strconv.ParseUint(matches[1][2*i:2*i+2], 16, 8)
				if err != nil {
					t.Error(err)
				}
				key[KeyLength-1-i] = byte(val) // the highest key bits are on the left
			}
		} else if ivRe.MatchString(text) {
			iv = [KeyLength]byte{}
			matches := ivRe.FindStringSubmatch(text)
			for i := 0; i < KeyLength; i++ {
				val, err := strconv.ParseUint(matches[1][2*i:2*i+2], 16, 8)
				if err != nil {
					t.Error(err)
				}
				iv[KeyLength-1-i] = byte(val) // the highest iv bits are on the left
			}
		} else if streamRe.MatchString(text) {
			tv = []byte{}
			matches := streamRe.FindStringSubmatch(text)
			startingByte, err = strconv.ParseUint(matches[1], 10, 64)
			if err != nil {
				t.Error(err)
			}
			for i := 0; i < testvectorLineLength; i++ {
				val, err := strconv.ParseUint(matches[2][2*i:2*i+2], 16, 8)
				if err != nil {
					t.Error(err)
				}
				tv = append(tv, byte(val))
			}
		} else if dataRe.MatchString(text) {
			matches := dataRe.FindStringSubmatch(text)
			for i := 0; i < testvectorLineLength; i++ {
				val, err := strconv.ParseUint(matches[1][2*i:2*i+2], 16, 8)
				if err != nil {
					t.Error(err)
				}
				tv = append(tv, byte(val))
			}
		} else if digestRe.MatchString(text) {
			tv = []byte{} // ignore the digest and only test the key stream
		}
		if len(tv) == 64 {
			var revKey, revIV [KeyLength]byte
			for i := 0; i < KeyLength; i++ { // the bit order needs to be reversed to correspond to test vectors
				revKey[i] = reverseByte(key[i])
				revIV[i] = reverseByte(iv[i])
			}
			trivium := NewTrivium(revKey, revIV)
			for i := uint64(0); i < startingByte; i++ {
				trivium.NextByte()
			}
			got := []byte{}
			for i := uint64(0); i < testvectorTotalLength; i++ {
				testByte = trivium.NextByte()
				got = append(got, testByte)

			}

			if reflect.DeepEqual(got, tv) != true {
				t.Errorf("key:   %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", key[9], key[8], key[7], key[6], key[5], key[4], key[3], key[2], key[1], key[0])
				t.Errorf("iv:    %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", iv[9], iv[8], iv[7], iv[6], iv[5], iv[4], iv[3], iv[2], iv[1], iv[0])
				t.Errorf("test vector starts at byte: %d", startingByte)
				t.Errorf("want:  %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", tv[0], tv[1], tv[2], tv[3], tv[4], tv[5], tv[6], tv[7], tv[8], tv[9], tv[10], tv[11], tv[12], tv[13], tv[14], tv[15])
				t.Errorf("got:   %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", got[0], got[1], got[2], got[3], got[4], got[5], got[6], got[7], got[8], got[9], got[10], got[11], got[12], got[13], got[14], got[15])
				t.Errorf("want:  %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", tv[16], tv[17], tv[18], tv[19], tv[20], tv[21], tv[22], tv[23], tv[24], tv[25], tv[26], tv[27], tv[28], tv[29], tv[30], tv[31])
				t.Errorf("got:   %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", got[16], got[17], got[18], got[19], got[20], got[21], got[22], got[23], got[24], got[25], got[26], got[27], got[28], got[29], got[30], got[31])
				t.Errorf("want:  %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", tv[32], tv[33], tv[34], tv[35], tv[36], tv[37], tv[38], tv[39], tv[40], tv[41], tv[42], tv[43], tv[44], tv[45], tv[46], tv[47])
				t.Errorf("got:   %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", got[32], got[33], got[34], got[35], got[36], got[37], got[38], got[39], got[40], got[41], got[42], got[43], got[44], got[45], got[46], got[47])
				t.Errorf("want:  %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", tv[48], tv[49], tv[50], tv[51], tv[52], tv[53], tv[54], tv[55], tv[56], tv[57], tv[58], tv[59], tv[60], tv[61], tv[62], tv[63])
				t.Errorf("got:   %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", got[48], got[49], got[50], got[51], got[52], got[53], got[54], got[55], got[56], got[57], got[58], got[59], got[60], got[61], got[62], got[63])
			}
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestTriviumSWAR(t *testing.T) {
	var key = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var IV = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var trivium = NewTrivium(key, IV)
	var triviumSWAR = NewTrivium(key, IV)
	var totalBitsToCompare uint = 4 * 288
	var maxSWARwidth uint = 32
	for SWARwidth := uint(1); SWARwidth <= maxSWARwidth; SWARwidth++ {
		for i := uint(0); i < totalBitsToCompare; {
			SWARbits := triviumSWAR.NextBits(SWARwidth)
			for j := uint(0); j < SWARwidth; j++ {
				i++
				bit := trivium.NextBit()
				if bit != (SWARbits>>j)&1 {
					t.Errorf(" for SWARwidth %d bits at %d don't match %d != %d", SWARwidth, i, bit, (SWARbits>>j)&1)
				}
			}
		}
	}
}

func TestTriviumBytes(t *testing.T) {
	var key = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var IV = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var trivium = NewTrivium(key, IV)
	var triviumBytes = NewTrivium(key, IV)
	var totalBytesToCompare uint = 4 * 288
	var maxBytes uint = (wordSize >> 3)
	for bytes := uint(1); bytes <= maxBytes; bytes++ {
		for i := uint(0); i < totalBytesToCompare; {
			KeyBytes := triviumBytes.NextBytes(bytes)
			for j := uint(0); j < bytes; j++ {
				i++
				KeyByte := KeyBytes[j]
				for k := uint(0); k < 8; k++ {
					bit := byte(trivium.NextBit())
					if bit != (KeyByte>>k)&1 {
						t.Errorf("Bytes in increments of %d at %d don't match %d != %d", bytes, i, bit, (KeyByte>>k)&1)
					}
				}
			}
		}
	}
}

var testBit uint64
var testByte byte
var testBytes []byte

func BenchmarkTriviumBit(b *testing.B) {
	var key = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var IV = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var trivium = NewTrivium(key, IV)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testBit = trivium.NextBit()
	}
	if trivium.NextBit() == 1 {
		testByte = 1
	} // to avoid optimizing out the loop entirely
}

func BenchmarkTriviumByte(b *testing.B) {
	var key = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var IV = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var trivium = NewTrivium(key, IV)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testByte = trivium.NextByte()
	}
	if trivium.NextBit() == 1 {
		testByte = 1
	} // to avoid optimizing out the loop entirely
}

func BenchmarkTriviumBytes(b *testing.B) {
	var key = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var IV = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var trivium = NewTrivium(key, IV)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testBytes = trivium.NextBytes(wordSize >> 3)
	}
	if trivium.NextBit() == 1 {
		testByte = 1
	} // to avoid optimizing out the loop entirely
}
