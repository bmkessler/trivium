package trivium

import (
	"fmt"
	"testing"
)

func ExampleNewTrivium() {

	var key = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var IV = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var trivium = NewTrivium(key, IV)

	fmt.Printf("key: ")
	for _, val := range key {
		fmt.Printf("%02X", val)
	}
	fmt.Println()
	fmt.Printf("IV:  ")
	for _, val := range IV {
		fmt.Printf("%02X", val)
	}
	fmt.Println()
	fmt.Println("First 64 bytes of key stream:")
	for j := 0; j < 4; j++ {
		for i := 0; i < 16; i++ {
			fmt.Printf("%02X", trivium.NextByte())
		}
		fmt.Println()
	}
	// Output:
	// key: 00000000000000000000
	// IV:  00000000000000000000
	// First 64 bytes of key stream:
	// FBE0BF265859051B517A2E4E239FC97F
	// 563203161907CF2DE7A8790FA1B2E9CD
	// F75292030268B7382B4C1A759AA2599A
	// 285549986E74805903801A4CB5A5D4F2
}

var testBit uint32
var testByte byte

func BenchmarkTriviumBits(b *testing.B) {
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

func BenchmarkTriviumBytes(b *testing.B) {
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
