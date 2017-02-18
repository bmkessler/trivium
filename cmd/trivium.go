package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/bmkessler/trivium"
)

// command line flags
const (
	DEFAULT = "-"
	ENCRYPT = "e"
	DECRYPT = "d"
	GENKEY  = "g"
)

func main() {
	var inputFile, outputFile, keyFile *os.File
	var b byte

	log.SetPrefix("trivium: ")

	inputFileName := flag.String("i", DEFAULT, "input file, \"-\" reads from stdin")
	outputFileName := flag.String("o", DEFAULT, "output file, \"-\" writes to stdout")
	keyFileName := flag.String("k", DEFAULT, "key file, \"-\" writes to stdout")
	mode := flag.String("m", DEFAULT, fmt.Sprintf("processing mode must be one of: %v=encrypt, %v=decrypt, %v=generate key", ENCRYPT, DECRYPT, GENKEY))

	flag.Parse()

	switch *mode {
	case ENCRYPT:
		fallthrough // encrypt and decrypt proccess similarly
	case DECRYPT:
		// open the key file
		keyFile = openFile(*keyFileName)
		defer keyFile.Close()
		// read the key
		keyreader := bufio.NewReader(keyFile)
		keybuffer := make([]byte, trivium.KeyLength)
		n, err := keyreader.Read(keybuffer)
		if err != nil {
			log.Fatalf("error reading key file %v: %v", keyFile.Name(), err)
		}
		if n != trivium.KeyLength {
			log.Fatalf("Only read %d bytes < %d of input file %v for key", n, trivium.KeyLength, keyFile.Name())
		}
		inputFile = openFile(*inputFileName)
		defer inputFile.Close()
		reader := bufio.NewReader(inputFile)
		// get the IV
		ivbuffer := make([]byte, trivium.KeyLength)
		if *mode == ENCRYPT { // encryption the IV is generated randomly
			_, err := rand.Read(ivbuffer)
			if err != nil {
				log.Fatalf("error generating %d random bytes for IV: %v", trivium.KeyLength, err)
			}
		} else { // decryption read the first 10-bytes of the input as the IV
			n, err := reader.Read(ivbuffer)
			if err != nil {
				log.Fatalf("error reading IV from file %v: %v", inputFile.Name(), err)
			}
			if n != trivium.KeyLength {
				log.Fatalf("Only read %d bytes < %d of input file %v for IV", n, trivium.KeyLength, inputFile.Name())
			}
		}
		var key, iv [trivium.KeyLength]byte
		for i := 0; i < trivium.KeyLength; i++ {
			key[i] = keybuffer[i]
			iv[i] = ivbuffer[i]
		}
		triv := trivium.NewTrivium(key, iv)

		outputFile = createFile(*outputFileName)
		defer outputFile.Close()

		writer := bufio.NewWriter(outputFile)
		defer writer.Flush()
		if *mode == ENCRYPT { // IV prepended to file when encrypting
			for i := 0; i < trivium.KeyLength; i++ {
				err := writer.WriteByte(iv[i])
				if err != nil {
					log.Fatalf("error writing IV to %v: %v", outputFile.Name(), err)
				}
			}
		}
		for b, err = reader.ReadByte(); err == nil; b, err = reader.ReadByte() {
			kb := triv.NextByte()           // next byte of the keystream
			err := writer.WriteByte(b ^ kb) // write the xor out
			if err != nil {
				log.Fatalf("error writing to %v: %v", outputFile.Name(), err)
			}
		}
		if err != io.EOF {
			log.Fatalf("error reading from %v: %v", inputFile.Name(), err)
		}
	case GENKEY:
		keyFile = createFile(*keyFileName)
		defer keyFile.Close()
		keybuffer := make([]byte, trivium.KeyLength)
		_, err := rand.Read(keybuffer)
		if err != nil {
			log.Fatalf("error generating %d random bytes for key: %v", trivium.KeyLength, err)
		}
		n, err := keyFile.Write(keybuffer)
		if err != nil {
			log.Fatalf("error writing to %v: %v", keyFile.Name(), err)
		}
		if n != trivium.KeyLength {
			log.Fatalf("error only able to write %d bytes to %v", n, keyFile.Name())
		}
		log.Printf("wrote new key to %v", keyFile.Name())
	default:
		// no other modes are supported
		flag.Usage()
	}

}

// openFile convenience method to open a file or stdin and fatally log on failure
func openFile(filename string) *os.File {
	var file *os.File
	var err error
	if filename == DEFAULT {
		file = os.Stdin
	} else {
		file, err = os.Open(filename)
		if err != nil {
			log.Fatalf("error opening %v: %v", filename, err)
		}
	}
	return file
}

// createFile convenience method to create a file or stdout and fatally log on failure
func createFile(filename string) *os.File {
	var file *os.File
	var err error
	if filename == DEFAULT {
		file = os.Stdout
	} else {
		file, err = os.Create(filename)
		if err != nil {
			log.Fatalf("error creating %v: %v", filename, err)
		}
	}
	return file
}
