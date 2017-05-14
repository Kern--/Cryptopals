package util

import (
	"encoding/base64"
	"encoding/hex"
	"math"
)

// HexToBase64 converts a hex encoded string to a base64 encoded string
func HexToBase64(str string) (string, error) {
	inputBytes, err := hex.DecodeString(str)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(inputBytes)
	return encoded, nil
}

// Xor xors two equal length byte arrays
func Xor(a []byte, b []byte) []byte {
	c := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

// SingleByteXor xors each element in an array by a byte key
func SingleByteXor(a []byte, key byte) []byte {
	length := len(a)
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = key
	}
	return Xor(a, b)
}

// HammingDistance computes the hamming distance between two equal length byte sequences
func HammingDistance(a []byte, b []byte) int {
	var result int
	for i := 0; i < len(a); i++ {
		diff := a[i] ^ b[i]
		var j uint
		for j = 0; j < 8; j++ {
			if (diff>>j)&1 == 1 {
				result++
			}
		}
	}
	return result
}

// Transpose transposes an input byte slice broken into blocks of size blocksize
//  into a byte slice where the first byte of every original block comes before
//  the second byte of every original block, etc.
func Transpose(input []byte, blockSize int) []byte {
	// Transposed block size = number of blocks in the input
	// Transposed number of blocks = original block size
	transposedBlockSize := int(math.Ceil(float64(len(input)) / float64(blockSize)))
	result := make([]byte, transposedBlockSize*blockSize)
	for i, b := range input {
		block := i % blockSize
		offset := i / blockSize
		result[block*transposedBlockSize+offset] = b
	}
	return result
}
