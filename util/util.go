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

// CountDuplicateBlocks counts the number of blocks that appear in the input which are
//  identical to an earlier block in the input
func CountDuplicateBlocks(input []byte, blocksize int) int {
	var count int
	// i = start of block we want try to find previous duplicate
	for i := blocksize; i < len(input); i += blocksize {
		// j = start of block we before i that we want to see if is duplicate
		for j := 0; j < i; j += blocksize {
			var k int
			// k = index into each block
			for k = 0; k < blocksize; k++ {
				// if blocki[k] != blockj[k], then these blocks cannot be duplicates, break
				if input[i+k] != input[j+k] {
					break
				}
			}
			// If we looked at the entire block, then blocki = blockj
			//  because otherwise we would have broken out of the k loop with k < blocksize
			//  since we found a duplicate, break so we don't have to keep looking for one
			if k == blocksize {
				count++
				break
			}
		}
	}
	return count
}

// AddPkcs7Padding pads and input to a multiple of the blocksize using PKCS#7 padding
func AddPkcs7Padding(input []byte, blocksize int) []byte {
	// Figure out how many padding bytes are required
	requiredPadding := blocksize - len(input)%blocksize
	// Create a new padded slice that is the next mutliple of blocksize above the length of the inpute slice
	padded := make([]byte, len(input)+requiredPadding)
	// Copy the input into the padded slice
	copy(padded, input)
	// Iterate through the last requiredPadding bytes in the padded slice and set their value
	//  equal to the number of padding bytes (i.e. requiredPadding)
	for i := 0; i < requiredPadding; i++ {
		padded[len(padded)-1-i] = byte(requiredPadding)
	}
	return padded
}
