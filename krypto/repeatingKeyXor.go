package krypto

import (
	"math"

	"github.com/kern--/Cryptopals/util"
)

// RepeatingKeyXor encrypts the input by xoring each successive input byte with each
//  successive key byte while wrapping if the key is shorter than the input
func RepeatingKeyXor(input []byte, key []byte) []byte {
	cipher := make([]byte, len(input))
	keylen := len(key)

	for i, b := range input {
		cipher[i] = b ^ key[i%keylen]
	}
	return cipher
}

// CrackRepeatingKeyXor finds the key and plaintext for a given cipher text
//  that has been encrypted with a repeating key xor
func CrackRepeatingKeyXor(input []byte) (plaintext []byte, key []byte) {
	// Find key size
	keySize := 0
	smallestNormalizedDistance := math.MaxFloat64
	for i := 6; i < 41; i++ {
		dist1 := util.HammingDistance(input[0:i], input[i:2*i])
		dist2 := util.HammingDistance(input[i:2*i], input[2*i:3*i])
		dist3 := util.HammingDistance(input[2*i:3*i], input[3*i:4*i])
		dist4 := util.HammingDistance(input[3*i:4*i], input[4*i:5*i])

		// Normalized average hamming distance between consecutive blocks for the
		//  first 5 blocks of the input
		aveDist := float64(dist1+dist2+dist3+dist4) / float64(4) / float64(i)
		if aveDist < smallestNormalizedDistance {
			smallestNormalizedDistance = aveDist
			keySize = i
		}
	}

	// Transpose array
	transposed := util.Transpose(input, keySize)

	// Find the key
	key = make([]byte, keySize)
	blockSize := len(input) / keySize
	for i := 0; i < keySize; i++ {
		start := i * blockSize
		end := (i + 1) * blockSize
		if end > len(transposed) {
			end = len(transposed) - 1
		}
		_, key[i], _ = CrackSingleByteXor(transposed[start:end])
	}

	// Decrypt results
	plaintext = RepeatingKeyXor(input, key)
	return
}
