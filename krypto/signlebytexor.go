package krypto

import (
	"math"

	"github.com/kern--/Cryptopals/util"
)

// CrackSingleByteXor takes a byte array which has been xor'd against a single byte
//  and finds the byte which it was xor'd against as well as the original message
func CrackSingleByteXor(input []byte) ([]byte, byte) {
	var bestKey byte
	var bestPlainText []byte
	bestScore := math.MaxFloat64

	// Peform a single byte xor of the input with every possible byte
	//  for each one, score the resulting plaintext
	//  return the one with the lowest score (i.e. most likely to be english)
	for i := 0; i <= 0xFF; i++ {
		plainTextBytes := util.SingleByteXor(input, byte(i))
		plainText := string(plainTextBytes)
		score := util.Score(plainText)
		if score < bestScore {
			bestScore = score
			bestKey = byte(i)
			bestPlainText = plainTextBytes
		}
	}
	return bestPlainText, bestKey
}
