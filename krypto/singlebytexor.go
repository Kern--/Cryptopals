package krypto

import (
	"math"

	"encoding/hex"

	"github.com/kern--/Cryptopals/util"
)

type singleByteXorResult struct {
	input     string
	plainText []byte
	key       byte
	score     float64
}

// CrackSingleByteXor takes a byte array which has been xor'd against a single byte
//  and finds the byte which it was xor'd against as well as the original message
//  and finally the english-liklihood score (lower = more likely english)
func CrackSingleByteXor(input []byte) ([]byte, byte, float64) {
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
	return bestPlainText, bestKey, bestScore
}

// DetectSingleByteXor takes a list of string inputs and finds the one
//  that is most likely to be english and returns the input itself,
//  the plaintext, the key, and the english-liklihood score (lower + more likely english)
func DetectSingleByteXor(inputs []string) (string, []byte, byte, float64) {
	numInputs := len(inputs)
	bestResult := singleByteXorResult{"", nil, 0, math.MaxFloat64}
	bestResults := make([]singleByteXorResult, numInputs)

	// Score all the inputs
	for i, input := range inputs {
		inputBytes, _ := hex.DecodeString(input)
		plainText, key, score := CrackSingleByteXor(inputBytes)
		bestResults[i] = singleByteXorResult{input, plainText, key, score}
	}

	// Find the lowest score
	for _, result := range bestResults {
		if result.score < bestResult.score {
			bestResult = result
		}
	}
	return bestResult.input, bestResult.plainText, bestResult.key, bestResult.score
}
