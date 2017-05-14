package set1

import (
	"fmt"

	"encoding/hex"

	"github.com/kern--/Cryptopals/krypto"
	"github.com/kern--/Cryptopals/util"
)

// RunChallenge1 tests that set1 challenge1 has been correctly implemented
func RunChallenge1() {
	util.PrintChallengeHeader(1, 1)
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	encoded, err := util.HexToBase64(input)
	if err != nil {
		fmt.Println("Base64 encode error:", err.Error())
	}
	util.PrintResults(expected, encoded)
}

// RunChallenge2 tests that set1 challenge2 has been correctly implemented
func RunChallenge2() {
	util.PrintChallengeHeader(1, 2)
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"

	input1Bytes, _ := hex.DecodeString(input1)
	input2Bytes, _ := hex.DecodeString(input2)

	result := util.Xor(input1Bytes, input2Bytes)
	resultString := hex.EncodeToString(result)
	util.PrintResults(expected, resultString)
}

// RunChallenge3 tests that set1 challenge3 has been correctly implemented
func RunChallenge3() {
	util.PrintChallengeHeader(1, 3)
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

	inputBytes, _ := hex.DecodeString(input)
	plaintext, key := krypto.CrackSingleByteXor(inputBytes)
	fmt.Println("Key:", key)
	fmt.Println("Plaintext:", string(plaintext))
}
