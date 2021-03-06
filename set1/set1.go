package set1

import (
	"fmt"
	"strings"

	"encoding/hex"

	"io/ioutil"

	"encoding/base64"

	"github.com/kern--/Cryptopals/krypto"
	"github.com/kern--/Cryptopals/krypto/aes"
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
	plaintext, key, _ := krypto.CrackSingleByteXor(inputBytes)
	fmt.Println("Key:", key)
	fmt.Println("Plaintext:", string(plaintext))
}

// RunChallenge4 tests that set1 challenge4 has been correctly implemented
func RunChallenge4() {
	util.PrintChallengeHeader(1, 4)
	data, err := ioutil.ReadFile("set1/resources/challenge4.txt")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	inputs := strings.Split(string(data), "\n")
	input, plaintext, key, _ := krypto.DetectSingleByteXor(inputs)
	fmt.Println("Input:", input)
	fmt.Println("Key", key)
	fmt.Println("Plaintext:", string(plaintext))
}

// RunChallenge5 tests that set1 challenge5 has been correctly implemented
func RunChallenge5() {
	util.PrintChallengeHeader(1, 5)
	input := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	result := krypto.RepeatingKeyXor([]byte(input), []byte(key))
	util.PrintResults(expected, hex.EncodeToString(result))
}

// RunChallenge6 tests that set1 challenge6 has been correctly implemented
func RunChallenge6() {
	util.PrintChallengeHeader(1, 6)
	// Test Hammingdistance
	hamminga := "this is a test"
	hammingb := "wokka wokka!!!"
	hammingDistance := util.HammingDistance([]byte(hamminga), []byte(hammingb))
	fmt.Println("Testing hamming distance implementation")
	fmt.Println(hamminga)
	fmt.Println(hammingb)
	util.PrintResults("37", fmt.Sprintf("%d", hammingDistance))

	// Test Transpose
	toTranspose := "11221122112211221122"
	toTransposeBytes, _ := hex.DecodeString(toTranspose)
	expectedTransposed := "11111111112222222222"
	transposed := util.Transpose(toTransposeBytes, 2)
	util.PrintResults(expectedTransposed, hex.EncodeToString(transposed))

	// Load data
	data, err := ioutil.ReadFile("set1/resources/challenge6.txt")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	input := string(data)
	input = strings.Replace(input, "\n", "", -1)
	data, _ = base64.StdEncoding.DecodeString(input)

	// Crack Data
	plaintext, key := krypto.CrackRepeatingKeyXor(data)
	fmt.Println("Key:", string(key))
	fmt.Println("Plaintext:", string(plaintext))
}

// RunChallenge7 tests that set1 challenge7 has been correctly implemented
func RunChallenge7() {
	util.PrintChallengeHeader(1, 7)
	key := "YELLOW SUBMARINE"

	// Load data
	data, err := ioutil.ReadFile("set1/resources/challenge7.txt")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	input := string(data)
	input = strings.Replace(input, "\n", "", -1)
	data, _ = base64.StdEncoding.DecodeString(input)

	// Decrypt with known key
	cipher := aes.NewAesEcbCipher([]byte(key))
	plaintext, _ := cipher.Decrypt(data)

	fmt.Println("Plaintext:", string(plaintext))
}

// RunChallenge8 tests that set1 challenge8 has been correctly implemented
func RunChallenge8() {
	util.PrintChallengeHeader(1, 8)

	// Test duplicate block detector
	fmt.Println("Testing dupliacte block detector")
	dupBlockInput := "112233441122334455661122"
	dupBlockInputBytes, _ := hex.DecodeString(dupBlockInput)
	dupBlockExpected := "3"
	dupBlockActual := util.CountDuplicateBlocks(dupBlockInputBytes, 2)
	util.PrintResults(dupBlockExpected, fmt.Sprintf("%d", dupBlockActual))

	// Load data
	fileData, err := ioutil.ReadFile("set1/resources/challenge8.txt")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fileStrings := strings.Split(string(fileData), "\n")
	inputs := make([][]byte, len(fileStrings))
	for i, str := range fileStrings {
		inputBytes, _ := hex.DecodeString(str)
		inputs[i] = inputBytes
	}

	// Find most likely AES ECB
	aesEcb, count := aes.DetectAesEcb(inputs)
	fmt.Println("Num Duplicate Blocks:", count)
	fmt.Println("AES ECB Ciphertext:", hex.EncodeToString(aesEcb))
}
