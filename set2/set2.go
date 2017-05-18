package set2

import (
	"encoding/hex"

	"fmt"

	"encoding/base64"

	"github.com/kern--/Cryptopals/krypto/aes"
	"github.com/kern--/Cryptopals/util"
)

// RunChallenge9 tests that set2 challenge9 has been correctly implemented
func RunChallenge9() {
	util.PrintChallengeHeader(2, 9)
	input := "YELLOW SUBMARINE"
	// "YELLOW SUBMARINE\x04\x04\x04\x04" hex encoded
	expected := "59454c4c4f57205355424d4152494e4504040404"
	actual := util.AddPkcs7Padding([]byte(input), 20)

	util.PrintResults(expected, hex.EncodeToString(actual))
}

// RunChallenge10 tests that set2 challenge10 has been correctly implemented
func RunChallenge10() {
	util.PrintChallengeHeader(2, 10)

	// The same key is used throughout this challenge
	key := []byte("YELLOW SUBMARINE")

	// Test ECB Encryption
	ecbPlainText := "This test really contains at exactly (3) blocks."

	ecbCipher := aes.NewAesEcbCipher(key)
	ecbCipherText, err := ecbCipher.Encrypt([]byte(ecbPlainText))
	if err != nil {
		fmt.Println("error encrypting with ecb:", err.Error())
		return
	}
	finalEcb, err := ecbCipher.Decrypt(ecbCipherText)
	if err != nil {
		fmt.Println("error decrypting with ecb:", err.Error())
		return
	}
	util.PrintResults(ecbPlainText, string(finalEcb))

	// Test CBC Encryption
	cbcPlainText := "This is not a block aligned"
	cbcIv := "DEFINITELYSECRET"

	cbcCipher := aes.NewAesCbcCipher(key)
	cbcCipherText, err := cbcCipher.Encrypt([]byte(cbcPlainText), []byte(cbcIv))
	if err != nil {
		fmt.Println("error encrypting with cbc:", err.Error())
		return
	}
	finalCbc, err := cbcCipher.Decrypt(cbcCipherText, []byte(cbcIv))
	if err != nil {
		fmt.Println("error decrypting with cbc:", err.Error())
		return
	}
	util.PrintResults(cbcPlainText, string(finalCbc))

	// Load Data
	input, err := util.ReadFileRemoveNewline("set2/resources/challenge10.txt")
	if err != nil {
		fmt.Println("error reading filedata", err.Error())
		return
	}
	data, _ := base64.StdEncoding.DecodeString(input)
	iv := make([]byte, 16)

	// Decrypt
	cbcCipher = aes.NewAesCbcCipher(key)
	plaintext, err := cbcCipher.Decrypt(data, iv)
	fmt.Println(string(plaintext))
}

// RunChallenge11 tests that set2 challenge11 has been correctly implemented
func RunChallenge11() {
	plaintext := "DUPLICATEBLOCKS!DUPLICATEBLOCKS!DUPLICATEBLOCKS!"
	for i := 0; i < 10; i++ {
		ciphertext, _ := aes.EncryptRandom([]byte(plaintext))
		fmt.Println(hex.EncodeToString(ciphertext))
		aesMode := aes.DetectAesMode(ciphertext, 16)
		switch aesMode {
		case aes.ECB:
			println("Probably AES ECB")
		case aes.CBC:
			println("Probably AES CBC")
		}
	}
}
