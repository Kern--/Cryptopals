package set2

import (
	"encoding/hex"

	"fmt"

	"encoding/base64"

	"github.com/kern--/Cryptopals/krypto"
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
	paddedPlaintext, err := ecbCipher.Decrypt(ecbCipherText)
	if err != nil {
		fmt.Println("error decrypting with ecb:", err.Error())
		return
	}
	finalEcb, err := util.RemovePkcs7Padding(paddedPlaintext, 16)
	if err != nil {
		fmt.Println("error removing padding from ecb:", err.Error())
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

// RunChallenge12 tests that set2 challenge12 has been correctly implemented
func RunChallenge12() {
	attacker := aes.NewEcbAttacker(aes.AddSecret)
	plaintext, err := attacker.DecryptEcbInnerSecret()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(plaintext))
}

// RunChallenge13 tests that set2 challenge13 has been correctly implemented
func RunChallenge13() {
	// Test KVP parser
	input := "email=test@test.com&uid=10&role=user"
	dict := krypto.ParseProfileKeyValuePairs(input)
	util.PrintResults("3", fmt.Sprintf("%d", len(dict)))
	util.PrintResults("test@test.com", dict["email"])
	util.PrintResults("10", dict["uid"])
	util.PrintResults("user", dict["role"])
	output := krypto.EncodeProfileKeyValuePairs(dict)
	util.PrintResults(input, output)

	// Test profile encryption/decryption
	encryptedProfile, err := krypto.GetProfile("test@test.com&role=admin")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	profile, err := krypto.ParseEncryptedProfile(encryptedProfile)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	util.PrintResults("3", fmt.Sprintf("%d", len(profile)))
	util.PrintResults("test@test.com&role=admin", profile["email"])
	util.PrintResults("10", profile["uid"])
	util.PrintResults("user", profile["role"])

	// Test forging an admin role
	fmt.Println("\nForging an admin user")
	encryptedProfile, err = krypto.GenerateAdminUserToken()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	profile, err = krypto.ParseEncryptedProfile(encryptedProfile)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	util.PrintResults("admin", profile["role"])
}

// RunChallenge14 tests that set2 challenge14 has been correctly implemented
func RunChallenge14() {
	attacker := aes.NewEcbAttacker(aes.AddSaltySecret)
	plaintext, err := attacker.DecryptEcbInnerSecret()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(plaintext))
}
