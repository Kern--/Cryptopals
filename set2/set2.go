package set2

import (
	"encoding/hex"

	"fmt"

	"encoding/base64"

	"github.com/kern--/Cryptopals/krypto/aes"
	"github.com/kern--/Cryptopals/krypto/application"
	"github.com/kern--/Cryptopals/krypto/attack"
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
	util.PrintChallengeHeader(2, 11)

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
	util.PrintChallengeHeader(2, 12)

	attacker := attack.NewEcbSuffixAttacker(application.NewSecretSuffixEcb(16))
	plaintext, err := attacker.DecryptSecretSuffix()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(plaintext))
}

// RunChallenge13 tests that set2 challenge13 has been correctly implemented
func RunChallenge13() {
	util.PrintChallengeHeader(2, 13)

	// Test KVP parser
	input := "email=test@test.com&uid=10&role=user"
	dict := util.DecodeQueryString(input, "=", "&")
	util.PrintResults("3", fmt.Sprintf("%d", len(dict)))
	util.PrintResults("test@test.com", dict["email"])
	util.PrintResults("10", dict["uid"])
	util.PrintResults("user", dict["role"])
	output := util.EncodeToQueryString(dict, []string{"email", "uid", "role"}, "=", "&")
	util.PrintResults(input, output)

	// Test profile encryption/decryption
	userProfile := application.NewEcbUserProfile()
	encryptedProfile, err := userProfile.GetEncryptedProfile("test@test.com&role=admin")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	hasAdmin, err := userProfile.HasAdminRole(encryptedProfile)
	if err != nil {
		fmt.Println(err.Error())
		return
	} else if hasAdmin {
		fmt.Println("FAILED - user got admin role when they shouldn't")
	} else {
		fmt.Println("OK")
	}

	// Test forging an admin role
	fmt.Println("\nForging an admin user")
	attacker := attack.NewUserProfileAttacker(userProfile)
	encryptedProfile, err = attacker.ForgeAdminToken()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	hasAdmin, err = userProfile.HasAdminRole(encryptedProfile)
	if err != nil {
		fmt.Println(err.Error())
		return
	} else if hasAdmin {
		fmt.Println("OK")
	} else {
		fmt.Println("FAILED - admin role forgery failed")
	}
}

// RunChallenge14 tests that set2 challenge14 has been correctly implemented
func RunChallenge14() {
	util.PrintChallengeHeader(2, 14)

	attacker := attack.NewEcbSuffixAttacker(application.NewPrefixedSecretSuffixEcb(16))
	plaintext, err := attacker.DecryptSecretSuffix()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(plaintext))
}

// RunChallenge15 tests that set2 challenge15 has been correctly implemented
func RunChallenge15() {
	util.PrintChallengeHeader(2, 15)
	// Valid test
	input := "FullBlockTest!"
	paddedInput := util.AddPkcs7Padding([]byte(input), 16)
	output, err := util.RemovePkcs7Padding(paddedInput, 16)
	if err != nil {
		fmt.Println("Error removing padding from valid input:", err.Error())
	}
	util.PrintResults(input, string(output))

	// Invalid test
	input = "NotCorrect\x03"
	_, err = util.RemovePkcs7Padding([]byte(input), 16)
	if err == nil {
		fmt.Println("No error on invalid padding")
	} else {
		fmt.Println("Correctly errored on invalid padding")
	}
}

// RunChallenge16 tests that set2 challenge16 has been correctly implemented
func RunChallenge16() {
	util.PrintChallengeHeader(2, 16)

	queryBuilder := application.NewCbcQueryBuilder()

	input := []byte(";admin=true")
	query, err := queryBuilder.GetEncryptedQuery(input)
	if err != nil {
		fmt.Println("Error generating encrypted query", err.Error())
	}
	hasRole, err := queryBuilder.HasAdminRole(query)
	if err != nil {
		fmt.Println("Error checking for admin role", err.Error())
	}
	if hasRole {
		fmt.Println("Unexpectedly has admin role")
	} else {
		fmt.Println("OK")
	}

	// Encrypt a known, block aligned plaintext such that we can manipulate the ciphertext to control how it will be decrypted.
	// Since CBC mode decryption XORs the previous ciphertext block with the next block AFTER decrypting
	//   the next block, any bit flips in the previous ciphertext result in the same bit flips in the next
	//   plaintext block.
	// We also have the property that a ^ (a ^ b) = b
	// The actual algorithm:
	// bbbbbbbbbbbbbbbb                    - create a block full of junk that we don't care about
	// bbbbbbbbbbbbbbbb aaaaa-admin-true   - append a block with sensitive characters replaced (in this case ';' and '=' replaced by '-')
	// ???????????????? ????????????????   - encrypt
	// ?????s?????e???? ????????????????   - xor bytes 5 and 11 by (';' ^ '-') and ('=' ^ '-') respectively
	// ################ aaaaa;admin=true   - decrypt. the first block will be meaningless
	//                                                the second block will have bytes 5 and 11 xored with (';' ^ '-') and ('=' ^ '-') respectively
	//                                                '-' ^ (';' ^ '-') = ';'
	//                                                '-' ^ ('=' ^ '-') = '='

	input = []byte("bbbbbbbbbbbbbbbbaaaaa-admin-true")
	query, err = queryBuilder.GetEncryptedQuery(input)
	if err != nil {
		fmt.Println("Error generating encrypted query", err.Error())
	}

	// ';' ^ '-' = 0x16
	// '=' ^ '-' = 0x10
	query[32+5] ^= 0x16  // convert '-' to ';'
	query[32+11] ^= 0x10 // convert '-' to '='

	hasRole, err = queryBuilder.HasAdminRole(query)
	if err != nil {
		fmt.Println("Error checking for admin role", err.Error())
	}
	if hasRole {
		fmt.Println("OK")
	} else {
		fmt.Println("Bit flip attack failed")
	}
}
