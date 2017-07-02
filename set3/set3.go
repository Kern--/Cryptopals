package set3

import (
	"fmt"

	"encoding/base64"

	"github.com/kern--/Cryptopals/krypto/aes"
	"github.com/kern--/Cryptopals/krypto/application"
	"github.com/kern--/Cryptopals/krypto/attack"
	"github.com/kern--/Cryptopals/util"
)

// RunChallenge17 tests that set3 challenge17 has been correctly implemented
func RunChallenge17() {
	util.PrintChallengeHeader(3, 17)
	paddingOracle := application.NewCbcPaddingOracle()
	paddingOracleAttack := attack.NewCbcPaddingOracleAttack(paddingOracle)
	plaintext, err := paddingOracleAttack.Decrypt()
	if err != nil {
		fmt.Println(err)
		return
	}
	plaintext, err = util.RemovePkcs7Padding(plaintext, 16)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(plaintext))
}

// RunChallenge18 tests that set3 challenge18 has been correctly implemented
func RunChallenge18() {
	util.PrintChallengeHeader(3, 18)
	cipherText := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	cipherTextBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	// Decrypt with key="YELLOW SUBMARINE", nonce=empty
	key := []byte("YELLOW SUBMARINE")
	cipher := aes.NewAesCtrCipher(key)
	plainText, err := cipher.Decrypt(cipherTextBytes, nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(string(plainText))
}
