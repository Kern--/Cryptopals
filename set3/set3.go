package set3

import (
	"fmt"

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
	}
	plaintext, err = util.RemovePkcs7Padding(plaintext, 16)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(plaintext))
}
