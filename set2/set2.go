package set2

import "github.com/kern--/Cryptopals/util"
import "encoding/hex"

// RunChallenge9 tests that set2 challenge9 has been correctly implemented
func RunChallenge9() {
	util.PrintChallengeHeader(2, 9)
	input := "YELLOW SUBMARINE"
	// "YELLOW SUBMARINE\x04\x04\x04\x04" hex encoded
	expected := "59454c4c4f57205355424d4152494e4504040404"
	actual := util.AddPkcs7Padding([]byte(input), 20)

	util.PrintResults(expected, hex.EncodeToString(actual))
}
