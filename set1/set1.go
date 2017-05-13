package set1

import (
	"fmt"

	"github.com/kern--/Cryptopals/util"
)

// RunChallenge1 tests that set1 challenge1 has been correctly implemented
func RunChallenge1() {
	fmt.Println("Running set 1 challeng 1")
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	encoded, err := util.HexToBase64(input)
	if err != nil {
		fmt.Println("Base64 encode error:", err.Error())
	}
	fmt.Println("Expected:", expected)
	fmt.Println("Actual:", encoded)
	if expected == encoded {
		fmt.Println("OK")
	} else {
		fmt.Println("FAILED")
	}
}
