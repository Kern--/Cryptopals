package util

import "fmt"
import "strings"
import "unicode/utf8"

// PrintChallengeHeader prints a standard block to indicate which challenge is running
func PrintChallengeHeader(set int, challenge int) {
	header := fmt.Sprintf("Running set %d challenge %d", set, challenge)
	fmt.Printf("\n%s\n", header)
	fmt.Println(strings.Repeat("-", utf8.RuneCountInString(header)))
}

// PrintReults prints the expected and actual values as well as whether or not they're equal
func PrintResults(expected string, result string) {
	fmt.Println("Expected:", expected)
	fmt.Println("Actual:  ", result)
	if expected == result {
		fmt.Println("OK")
	} else {
		fmt.Println("FAILED")
	}
}
