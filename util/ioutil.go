package util

import "fmt"

// PrintChallengeHeader prints a standard block to indicate which challenge is running
func PrintChallengeHeader(set int, challenge int) {
	fmt.Println("\nRunning set", set, "challenge", challenge)
}

// PrintReults prints the expected and actual values as well as whether or not they're equal
func PrintResults(expected string, result string) {
	fmt.Println("Expected:", expected)
	fmt.Println("Actual:", result)
	if expected == result {
		fmt.Println("OK")
	} else {
		fmt.Println("FAILED")
	}
}