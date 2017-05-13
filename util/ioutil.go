package util

import "fmt"

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
