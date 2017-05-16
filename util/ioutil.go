package util

import (
	"fmt"
	"io/ioutil"
	"strings"
	"unicode/utf8"
)

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

// ReadFileRemoveNewline reads in an entire file and removes all newlines
func ReadFileRemoveNewline(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	output := string(data)
	output = strings.Replace(output, "\n", "", -1)
	return output, nil
}
