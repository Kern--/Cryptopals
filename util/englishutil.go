package util

import (
	"math"
)

// The frequency of each letter in the english language as a percentage
//  taken from wikipedia: https://en.wikipedia.org/wiki/Letter_frequency
var characterFrequency = map[rune]float64{
	'a': 0.08167,
	'b': 0.01492,
	'c': 0.02782,
	'd': 0.04253,
	'e': 0.12702,
	'f': 0.02228,
	'g': 0.02015,
	'h': 0.06094,
	'i': 0.06966,
	'j': 0.00153,
	'k': 0.00772,
	'l': 0.04025,
	'm': 0.02406,
	'n': 0.06749,
	'o': 0.07507,
	'p': 0.01929,
	'q': 0.00095,
	'r': 0.05987,
	's': 0.06327,
	't': 0.09056,
	'u': 0.02758,
	'v': 0.00978,
	'w': 0.02360,
	'x': 0.00150,
	'y': 0.01974,
	'z': 0.00074,
}

// Score scores a piece of text where a lower score means that the text is more likely to be english
func Score(english string) float64 {
	englishLen := len(english)
	charCounts := make(map[rune]int)
	var score float64

	// Find the number of occurances of each character
	for _, char := range english {
		count, exists := charCounts[char]
		if !exists {
			count = 0
		}
		charCounts[char] = count + 1
	}

	// For each english letter, let penalty = abs(frequency in english - frequency in input)
	//  let score = sum of penalties for all english letters
	for char, engFrequency := range characterFrequency {
		count, exists := charCounts[char]
		if !exists {
			count = 0
		}
		frequency := float64(count) / float64(englishLen)
		score = score + math.Abs(engFrequency-frequency)
	}

	// Add extra penalty for using non-letters, except for ' '
	for char := range charCounts {
		frequency, exists := charCounts[char]
		if !exists && frequency != ' ' {
			score++
		}
	}
	return score
}
