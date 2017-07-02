package main

import (
	"flag"
	"fmt"

	"github.com/kern--/Cryptopals/set1"
	"github.com/kern--/Cryptopals/set2"
	"github.com/kern--/Cryptopals/set3"
)

type challenge func()

var challenges = [...]challenge{
	// Insert noop function so that numbering starts at 1
	noop,
	set1.RunChallenge1,
	set1.RunChallenge2,
	set1.RunChallenge3,
	set1.RunChallenge4,
	set1.RunChallenge5,
	set1.RunChallenge6,
	set1.RunChallenge7,
	set1.RunChallenge8,
	set2.RunChallenge9,
	set2.RunChallenge10,
	set2.RunChallenge11,
	set2.RunChallenge12,
	set2.RunChallenge13,
	set2.RunChallenge14,
	set2.RunChallenge15,
	set2.RunChallenge16,
	set3.RunChallenge17,
	set3.RunChallenge18,
}

var sets = [...][]challenge{
	// 0 = all sets
	challenges[1:],
	challenges[1:8],
	challenges[9:16],
	challenges[17:],
}

func main() {
	var set = flag.Int("set", -1, fmt.Sprintf("runs the specified set of challenges. (0-%d), 0 = all sets", len(sets)-1))
	var challenge = flag.Int("challenge", -1, fmt.Sprintf("runs the specified challenge. (1-%d)", len(challenges)-1))
	flag.Parse()

	// If the user specified a challenge, run it.
	if *challenge > 0 && *challenge < len(challenges) {
		runChallenge(*challenge)
		return
	}
	// If  the user specified a set, run it.
	if *set >= 0 && *set < len(sets) {
		runSet(*set)
		return
	}
	// If the user didn't supply a valid set or challenge, run all
	runSet(0)
}

func runSet(set int) {
	runChallenges(sets[set])
}

func runChallenge(challenge int) {
	runChallenges(challenges[challenge : challenge+1])
}

func runChallenges(challenges []challenge) {
	for _, challenge := range challenges {
		challenge()
	}
}

// noop does absolutely nothing. Useful for filling space in the challenges slice so that it is numbered from 1
func noop() {}
