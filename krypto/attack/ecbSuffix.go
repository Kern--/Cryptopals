package attack

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/kern--/Cryptopals/krypto/aes"
	"github.com/kern--/Cryptopals/krypto/application"
)

// EcbSuffixAttacker is a type that can break inner secrets appended to a plaintext before encrypting with AES ECB
type EcbSuffixAttacker struct {
	app *application.Ecb
}

// NewEcbSuffixAttacker creates a new EcbSuffixAttacker
func NewEcbSuffixAttacker(app *application.Ecb) *EcbSuffixAttacker {
	return &EcbSuffixAttacker{app}
}

// DecryptSecretSuffix given that the ECB encryption method inside this
// function encrypts a user input concatenated with a secret plaintext before
// encrypting with a consistent, unknown key, decrypt that secret plaintext
// and return it
func (attacker *EcbSuffixAttacker) DecryptSecretSuffix() ([]byte, error) {
	// Determine block size
	input := []byte("a")
	initialCipher, err := attacker.app.Encrypt(input)
	if err != nil {
		return nil, err
	}
	initialLen := len(initialCipher)
	increasedLen := initialLen
	i := 0
	for initialLen == increasedLen {
		input = append(input, byte('a'))
		newCipher, err := attacker.app.Encrypt(input)
		if err != nil {
			return nil, err
		}
		increasedLen = len(newCipher)
		i++
	}
	blockSize := increasedLen - initialLen

	// Determine encryption mode
	input = []byte(strings.Repeat("b", 8*blockSize))
	ciphertext, err := attacker.app.Encrypt(input)
	if err != nil {
		return nil, err
	}
	mode := aes.DetectAesMode(ciphertext, blockSize)
	if mode != aes.ECB {
		return nil, errors.New("Cannot decrypt secret of cipher that doesn't use ECB")
	}

	// Determine the salt length
	saltLen, padLen, err := attacker.determineSaltLength(blockSize)
	if err != nil {
		return nil, err
	}

	// Determine the number of blocks filled by salt if we pad it to be an even multiple of the block size
	//  This allows us to crack the secret as if there were no salt by simply ignoring the first n blocks,
	//  which are completely filled by a padded salt
	blockOffset := (saltLen + padLen) / blockSize

	// Determine the secret length
	secretLen, err := attacker.determineSecretLength(blockSize, saltLen, padLen)
	if err != nil {
		return nil, err
	}

	// Decrypt the secret
	prevBlock := []byte(strings.Repeat("b", blockSize))
	plainText := make([]byte, secretLen)
	for i := 0; i*blockSize < secretLen; i++ {
		plaintextBlock, err := attacker.crackBlock(i, padLen, prevBlock, blockSize, blockOffset)
		if err != nil {
			return nil, err
		}
		prevBlock = plaintextBlock
		copy(plainText[i*blockSize:], plaintextBlock)
	}
	return plainText, nil
}

// determineSaltLength the determines the legnth of an unknown salt prepended to every plaintext
func (attacker *EcbSuffixAttacker) determineSaltLength(blockSize int) (int, int, error) {
	for padLen := 0; padLen < blockSize; padLen++ {
		pad := []byte(strings.Repeat("a", padLen))
		input := []byte(strings.Repeat("b", 3*blockSize))
		input = append(pad, input...)
		ciphertext, err := attacker.app.Encrypt(input)
		if err != nil {
			return 0, 0, err
		}
		inputStart := findConsecutiveIdenticalBlocks(ciphertext, blockSize, 3)
		if inputStart > 0 {
			return inputStart - padLen, padLen, nil
		}
	}
	return 0, 0, nil
}

// determineSecretLength determines the length of a secret that is appeneded to every plaintext
//  this assumes you already know if there is a prepended salt, what that salt's length is,
//  and how many bytes must be added to the salt to block align it
func (attacker *EcbSuffixAttacker) determineSecretLength(blockSize int, saltLen int, padLen int) (int, error) {
	pad := []byte(strings.Repeat("a", padLen))
	ciphertext, err := attacker.app.Encrypt(pad)
	if err != nil {
		return 0, err
	}
	initialLen := len(ciphertext)

	for inputLen := 1; inputLen < blockSize+1; inputLen++ {
		input := pad
		input = append(input, []byte(strings.Repeat("a", inputLen))...)
		ciphertext, err := attacker.app.Encrypt(input)
		if err != nil {
			return 0, err
		}
		if len(ciphertext) != initialLen {
			prefixLen := saltLen + padLen
			return len(ciphertext) - prefixLen - inputLen - blockSize + 1, nil
		}
	}
	return 0, errors.New("Did not find the secret length. This should not happen")
}

// findConsecutiveIdenticalBlocks finds the starting index of the first instance
//  where there are numBlocks identical consecutive blocks.
//  returns -1 if there are no instances of consecutive identical blocks
func findConsecutiveIdenticalBlocks(input []byte, blockSize int, numBlocks int) int {
	// i = start index
	// j = offset within a block
	// k = block to compare against
	for i := 0; i+numBlocks*blockSize < len(input); i += blockSize {
		identical := true
		for j := 0; j < blockSize; j++ {
			for k := 0; k < numBlocks; k++ {
				if input[i+j] != input[i+j+k*blockSize] {
					identical = false
					break
				}
			}
			if identical {
				return i
			}
		}
	}
	return -1
}

// crackBlock cracks a block of the unknown secret that is appended to a give plaintext before encrypting
func (attacker *EcbSuffixAttacker) crackBlock(blockNum int, padLen int, prevBlock []byte, blockSize int, blockOffset int) ([]byte, error) {
	plainTextBlock := make([]byte, blockSize)
	pad := []byte(strings.Repeat("a", padLen))
	for i := 0; i < blockSize; i++ {
		attackBlock := make([]byte, blockSize)
		copy(attackBlock, prevBlock[i+1:])
		copy(attackBlock[blockSize-1-i:], plainTextBlock[:i])
		attackBlock = append(pad, attackBlock...)
		cipherBlockDict, err := attacker.generateBlockDictionary(attackBlock, blockSize, blockOffset)
		if err != nil {
			return nil, err
		}
		junk := []byte(strings.Repeat("b", blockSize-1-i))
		junk = append(pad, junk...)
		cipherText, err := attacker.app.Encrypt(junk)
		correctBlock := cipherText[(blockNum+blockOffset)*blockSize : (blockNum+blockOffset+1)*blockSize]
		plainTextByte, exists := cipherBlockDict[hex.EncodeToString(correctBlock)]
		if !exists {
			// This should never happen on a real plaintext byte because we've made a dictionary
			//  of every possible value for the last byte and already knowing ever plaintext byte
			//  that comest before it.
			// However, once we start cracking the PKCS#7 padding, we will find the first byte =0x1
			//  and when we build our dictionary, we will use this value as the second to last
			//  byte. In the real situation, though, we added a byte, so the padding will change to 0x2
			//  which means that all our dictionary entries were using the last second to last byte
			//  and we will not find a match.
			// Therefore, we assume that if the dictionary does not contain a match, we're cracking the
			//  padding which means we were already done 1 byte ago
			return plainTextBlock[:i-1], nil
		}
		plainTextBlock[i] = byte(plainTextByte)
	}
	return plainTextBlock, nil
}

// Given a block, create a dictionary of the encrypted block for every possible last byte value
func (attacker *EcbSuffixAttacker) generateBlockDictionary(baseBlock []byte, blockSize int, blockOffset int) (map[string]byte, error) {
	dictionary := make(map[string]byte)
	baseBlockCopy := make([]byte, len(baseBlock))
	copy(baseBlockCopy, baseBlock)

	for i := 0; i <= 0xFF; i++ {
		baseBlockCopy[len(baseBlockCopy)-1] = byte(i)
		cipherText, err := attacker.app.Encrypt(baseBlockCopy)
		if err != nil {
			return nil, err
		}
		block := cipherText[blockOffset*blockSize : (blockOffset+1)*blockSize]
		dictionary[hex.EncodeToString(block)] = byte(i)
	}
	return dictionary, nil
}
