package aes

import (
	"encoding/hex"
	"errors"
	"strings"
)

func DecryptEcbInnerSecret() ([]byte, error) {
	// Find block size
	input := []byte("a")
	initialCipher, err := EncryptRandomConsistent(input)
	if err != nil {
		return nil, err
	}
	initialLength := len(initialCipher)
	increasedLength := initialLength
	i := 0
	for initialLength == increasedLength {
		input = append(input, byte('a'))
		newCipher, err := EncryptRandomConsistent(input)
		if err != nil {
			return nil, err
		}
		increasedLength = len(newCipher)
		i++
	}
	blockSize := increasedLength - initialLength
	// If we added a whole block's worth of junk before we increase the length
	//  then that means that the initial secret was an exact multiple of the block size
	//  and so therefore our initial size calculation included in char + blocksize-1 padding
	//  and so we should remove that from the secret length
	secretLength := initialLength - (i/blockSize)*blockSize

	// Determine encryption mode
	input = []byte("DUPLICATEBLOCKS!DUPLICATEBLOCKS!DUPLICATEBLOCKS!")
	ciphertext, err := EncryptRandomConsistent(input)
	if err != nil {
		return nil, err
	}
	mode := DetectAesMode(ciphertext, blockSize)
	if mode != ECB {
		return nil, errors.New("Cannot decrypt secret of cipher that doesn't use ECB")
	}

	// Decrypt the secret
	prevBlock := []byte(strings.Repeat("a", blockSize))
	plainText := make([]byte, secretLength)
	for i := 0; i*blockSize < secretLength; i++ {
		plaintextBlock, err := crackBlock(i, prevBlock, blockSize)
		if err != nil {
			return nil, err
		}
		prevBlock = plaintextBlock
		copy(plainText[i*blockSize:], plaintextBlock)
	}
	return plainText, nil
}

// crackBlock cracks a block of the unknown secret that is appended to a give plaintext before encrypting
func crackBlock(blockNum int, prevBlock []byte, blockSize int) ([]byte, error) {
	plainTextBlock := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		attackBlock := make([]byte, blockSize)
		copy(attackBlock, prevBlock[i+1:])
		copy(attackBlock[blockSize-1-i:], plainTextBlock[:i])
		cipherBlockDict, err := generateBlockDictionary(attackBlock, blockSize)
		if err != nil {
			return nil, err
		}
		junk := []byte(strings.Repeat("a", blockSize-1-i))
		cipherText, err := EncryptRandomConsistent(junk)
		correctBlock := cipherText[blockNum*blockSize : (blockNum+1)*blockSize]
		plainTextByte, exists := cipherBlockDict[hex.EncodeToString(correctBlock)]
		if !exists {
			// This shouldn't happen, but it seems to once I get to the padding
			//  bytes. I need to figure out what's wrong here...
			return plainTextBlock, nil
		}
		plainTextBlock[i] = byte(plainTextByte)
	}
	return plainTextBlock, nil
}

// Given a block, create a dictionary of the encrypted block for every possible last byte value
func generateBlockDictionary(baseBlock []byte, blockSize int) (map[string]byte, error) {
	dictionary := make(map[string]byte)
	baseBlockCopy := make([]byte, len(baseBlock))
	copy(baseBlockCopy, baseBlock)

	for i := 0; i <= 0xFF; i++ {
		baseBlockCopy[blockSize-1] = byte(i)
		cipherText, err := EncryptRandomConsistent(baseBlockCopy)
		if err != nil {
			return nil, err
		}
		block := cipherText[:blockSize]
		dictionary[hex.EncodeToString(block)] = byte(i)
	}
	return dictionary, nil
}
