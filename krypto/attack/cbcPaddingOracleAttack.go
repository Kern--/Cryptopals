package attack

import (
	"errors"

	"github.com/kern--/Cryptopals/krypto/application"
	"github.com/kern--/Cryptopals/util"
)

// CbcPaddingOracleAttack is a struct that can decrypt a secret given a CBC padding oracle
type CbcPaddingOracleAttack struct {
	oracle *application.CbcPaddingOracle
}

// NewCbcPaddingOracleAttack creates a new CbcPaddingOracleAttack
func NewCbcPaddingOracleAttack(oracle *application.CbcPaddingOracle) *CbcPaddingOracleAttack {
	return &CbcPaddingOracleAttack{oracle}
}

// Decrypt decrypts the secret contained within a CbcPaddingOracle
func (attack *CbcPaddingOracleAttack) Decrypt() ([]byte, error) {
	cipherText, iv, err := attack.oracle.GetCipherText()
	lenCipherText := len(cipherText)
	if err != nil {
		return nil, err
	}
	plainText := make([]byte, lenCipherText)

	// Decrypt each block starting from the end
	for i := 0; i < lenCipherText; i += 16 {
		truncatedCipherTextLen := lenCipherText - i
		plainTextBlock, err := attack.decryptBlock(cipherText[0:truncatedCipherTextLen], iv)
		if err != nil {
			return nil, err
		}
		copy(plainText[lenCipherText-i-16:], plainTextBlock)
	}
	return plainText, nil
}

// decryptBlock decryptes the final block of a cipher text.
func (attack *CbcPaddingOracleAttack) decryptBlock(cipherText []byte, iv []byte) ([]byte, error) {
	blockSize := len(iv)
	plainTextBlock := make([]byte, blockSize)
	cipherLen := len(cipherText)
	ivCopy := make([]byte, blockSize)
	cipherTextCopy := make([]byte, cipherLen)

	// Repeat until we've decrypted the whole block
	for i := blockSize - 1; i >= 0; i-- {
		// Guess the value of the ith byte of the final block in the cipher text
		for guess := 0; guess < 256; guess++ {

			// Make a copy of the cipherText and iv so we can modify them
			copy(cipherTextCopy, cipherText)
			copy(ivCopy, iv)

			// Determine which block will modify. If there is more that one block, use the previous block
			//  if there is only one block, use the IV
			attackBlock := ivCopy
			if cipherLen >= 2*blockSize {
				attackBlock = cipherTextCopy[cipherLen-2*blockSize : cipherLen-blockSize]
			}

			// Prepare ciphertext by applying the transforms the the attack block
			//  if successful, CanDecrypt should return no error, indicating that
			//  the padding is correct
			applyPlaintextGuess(attackBlock, plainTextBlock, i, byte(guess))
			err := attack.oracle.CanDecrypt(cipherTextCopy, ivCopy)
			if err == nil {
				plainTextBlock[i] = byte(guess)
				break
			}
			if err != util.ErrInvalidPadding {
				return nil, err
			}
			if guess == 255 {
				return nil, errors.New("Could not find a valid plaintext byte")
			}
		}
	}
	return plainTextBlock, nil
}

func applyPlaintextGuess(attackBlock []byte, plainTextBlock []byte, guessIndex int, guess byte) {
	blockSize := len(attackBlock)
	// xor all known values with the previous block
	attackedBlock := util.Xor(attackBlock, plainTextBlock)
	// guess the current byte value
	attackedBlock[guessIndex] ^= guess

	// If we're trying to guess the last byte in the block and we're guessing 1,
	//  mess with the second to last byte in the block. Since the guess is 1
	//  and the padding is 1, we're doing cipherByte^1^1, i.e. not changing the cipher byte.
	//  This means the padding oracle will accept ANY valid pkcs#7 padding, but we
	//  only want it to accept the padding the plaintext byte is 1 (since that's our guess)
	// By messing with the second to last byte, we ensure that the padding cannot be valid
	//  unless the guess of 1 is correct
	if guessIndex == blockSize-1 && guess == 1 {
		attackedBlock[guessIndex-1] ^= 1
	}

	// Mix in the padding
	lenPadding := blockSize - guessIndex

	for i := 0; i < lenPadding; i++ {
		attackedBlock[blockSize-1-i] ^= byte(lenPadding)
	}
	// Copy back into the block to attack
	copy(attackBlock, attackedBlock)
}
