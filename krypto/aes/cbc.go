package aes

import (
	"fmt"

	"github.com/kern--/Cryptopals/util"
)

// CbcCipher represents an AES CBC Cipher
type CbcCipher struct {
	key []byte
}

// NewAesCbcCipher creates a new AES CBC cipher
func NewAesCbcCipher(key []byte) *CbcCipher {
	return &CbcCipher{key}
}

// Encrypt encrypts a plaintext with AES CBC
func (cipher *CbcCipher) Encrypt(plaintext []byte, iv []byte) ([]byte, error) {
	blockSize := len(cipher.key)

	// Ensure IV is valid and is of the right length
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length (%d) != block size (%d)", len(iv), blockSize)
	}

	// Setup plaintext and ciphertext
	paddedPlaintext := util.AddPkcs7Padding(plaintext, blockSize)
	cipherText := make([]byte, len(paddedPlaintext))

	// Create an ecb cipher to actually perform the work
	ecbCipher := &EcbCipher{cipher.key}

	// Setup initial previous block
	previousBlock := iv
	for i := 0; i < len(paddedPlaintext); i += blockSize {
		// XOR previous block and current block
		curPlaintextBlock := util.Xor(previousBlock, paddedPlaintext[i:i+blockSize])
		// Encrypt XOR result to get current cipher block
		//   NOTE: since the ecb cipher uses pkcs7 and our plaintext
		//   is always block aligned, there will be an extra padding
		//   block in the resulting ciphertext
		curCipherText, err := ecbCipher.Encrypt(curPlaintextBlock)
		if err != nil {
			return nil, err
		}
		// Copy current cipher block into ciphertext (Probably should allow for a dst byte slice instead)
		copy(cipherText[i:i+blockSize], curCipherText[:blockSize])
		// Update previous block
		previousBlock = curCipherText[:blockSize]
	}
	return cipherText, nil
}

// Decrypt decrypts a ciphertext with AES CBC
func (cipher *CbcCipher) Decrypt(ciphertext []byte, iv []byte) ([]byte, error) {
	blockSize := len(cipher.key)

	// Ensure IV is valid and is of the right length
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length (%d) != block size (%d)", len(iv), blockSize)
	}

	// Setup plaintext
	plaintext := make([]byte, len(ciphertext))

	// Create an ecb cipher to actually perform the work
	ecbCipher := &EcbCipher{cipher.key}

	// Setup initial previous block
	previousBlock := iv
	for i := 0; i < len(ciphertext); i += blockSize {
		curCipherBlock := ciphertext[i : i+blockSize]
		// Decrypt current block
		curPlaintextBlock, err := ecbCipher.Decrypt(curCipherBlock)
		if err != nil {
			return nil, err
		}
		// XOR previous block and current block
		curPlaintextBlock = util.Xor(previousBlock, curPlaintextBlock)
		// Copy current cipher block into ciphertext (Probably should allow for a dst byte slice instead)
		copy(plaintext[i:i+blockSize], curPlaintextBlock)
		// Update previous block
		previousBlock = curCipherBlock
	}

	// Assume padding is correct for now and remove it
	numPaddingBytes := int(plaintext[len(plaintext)-1])

	return plaintext[:len(plaintext)-numPaddingBytes], nil
}
