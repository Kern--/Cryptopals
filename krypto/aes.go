package krypto

import (
	"crypto/aes"
)

// EcbCipher represents an AES ECB cipher since golang does not ship with this mode
type EcbCipher struct {
	key []byte
}

// NewAesEcbCipher creates a new cipher that can be used to handle AES ECB encryption
func NewAesEcbCipher(key []byte) *EcbCipher {
	return &EcbCipher{key}
}

// Decrypt decrypts a ciphertext that has been encrypted with AES ECB
func (cipher *EcbCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext := make([]byte, len(ciphertext))
	blockSize := len(cipher.key)

	// Create a real AES cipher
	aesCipher, err := aes.NewCipher(cipher.key)
	if err != nil {
		return nil, err
	}

	// Decrypt each block as if it were a whole ciphertext
	for start := 0; start < len(ciphertext); start += blockSize {
		size := blockSize
		if start+size > len(ciphertext) {
			size = len(ciphertext) - start - 1
		}
		aesCipher.Decrypt(plaintext[start:], ciphertext[start:start+size])
	}
	return plaintext, nil
}
