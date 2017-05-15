package krypto

import (
	"crypto/aes"
)

type EcbCipher struct {
	key []byte
}

func NewAesEcbCipher(key []byte) *EcbCipher {
	return &EcbCipher{key}
}

func (cipher *EcbCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext := make([]byte, len(ciphertext))
	blockSize := len(cipher.key)
	aesCipher, err := aes.NewCipher(cipher.key)
	if err != nil {
		return nil, err
	}

	for start := 0; start < len(ciphertext); start += blockSize {
		size := blockSize
		if start+size > len(ciphertext) {
			size = len(ciphertext) - start - 1
		}
		aesCipher.Decrypt(plaintext[start:], ciphertext[start:start+size])
	}
	return plaintext, nil
}
