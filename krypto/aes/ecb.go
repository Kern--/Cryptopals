package aes

import (
	"crypto/aes"

	"github.com/kern--/Cryptopals/util"
)

// EcbCipher represents an AES ECB cipher since golang does not ship with this mode
type EcbCipher struct {
	key []byte
}

// NewAesEcbCipher creates a new cipher that can be used to handle AES ECB encryption
func NewAesEcbCipher(key []byte) *EcbCipher {
	return &EcbCipher{key}
}

// Encrypt encrypts a plaintext with AES ECB
//  Only works if the plaintext is aligned to the block size
func (cipher *EcbCipher) Encrypt(plaintext []byte) ([]byte, error) {
	blockSize := len(cipher.key)

	// Setup plaintext and ciphertext
	paddedPlaintext := util.AddPkcs7Padding(plaintext, blockSize)
	cipherText := make([]byte, len(paddedPlaintext))

	// Create a real AES Cipher
	aesCipher, err := aes.NewCipher(cipher.key)
	if err != nil {
		return nil, err
	}

	// Encrypt each block as if it were a whole plaintext
	for start := 0; start < len(paddedPlaintext); start += blockSize {
		aesCipher.Encrypt(cipherText[start:], paddedPlaintext[start:start+blockSize])
	}
	return cipherText, nil
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

// DetectAesEcb detect which of a set of input byte slices is most likely to be encrypted with AES in ECB mode
//  as well as the number of duplicate blocks used to make that decision
func DetectAesEcb(inputs [][]byte) ([]byte, int) {
	var likelyEncrypted []byte
	var likelyEncryptedDupBlockCount int
	for _, input := range inputs {
		count := util.CountDuplicateBlocks(input, 16)
		if count > likelyEncryptedDupBlockCount {
			likelyEncryptedDupBlockCount = count
			likelyEncrypted = input
		}
	}
	return likelyEncrypted, likelyEncryptedDupBlockCount
}
