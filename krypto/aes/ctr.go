package aes

import (
	"encoding/binary"

	"github.com/kern--/Cryptopals/util"
)

// CtrCipher is a struct for encrypting plaintexts using the AES CTR stream cipher
type CtrCipher struct {
	ecbCipher *EcbCipher
}

// NewAesCtrCipher creates a new CtrCipher
func NewAesCtrCipher(key []byte) *CtrCipher {
	return &CtrCipher{NewAesEcbCipher(key)}
}

// Encrypt encrypts a plaintext
func (cipher *CtrCipher) Encrypt(plainText []byte, nonce []byte) ([]byte, error) {
	// If nonce is nil, use an empty nonce
	if nonce == nil {
		nonce = make([]byte, 8)
	}

	// Copy the plain text to the cipher
	cipherText := make([]byte, len(plainText))
	copy(cipherText, plainText)

	counter := uint64(0)
	counterBytes := make([]byte, 8)

	for i := 0; i < len(plainText); i += 16 {
		// Create the "seed" - the counter that will be encrypted to produce the keystream
		//  = [nonce || little endian counter]
		binary.LittleEndian.PutUint64(counterBytes, counter)
		seed := append(nonce, counterBytes...)
		// Generate the keystream
		ecbCipherText, err := cipher.ecbCipher.Encrypt(seed)
		if err != nil {
			return nil, err
		}
		keyStream := ecbCipherText[:16]
		// Calculate the amount of this keystream that will be applied
		streamLength := util.Min(16, len(plainText)-i)
		// Apply keystream
		util.InlineXor(cipherText[i:i+streamLength], keyStream[:streamLength])
		// Increment counter
		counter++
	}
	return cipherText, nil
}

// Decrypt decrypts a ciphertext
func (cipher *CtrCipher) Decrypt(cipherText []byte, nonce []byte) ([]byte, error) {
	// CTR mode is 100% symmetric
	return cipher.Encrypt(cipherText, nonce)
}
