package application

import (
	"encoding/base64"
	"math/rand"

	"github.com/kern--/Cryptopals/krypto/aes"
)

// Ecb is a struct that can encrypt plaintexts that have been modified with an arbitrary function
type Ecb struct {
	cipher *aes.EcbCipher
	modify func([]byte) []byte
}

// NewEcb creates a new application.Ecb with a given block size and optional
//  function to modify the input before encrypting
func NewEcb(blockSize int, modify func([]byte) []byte) *Ecb {
	key := make([]byte, blockSize)
	rand.Read(key)
	cipher := aes.NewAesEcbCipher(key)
	return &Ecb{cipher, modify}
}

// NewSecretSuffixEcb creates a new application.Ecb with a given blocksize
//   where a consistent secret is appended to the plaintext before encrypting
func NewSecretSuffixEcb(blockSize int) *Ecb {
	secret := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	secretBytes, _ := base64.StdEncoding.DecodeString(secret)

	modify := func(input []byte) []byte {
		return append(input, secretBytes...)
	}
	return NewEcb(blockSize, modify)
}

// NewPrefixedSecretSuffixEcb creates a new application.Ecb with a given blocksize
//   where a consistent secret is appended to the plaintext and a consistent
//   salt is prepended to the plaintext before encrypting
func NewPrefixedSecretSuffixEcb(blockSize int) *Ecb {
	secret := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	secretBytes, _ := base64.StdEncoding.DecodeString(secret)
	saltLen := rand.Int31n(int32(2 * blockSize))
	salt := make([]byte, saltLen)
	rand.Read(salt)

	modify := func(input []byte) []byte {
		return append(append(salt, input...), secretBytes...)
	}
	return NewEcb(blockSize, modify)
}

// Encrypt encrypts a plaintext
func (app *Ecb) Encrypt(plaintext []byte) ([]byte, error) {
	input := plaintext
	if app.modify != nil {
		input = app.modify(input)
	}
	return app.cipher.Encrypt(input)
}
