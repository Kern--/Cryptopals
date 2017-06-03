package aes

import "math/rand"
import "encoding/base64"

// SecretAdder takes a plaintext and adds some secrets to it
type SecretAdder func([]byte) []byte

var instanceKey = make([]byte, 16)
var saltLen = rand.Int31n(32)
var salt = make([]byte, saltLen)
var secretBytes []byte

var initialized bool

func init() {
	if !initialized {
		rand.Read(instanceKey)
		rand.Read(salt)
		secret := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
		secretBytes, _ = base64.StdEncoding.DecodeString(secret)
		initialized = true
	}
}

// AddSecret appends a secret plaintext to a plaintext
func AddSecret(input []byte) []byte {
	return append(input, secretBytes...)
}

// AddSaltySecret prepends a salt and appends a secret plaintext to a plaintext
func AddSaltySecret(input []byte) []byte {
	return append(salt, AddSecret(input)...)
}

// EncryptRandom adds a random prefix and suffix to a plain text and then encrypts it under
//  AES ECB or CBC with a random key
func EncryptRandom(plaintext []byte) ([]byte, error) {
	prefixLength := rand.Intn(5) + 5
	suffixLength := rand.Intn(5) + 5

	// Generate a random key
	key := make([]byte, 16)
	rand.Read(key)

	// Create a slice to hold the padded plaintext
	paddedPlaintext := make([]byte, prefixLength+suffixLength+len(plaintext))

	// Fill the padded plaintext with secure random data
	rand.Read(paddedPlaintext[:])
	// Overwrite the middle of the padded plaintext with the original plaintext
	copy(paddedPlaintext[prefixLength:], plaintext)

	// Chose which encryption to use and do it
	useEcb := rand.Intn(2) == ECB
	if useEcb {
		cipher := NewAesEcbCipher(key)
		return cipher.Encrypt(paddedPlaintext)
	}

	cipher := NewAesCbcCipher(key)
	iv := make([]byte, 16)
	rand.Read(iv)
	return cipher.Encrypt(paddedPlaintext, iv)
}

// EncryptRandomConsistent encrypts a plaintext appended with a secret plaintext
//   under a random, but consistent key
func EncryptRandomConsistent(plaintext []byte, addSecret SecretAdder) ([]byte, error) {
	input := addSecret(plaintext)

	// Setup key if it hasn't already been
	if instanceKey == nil {
		rand.Read(instanceKey)
	}

	ecbCipher := NewAesEcbCipher(instanceKey)
	return ecbCipher.Encrypt(input)
}

// DetectAesMode takes a ciphertext that was encrypted under AES ECB or CBC and
//  determines which one was used. It is assumed that the plaintext that was encrypted
//  enough sequential identical blocks to be detectible, even if the encryption method padded them
func DetectAesMode(ciphertext []byte, blockSize int) int {
	countDuplicateBlocks := 0
	for i := 0; i+blockSize < len(ciphertext); i++ {
		var j int
		// See if the next block is identical. If it is, strong indication of ECB mode
		for j = 0; j < blockSize; j++ {
			if ciphertext[i+j] != ciphertext[i+j+blockSize] {
				break
			}
		}
		if j == blockSize {
			countDuplicateBlocks++
		}
	}
	if countDuplicateBlocks > 0 {
		return ECB
	}
	return CBC
}
