package aes

import "math/rand"

var instanceKey = make([]byte, 16)

func init() {
	rand.Read(instanceKey)
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
