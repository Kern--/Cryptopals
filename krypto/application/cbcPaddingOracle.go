package application

import (
	"crypto/rand"

	"encoding/base64"

	"github.com/kern--/Cryptopals/krypto/aes"
)

var blocksize = 16

var plaintexts = []string{
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZBSWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
}

// CbcPaddingOracle is a struct that can be used to perform CBC padding oracle
//  attacks to decrypt a random ciphertext
type CbcPaddingOracle struct {
	cipher    *aes.CbcCipher
	iv        []byte
	plaintext []byte
}

// NewCbcPaddingOracle creates a new CbcPaddingOracle
func NewCbcPaddingOracle() *CbcPaddingOracle {
	key := make([]byte, blocksize)
	iv := make([]byte, blocksize)
	plaintextIndex := make([]byte, 1)
	rand.Read(key)
	rand.Read(iv)
	rand.Read(plaintextIndex)

	plaintext := plaintexts[int(plaintextIndex[0])%len(plaintexts)]
	plaintextBytes, _ := base64.StdEncoding.DecodeString(plaintext)
	cipher := aes.NewAesCbcCipher(key)
	return &CbcPaddingOracle{cipher, iv, plaintextBytes}
}

// GetCipherText gets a consistent cipher text that is associated with the padding oracle
func (oracle *CbcPaddingOracle) GetCipherText() ([]byte, []byte, error) {
	cipherText, err := oracle.cipher.Encrypt(oracle.plaintext, oracle.iv)
	return cipherText, oracle.iv, err
}

// CanDecrypt attempts to decrypt a ciphertext
//  returns nil if decryption is successful, otherwise and error
func (oracle *CbcPaddingOracle) CanDecrypt(ciphertext []byte, iv []byte) error {
	_, err := oracle.cipher.Decrypt(ciphertext, iv)
	return err
}
