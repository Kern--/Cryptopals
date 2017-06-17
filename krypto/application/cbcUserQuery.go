package application

import (
	"crypto/rand"
	"net/url"

	"github.com/kern--/Cryptopals/krypto/aes"
	"github.com/kern--/Cryptopals/util"
)

// CbcQueryBuilder can generate encrypted queries
type CbcQueryBuilder struct {
	cipher *aes.CbcCipher
	iv     []byte
}

// NewCbcQueryBuilder creates a new CbcQueryBuilder
func NewCbcQueryBuilder() *CbcQueryBuilder {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)
	return &CbcQueryBuilder{aes.NewAesCbcCipher(key), iv}
}

// GetEncryptedQuery generates an encrypted query where userdata is sandwiched between non-userdata in a key-value query
func (builder *CbcQueryBuilder) GetEncryptedQuery(input []byte) ([]byte, error) {
	input = builder.buildQuery(input)
	cipher := builder.cipher
	iv := builder.iv
	return cipher.Encrypt(input, iv)
}

// HasAdminRole checks whether an encerypted query contains the admin role
func (builder *CbcQueryBuilder) HasAdminRole(encryptedQuery []byte) (bool, error) {
	cipher := builder.cipher
	iv := builder.iv
	plaintextQuery, err := cipher.Decrypt(encryptedQuery, iv)
	if err != nil {
		return false, err
	}
	queryParts := util.DecodeQueryString(string(plaintextQuery), "=", ";")
	return queryParts["admin"] == "true", nil
}

func (builder *CbcQueryBuilder) buildQuery(input []byte) []byte {
	prefix := []byte("comment1=cooking%20MCs;userdata=")
	suffix := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	input = []byte(url.QueryEscape(string(input)))
	return append(append(prefix, input...), suffix...)
}
