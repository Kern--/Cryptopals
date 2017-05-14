package util

import (
	"encoding/base64"
	"encoding/hex"
)

// HexToBase64 converts a hex encoded string to a base64 encoded string
func HexToBase64(str string) (string, error) {
	inputBytes, err := hex.DecodeString(str)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(inputBytes)
	return encoded, nil
}

// Xor xors two equal length byte arrays
func Xor(a []byte, b []byte) []byte {
	c := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		c[i] = a[i] ^ b[i]
	}
	return c
}

// SingleByteXor xors each element in an array by a byte key
func SingleByteXor(a []byte, key byte) []byte {
	length := len(a)
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = key
	}
	return Xor(a, b)
}
