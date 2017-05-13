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
