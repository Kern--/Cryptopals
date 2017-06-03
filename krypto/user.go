package krypto

import (
	"crypto/rand"
	"net/url"
	"strings"

	"github.com/kern--/Cryptopals/krypto/aes"
)

var key = make([]byte, 16)
var iv = make([]byte, 16)

func init() {
	rand.Read(key)
	rand.Read(iv)
}

func getCipher() *aes.EcbCipher {
	return aes.NewAesEcbCipher(key)
}

func getCbcCipher() *aes.CbcCipher {
	return aes.NewAesCbcCipher(key)
}

// buildUserQuery embeds an escaped input into a query
func buildUserQuery(input []byte) []byte {
	prefix := []byte("comment1=cooking%20MCs;userdata=")
	suffix := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	input = []byte(url.QueryEscape(string(input)))
	return append(append(prefix, input...), suffix...)
}

// GenerateEncryptedQuery generates an encrypted query from the specified user data
func GenerateEncryptedQuery(input []byte) ([]byte, error) {
	input = buildUserQuery(input)
	cipher := getCbcCipher()
	return cipher.Encrypt(input, iv)
}

// DecryptQuery decrypts a user query
func DecryptQuery(input []byte) ([]byte, error) {
	cipher := getCbcCipher()
	return cipher.Decrypt(input, iv)
}

// GetProfile gets an ECB encrypted profile for a given email
func GetProfile(email string) ([]byte, error) {
	dict := make(map[string]string)
	// Do a dumb replacement so that I can still put '=' and padding bytes
	//  into my email
	dict["email"] = strings.Replace(email, "&", " ", -1)
	dict["uid"] = "10"
	dict["role"] = "user"

	profileQuery := EncodeProfileKeyValuePairs(dict)

	cipher := getCipher()
	return cipher.Encrypt([]byte(profileQuery))
}

// ParseEncryptedProfile decrypts an encrypted profile and parses it into a map of properties for the profile
func ParseEncryptedProfile(encryptedProfile []byte) (map[string]string, error) {
	cipher := getCipher()
	plainText, err := cipher.Decrypt(encryptedProfile)
	plainTextLength := len(plainText)

	// Remove padding and just assume it's correct
	plainText = plainText[:plainTextLength-int(plainText[plainTextLength-1])]

	if err != nil {
		return nil, err
	}
	dict := ParseProfileKeyValuePairs(string(plainText), "=", "&")
	escapedEmail, _ := url.QueryUnescape(dict["email"])
	dict["email"] = strings.Replace(escapedEmail, " ", "&", -1)
	return dict, nil
}

// ParseProfileKeyValuePairs parse a string encoding of key value pairs as key1=value1&key2=value2... into
//  a map with the keys to values
func ParseProfileKeyValuePairs(input string, keyValueSparator string, tupleSeparator string) map[string]string {
	dict := make(map[string]string)
	keyvaluepairs := strings.Split(input, tupleSeparator)
	for _, pair := range keyvaluepairs {
		keyandvalue := strings.Split(pair, keyValueSparator)
		var value string
		// if the length > 2 then there is an "=" in the value so we should rejoin
		//  it to make the value whole again

		switch {
		case len(keyandvalue) > 2:
			value = strings.Join(keyandvalue[1:], keyValueSparator)
		case len(keyandvalue) == 2:
			value = keyandvalue[1]
		default:
			continue
		}
		key := keyandvalue[0]
		dict[key] = value
	}
	return dict
}

// EncodeProfileKeyValuePairs encodes a map into a string of the form email=value1&uid=value2&role=value3
func EncodeProfileKeyValuePairs(input map[string]string) string {
	keyvaluepairs := make([]string, len(input))
	// Hardcoded this way to make sure role comes last in the string
	//  for my attack to be easier
	keyvaluepairs[0] = "email=" + input["email"]
	keyvaluepairs[1] = "uid=" + input["uid"]
	keyvaluepairs[2] = "role=" + input["role"]
	return strings.Join(keyvaluepairs, "&")
}
