package krypto

import (
	"crypto/rand"
	"net/url"
	"strings"

	"github.com/kern--/Cryptopals/krypto/aes"
)

var initialized = false
var key = make([]byte, 16)

func getCipher() *aes.EcbCipher {
	if !initialized {
		rand.Read(key)
		initialized = true
	}
	return aes.NewAesEcbCipher(key)
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
	dict := ParseProfileKeyValuePairs(string(plainText))
	escapedEmail, _ := url.QueryUnescape(dict["email"])
	dict["email"] = strings.Replace(escapedEmail, " ", "&", -1)
	return dict, nil
}

// ParseProfileKeyValuePairs parse a string encoding of key value pairs as key1=value1&key2=value2... into
//  a map with the keys to values
func ParseProfileKeyValuePairs(input string) map[string]string {
	dict := make(map[string]string)
	keyvaluepairs := strings.Split(input, "&")
	for _, pair := range keyvaluepairs {
		keyandvalue := strings.Split(pair, "=")
		var value string
		// if the length > 2 then there is an "=" in the value so we should rejoin
		//  it to make the value whole again
		if len(keyandvalue) > 2 {
			value = strings.Join(keyandvalue[1:], "=")
		} else {
			value = keyandvalue[1]
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
