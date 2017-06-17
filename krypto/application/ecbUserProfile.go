package application

import (
	"crypto/rand"
	"strings"

	"github.com/kern--/Cryptopals/krypto/aes"
	"github.com/kern--/Cryptopals/util"
)

// EcbUserProfile can generate encrypted user profiles
type EcbUserProfile struct {
	cipher *aes.EcbCipher
}

// NewEcbUserProfile creates a new EcbUserProfile
func NewEcbUserProfile() *EcbUserProfile {
	key := make([]byte, 16)
	rand.Read(key)
	return &EcbUserProfile{aes.NewAesEcbCipher(key)}
}

// GetEncryptedProfile gets an encrypted profile for a give email address
func (user *EcbUserProfile) GetEncryptedProfile(email string) ([]byte, error) {
	dict := make(map[string]string)
	// Do a dumb replacement so that I can still put '=' and padding bytes
	//  into my email
	dict["email"] = strings.Replace(email, "&", " ", -1)
	dict["uid"] = "10"
	dict["role"] = "user"
	keys := []string{"email", "uid", "role"}

	profileQuery := util.EncodeToQueryString(dict, keys, "=", "&")

	return user.cipher.Encrypt([]byte(profileQuery))
}

// HasAdminRole checks whether an encrypted user profile has the admin role
func (user *EcbUserProfile) HasAdminRole(encryptedProfile []byte) (bool, error) {
	plainText, err := user.cipher.Decrypt(encryptedProfile)
	if err != nil {
		return false, err
	}

	// Remove padding and just assume it's correct
	plainTextLength := len(plainText)
	plainText = plainText[:plainTextLength-int(plainText[plainTextLength-1])]

	dict := util.DecodeQueryString(string(plainText), "=", "&")
	return dict["role"] == "admin", nil
}
