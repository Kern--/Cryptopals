package attack

import "github.com/kern--/Cryptopals/krypto/application"

// UserProfileAttacker is a type that can forge admin tokens
type UserProfileAttacker struct {
	profile *application.EcbUserProfile
}

// NewUserProfileAttacker creates a new UserProfileAttacker for a given EcbUserProfile application
func NewUserProfileAttacker(profile *application.EcbUserProfile) *UserProfileAttacker {
	return &UserProfileAttacker{profile}
}

// ForgeAdminToken creates a valid user token where the role is set to admin.
//  no guarantees are made about the email associated with the user
func (attacker *UserProfileAttacker) ForgeAdminToken() ([]byte, error) {
	// Find the encrypted value of the string "role=admin" that's validly padded
	// The string that get's encrypted should look like this:
	// email=aaaaarole=|admin           |&uid=...
	// where | just show block boundaries and the ' ' characters are valid padding bytes
	email := "aaaaarole=admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
	encryptedProfile, err := attacker.profile.GetEncryptedProfile(email)
	if err != nil {
		return nil, err
	}
	// role=admin is in the second block
	roleAdminBlock := encryptedProfile[16:32]

	// Get a profile for a user which forces the last block to be "role=user" with padding.
	//  Input should look like this:
	//  email=aaaaaaaaaa|bbb&uid=10&role=|user            |
	email = "aaaaaaaaaabbb"
	encryptedProfile, err = attacker.profile.GetEncryptedProfile(email)
	if err != nil {
		return nil, err
	}

	// Replace the last block with our calculated role=admin block
	length := len(encryptedProfile)
	copy(encryptedProfile[length-16:], roleAdminBlock)
	return encryptedProfile, nil
}
