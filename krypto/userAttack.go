package krypto

// GenerateAdminUserToken creates a valid user token where the role is set to admin.
//  no guarantees are made about the email associated with the user
func GenerateAdminUserToken() ([]byte, error) {
	// Find the encrypted value of the string "role=admin" that's validly padded
	// The string that get's encrypted should look like this:
	// email=aaaaaaaaaa|role=admin      |&uid=...
	// where | just show block boundaries and the ' ' characters are valid padding bytes
	email := "aaaaaaaaaarole=admin\x06\x06\x06\x06\x06\x06"
	encryptedProfile, err := GetProfile(email)
	if err != nil {
		return nil, err
	}
	// role=admin is in the second block
	roleAdminBlock := encryptedProfile[16:32]

	// Get a profile for a user which forces the last block to be "role=user" with padding.
	//  Input should look like this:
	//  email=aaaaaaaaaa|bbbbbbbb&uid=10&|role=user       |
	email = "aaaaaaaaaabbbbbbbb"
	encryptedProfile, err = GetProfile(email)
	if err != nil {
		return nil, err
	}

	// Replace the last block with our calculated role=admin block
	length := len(encryptedProfile)
	copy(encryptedProfile[length-16:], roleAdminBlock)
	return encryptedProfile, nil
}

// HasAdminRole detects whether an encrypted query contains the admin role
func HasAdminRole(encryptedQuery []byte) (bool, error) {
	plaintext, err := DecryptQuery(encryptedQuery)
	if err != nil {
		return false, err
	}
	kvp := ParseProfileKeyValuePairs(string(plaintext), "=", ";")
	_, exists := kvp["admin"]
	return exists, nil
}
