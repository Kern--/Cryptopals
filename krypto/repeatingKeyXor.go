package krypto

// RepeatingKeyXor encrypts the input by xoring each successive input byte with each
//  successive key byte while wrapping if the key is shorter than the input
func RepeatingKeyXor(input []byte, key []byte) []byte {
	cipher := make([]byte, len(input))
	keylen := len(key)

	for i, b := range input {
		cipher[i] = b ^ key[i%keylen]
	}
	return cipher
}
