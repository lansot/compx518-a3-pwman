package tests

import (
	"pwman/util"
	"testing"
)

func TestAES(t *testing.T) {
	inputPass := []byte("testpassword")
	randomSalt, _ := util.GenerateCryptoString(8)
	key := util.PBKDF2StretchKey(inputPass, []byte(randomSalt))
	inputText := "this is a plain text example blahblahblah"

	cryptText, err := util.EncryptAES(key, []byte(inputText))

	if err != nil {
		t.Fatalf("Encryption failed")
	}

	t.Logf("Encrypted text: %v (%v)", cryptText, string(cryptText[:]))

	decryptedText := util.DecryptAES(key, cryptText)

	t.Logf("Decrypted text: %v", string(decryptedText[:]))

	if inputText != string(decryptedText[:]) {
		t.Fatalf("Input text and decrypted text do not match (%v AND %v",
			inputText, decryptedText)
	}
}
