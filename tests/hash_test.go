package tests

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashing(t *testing.T) {
	plainString := "this_is_a_test_string"
	inBytes := []byte(plainString)
	saltedHash, _ := bcrypt.GenerateFromPassword(inBytes, bcrypt.DefaultCost)

	r := bcrypt.CompareHashAndPassword(saltedHash, []byte(plainString))

	if r != nil {
		t.Fatalf("Comparing the input string to the salted hash was not successful")
	}
}
