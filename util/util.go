package util

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// Generates a random ASCII string of specified length using a cryptographic PRNG.
func GenerateCryptoString(strLength int) (string, error) {
	if strLength <= 0 {
		return "", errors.New("invalid length (must be greater than 0)")
	}

	bytes := make([]byte, strLength)

	// usable ASCII characters are 33 to 126.
	// stuff like the space character is considered printable,
	// but we can't exactly use those...
	for i := 0; i < strLength; i++ {
		r, _ := rand.Int(rand.Reader, big.NewInt(int64(94)))
		bytes[i] = byte(r.Int64() + 33)
	}

	return string(bytes), nil
}
