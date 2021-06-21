package util

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

type Vault struct {
	SaltedHash string
	PBKDFsalt  string
	KVstore    string // base64 encoded
}

// Generates a random ASCII string of specified length using a cryptographic PRNG.
func GenerateCryptoString(strLength int) (string, error) {
	if strLength <= 0 {
		return "", errors.New("invalid length (must be greater than 0)")
	}

	bytes := make([]byte, strLength)

	// usable ASCII characters are 33 to 126. total 93
	// stuff like the space character is considered printable,
	// but we can't exactly use those...
	for i := 0; i < strLength; i++ {
		r, _ := rand.Int(rand.Reader, big.NewInt(int64(94)))
		bytes[i] = byte(r.Int64() + 33)
	}

	return string(bytes), nil
}

// Encrypt input bytes with an input key,
// and return the encrypted bytes.
func EncryptAES(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// pad the input for AES
	input, err := PKCS7pad(plaintext, aes.BlockSize)
	if err != nil {
		panic(err)
	}

	// allocate space for ciphered data plus IV/
	// we're going to make a new IV every time we encrypt,
	// and prepend it to the encrypted result.
	outBytes := make([]byte, aes.BlockSize+len(input))
	iv := outBytes[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)

	// encrypt
	cbc.CryptBlocks(outBytes[aes.BlockSize:], input)

	return outBytes, nil
}

// Decrypt input bytes with an input key,
// and return the decrypted bytes.
func DecryptAES(key, ciphertext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// the EncryptAES function prepended the IV to the encrypted value
	// so to speak, time to Chop It Up
	iv := ciphertext[:aes.BlockSize]
	body := ciphertext[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(block, iv)

	processingBuf := make([]byte, len(body))
	cbc.CryptBlocks(processingBuf, body)

	outBytes, err := PKCS7strip(processingBuf, aes.BlockSize)
	if err != nil {
		panic(err)
	}

	return outBytes
}

// Add PKCS7 padding to some data to make evenly-sized blocks
func PKCS7pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 0 || blockSize > 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	} else {
		padLen := blockSize - (len(data) % blockSize)
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
		return append(data, padding...), nil
	}
}

// Strip PKCS7 padding from some data
func PKCS7strip(data []byte, blockSize int) ([]byte, error) {
	length := len(data)

	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}

	if (length % blockSize) != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}

	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		// return nil, errors.New("pkcs7: Invalid padding")
		return nil, fmt.Errorf("invalid padding. ref: %v. padlen: %v, blocksize: %v, input data: %v",
			ref, padLen, blockSize, data)
	}
	return data[:length-padLen], nil
}

// Stretch a password into a key using PBKDF2
func PBKDF2StretchKey(inputPW []byte, salt []byte) []byte {
	return pbkdf2.Key(inputPW, salt, 4096, 32, sha1.New)
}

// Write the contents of a Vault struct to a new Vaultfile
func SaveVault(vault Vault) {
	file, err := os.Create("./Vaultfile")
	if err != nil {
		panic(err)
	}

	writer := bufio.NewWriter(file)
	linesToWrite := []string{vault.SaltedHash, vault.PBKDFsalt, vault.KVstore}
	for _, line := range linesToWrite {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			panic(err)
		}
	}
	writer.Flush()
}

// Read in the contents of a Vaultfile and return a Vault struct
func ReadVault() Vault {
	vault := Vault{}

	file, err := os.Open("./Vaultfile")
	if err != nil {
		panic(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) != 3 {
		panic("Vaultfile had unexpected number of lines. Possible file corruption?")
	}
	vault.SaltedHash = lines[0]
	vault.PBKDFsalt = lines[1]
	vault.KVstore = lines[2]

	err = scanner.Err()
	if err != nil {
		panic(err)
	}

	return vault
}

// Print some help text on invalid program invokation.
func PrintHelp() {
	fmt.Println("Invalid arguments.")
	fmt.Println("Valid arguments are: init, add, remove, fetch")
}

// Print a helpful error message when trying to invoke a command that requires
// an existing vault, when none is found.
func PrintNoVaultFound() {
	fmt.Println("No vaultfile found in the current directory. Generate one with \"pwman init\".")
}

// Returns true if a vaultfile is found in the current directory.
func VaultExists() bool {
	if _, err := os.Stat("./vaultfile"); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}
