package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"os"
	"pwman/util"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	args := os.Args

	// Program must only be invoked with 1 subcommand
	if len(args) == 2 {
		switch args[1] {
		case "init":
			if util.VaultExists() {
				fmt.Println("A vaultfile already exists in the current directory. If you wish to overwrite it, first delete it manually.")
			} else {
				initializeVault()
			}
		case "add":
			if util.VaultExists() {
				fmt.Println("blahblahblah do adding stuff")
			} else {
				util.PrintNoVaultFound()
			}
		case "remove":
			if util.VaultExists() {
				fmt.Println("blahblahblah do removal stuff")
			} else {
				util.PrintNoVaultFound()
			}
		case "fetch":
			if util.VaultExists() {
				fmt.Println("blahblahblah do fetching stuff")
			} else {
				util.PrintNoVaultFound()
			}
		default:
			util.PrintHelp()
		}
	} else {
		util.PrintHelp()
	}
}

// Create a new Vaultfile.
// Prompt for a new master password, then bcrypt hash it.
// Gob serialize an empty key/value store, then AES-256 encrypt with the
// master password.
func initializeVault() {
	vault := util.Vault{}
	var inMasterPassword string

	fmt.Println("Creating a new Vaultfile...")
	fmt.Println("Please enter a master password to use for the new vault.")

	inTokens, err := fmt.Scanf("%s", &inMasterPassword)

	// Master password must not contain any spaces
	for inTokens != 1 || err != nil {
		fmt.Println("Invalid input. Master passwords must be a single continuous string of alphanumeric characters.")
		fmt.Println("Please enter a master password to use for the new vault.")
		inTokens, err = fmt.Scanf("%s", &inMasterPassword)
	}

	// bcrypt hash the input master password
	saltedHash, _ := bcrypt.GenerateFromPassword([]byte(inMasterPassword), bcrypt.DefaultCost)
	vault.SaltedHash = string(saltedHash[:])

	// get a serialized empty KV store (map).
	// gob encode and encrypt.
	bytesBuf := new(bytes.Buffer)
	encoder := gob.NewEncoder(bytesBuf)
	encoder.Encode(map[string]string{})

	randomSalt, _ := util.GenerateCryptoString(8)
	vault.PBKDFsalt = randomSalt
	key := util.PBKDF2StretchKey([]byte(inMasterPassword), []byte(vault.PBKDFsalt))

	encryptedGob, _ := util.EncryptAES(key, bytesBuf.Bytes())

	// store encrypted gob as base64 string
	vault.KVstore = base64.StdEncoding.EncodeToString(encryptedGob)

	// aaand now we write the vault information to the vaultfile
	util.SaveVault(vault)

	fmt.Println("New Vaultfile created.")
}
