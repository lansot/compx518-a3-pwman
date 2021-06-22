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

// lord, forgive me for what i am about to do.
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
				vault, kv, key := openVault()
				if len(kv) != 0 {
					fmt.Println("Vault contents:")
					for k := range kv {
						fmt.Println(k)
					}
				}
				var inputIdentifier string
				var pwLength int
				fmt.Println("Enter an identifier for the new password entry. (Entering an existing identifier updates its corresponding entry.)")
				inTokens, err := fmt.Scanf("%s", &inputIdentifier)
				for inTokens != 1 || err != nil {
					fmt.Println("Invalid input. Password identifiers must be a single continuous string of alphanumeric characters.")
					fmt.Println("Enter an identifier for the new password entry.")
					inTokens, err = fmt.Scanf("%s", &inputIdentifier)
				}

				fmt.Println("Enter a length for the new password. (8~80)")
				inTokens, err = fmt.Scanf("%d", &pwLength)
				for inTokens != 1 || err != nil || pwLength < 8 || pwLength > 80 {
					fmt.Println("Invalid input.")
					fmt.Println("Enter a length for the new password. (8~80)")
					inTokens, err = fmt.Scanf("%d", &pwLength)
				}

				// now generate the mf password!!
				generatedPW, _ := util.GenerateCryptoString(pwLength)
				kv[inputIdentifier] = generatedPW
				fmt.Println("Entry added. Writing updated vault to disk...")

				// now encode, encrypt, base64-encode the kvstore and write the mf vault!!
				bytesBuf := new(bytes.Buffer)
				encoder := gob.NewEncoder(bytesBuf)
				encoder.Encode(kv)

				encryptedGob, _ := util.EncryptAES(key, bytesBuf.Bytes())
				vault.KVstore = base64.StdEncoding.EncodeToString(encryptedGob)
				util.SaveVault(vault)
			} else {
				util.PrintNoVaultFound()
			}
		case "remove":
			if util.VaultExists() {
				vault, kv, key := openVault()
				if len(kv) == 0 {
					fmt.Println("Vault is empty. You can add new entries with the \"add\" command.")
				} else {
					fmt.Println("Vault contents:")
					for k := range kv {
						fmt.Println(k)
					}
					var inputIdentifier string
					fmt.Println("Enter an identifier for the password entry to remove.")
					fmt.Scanf("%s", &inputIdentifier)
					_, exists := kv[inputIdentifier]
					for !exists {
						fmt.Println("No entry corresponding to that identifier was found.")
						fmt.Println("Enter an identifier for the password entry to remove.")
						fmt.Scanf("%s", &inputIdentifier)
						_, exists = kv[inputIdentifier]
					}

					delete(kv, inputIdentifier)
					fmt.Println("Entry deleted. Writing updated vault to disk...")

					// now encode, encrypt, base64-encode the kvstore and write the mf vault!!
					bytesBuf := new(bytes.Buffer)
					encoder := gob.NewEncoder(bytesBuf)
					encoder.Encode(kv)

					encryptedGob, _ := util.EncryptAES(key, bytesBuf.Bytes())
					vault.KVstore = base64.StdEncoding.EncodeToString(encryptedGob)
					util.SaveVault(vault)
				}
			} else {
				util.PrintNoVaultFound()
			}
		case "fetch":
			if util.VaultExists() {
				_, kv, _ := openVault()
				if len(kv) == 0 {
					fmt.Println("Vault is empty. You can add new entries with the \"add\" command.")
				} else {
					fmt.Println("Vault contents:")
					for k := range kv {
						fmt.Println(k)
					}
					var inputIdentifier string
					var requestedPW string
					choiceExists := false
					for !choiceExists {
						fmt.Println("Choose an identifier to see the corresponding password.")
						inTokens, err := fmt.Scanf("%s", &inputIdentifier)
						for inTokens != 1 || err != nil {
							fmt.Println("Invalid input. Password identifiers must be a single continuous string of alphanumeric characters.")
							fmt.Println("Choose an identifier to see the corresponding password.")
							inTokens, err = fmt.Scanf("%s", &inputIdentifier)
						}
						requestedPW, choiceExists = kv[inputIdentifier]
						if choiceExists {
							fmt.Printf("Requested password: %v\n", requestedPW)
						} else {
							fmt.Printf("No corresponding password found for \"%v\".\n", inputIdentifier)
						}
					}
				}
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

// Open an existing Vaultfile.
// Prompt for a new master password, then authenticate.
// Return the Vault struct, and the unencoded and decrypted KVstore map object.
// Also return the key for future encryption operations.
func openVault() (util.Vault, map[string]string, []byte) {
	vault := util.ReadVault()

	var inMasterPassword string
	authSuccess := fmt.Errorf("authSuccess becomes nil when auth succeeds")

	fmt.Println("Opening an existing Vaultfile...")

	for authSuccess != nil {
		fmt.Println("Please enter the vault's master password.")

		inTokens, err := fmt.Scanf("%s", &inMasterPassword)

		// Master password must not contain any spaces
		for inTokens != 1 || err != nil {
			fmt.Println("Invalid input. Master passwords must be a single continuous string of alphanumeric characters.")
			fmt.Println("Please enter the vault's master password.")
			inTokens, err = fmt.Scanf("%s", &inMasterPassword)
		}

		// bcrypt compare to authenticate
		authSuccess = bcrypt.CompareHashAndPassword([]byte(vault.SaltedHash), []byte(inMasterPassword))
		if authSuccess != nil {
			fmt.Println("Authentication failed. Check password?")
		}
	}

	// decode encrypted gob
	encryptedKVGob, err := base64.StdEncoding.DecodeString(vault.KVstore)
	if err != nil {
		panic(err)
	}

	// stretch password to make key
	key := util.PBKDF2StretchKey([]byte(inMasterPassword), []byte(vault.PBKDFsalt))

	// decrypt the decoded gob
	decryptedKVGob := util.DecryptAES(key, encryptedKVGob)

	// unpack the gob
	bytesBuf := bytes.NewBuffer(decryptedKVGob)
	decoder := gob.NewDecoder(bytesBuf)
	var kvMap map[string]string
	decoder.Decode(&kvMap)

	return vault, kvMap, key
}
