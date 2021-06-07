package main

import (
	"fmt"
	"os"
)

func main() {
	args := os.Args

	if len(args) == 2 {
		switch args[1] {
		case "init":
			if vaultExists() {
				fmt.Println("A vaultfile already exists in the current directory. If you wish to overwrite it, first delete it manually.")
			} else {
				fmt.Println("generate vault stuff blahblah")
			}
		case "add":
			if vaultExists() {
				fmt.Println("blahblahblah do adding stuff")
			} else {
				printNoVaultFound()
			}
		case "remove":
			if vaultExists() {
				fmt.Println("blahblahblah do removal stuff")
			} else {
				printNoVaultFound()
			}
		case "fetch":
			if vaultExists() {
				fmt.Println("blahblahblah do fetching stuff")
			} else {
				printNoVaultFound()
			}
		default:
			printHelp()
		}
	} else {
		printHelp()
	}
}

func printHelp() {
	fmt.Println("Invalid arguments.")
	fmt.Println("Valid arguments are: init, add, remove, fetch")
}

func printNoVaultFound() {
	fmt.Println("No vaultfile found in the current directory. Generate one with \"pwman init\".")
}

func vaultExists() bool {
	if _, err := os.Stat("./vaultfile"); os.IsNotExist(err) {
		return false
	} else {
		return true
	}
}
