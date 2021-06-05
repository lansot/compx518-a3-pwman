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
			fmt.Println("init command")
		case "add":
			fmt.Println("add command")
		case "remove":
			fmt.Println("remove command")
		case "fetch":
			fmt.Println("fetch command")
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
