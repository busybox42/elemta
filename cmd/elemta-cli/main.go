package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: elemta-cli <command>")
		fmt.Println("Commands:")
		fmt.Println("  status   - Show server status")
		fmt.Println("  queue    - Show queue statistics")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "status":
		fmt.Println("Elemta CLI - Status command")
		fmt.Println("Server: Running")
	case "queue":
		fmt.Println("Elemta CLI - Queue statistics")
		fmt.Println("Active: 0")
		fmt.Println("Deferred: 0")
		fmt.Println("Failed: 0")
	default:
		log.Fatalf("Unknown command: %s", command)
	}
}
