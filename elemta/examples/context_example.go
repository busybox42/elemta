package main

import (
	"fmt"
	"time"

	"github.com/elemta/elemta/internal/context"
)

func main() {
	// Create a new context
	ctx := context.NewContext()

	// Set some values
	ctx.Set("user", "john.doe@example.com")
	ctx.Set("ip", "192.168.1.1")
	ctx.Set("authenticated", true)
	ctx.Set("score", 0.95)
	ctx.SetWithExpiration("token", "abc123", 5*time.Second)

	// Get values
	if user, ok := ctx.GetString("user"); ok {
		fmt.Printf("User: %s\n", user)
	}

	if ip, ok := ctx.GetString("ip"); ok {
		fmt.Printf("IP: %s\n", ip)
	}

	if authenticated, ok := ctx.GetBool("authenticated"); ok {
		fmt.Printf("Authenticated: %v\n", authenticated)
	}

	if score, ok := ctx.GetFloat("score"); ok {
		fmt.Printf("Score: %.2f\n", score)
	}

	if token, ok := ctx.GetString("token"); ok {
		fmt.Printf("Token: %s\n", token)
	}

	// Dump the context
	fmt.Println("\nContext dump:")
	fmt.Println(ctx.Dump())

	// Wait for token to expire
	fmt.Println("\nWaiting for token to expire...")
	time.Sleep(6 * time.Second)

	// Try to get the token again
	if token, ok := ctx.GetString("token"); ok {
		fmt.Printf("Token: %s\n", token)
	} else {
		fmt.Println("Token has expired")
	}

	// Dump the context again
	fmt.Println("\nContext dump after expiration:")
	fmt.Println(ctx.Dump())

	// Delete a value
	ctx.Delete("user")

	// Dump the context again
	fmt.Println("\nContext dump after deletion:")
	fmt.Println(ctx.Dump())

	// Clear the context
	ctx.Clear()

	// Dump the context again
	fmt.Println("\nContext dump after clearing:")
	fmt.Println(ctx.Dump())
}
