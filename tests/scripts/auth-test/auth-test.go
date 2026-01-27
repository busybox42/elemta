package main

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
)

func main() {
	// Test successful authentication
	fmt.Println("Testing successful authentication...")
	if err := testAuthSuccess(); err != nil {
		fmt.Printf("Auth success test failed: %v\n", err)
	} else {
		fmt.Println("Auth success test passed")
	}

	fmt.Println()

	// Test failed authentication
	fmt.Println("Testing failed authentication...")
	if err := testAuthFailure(); err != nil {
		fmt.Printf("Auth failure test failed: %v\n", err)
	} else {
		fmt.Println("Auth failure test passed")
	}
}

func testAuthSuccess() error {
	// Connect with TLS
	conn, err := tls.Dial("tcp", "localhost:2525", &tls.Config{
		InsecureSkipVerify: true, // For testing
	})
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %v", err)
	}
	defer client.Quit()

	// Test AUTH PLAIN with valid credentials
	auth := smtp.PlainAuth("", "testuser", "testpass", "localhost")
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("AUTH PLAIN failed: %v", err)
	}

	fmt.Println("✓ AUTH PLAIN successful")

	// Test MAIL FROM after authentication
	if err := client.Mail("sender@example.com"); err != nil {
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}

	if err := client.Rcpt("recipient@example.com"); err != nil {
		return fmt.Errorf("RCPT TO failed: %v", err)
	}

	fmt.Println("✓ Post-auth MAIL FROM/RCPT TO successful")

	return nil
}

func testAuthFailure() error {
	// Connect with TLS
	conn, err := tls.Dial("tcp", "localhost:2525", &tls.Config{
		InsecureSkipVerify: true, // For testing
	})
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %v", err)
	}
	defer client.Quit()

	// Test AUTH PLAIN with invalid credentials
	auth := smtp.PlainAuth("", "wronguser", "wrongpass", "localhost")
	err = client.Auth(auth)
	if err == nil {
		return fmt.Errorf("expected AUTH to fail with wrong credentials")
	}

	if !strings.Contains(err.Error(), "535") {
		return fmt.Errorf("expected 535 error code, got: %v", err)
	}

	fmt.Println("✓ AUTH PLAIN correctly rejected invalid credentials")

	return nil
}
