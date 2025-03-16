package main

import (
	"fmt"
	"net/smtp"
)

func main() {
	// Connect to the server
	c, err := smtp.Dial("localhost:2525")
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer c.Close()

	// Set the sender and recipient
	if err := c.Mail("sender@example.com"); err != nil {
		fmt.Println("Error setting sender:", err)
		return
	}
	if err := c.Rcpt("recipient@example.org"); err != nil {
		fmt.Println("Error setting recipient:", err)
		return
	}

	// Send the email body
	wc, err := c.Data()
	if err != nil {
		fmt.Println("Error getting data writer:", err)
		return
	}
	defer wc.Close()

	message := `From: sender@example.com
To: recipient@example.org
Subject: Test Email

This is a test email sent from the Elemta test script.
`

	if _, err = fmt.Fprintf(wc, message); err != nil {
		fmt.Println("Error writing message:", err)
		return
	}

	fmt.Println("Test email sent successfully!")
}
