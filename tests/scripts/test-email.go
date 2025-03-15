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
	if err := c.Rcpt("recipient@example.com"); err != nil {
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

	msg := []byte("To: recipient@example.com\r\n" +
		"Subject: Test Email\r\n" +
		"\r\n" +
		"This is a test email from Go.\r\n")

	if _, err = wc.Write(msg); err != nil {
		fmt.Println("Error writing message:", err)
		return
	}

	// Send the QUIT command and close the connection
	if err := c.Quit(); err != nil {
		fmt.Println("Error closing connection:", err)
		return
	}

	fmt.Println("Email sent successfully!")
}
