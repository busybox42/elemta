package main

import (
	"fmt"
	"net/smtp"
	"strings"
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

	// GTUBE pattern for spam testing
	msg := []byte("To: recipient@example.com\r\n" +
		"Subject: GTUBE Test\r\n" +
		"\r\n" +
		"XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n")

	if _, err = wc.Write(msg); err != nil {
		fmt.Println("Error writing message:", err)
		return
	}

	// Send the QUIT command and close the connection
	err = c.Quit()
	if err != nil {
		// Check if this is the expected response for spam detection
		if strings.Contains(err.Error(), "554 5.7.1 Spam score") {
			fmt.Println("Spam detected successfully!")
			return
		}
		fmt.Println("Error closing connection:", err)
		return
	}

	fmt.Println("Email sent successfully, but spam was not detected!")
}
