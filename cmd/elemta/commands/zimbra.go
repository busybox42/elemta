package commands

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/busybox42/elemta/internal/zimbra"
	"github.com/busybox42/elemta/internal/zimbra/ldap"
	"github.com/busybox42/elemta/internal/zimbra/soap"
	"github.com/spf13/cobra"
)

// zimbraCmd represents the zimbra command
var zimbraCmd = &cobra.Command{
	Use:   "zimbra",
	Short: "Zimbra integration commands",
	Long:  "Commands for testing and managing Zimbra integration via LDAP and SOAP.",
}

// zimbraLDAPCmd represents the zimbra ldap command
var zimbraLDAPCmd = &cobra.Command{
	Use:   "ldap",
	Short: "LDAP integration commands",
	Long:  "Commands for testing and managing LDAP integration with Zimbra.",
}

// zimbraSOAPCmd represents the zimbra soap command
var zimbraSOAPCmd = &cobra.Command{
	Use:   "soap",
	Short: "SOAP API integration commands",
	Long:  "Commands for testing and managing SOAP API integration with Zimbra.",
}

// zimbraLDAPTestCmd tests LDAP connection
var zimbraLDAPTestCmd = &cobra.Command{
	Use:   "test-connection",
	Short: "Test LDAP connection to Zimbra",
	Long:  "Test the LDAP connection to Zimbra server and validate configuration.",
	RunE:  runZimbraLDAPTest,
}

// zimbraLDAPUserCmd tests user lookup
var zimbraLDAPUserCmd = &cobra.Command{
	Use:   "test-user <email>",
	Short: "Test user lookup via LDAP",
	Long:  "Test looking up a user in Zimbra LDAP directory.",
	Args:  cobra.ExactArgs(1),
	RunE:  runZimbraLDAPUser,
}

// zimbraSOAPTestCmd tests SOAP connection
var zimbraSOAPTestCmd = &cobra.Command{
	Use:   "test-connection",
	Short: "Test SOAP API connection to Zimbra",
	Long:  "Test the SOAP API connection to Zimbra server and validate authentication.",
	RunE:  runZimbraSOAPTest,
}

// Zimbra configuration flags
var (
	zimbraLDAPServer   string
	zimbraLDAPPort     int
	zimbraLDAPBaseDN   string
	zimbraLDAPBindDN   string
	zimbraLDAPBindPass string
	zimbraLDAPTLS      bool

	zimbraSOAPURL      string
	zimbraSOAPAdminURL string
	zimbraSOAPUser     string
	zimbraSOAPPass     string
	zimbraSOAPSkipTLS  bool
)

func init() {
	// Add zimbra command and subcommands
	rootCmd.AddCommand(zimbraCmd)
	zimbraCmd.AddCommand(zimbraLDAPCmd)
	zimbraCmd.AddCommand(zimbraSOAPCmd)

	// Add LDAP subcommands
	zimbraLDAPCmd.AddCommand(zimbraLDAPTestCmd)
	zimbraLDAPCmd.AddCommand(zimbraLDAPUserCmd)

	// Add SOAP subcommands
	zimbraSOAPCmd.AddCommand(zimbraSOAPTestCmd)

	// LDAP flags
	zimbraLDAPCmd.PersistentFlags().StringVar(&zimbraLDAPServer, "server", "zimbra-test.local", "LDAP server hostname")
	zimbraLDAPCmd.PersistentFlags().IntVar(&zimbraLDAPPort, "port", 389, "LDAP server port")
	zimbraLDAPCmd.PersistentFlags().StringVar(&zimbraLDAPBaseDN, "base-dn", "dc=zimbra-test,dc=local", "LDAP base DN")
	zimbraLDAPCmd.PersistentFlags().StringVar(&zimbraLDAPBindDN, "bind-dn", "", "LDAP bind DN")
	zimbraLDAPCmd.PersistentFlags().StringVar(&zimbraLDAPBindPass, "bind-password", "", "LDAP bind password")
	zimbraLDAPCmd.PersistentFlags().BoolVar(&zimbraLDAPTLS, "tls", false, "Use TLS/SSL")

	// SOAP flags
	zimbraSOAPCmd.PersistentFlags().StringVar(&zimbraSOAPURL, "url", "https://zimbra-test.local:7071/service/soap", "SOAP API URL")
	zimbraSOAPCmd.PersistentFlags().StringVar(&zimbraSOAPAdminURL, "admin-url", "https://zimbra-test.local:7071/service/admin/soap", "SOAP Admin API URL")
	zimbraSOAPCmd.PersistentFlags().StringVar(&zimbraSOAPUser, "user", "admin", "Admin username")
	zimbraSOAPCmd.PersistentFlags().StringVar(&zimbraSOAPPass, "password", "", "Admin password")
	zimbraSOAPCmd.PersistentFlags().BoolVar(&zimbraSOAPSkipTLS, "skip-tls-verify", true, "Skip TLS certificate verification")
}

func runZimbraLDAPTest(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	// Create LDAP configuration
	config := &zimbra.LDAPConfig{
		Servers:          []string{zimbraLDAPServer},
		Port:             zimbraLDAPPort,
		BaseDN:           zimbraLDAPBaseDN,
		BindDN:           zimbraLDAPBindDN,
		BindPass:         zimbraLDAPBindPass,
		TLS:              zimbraLDAPTLS,
		MaxConnections:   1,
		MaxIdleTime:      5 * time.Minute,
		ConnectTimeout:   10 * time.Second,
		SearchTimeout:    30 * time.Second,
		UserSearchBase:   "ou=people",
		UserSearchFilter: "(mail=%s)",
		LocalDomains:     []string{"zimbra-test.local"},
	}

	fmt.Printf("Testing LDAP connection to %s:%d...\n", zimbraLDAPServer, zimbraLDAPPort)
	fmt.Printf("Base DN: %s\n", zimbraLDAPBaseDN)
	if zimbraLDAPBindDN != "" {
		fmt.Printf("Bind DN: %s\n", zimbraLDAPBindDN)
	}
	fmt.Printf("TLS: %v\n", zimbraLDAPTLS)
	fmt.Println()

	// Create LDAP client
	client := ldap.NewClient(config, logger)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Get statistics
	stats := client.GetStats()

	fmt.Println("✅ LDAP connection successful!")
	fmt.Printf("Pool size: %v\n", stats["pool_size"])
	fmt.Printf("Active connections: %v\n", stats["active_connections"])
	fmt.Printf("Total connections: %v\n", stats["total_connections"])

	return nil
}

func runZimbraLDAPUser(cmd *cobra.Command, args []string) error {
	email := args[0]
	logger := slog.Default()

	// Create LDAP configuration
	config := &zimbra.LDAPConfig{
		Servers:          []string{zimbraLDAPServer},
		Port:             zimbraLDAPPort,
		BaseDN:           zimbraLDAPBaseDN,
		BindDN:           zimbraLDAPBindDN,
		BindPass:         zimbraLDAPBindPass,
		TLS:              zimbraLDAPTLS,
		MaxConnections:   1,
		MaxIdleTime:      5 * time.Minute,
		ConnectTimeout:   10 * time.Second,
		SearchTimeout:    30 * time.Second,
		UserSearchBase:   "ou=people",
		UserSearchFilter: "(mail=%s)",
		LocalDomains:     []string{"zimbra-test.local"},
	}

	fmt.Printf("Looking up user: %s\n", email)
	fmt.Printf("LDAP server: %s:%d\n", zimbraLDAPServer, zimbraLDAPPort)
	fmt.Println()

	// Create LDAP client and user service
	client := ldap.NewClient(config, logger)
	userService := ldap.NewUserService(client, logger)

	// Connect to LDAP
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Look up user
	user, err := userService.FindUser(ctx, email)
	if err != nil {
		return fmt.Errorf("user lookup failed: %w", err)
	}

	// Display user information
	fmt.Println("✅ User found!")
	fmt.Printf("DN: %s\n", user.DN)
	fmt.Printf("Mail: %s\n", user.Mail)
	fmt.Printf("UID: %s\n", user.UID)
	fmt.Printf("CN: %s\n", user.CN)
	fmt.Printf("Display Name: %s\n", user.DisplayName)
	fmt.Printf("Account Status: %s\n", user.ZimbraAccountStatus)
	fmt.Printf("Mail Host: %s\n", user.ZimbraMailHost)
	fmt.Printf("Mail Quota: %s\n", user.ZimbraMailQuota)
	if len(user.ZimbraMailAlias) > 0 {
		fmt.Printf("Aliases: %v\n", user.ZimbraMailAlias)
	}

	// Test mailbox validation
	valid, err := userService.ValidateMailbox(ctx, email)
	if err != nil {
		fmt.Printf("⚠️  Mailbox validation failed: %v\n", err)
	} else if valid {
		fmt.Println("✅ Mailbox validation successful!")
	}

	return nil
}

func runZimbraSOAPTest(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	// Create SOAP configuration
	config := &zimbra.SOAPConfig{
		URL:                     zimbraSOAPURL,
		AdminURL:                zimbraSOAPAdminURL,
		AdminUser:               zimbraSOAPUser,
		AdminPassword:           zimbraSOAPPass,
		Timeout:                 30 * time.Second,
		MaxRetries:              3,
		RetryDelay:              time.Second,
		SkipTLSVerify:           zimbraSOAPSkipTLS,
		TokenLifetime:           24 * time.Hour,
		CircuitBreakerThreshold: 5,
		CircuitBreakerTimeout:   30 * time.Second,
	}

	fmt.Printf("Testing SOAP connection to %s...\n", zimbraSOAPAdminURL)
	fmt.Printf("Admin user: %s\n", zimbraSOAPUser)
	fmt.Printf("Skip TLS verification: %v\n", zimbraSOAPSkipTLS)
	fmt.Println()

	// Create SOAP client
	client := soap.NewClient(config, logger)

	// Test connection and authentication
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Connect(ctx)
	if err != nil {
		return fmt.Errorf("SOAP connection failed: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Get statistics
	stats := client.GetStats()

	fmt.Println("✅ SOAP connection and authentication successful!")
	fmt.Printf("Total requests: %v\n", stats["total_requests"])
	fmt.Printf("Total errors: %v\n", stats["total_errors"])
	fmt.Printf("Has auth token: %v\n", stats["has_auth_token"])
	fmt.Printf("Auth token expiry: %v\n", stats["auth_token_expiry"])
	fmt.Printf("Circuit open: %v\n", stats["circuit_open"])

	return nil
}
