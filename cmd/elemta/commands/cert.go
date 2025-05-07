package commands

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/busybox42/elemta/internal/smtp"
	"github.com/spf13/cobra"
)

func init() {
	// Add certificate management commands
	rootCmd.AddCommand(certCmd)
	certCmd.AddCommand(certInfoCmd)
	certCmd.AddCommand(certRenewCmd)
	certCmd.AddCommand(certTestCmd)
}

// certCmd represents the certificate management command
var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Certificate management commands",
	Long:  `Commands for managing TLS certificates, including Let's Encrypt integration.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// certInfoCmd displays information about the current certificates
var certInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display certificate information",
	Long:  `Display detailed information about the current TLS certificates.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Load configuration
		config, err := loadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
		}

		// Check if TLS is enabled
		if config.TLS == nil || !config.TLS.Enabled {
			fmt.Println("TLS is not enabled in the configuration.")
			os.Exit(1)
		}

		// Create TLS manager
		tlsManager, err := smtp.NewTLSManager(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating TLS manager: %v\n", err)
			os.Exit(1)
		}
		defer tlsManager.Stop()

		// Get certificate info
		info, err := tlsManager.GetCertificateInfo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting certificate info: %v\n", err)
			os.Exit(1)
		}

		// Display certificate info
		fmt.Println("Certificate Information:")
		fmt.Println("------------------------")
		fmt.Printf("Type: %s\n", info["type"])

		if info["domain"] != nil {
			fmt.Printf("Domain: %s\n", info["domain"])
		}

		if info["not_before"] != nil {
			notBefore := info["not_before"].(time.Time)
			fmt.Printf("Valid From: %s\n", notBefore.Format(time.RFC3339))
		}

		if info["not_after"] != nil {
			notAfter := info["not_after"].(time.Time)
			fmt.Printf("Valid Until: %s\n", notAfter.Format(time.RFC3339))
		}

		if info["days_until_expiration"] != nil {
			days := info["days_until_expiration"].(int)
			fmt.Printf("Days Until Expiration: %d\n", days)
		}

		if info["issuer"] != nil {
			fmt.Printf("Issuer: %s\n", info["issuer"])
		}

		if info["last_renewed"] != nil {
			renewed := info["last_renewed"].(time.Time)
			fmt.Printf("Last Renewed: %s\n", renewed.Format(time.RFC3339))
		}

		// Let's Encrypt specific info
		if info["type"] == "letsencrypt" {
			fmt.Println("\nLet's Encrypt Configuration:")
			fmt.Printf("Email: %s\n", info["email"])
			fmt.Printf("Staging: %t\n", info["staging"])

			if info["cached_certs"] != nil {
				certs := info["cached_certs"].([]string)
				if len(certs) > 0 {
					fmt.Println("\nCached Certificates:")
					for _, cert := range certs {
						fmt.Printf("- %s\n", cert)
					}
				}
			}
		} else {
			fmt.Println("\nManual Certificate Configuration:")
			fmt.Printf("Certificate File: %s\n", info["cert_file"])
			fmt.Printf("Key File: %s\n", info["key_file"])
		}
	},
}

// certRenewCmd forces renewal of the Let's Encrypt certificate
var certRenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Force renewal of the Let's Encrypt certificate",
	Long:  `Force renewal of the Let's Encrypt certificate regardless of expiration date.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Load configuration
		config, err := loadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
		}

		// Check if TLS is enabled
		if config.TLS == nil || !config.TLS.Enabled {
			fmt.Println("TLS is not enabled in the configuration.")
			os.Exit(1)
		}

		// Check if Let's Encrypt is enabled
		if config.TLS.LetsEncrypt == nil || !config.TLS.LetsEncrypt.Enabled {
			fmt.Println("Let's Encrypt is not enabled in the configuration.")
			os.Exit(1)
		}

		// Create TLS manager
		tlsManager, err := smtp.NewTLSManager(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating TLS manager: %v\n", err)
			os.Exit(1)
		}
		defer tlsManager.Stop()

		// Force renewal
		fmt.Println("Forcing certificate renewal...")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		if err := tlsManager.RenewCertificates(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Error renewing certificate: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Certificate renewal completed successfully.")
	},
}

// certTestCmd tests the ACME challenge setup for Let's Encrypt
var certTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test ACME challenge setup for Let's Encrypt",
	Long:  `Test if the ACME HTTP-01 challenge is properly configured for Let's Encrypt domain validation.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Load configuration
		config, err := loadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
		}

		// Check if TLS is enabled
		if config.TLS == nil || !config.TLS.Enabled {
			fmt.Println("TLS is not enabled in the configuration.")
			os.Exit(1)
		}

		// Check if Let's Encrypt is enabled
		if config.TLS.LetsEncrypt == nil || !config.TLS.LetsEncrypt.Enabled {
			fmt.Println("Let's Encrypt is not enabled in the configuration.")
			os.Exit(1)
		}

		domain := config.TLS.LetsEncrypt.Domain
		if domain == "" {
			fmt.Println("No domain specified in Let's Encrypt configuration.")
			os.Exit(1)
		}

		fmt.Printf("Testing ACME challenge setup for domain: %s\n", domain)
		fmt.Println("")
		fmt.Println("Validation Requirements:")
		fmt.Println("1. HTTP port 80 must be accessible from the internet")
		fmt.Println("2. DNS must be properly configured to point to this server")
		fmt.Println("3. Firewall rules must allow incoming connections on port 80")
		fmt.Println("")
		fmt.Printf("You can manually test HTTP-01 challenge by visiting: http://%s/.well-known/acme-challenge/test\n", domain)
		fmt.Println("It should return a 404 Not Found, which indicates the path is properly accessible.")
		fmt.Println("")
		fmt.Println("For production use, you should also ensure port 443 is open for TLS connections.")
	},
}

// loadConfig loads the configuration file
func loadConfig() (*smtp.Config, error) {
	// If we already have a config loaded, create SMTP config from it
	if cfg != nil {
		// Create SMTP configuration
		smtpConfig := &smtp.Config{
			Hostname:   cfg.Server.Hostname,
			ListenAddr: cfg.Server.Listen,
			QueueDir:   cfg.QueueDir,
			MaxSize:    10 * 1024 * 1024, // Use 10MB default if not specified
		}

		// Set up basic TLS configuration from Server section
		if cfg.Server.TLS {
			smtpConfig.TLS = &smtp.TLSConfig{
				Enabled:  true,
				CertFile: cfg.Server.CertFile,
				KeyFile:  cfg.Server.KeyFile,
			}
		}

		// If enhanced TLS configuration exists, use it instead
		if cfg.TLS.Enabled {
			// Create or update TLS config
			if smtpConfig.TLS == nil {
				smtpConfig.TLS = &smtp.TLSConfig{}
			}

			// Copy all enhanced TLS settings
			smtpConfig.TLS.Enabled = cfg.TLS.Enabled
			smtpConfig.TLS.ListenAddr = cfg.TLS.ListenAddr
			smtpConfig.TLS.CertFile = cfg.TLS.CertFile
			smtpConfig.TLS.KeyFile = cfg.TLS.KeyFile
			smtpConfig.TLS.MinVersion = cfg.TLS.MinVersion
			smtpConfig.TLS.MaxVersion = cfg.TLS.MaxVersion
			smtpConfig.TLS.Ciphers = cfg.TLS.Ciphers
			smtpConfig.TLS.Curves = cfg.TLS.Curves
			smtpConfig.TLS.ClientAuth = cfg.TLS.ClientAuth
			smtpConfig.TLS.EnableStartTLS = cfg.TLS.EnableStartTLS

			// Let's Encrypt settings
			if cfg.TLS.LetsEncrypt.Enabled {
				smtpConfig.TLS.LetsEncrypt = &smtp.LetsEncryptConfig{
					Enabled:  cfg.TLS.LetsEncrypt.Enabled,
					Domain:   cfg.TLS.LetsEncrypt.Domain,
					Email:    cfg.TLS.LetsEncrypt.Email,
					CacheDir: cfg.TLS.LetsEncrypt.CacheDir,
					Staging:  cfg.TLS.LetsEncrypt.Staging,
				}
			}

			// Renewal settings
			if cfg.TLS.Renewal.AutoRenew {
				smtpConfig.TLS.RenewalConfig = &smtp.CertRenewalConfig{
					AutoRenew:      cfg.TLS.Renewal.AutoRenew,
					RenewalDays:    cfg.TLS.Renewal.RenewalDays,
					CheckInterval:  cfg.TLS.Renewal.CheckInterval,
					RenewalTimeout: cfg.TLS.Renewal.RenewalTimeout,
				}
			}
		}

		return smtpConfig, nil
	}

	return nil, fmt.Errorf("configuration not loaded, use --config flag to specify a config file")
}
