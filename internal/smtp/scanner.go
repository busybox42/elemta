package smtp

import (
	"context"
	"fmt"
	"log"

	"github.com/busybox42/elemta/internal/antispam"
	"github.com/busybox42/elemta/internal/antivirus"
)

// ScannerManager manages both antivirus and antispam scanners
type ScannerManager struct {
	config           *Config
	antivirusManager *antivirus.Manager
	antispamManager  *antispam.Manager
	scanners         map[string]interface{} // Generic map to store all scanner types
	server           *Server
}

// NewScannerManager creates a new scanner manager
func NewScannerManager(config *Config, server *Server) *ScannerManager {
	return &ScannerManager{
		config:           config,
		antivirusManager: antivirus.NewManager(),
		antispamManager:  antispam.NewManager(),
		scanners:         make(map[string]interface{}),
		server:           server,
	}
}

// Initialize initializes all configured scanners
func (m *ScannerManager) Initialize(ctx context.Context) error {
	// Initialize antivirus scanners
	if err := m.initializeAntivirusScanners(ctx); err != nil {
		log.Printf("Warning: Error initializing antivirus scanners: %v", err)
	}

	// Initialize antispam scanners
	if err := m.initializeAntispamScanners(ctx); err != nil {
		log.Printf("Warning: Error initializing antispam scanners: %v", err)
	}

	// Initialize plugin scanners if plugin manager is available
	if m.config.Plugins != nil && m.config.Plugins.Enabled && m.server != nil && m.server.pluginManager != nil {
		if err := m.initializePluginScanners(ctx); err != nil {
			log.Printf("Warning: Error initializing plugin scanners: %v", err)
		}
	}

	return nil
}

// initializeAntivirusScanners initializes all configured antivirus scanners
func (m *ScannerManager) initializeAntivirusScanners(ctx context.Context) error {
	// Initialize ClamAV if enabled
	if m.config.Antivirus != nil && m.config.Antivirus.ClamAV != nil && m.config.Antivirus.ClamAV.Enabled {
		clamavConfig := antivirus.Config{
			Type:    "clamav",
			Name:    "clamav",
			Address: m.config.Antivirus.ClamAV.Address,
			Options: map[string]interface{}{
				"timeout":     m.config.Antivirus.ClamAV.Timeout,
				"scan_limit":  m.config.Antivirus.ClamAV.ScanLimit,
				"scan_buffer": 8192, // Default buffer size
			},
		}

		scanner, err := antivirus.Factory(clamavConfig)
		if err != nil {
			log.Printf("Warning: Failed to create ClamAV scanner: %v", err)
			return err
		}

		if err := scanner.Connect(); err != nil {
			log.Printf("Warning: Failed to connect to ClamAV: %v", err)
			return err
		}

		if err := m.antivirusManager.Register(scanner); err != nil {
			log.Printf("Warning: Failed to register ClamAV: %v", err)
			return err
		}

		// Store in generic scanners map
		m.scanners["antivirus:"+scanner.Name()] = scanner
		log.Printf("ClamAV scanner registered and connected to %s", clamavConfig.Address)
	}

	return nil
}

// initializeAntispamScanners initializes all configured antispam scanners
func (m *ScannerManager) initializeAntispamScanners(ctx context.Context) error {
	// Initialize SpamAssassin if enabled
	if m.config.Antispam != nil && m.config.Antispam.SpamAssassin != nil && m.config.Antispam.SpamAssassin.Enabled {
		spamassassinConfig := antispam.Config{
			Type:      "spamassassin",
			Name:      "spamassassin",
			Address:   m.config.Antispam.SpamAssassin.Address,
			Threshold: m.config.Antispam.SpamAssassin.Threshold,
			Options: map[string]interface{}{
				"timeout":    m.config.Antispam.SpamAssassin.Timeout,
				"scan_limit": m.config.Antispam.SpamAssassin.ScanLimit,
			},
		}

		scanner, err := antispam.Factory(spamassassinConfig)
		if err != nil {
			log.Printf("Warning: Failed to create SpamAssassin scanner: %v", err)
			return err
		}

		if err := scanner.Connect(); err != nil {
			log.Printf("Warning: Failed to connect to SpamAssassin: %v", err)
			return err
		}

		if err := m.antispamManager.Register(scanner); err != nil {
			log.Printf("Warning: Failed to register SpamAssassin: %v", err)
			return err
		}

		// Store in generic scanners map
		m.scanners["antispam:"+scanner.Name()] = scanner
		log.Printf("SpamAssassin scanner registered and connected to %s", spamassassinConfig.Address)
	}

	// Initialize Rspamd if enabled
	if m.config.Antispam != nil && m.config.Antispam.Rspamd != nil && m.config.Antispam.Rspamd.Enabled {
		rspamdConfig := antispam.Config{
			Type:      "rspamd",
			Name:      "rspamd",
			Address:   m.config.Antispam.Rspamd.Address,
			Threshold: m.config.Antispam.Rspamd.Threshold,
			Options: map[string]interface{}{
				"timeout":    m.config.Antispam.Rspamd.Timeout,
				"scan_limit": m.config.Antispam.Rspamd.ScanLimit,
				"api_key":    m.config.Antispam.Rspamd.APIKey,
			},
		}

		scanner, err := antispam.Factory(rspamdConfig)
		if err != nil {
			log.Printf("Warning: Failed to create Rspamd scanner: %v", err)
			return err
		}

		if err := scanner.Connect(); err != nil {
			log.Printf("Warning: Failed to connect to Rspamd: %v", err)
			return err
		}

		if err := m.antispamManager.Register(scanner); err != nil {
			log.Printf("Warning: Failed to register Rspamd: %v", err)
			return err
		}

		// Store in generic scanners map
		m.scanners["antispam:"+scanner.Name()] = scanner
		log.Printf("Rspamd scanner registered and connected to %s", rspamdConfig.Address)
	}

	return nil
}

// initializePluginScanners initializes scanners from plugins
func (m *ScannerManager) initializePluginScanners(ctx context.Context) error {
	// Initialize antivirus plugins
	for _, pluginName := range m.server.pluginManager.ListAntivirusPlugins() {
		plugin, err := m.server.pluginManager.GetAntivirusPlugin(pluginName)
		if err != nil {
			log.Printf("Warning: Failed to get antivirus plugin %s: %v", pluginName, err)
			continue
		}

		scanner := plugin.GetScanner()
		info := plugin.GetInfo()

		log.Printf("Initializing antivirus plugin scanner: %s (%s)", info.Name, info.Description)

		if err := scanner.Connect(); err != nil {
			log.Printf("Warning: Failed to connect to antivirus plugin scanner %s: %v", info.Name, err)
			continue
		}

		if err := m.antivirusManager.Register(scanner); err != nil {
			log.Printf("Warning: Failed to register antivirus plugin scanner %s: %v", info.Name, err)
			continue
		}

		// Store in generic scanners map
		m.scanners["antivirus:plugin:"+scanner.Name()] = scanner
		log.Printf("Antivirus plugin scanner %s registered and connected", info.Name)
	}

	// Initialize antispam plugins
	for _, pluginName := range m.server.pluginManager.ListAntispamPlugins() {
		plugin, err := m.server.pluginManager.GetAntispamPlugin(pluginName)
		if err != nil {
			log.Printf("Warning: Failed to get antispam plugin %s: %v", pluginName, err)
			continue
		}

		scanner := plugin.GetScanner()
		info := plugin.GetInfo()

		log.Printf("Initializing antispam plugin scanner: %s (%s)", info.Name, info.Description)

		if err := scanner.Connect(); err != nil {
			log.Printf("Warning: Failed to connect to antispam plugin scanner %s: %v", info.Name, err)
			continue
		}

		if err := m.antispamManager.Register(scanner); err != nil {
			log.Printf("Warning: Failed to register antispam plugin scanner %s: %v", info.Name, err)
			continue
		}

		// Store in generic scanners map
		m.scanners["antispam:plugin:"+scanner.Name()] = scanner
		log.Printf("Antispam plugin scanner %s registered and connected", info.Name)
	}

	return nil
}

// RegisterScanner registers a custom scanner
func (m *ScannerManager) RegisterScanner(scannerType string, scanner interface{}) error {
	switch scannerType {
	case "antivirus":
		if avScanner, ok := scanner.(antivirus.Scanner); ok {
			if err := m.antivirusManager.Register(avScanner); err != nil {
				return err
			}
			m.scanners["antivirus:"+avScanner.Name()] = avScanner
			return nil
		}
		return fmt.Errorf("invalid antivirus scanner type")
	case "antispam":
		if asScanner, ok := scanner.(antispam.Scanner); ok {
			if err := m.antispamManager.Register(asScanner); err != nil {
				return err
			}
			m.scanners["antispam:"+asScanner.Name()] = asScanner
			return nil
		}
		return fmt.Errorf("invalid antispam scanner type")
	default:
		return fmt.Errorf("unsupported scanner type: %s", scannerType)
	}
}

// Close closes all scanners
func (m *ScannerManager) Close() error {
	if err := m.antivirusManager.CloseAll(); err != nil {
		log.Printf("Warning: Error closing antivirus scanners: %v", err)
	}

	if err := m.antispamManager.CloseAll(); err != nil {
		log.Printf("Warning: Error closing antispam scanners: %v", err)
	}

	return nil
}

// ScanForViruses scans data for viruses
func (m *ScannerManager) ScanForViruses(ctx context.Context, data []byte) ([]*antivirus.ScanResult, error) {
	return m.antivirusManager.ScanBytes(ctx, data)
}

// ScanForSpam scans data for spam
func (m *ScannerManager) ScanForSpam(ctx context.Context, data []byte) ([]*antispam.ScanResult, error) {
	return m.antispamManager.ScanBytes(ctx, data)
}

// ScanWithAll scans data with all registered scanners
func (m *ScannerManager) ScanWithAll(ctx context.Context, data []byte) (map[string]interface{}, error) {
	results := make(map[string]interface{})
	var errs []error

	// Scan with antivirus scanners
	avResults, err := m.ScanForViruses(ctx, data)
	if err != nil {
		errs = append(errs, fmt.Errorf("antivirus scan failed: %w", err))
	} else {
		results["antivirus"] = avResults
	}

	// Scan with antispam scanners
	asResults, err := m.ScanForSpam(ctx, data)
	if err != nil {
		errs = append(errs, fmt.Errorf("antispam scan failed: %w", err))
	} else {
		results["antispam"] = asResults
	}

	if len(results) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("all scans failed: %v", errs)
	}

	return results, nil
}

// HasAntivirusScanners returns true if there are any antivirus scanners registered
func (m *ScannerManager) HasAntivirusScanners() bool {
	return len(m.antivirusManager.List()) > 0
}

// HasAntispamScanners returns true if there are any antispam scanners registered
func (m *ScannerManager) HasAntispamScanners() bool {
	return len(m.antispamManager.List()) > 0
}

// GetAntivirusScanner returns an antivirus scanner by name
func (m *ScannerManager) GetAntivirusScanner(name string) (antivirus.Scanner, error) {
	return m.antivirusManager.Get(name)
}

// GetAntispamScanner returns an antispam scanner by name
func (m *ScannerManager) GetAntispamScanner(name string) (antispam.Scanner, error) {
	return m.antispamManager.Get(name)
}

// ListAntivirusScanners returns all registered antivirus scanners
func (m *ScannerManager) ListAntivirusScanners() map[string]antivirus.Scanner {
	return m.antivirusManager.List()
}

// ListAntispamScanners returns all registered antispam scanners
func (m *ScannerManager) ListAntispamScanners() map[string]antispam.Scanner {
	return m.antispamManager.List()
}

// GetAllScanners returns all registered scanners
func (m *ScannerManager) GetAllScanners() map[string]interface{} {
	return m.scanners
}
