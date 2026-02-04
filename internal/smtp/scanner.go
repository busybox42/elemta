package smtp

import (
	"context"
	"fmt"
	"log/slog"

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
	logger           *slog.Logger
}

// NewScannerManager creates a new scanner manager
func NewScannerManager(config *Config, server *Server) *ScannerManager {
	logger := slog.Default().With("component", "scanner-manager")
	return &ScannerManager{
		config:           config,
		antivirusManager: antivirus.NewManager(),
		antispamManager:  antispam.NewManager(),
		scanners:         make(map[string]interface{}),
		server:           server,
		logger:           logger,
	}
}

// Initialize initializes all configured scanners
func (m *ScannerManager) Initialize(ctx context.Context) error {
	// Initialize antivirus scanners
	if err := m.initializeAntivirusScanners(ctx); err != nil {
		m.logger.WarnContext(ctx, "Error initializing antivirus scanners", "error", err)
	}

	// Initialize antispam scanners
	if err := m.initializeAntispamScanners(ctx); err != nil {
		m.logger.WarnContext(ctx, "Error initializing antispam scanners", "error", err)
	}

	// Initialize plugin scanners if plugin manager is available
	if m.config.Plugins != nil && m.config.Plugins.Enabled && m.server != nil && m.server.pluginManager != nil {
		if err := m.initializePluginScanners(ctx); err != nil {
			m.logger.WarnContext(ctx, "Error initializing plugin scanners", "error", err)
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
			m.logger.WarnContext(ctx, "Failed to create ClamAV scanner", "error", err, "address", m.config.Antivirus.ClamAV.Address)
			return err
		}

		if err := scanner.Connect(); err != nil {
			m.logger.WarnContext(ctx, "Failed to connect to ClamAV", "error", err, "address", m.config.Antivirus.ClamAV.Address)
			return err
		}

		if err := m.antivirusManager.Register(scanner); err != nil {
			m.logger.WarnContext(ctx, "Failed to register ClamAV", "error", err, "address", m.config.Antivirus.ClamAV.Address)
			return err
		}

		// Store in generic scanners map
		m.scanners["antivirus:"+scanner.Name()] = scanner
		m.logger.InfoContext(ctx, "ClamAV scanner registered and connected", "address", clamavConfig.Address, "scanner", scanner.Name())
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
			m.logger.WarnContext(ctx, "Failed to create SpamAssassin scanner", "error", err, "address", m.config.Antispam.SpamAssassin.Address)
			return err
		}

		if err := scanner.Connect(); err != nil {
			m.logger.WarnContext(ctx, "Failed to connect to SpamAssassin", "error", err, "address", m.config.Antispam.SpamAssassin.Address)
			return err
		}

		if err := m.antispamManager.Register(scanner); err != nil {
			m.logger.WarnContext(ctx, "Failed to register SpamAssassin", "error", err, "address", m.config.Antispam.SpamAssassin.Address)
			return err
		}

		// Store in generic scanners map
		m.scanners["antispam:"+scanner.Name()] = scanner
		m.logger.InfoContext(ctx, "SpamAssassin scanner registered and connected", "address", spamassassinConfig.Address, "scanner", scanner.Name())
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
			m.logger.WarnContext(ctx, "Failed to create Rspamd scanner", "error", err, "address", m.config.Antispam.Rspamd.Address)
			return err
		}

		if err := scanner.Connect(); err != nil {
			m.logger.WarnContext(ctx, "Failed to connect to Rspamd", "error", err, "address", m.config.Antispam.Rspamd.Address)
			return err
		}

		if err := m.antispamManager.Register(scanner); err != nil {
			m.logger.WarnContext(ctx, "Failed to register Rspamd", "error", err, "address", m.config.Antispam.Rspamd.Address)
			return err
		}

		// Store in generic scanners map
		m.scanners["antispam:"+scanner.Name()] = scanner
		m.logger.InfoContext(ctx, "Rspamd scanner registered and connected", "address", rspamdConfig.Address, "scanner", scanner.Name())
	}

	return nil
}

// initializePluginScanners initializes scanners from plugins
func (m *ScannerManager) initializePluginScanners(ctx context.Context) error {
	// Initialize antivirus plugins
	for _, pluginName := range m.server.pluginManager.ListAntivirusPlugins() {
		plugin, err := m.server.pluginManager.GetAntivirusPlugin(pluginName)
		if err != nil {
			m.logger.WarnContext(ctx, "Failed to get antivirus plugin", "plugin", pluginName, "error", err)
			continue
		}

		scanner := plugin.GetScanner()
		info := plugin.GetInfo()

		m.logger.InfoContext(ctx, "Initializing antivirus plugin scanner", "plugin", info.Name, "description", info.Description)

		if err := scanner.Connect(); err != nil {
			m.logger.WarnContext(ctx, "Failed to connect to antivirus plugin scanner", "plugin", info.Name, "error", err)
			continue
		}

		if err := m.antivirusManager.Register(scanner); err != nil {
			m.logger.WarnContext(ctx, "Failed to register antivirus plugin scanner", "plugin", info.Name, "error", err)
			continue
		}

		// Store in generic scanners map
		m.scanners["antivirus:plugin:"+scanner.Name()] = scanner
		m.logger.InfoContext(ctx, "Antivirus plugin scanner registered and connected", "plugin", info.Name)
	}

	// Initialize antispam plugins
	for _, pluginName := range m.server.pluginManager.ListAntispamPlugins() {
		plugin, err := m.server.pluginManager.GetAntispamPlugin(pluginName)
		if err != nil {
			m.logger.WarnContext(ctx, "Failed to get antispam plugin", "plugin", pluginName, "error", err)
			continue
		}

		scanner := plugin.GetScanner()
		info := plugin.GetInfo()

		m.logger.InfoContext(ctx, "Initializing antispam plugin scanner", "plugin", info.Name, "description", info.Description)

		if err := scanner.Connect(); err != nil {
			m.logger.WarnContext(ctx, "Failed to connect to antispam plugin scanner", "plugin", info.Name, "error", err)
			continue
		}

		if err := m.antispamManager.Register(scanner); err != nil {
			m.logger.WarnContext(ctx, "Failed to register antispam plugin scanner", "plugin", info.Name, "error", err)
			continue
		}

		// Store in generic scanners map
		m.scanners["antispam:plugin:"+scanner.Name()] = scanner
		m.logger.InfoContext(ctx, "Antispam plugin scanner registered and connected", "plugin", info.Name)
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
	ctx := context.Background()
	if err := m.antivirusManager.CloseAll(); err != nil {
		m.logger.WarnContext(ctx, "Error closing antivirus scanners", "error", err)
	}

	if err := m.antispamManager.CloseAll(); err != nil {
		m.logger.WarnContext(ctx, "Error closing antispam scanners", "error", err)
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
