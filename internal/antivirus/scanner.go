package antivirus

import (
	"context"
	"errors"
	"io"
	"time"
)

// Common errors
var (
	ErrNotFound     = errors.New("scanner not found")
	ErrNotConnected = errors.New("not connected to scanner")
	ErrScanFailed   = errors.New("scan failed")
)

// Scanner defines the interface that all virus scanners must satisfy
type Scanner interface {
	// Connect establishes a connection to the scanner
	Connect() error

	// Close closes the connection to the scanner
	Close() error

	// IsConnected returns true if the scanner is connected
	IsConnected() bool

	// Name returns the name of the scanner
	Name() string

	// Type returns the type of the scanner
	Type() string

	// ScanBytes scans a byte slice for viruses
	ScanBytes(ctx context.Context, data []byte) (*ScanResult, error)

	// ScanReader scans a reader for viruses
	ScanReader(ctx context.Context, reader io.Reader) (*ScanResult, error)

	// ScanFile scans a file for viruses
	ScanFile(ctx context.Context, filePath string) (*ScanResult, error)
}

// ScanResult represents the result of a virus scan
type ScanResult struct {
	Engine     string                 // Name of the scanner engine
	Timestamp  time.Time              // Time of the scan
	Clean      bool                   // True if no viruses were found
	Infections []string               // List of infections found
	Score      float64                // Score (for spam scanners)
	Details    map[string]interface{} // Additional details
}

// Config represents the configuration for a scanner
type Config struct {
	Type    string                 // Type of scanner (clamav, etc.)
	Name    string                 // Name of this scanner instance
	Address string                 // Address of the scanner server
	Options map[string]interface{} // Additional options specific to the scanner type
}

// Factory creates scanner instances based on configuration
func Factory(config Config) (Scanner, error) {
	switch config.Type {
	case "clamav":
		return NewClamAV(config), nil
	default:
		return nil, errors.New("unsupported scanner type: " + config.Type)
	}
}

// Manager manages multiple scanners
type Manager struct {
	scanners map[string]Scanner
}

// NewManager creates a new scanner manager
func NewManager() *Manager {
	return &Manager{
		scanners: make(map[string]Scanner),
	}
}

// Register adds a scanner to the manager
func (m *Manager) Register(scanner Scanner) error {
	name := scanner.Name()
	if _, exists := m.scanners[name]; exists {
		return errors.New("scanner with name '" + name + "' already registered")
	}

	m.scanners[name] = scanner
	return nil
}

// Get retrieves a scanner by name
func (m *Manager) Get(name string) (Scanner, error) {
	scanner, exists := m.scanners[name]
	if !exists {
		return nil, ErrNotFound
	}

	return scanner, nil
}

// List returns all registered scanners
func (m *Manager) List() map[string]Scanner {
	return m.scanners
}

// Remove removes a scanner from the manager
func (m *Manager) Remove(name string) error {
	scanner, exists := m.scanners[name]
	if !exists {
		return ErrNotFound
	}

	if scanner.IsConnected() {
		if err := scanner.Close(); err != nil {
			return err
		}
	}

	delete(m.scanners, name)
	return nil
}

// CloseAll closes all scanners
func (m *Manager) CloseAll() error {
	var errs []error
	for name, scanner := range m.scanners {
		if scanner.IsConnected() {
			if err := scanner.Close(); err != nil {
				errs = append(errs, errors.New("failed to close scanner '"+name+"': "+err.Error()))
			}
		}
	}

	if len(errs) > 0 {
		return errors.New("errors closing scanners")
	}

	return nil
}

// ScanBytes scans a byte slice with all registered scanners
func (m *Manager) ScanBytes(ctx context.Context, data []byte) ([]*ScanResult, error) {
	var results []*ScanResult
	var errs []error

	for name, scanner := range m.scanners {
		if !scanner.IsConnected() {
			errs = append(errs, errors.New("scanner '"+name+"' not connected"))
			continue
		}

		result, err := scanner.ScanBytes(ctx, data)
		if err != nil {
			errs = append(errs, errors.New("scan failed with scanner '"+name+"': "+err.Error()))
			continue
		}

		results = append(results, result)
	}

	if len(results) == 0 && len(errs) > 0 {
		return nil, ErrScanFailed
	}

	return results, nil
}

// ScanReader scans a reader with all registered scanners
func (m *Manager) ScanReader(ctx context.Context, reader io.Reader) ([]*ScanResult, error) {
	// Read all data from the reader
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return m.ScanBytes(ctx, data)
}

// ScanFile scans a file with all registered scanners
func (m *Manager) ScanFile(ctx context.Context, filePath string) ([]*ScanResult, error) {
	var results []*ScanResult
	var errs []error

	for name, scanner := range m.scanners {
		if !scanner.IsConnected() {
			errs = append(errs, errors.New("scanner '"+name+"' not connected"))
			continue
		}

		result, err := scanner.ScanFile(ctx, filePath)
		if err != nil {
			errs = append(errs, errors.New("scan failed with scanner '"+name+"': "+err.Error()))
			continue
		}

		results = append(results, result)
	}

	if len(results) == 0 && len(errs) > 0 {
		return nil, ErrScanFailed
	}

	return results, nil
}
