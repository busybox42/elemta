package antivirus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/dutchcoders/go-clamd"
)

// ClamAV represents a ClamAV virus scanner
type ClamAV struct {
	client     *clamd.Clamd
	address    string
	timeout    time.Duration
	connected  bool
	scanLimit  int64
	scanBuffer int
}

// NewClamAV creates a new ClamAV scanner
func NewClamAV(config Config) *ClamAV {
	address := config.Address
	if address == "" {
		address = "localhost:3310" // Default ClamAV address
	}

	timeout := time.Duration(0)
	if t, ok := config.Options["timeout"].(int); ok {
		timeout = time.Duration(t) * time.Second
	}

	scanLimit := int64(0)
	if sl, ok := config.Options["scan_limit"].(int64); ok {
		scanLimit = sl
	}

	scanBuffer := 8192 // Default buffer size
	if sb, ok := config.Options["scan_buffer"].(int); ok {
		scanBuffer = sb
	}

	return &ClamAV{
		address:    address,
		timeout:    timeout,
		scanLimit:  scanLimit,
		scanBuffer: scanBuffer,
	}
}

// Connect establishes a connection to the ClamAV server
func (c *ClamAV) Connect() error {
	if c.connected {
		return nil
	}

	c.client = clamd.NewClamd(c.address)

	// Test connection by pinging the server
	err := c.client.Ping()
	if err != nil {
		return fmt.Errorf("failed to connect to ClamAV: %w", err)
	}

	// Check version to ensure server is responsive
	versionChan, err := c.client.Version()
	if err != nil {
		return fmt.Errorf("failed to get ClamAV version: %w", err)
	}

	// Read at least one version response
	gotVersion := false
	for range versionChan {
		gotVersion = true
		break
	}

	if !gotVersion {
		return errors.New("failed to get ClamAV version")
	}

	c.connected = true
	return nil
}

// Close closes the connection to the ClamAV server
func (c *ClamAV) Close() error {
	c.connected = false
	return nil
}

// IsConnected returns true if the scanner is connected
func (c *ClamAV) IsConnected() bool {
	return c.connected
}

// Name returns the name of the scanner
func (c *ClamAV) Name() string {
	return "clamav"
}

// Type returns the type of the scanner
func (c *ClamAV) Type() string {
	return "clamav"
}

// ScanBytes scans a byte slice for viruses
func (c *ClamAV) ScanBytes(ctx context.Context, data []byte) (*ScanResult, error) {
	if !c.connected {
		return nil, ErrNotConnected
	}

	// Limit scan size if configured
	if c.scanLimit > 0 && int64(len(data)) > c.scanLimit {
		data = data[:c.scanLimit]
	}

	reader := bytes.NewReader(data)
	return c.ScanReader(ctx, reader)
}

// ScanReader scans a reader for viruses
func (c *ClamAV) ScanReader(ctx context.Context, reader io.Reader) (*ScanResult, error) {
	if !c.connected {
		return nil, ErrNotConnected
	}

	// Apply context timeout if needed
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Create a pipe to stream data to ClamAV
	pr, pw := io.Pipe()
	defer pr.Close()

	// Create abort channel
	abortCh := make(chan bool)
	defer close(abortCh)

	// Start scanning in a goroutine
	scanCh := make(chan *ScanResult, 1)
	errCh := make(chan error, 1)

	go func() {
		// Start the scan
		responseChan, err := c.client.ScanStream(pr, abortCh)
		if err != nil {
			errCh <- err
			return
		}

		result := &ScanResult{
			Engine:    c.Name(),
			Timestamp: time.Now(),
			Clean:     true,
		}

		// Process scan results
		for r := range responseChan {
			if r.Status == clamd.RES_FOUND {
				result.Clean = false
				result.Infections = append(result.Infections, r.Description)
			}
		}

		scanCh <- result
	}()

	// Copy data to the pipe
	go func() {
		defer pw.Close()
		if _, err := io.Copy(pw, reader); err != nil {
			errCh <- err
		}
	}()

	// Wait for scan result or error
	select {
	case <-ctx.Done():
		// Signal abort
		abortCh <- true
		return nil, ctx.Err()
	case err := <-errCh:
		return nil, err
	case result := <-scanCh:
		return result, nil
	}
}

// ScanFile scans a file for viruses
func (c *ClamAV) ScanFile(ctx context.Context, filePath string) (*ScanResult, error) {
	if !c.connected {
		return nil, ErrNotConnected
	}

	// Apply context timeout if needed
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Scan the file
	responseChan, err := c.client.ScanFile(filePath)
	if err != nil {
		return nil, err
	}

	result := &ScanResult{
		Engine:    c.Name(),
		Timestamp: time.Now(),
		Clean:     true,
	}

	// Process scan results
	for r := range responseChan {
		if r.Status == clamd.RES_FOUND {
			result.Clean = false
			result.Infections = append(result.Infections, r.Description)
		}
	}

	return result, nil
}

// Ping checks if the ClamAV server is responsive
func (c *ClamAV) Ping(ctx context.Context) error {
	if !c.connected {
		return ErrNotConnected
	}

	// Apply context timeout if needed
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	return c.client.Ping()
}

// Stats returns statistics from the ClamAV server
func (c *ClamAV) Stats(ctx context.Context) (map[string]string, error) {
	if !c.connected {
		return nil, ErrNotConnected
	}

	// Apply context timeout if needed
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Get stats from ClamAV
	stats, err := c.client.Stats()
	if err != nil {
		return nil, err
	}

	// Convert stats to map
	result := make(map[string]string)
	result["POOLS"] = stats.Pools
	result["STATE"] = stats.State
	result["THREADS"] = stats.Threads
	result["QUEUE"] = stats.Queue
	result["MEMSTATS"] = stats.Memstats

	return result, nil
}

// Version returns the version of the ClamAV server
func (c *ClamAV) Version(ctx context.Context) (string, error) {
	if !c.connected {
		return "", ErrNotConnected
	}

	// Apply context timeout if needed
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Get version from ClamAV
	versionChan, err := c.client.Version()
	if err != nil {
		return "", err
	}

	// Read the first version response
	for r := range versionChan {
		return r.Description, nil
	}

	return "", errors.New("failed to get version")
}
