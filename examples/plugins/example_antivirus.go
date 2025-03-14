package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/busybox42/elemta/internal/antivirus"
	"github.com/busybox42/elemta/internal/plugin"
)

// ExampleScanner is a simple example antivirus scanner
type ExampleScanner struct {
	connected bool
	config    *antivirus.Config
}

// NewExampleScanner creates a new example scanner
func NewExampleScanner(config *antivirus.Config) *ExampleScanner {
	return &ExampleScanner{
		connected: false,
		config:    config,
	}
}

// Connect connects to the scanner
func (s *ExampleScanner) Connect() error {
	// Simulate connection delay
	time.Sleep(100 * time.Millisecond)
	s.connected = true
	return nil
}

// Close closes the connection to the scanner
func (s *ExampleScanner) Close() error {
	s.connected = false
	return nil
}

// IsConnected returns true if the scanner is connected
func (s *ExampleScanner) IsConnected() bool {
	return s.connected
}

// Name returns the name of the scanner
func (s *ExampleScanner) Name() string {
	return "ExampleAV"
}

// Type returns the type of the scanner
func (s *ExampleScanner) Type() string {
	return "antivirus"
}

// ScanBytes scans a byte slice for viruses
func (s *ExampleScanner) ScanBytes(ctx context.Context, data []byte) (*antivirus.ScanResult, error) {
	if !s.connected {
		return nil, antivirus.ErrNotConnected
	}

	// Simulate scanning delay
	select {
	case <-time.After(200 * time.Millisecond):
		// For demonstration, detect a "virus" if the data contains the word "virus"
		clean := true
		infections := []string{}

		if containsVirus(data) {
			clean = false
			infections = append(infections, "EXAMPLE.VIRUS")
		}

		return &antivirus.ScanResult{
			Engine:     s.Name(),
			Timestamp:  time.Now(),
			Clean:      clean,
			Infections: infections,
			Score:      0,
			Details:    map[string]interface{}{"scanned_bytes": len(data)},
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ScanReader scans data from an io.Reader for viruses
func (s *ExampleScanner) ScanReader(ctx context.Context, reader io.Reader) (*antivirus.ScanResult, error) {
	if !s.connected {
		return nil, antivirus.ErrNotConnected
	}

	// Read all data from the reader
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Scan the data
	return s.ScanBytes(ctx, data)
}

// ScanFile scans a file for viruses
func (s *ExampleScanner) ScanFile(ctx context.Context, filePath string) (*antivirus.ScanResult, error) {
	return nil, errors.New("file scanning not implemented in example scanner")
}

// Helper function to check if data contains the word "virus"
func containsVirus(data []byte) bool {
	return contains(data, []byte("virus"))
}

// Helper function to check if a byte slice contains another byte slice
func contains(data, substr []byte) bool {
	for i := 0; i <= len(data)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if data[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ExamplePlugin is the plugin implementation
type ExamplePlugin struct {
	plugin.AntivirusPluginBase
}

// Create a new instance of the plugin
var AntivirusPlugin = &ExamplePlugin{
	AntivirusPluginBase: *plugin.NewAntivirusPluginBase(
		&plugin.PluginInfo{
			Name:        "ExampleAV",
			Version:     "1.0.0",
			Description: "An example antivirus plugin",
			Author:      "Elemta Team",
			Type:        plugin.PluginTypeAntivirus,
		},
		NewExampleScanner(&antivirus.Config{
			Type:    "example",
			Name:    "ExampleAV",
			Address: "localhost:3310",
			Options: map[string]interface{}{
				"scan_timeout": 30,
			},
		}),
	),
}
