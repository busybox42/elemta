package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/busybox42/elemta/internal/antispam"
	"github.com/busybox42/elemta/internal/plugin"
)

// ExampleSpamScanner is a simple example antispam scanner
type ExampleSpamScanner struct {
	connected bool
	config    *antispam.Config
	threshold float64
}

// NewExampleSpamScanner creates a new example scanner
func NewExampleSpamScanner(config *antispam.Config) *ExampleSpamScanner {
	threshold := 5.0
	if val, ok := config.Options["threshold"]; ok {
		if t, ok := val.(float64); ok {
			threshold = t
		}
	}

	return &ExampleSpamScanner{
		connected: false,
		config:    config,
		threshold: threshold,
	}
}

// Connect connects to the scanner
func (s *ExampleSpamScanner) Connect() error {
	// Simulate connection delay
	time.Sleep(100 * time.Millisecond)
	s.connected = true
	return nil
}

// Close closes the connection to the scanner
func (s *ExampleSpamScanner) Close() error {
	s.connected = false
	return nil
}

// IsConnected returns true if the scanner is connected
func (s *ExampleSpamScanner) IsConnected() bool {
	return s.connected
}

// Name returns the name of the scanner
func (s *ExampleSpamScanner) Name() string {
	return "ExampleSpam"
}

// Type returns the type of the scanner
func (s *ExampleSpamScanner) Type() string {
	return "antispam"
}

// ScanBytes scans a byte slice for spam
func (s *ExampleSpamScanner) ScanBytes(ctx context.Context, data []byte) (*antispam.ScanResult, error) {
	if !s.connected {
		return nil, antispam.ErrNotConnected
	}

	// Simulate scanning delay
	select {
	case <-time.After(200 * time.Millisecond):
		// For demonstration, calculate a spam score based on spam keywords
		content := string(data)
		score := calculateSpamScore(content)
		clean := score < s.threshold

		return &antispam.ScanResult{
			Engine:    s.Name(),
			Timestamp: time.Now(),
			Clean:     clean,
			Score:     score,
			Threshold: s.threshold,
			Rules:     []string{},
			Details: map[string]interface{}{
				"scanned_bytes": len(data),
				"threshold":     s.threshold,
			},
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ScanReader scans data from an io.Reader for spam
func (s *ExampleSpamScanner) ScanReader(ctx context.Context, reader io.Reader) (*antispam.ScanResult, error) {
	if !s.connected {
		return nil, antispam.ErrNotConnected
	}

	// Read all data from the reader
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Scan the data
	return s.ScanBytes(ctx, data)
}

// ScanFile scans a file for spam
func (s *ExampleSpamScanner) ScanFile(ctx context.Context, filePath string) (*antispam.ScanResult, error) {
	return nil, errors.New("file scanning not implemented in example scanner")
}

// Helper function to calculate a spam score based on spam keywords
func calculateSpamScore(content string) float64 {
	spamKeywords := []string{
		"viagra", "cialis", "buy now", "free offer", "limited time",
		"discount", "cheap", "money back", "guarantee", "winner",
		"lottery", "prize", "congratulations", "million dollars",
	}

	content = strings.ToLower(content)
	var score float64

	for _, keyword := range spamKeywords {
		if strings.Contains(content, keyword) {
			score += 1.0
		}
	}

	return score
}

// ExampleSpamPlugin is the plugin implementation
type ExampleSpamPlugin struct {
	plugin.AntispamPluginBase
}

// Create a new instance of the plugin
var AntispamPlugin = &ExampleSpamPlugin{
	AntispamPluginBase: *plugin.NewAntispamPluginBase(
		&plugin.PluginInfo{
			Name:        "ExampleSpam",
			Version:     "1.0.0",
			Description: "An example antispam plugin",
			Author:      "Elemta Team",
			Type:        plugin.PluginTypeAntispam,
		},
		NewExampleSpamScanner(&antispam.Config{
			Type:      "example",
			Name:      "ExampleSpam",
			Address:   "localhost:783",
			Threshold: 5.0,
			Options: map[string]interface{}{
				"threshold": 5.0,
			},
		}),
	),
}
