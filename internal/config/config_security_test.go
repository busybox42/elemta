package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigEnsureQueueDirectorySecurity(t *testing.T) {
	// Create temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "elemta_config_security_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create config with queue directory
	cfg := &Config{
		Queue: struct {
			Dir string `toml:"dir"`
		}{
			Dir: filepath.Join(tmpDir, "queue"),
		},
	}

	// Test EnsureQueueDirectory creates secure permissions
	if err := cfg.EnsureQueueDirectory(); err != nil {
		t.Fatalf("Failed to ensure queue directory: %v", err)
	}

	// Check main queue directory permissions
	info, err := os.Stat(cfg.Queue.Dir)
	if err != nil {
		t.Fatalf("Failed to stat main queue directory: %v", err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("Main queue directory has incorrect permissions: got %o, want 0700", info.Mode().Perm())
	}

	// Check subdirectory permissions
	queueTypes := []string{"active", "deferred", "hold", "failed", "data", "tmp", "quarantine"}
	for _, qType := range queueTypes {
		qDir := filepath.Join(cfg.Queue.Dir, qType)
		info, err := os.Stat(qDir)
		if err != nil {
			t.Fatalf("Failed to stat queue directory %s: %v", qType, err)
		}
		if info.Mode().Perm() != 0700 {
			t.Errorf("Queue directory %s has incorrect permissions: got %o, want 0700", qType, info.Mode().Perm())
		}
	}
}
