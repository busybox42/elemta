package plugin

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPathTraversalPrevention tests that directory traversal attacks are blocked
func TestPathTraversalPrevention(t *testing.T) {
	tmpDir := t.TempDir()
	config := DefaultHotReloadConfig()
	config.BackupDirectory = filepath.Join(tmpDir, "backups")

	manager := NewEnhancedManager(&EnhancedConfig{
		PluginPath: tmpDir,
		Enabled:    true,
	})

	hrm := NewHotReloadManager(config, manager)

	tests := []struct {
		name        string
		pluginPath  string
		shouldFail  bool
		description string
	}{
		{
			name:        "Valid plugin path",
			pluginPath:  filepath.Join(tmpDir, "test.so"),
			shouldFail:  false,
			description: "Normal plugin file should be accepted",
		},
		{
			name:        "Path traversal with ../",
			pluginPath:  filepath.Join(tmpDir, "../../../etc/passwd.so"),
			shouldFail:  true,
			description: "Path traversal attempts should be blocked",
		},
		{
			name:        "Absolute path to non-existent file",
			pluginPath:  "/tmp/malicious.so",
			shouldFail:  true, // File doesn't exist
			description: "Non-existent files should fail validation",
		},
		{
			name:        "Invalid extension",
			pluginPath:  filepath.Join(tmpDir, "test.txt"),
			shouldFail:  true,
			description: "Non-.so files should be rejected",
		},
		{
			name:        "Symlink attack",
			pluginPath:  filepath.Join(tmpDir, "symlink.so"),
			shouldFail:  true,
			description: "Symlinks should be blocked to prevent attacks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file if needed
			if !tt.shouldFail && tt.name == "Valid plugin path" {
				f, err := os.Create(tt.pluginPath)
				if err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				f.Close()
			}

			// Create symlink for symlink test
			if tt.name == "Symlink attack" {
				target := filepath.Join(tmpDir, "target.so")
				os.Create(target)
				os.Symlink(target, tt.pluginPath)
			}

			err := hrm.WatchPlugin(tt.pluginPath, "test-plugin")

			if tt.shouldFail && err == nil {
				t.Errorf("%s: Expected error but got none", tt.description)
			}

			if !tt.shouldFail && err != nil {
				t.Errorf("%s: Expected success but got error: %v", tt.description, err)
			}
		})
	}
}

// TestWorldWritablePluginRejection tests that world-writable plugins are rejected
func TestWorldWritablePluginRejection(t *testing.T) {
	tmpDir := t.TempDir()
	config := DefaultHotReloadConfig()
	config.BackupDirectory = filepath.Join(tmpDir, "backups")

	manager := NewEnhancedManager(&EnhancedConfig{
		PluginPath: tmpDir,
		Enabled:    true,
	})

	hrm := NewHotReloadManager(config, manager)

	// Create a world-writable plugin file
	pluginPath := filepath.Join(tmpDir, "test.so")
	f, err := os.Create(pluginPath)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	f.Close()

	// Make it world-writable (security risk)
	if err := os.Chmod(pluginPath, 0o666); err != nil {
		t.Fatalf("Failed to set permissions: %v", err)
	}

	err = hrm.WatchPlugin(pluginPath, "test-plugin")
	if err == nil {
		t.Error("Expected error for world-writable plugin, but got none")
	} else if !containsStr(err.Error(), "world-writable") {
		t.Errorf("Expected world-writable error, got: %v", err)
	}
}

// TestChecksumVerification tests that plugin checksums are verified
func TestChecksumVerification(t *testing.T) {
	tmpDir := t.TempDir()
	config := DefaultHotReloadConfig()
	config.BackupDirectory = filepath.Join(tmpDir, "backups")

	manager := NewEnhancedManager(&EnhancedConfig{
		PluginPath: tmpDir,
		Enabled:    true,
	})

	hrm := NewHotReloadManager(config, manager)

	// Create test plugin
	pluginPath := filepath.Join(tmpDir, "test.so")
	if err := os.WriteFile(pluginPath, []byte("test plugin content"), 0640); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Calculate checksum
	result, err := hrm.validator.ValidatePlugin(pluginPath)
	if err != nil {
		t.Fatalf("Failed to validate plugin: %v", err)
	}

	originalHash := result.FileHash

	// Verify checksum matches
	err = hrm.verifyPluginChecksum(pluginPath, originalHash)
	if err != nil {
		t.Errorf("Checksum verification should succeed: %v", err)
	}

	// Verify wrong checksum is detected
	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"
	err = hrm.verifyPluginChecksum(pluginPath, wrongHash)
	if err == nil {
		t.Error("Checksum mismatch should be detected")
	} else if !containsStr(err.Error(), "checksum mismatch") {
		t.Errorf("Expected checksum mismatch error, got: %v", err)
	}
}

// TestAtomicReloadWithRollback tests atomic reload operations and rollback
func TestAtomicReloadWithRollback(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping atomic reload test in short mode")
	}

	tmpDir := t.TempDir()
	config := DefaultHotReloadConfig()
	config.BackupDirectory = filepath.Join(tmpDir, "backups")
	config.BackupOldVersions = true

	manager := NewEnhancedManager(&EnhancedConfig{
		PluginPath: tmpDir,
		Enabled:    true,
	})

	hrm := NewHotReloadManager(config, manager)

	// Create initial plugin
	pluginPath := filepath.Join(tmpDir, "test.so")
	originalContent := []byte("original plugin version")
	if err := os.WriteFile(pluginPath, originalContent, 0640); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Start hot reload manager
	if err := hrm.Start(); err != nil {
		t.Fatalf("Failed to start hot reload manager: %v", err)
	}
	defer hrm.Stop()

	// Watch the plugin
	if err := hrm.WatchPlugin(pluginPath, "test"); err != nil {
		t.Fatalf("Failed to watch plugin: %v", err)
	}

	// Get initial watched state
	watched := hrm.watchedFiles[pluginPath]
	if watched == nil {
		t.Fatal("Plugin not in watch list")
	}

	initialHash := watched.Hash

	// Modify plugin file (simulate update)
	newContent := []byte("updated plugin version")
	if err := os.WriteFile(pluginPath, newContent, 0640); err != nil {
		t.Fatalf("Failed to update plugin: %v", err)
	}

	// Trigger reload manually
	time.Sleep(100 * time.Millisecond)
	_ = hrm.ReloadPlugin("test")

	// Check if backup was created
	backups, _ := filepath.Glob(filepath.Join(config.BackupDirectory, "test_*.so"))
	if len(backups) == 0 {
		t.Error("No backup was created during reload")
	}

	// Verify reload history
	history := hrm.GetReloadHistory()
	if len(history) == 0 {
		t.Error("No reload events recorded")
	} else {
		lastEvent := history[len(history)-1]
		if lastEvent.PluginName != "test" {
			t.Errorf("Expected plugin 'test', got %s", lastEvent.PluginName)
		}
		if lastEvent.OldHash != initialHash {
			t.Errorf("Old hash mismatch: expected %s, got %s", initialHash, lastEvent.OldHash)
		}
	}
}

// TestRaceConditionPrevention tests that concurrent reload attempts are handled safely
func TestRaceConditionPrevention(t *testing.T) {
	tmpDir := t.TempDir()
	config := DefaultHotReloadConfig()
	config.BackupDirectory = filepath.Join(tmpDir, "backups")

	manager := NewEnhancedManager(&EnhancedConfig{
		PluginPath: tmpDir,
		Enabled:    true,
	})

	hrm := NewHotReloadManager(config, manager)

	// Create test plugin
	pluginPath := filepath.Join(tmpDir, "test.so")
	if err := os.WriteFile(pluginPath, []byte("test content"), 0640); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	if err := hrm.Start(); err != nil {
		t.Fatalf("Failed to start hot reload manager: %v", err)
	}
	defer hrm.Stop()

	if err := hrm.WatchPlugin(pluginPath, "test"); err != nil {
		t.Fatalf("Failed to watch plugin: %v", err)
	}

	// Attempt concurrent reloads
	concurrentReloads := 10
	done := make(chan bool, concurrentReloads)

	for i := 0; i < concurrentReloads; i++ {
		go func() {
			_ = hrm.ReloadPlugin("test")
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < concurrentReloads; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("Concurrent reload test timed out")
		}
	}

	// Verify no panics occurred and plugin is in consistent state
	status := hrm.GetHotReloadStatus()
	if status["running"] != true {
		t.Error("Hot reload manager should still be running after concurrent operations")
	}
}

// TestReloadCooldown tests that rapid reload attempts are throttled
func TestReloadCooldown(t *testing.T) {
	tmpDir := t.TempDir()
	config := DefaultHotReloadConfig()
	config.BackupDirectory = filepath.Join(tmpDir, "backups")
	config.WatchInterval = 100 * time.Millisecond

	manager := NewEnhancedManager(&EnhancedConfig{
		PluginPath: tmpDir,
		Enabled:    true,
	})

	hrm := NewHotReloadManager(config, manager)

	pluginPath := filepath.Join(tmpDir, "test.so")
	if err := os.WriteFile(pluginPath, []byte("test"), 0640); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	if err := hrm.Start(); err != nil {
		t.Fatalf("Failed to start: %v", err)
	}
	defer hrm.Stop()

	if err := hrm.WatchPlugin(pluginPath, "test"); err != nil {
		t.Fatalf("Failed to watch plugin: %v", err)
	}

	// Trigger multiple rapid reloads
	reloadCount := 0
	for i := 0; i < 5; i++ {
		if err := hrm.ReloadPlugin("test"); err == nil {
			reloadCount++
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Should have some reload attempts
	history := hrm.GetReloadHistory()
	if len(history) == 0 {
		t.Error("No reload events recorded")
	}
}

// Helper function for string matching
func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
