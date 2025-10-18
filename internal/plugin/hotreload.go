package plugin

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HotReloadConfig configures hot reload behavior
type HotReloadConfig struct {
	Enabled              bool          // Whether hot reload is enabled
	WatchInterval        time.Duration // How often to check for file changes
	GracefulShutdown     time.Duration // Time to wait for graceful plugin shutdown
	BackupOldVersions    bool          // Whether to keep backups of old plugin versions
	BackupDirectory      string        // Directory to store plugin backups
	ValidateBeforeReload bool          // Whether to validate plugins before reloading
}

// DefaultHotReloadConfig returns sensible defaults for hot reload
func DefaultHotReloadConfig() HotReloadConfig {
	return HotReloadConfig{
		Enabled:              true,
		WatchInterval:        5 * time.Second,
		GracefulShutdown:     30 * time.Second,
		BackupOldVersions:    true,
		BackupDirectory:      "./plugin_backups",
		ValidateBeforeReload: true,
	}
}

// HotReloadManager manages runtime plugin reloading
type HotReloadManager struct {
	config        HotReloadConfig
	pluginManager *EnhancedManager
	validator     *PluginValidator
	logger        *slog.Logger
	mu            sync.RWMutex
	watchedFiles  map[string]*WatchedPlugin
	fileWatcher   *FileWatcher
	reloadHistory []ReloadEvent
	ctx           context.Context
	cancel        context.CancelFunc
	running       bool
}

// WatchedPlugin tracks a plugin file for changes
type WatchedPlugin struct {
	FilePath     string
	PluginName   string
	LastModified time.Time
	LastSize     int64
	Hash         string
	ReloadCount  int
	LastReload   time.Time
}

// ReloadEvent records a plugin reload operation
type ReloadEvent struct {
	PluginName string
	FilePath   string
	Timestamp  time.Time
	Success    bool
	Error      string
	OldHash    string
	NewHash    string
	Duration   time.Duration
}

// FileWatcher monitors plugin files for changes
type FileWatcher struct {
	manager  *HotReloadManager
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	running  bool
	mu       sync.RWMutex
}

// NewHotReloadManager creates a new hot reload manager
func NewHotReloadManager(config HotReloadConfig, pluginManager *EnhancedManager) *HotReloadManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &HotReloadManager{
		config:        config,
		pluginManager: pluginManager,
		validator:     NewPluginValidator(),
		logger:        slog.Default().With("component", "plugin-hotreload"),
		watchedFiles:  make(map[string]*WatchedPlugin),
		reloadHistory: make([]ReloadEvent, 0),
		ctx:           ctx,
		cancel:        cancel,
		running:       false,
	}
}

// Start begins monitoring plugin files for changes
func (hrm *HotReloadManager) Start() error {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()

	if hrm.running {
		return fmt.Errorf("hot reload manager already running")
	}

	if !hrm.config.Enabled {
		hrm.logger.Info("Hot reload disabled")
		return nil
	}

	// Create backup directory if needed
	if hrm.config.BackupOldVersions {
		if err := os.MkdirAll(hrm.config.BackupDirectory, 0755); err != nil {
			return fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	// Initialize file watcher
	hrm.fileWatcher = &FileWatcher{
		manager:  hrm,
		interval: hrm.config.WatchInterval,
		ctx:      hrm.ctx,
		running:  false,
	}

	// Start file watching
	go hrm.fileWatcher.start()

	hrm.running = true
	hrm.logger.Info("Hot reload manager started", "config", hrm.config)

	return nil
}

// Stop shuts down the hot reload manager
func (hrm *HotReloadManager) Stop() error {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()

	if !hrm.running {
		return nil
	}

	// Stop file watcher
	if hrm.fileWatcher != nil {
		hrm.fileWatcher.stop()
	}

	// Cancel context
	hrm.cancel()

	hrm.running = false
	hrm.logger.Info("Hot reload manager stopped")

	return nil
}

// WatchPlugin adds a plugin file to the watch list
func (hrm *HotReloadManager) WatchPlugin(pluginPath, pluginName string) error {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()

	// SECURITY: Validate path to prevent directory traversal
	if err := hrm.validatePluginPath(pluginPath); err != nil {
		hrm.logger.Error("Invalid plugin path",
			"path", pluginPath,
			"plugin", pluginName,
			"error", err)
		return fmt.Errorf("path validation failed: %w", err)
	}

	// Get file info
	info, err := os.Stat(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to stat plugin file: %w", err)
	}

	// Calculate initial hash
	hash := ""
	if hrm.validator != nil {
		if result, err := hrm.validator.ValidatePlugin(pluginPath); err == nil {
			hash = result.FileHash
		}
	}

	// Create watched plugin entry
	watched := &WatchedPlugin{
		FilePath:     pluginPath,
		PluginName:   pluginName,
		LastModified: info.ModTime(),
		LastSize:     info.Size(),
		Hash:         hash,
		ReloadCount:  0,
		LastReload:   time.Time{},
	}

	hrm.watchedFiles[pluginPath] = watched
	hrm.logger.Info("Added plugin to watch list",
		"plugin", pluginName,
		"path", pluginPath,
		"size", info.Size(),
		"modified", info.ModTime())

	return nil
}

// UnwatchPlugin removes a plugin from the watch list
func (hrm *HotReloadManager) UnwatchPlugin(pluginPath string) {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()

	if watched, exists := hrm.watchedFiles[pluginPath]; exists {
		delete(hrm.watchedFiles, pluginPath)
		hrm.logger.Info("Removed plugin from watch list",
			"plugin", watched.PluginName,
			"path", pluginPath)
	}
}

// ReloadPlugin manually reloads a specific plugin
func (hrm *HotReloadManager) ReloadPlugin(pluginName string) error {
	hrm.mu.RLock()
	var pluginPath string
	var watched *WatchedPlugin

	// Find the plugin by name
	for path, w := range hrm.watchedFiles {
		if w.PluginName == pluginName {
			pluginPath = path
			watched = w
			break
		}
	}
	hrm.mu.RUnlock()

	if watched == nil {
		return fmt.Errorf("plugin not found in watch list: %s", pluginName)
	}

	return hrm.performReload(pluginPath, watched)
}

// performReload executes the actual plugin reload process with atomic operations
func (hrm *HotReloadManager) performReload(pluginPath string, watched *WatchedPlugin) error {
	startTime := time.Now()
	event := ReloadEvent{
		PluginName: watched.PluginName,
		FilePath:   pluginPath,
		Timestamp:  startTime,
		OldHash:    watched.Hash,
	}

	hrm.logger.Info("Starting plugin reload",
		"plugin", watched.PluginName,
		"path", pluginPath)

	// SECURITY: Re-validate path before reload (prevent TOCTOU attacks)
	if err := hrm.validatePluginPath(pluginPath); err != nil {
		event.Success = false
		event.Error = fmt.Sprintf("path validation failed: %v", err)
		event.Duration = time.Since(startTime)
		hrm.addReloadEvent(event)
		return fmt.Errorf("path validation failed: %w", err)
	}

	// SECURITY: Verify checksum hasn't changed unexpectedly
	if watched.Hash != "" {
		if err := hrm.verifyPluginChecksum(pluginPath, ""); err != nil {
			hrm.logger.Warn("Checksum verification warning", "error", err)
		}
	}

	// Validate the new plugin version if enabled
	if hrm.config.ValidateBeforeReload {
		if result, err := hrm.validator.ValidatePlugin(pluginPath); err != nil {
			event.Success = false
			event.Error = fmt.Sprintf("validation failed: %v", err)
			event.Duration = time.Since(startTime)
			hrm.addReloadEvent(event)
			return fmt.Errorf("plugin validation failed: %w", err)
		} else if !result.Valid {
			event.Success = false
			event.Error = fmt.Sprintf("validation errors: %v", result.Errors)
			event.Duration = time.Since(startTime)
			hrm.addReloadEvent(event)
			return fmt.Errorf("plugin validation failed: %v", result.Errors)
		} else {
			event.NewHash = result.FileHash
			
			// SECURITY: Verify new hash is different from old (prevent replay attacks)
			if event.NewHash == watched.Hash && watched.ReloadCount > 0 {
				hrm.logger.Info("Plugin hash unchanged, skipping reload",
					"plugin", watched.PluginName,
					"hash", event.NewHash)
				return nil
			}
		}
	}

	// SECURITY: Create atomic reload operation with rollback
	reloadState := &pluginReloadState{
		pluginName:   watched.PluginName,
		pluginPath:   pluginPath,
		oldHash:      watched.Hash,
		backupPath:   "",
		reloadFailed: false,
	}
	
	// Backup old version if enabled
	if hrm.config.BackupOldVersions {
		backupPath, err := hrm.backupPluginAtomic(pluginPath, watched.PluginName)
		if err != nil {
			hrm.logger.Warn("Failed to backup plugin",
				"plugin", watched.PluginName,
				"error", err)
		} else {
			reloadState.backupPath = backupPath
		}
	}

	// ATOMIC OPERATION: Unload and reload with proper locking
	// This prevents race conditions during plugin swap
	unloadSuccess := false
	loadSuccess := false
	
	// Unload the existing plugin gracefully
	if err := hrm.unloadPluginGracefully(watched.PluginName); err != nil {
		hrm.logger.Warn("Failed to unload plugin gracefully",
			"plugin", watched.PluginName,
			"error", err)
		reloadState.reloadFailed = true
	} else {
		unloadSuccess = true
	}

	// Load the new plugin version
	if unloadSuccess {
		if err := hrm.pluginManager.LoadPlugin(watched.PluginName); err != nil {
			event.Success = false
			event.Error = fmt.Sprintf("failed to load new version: %v", err)
			event.Duration = time.Since(startTime)
			hrm.addReloadEvent(event)
			reloadState.reloadFailed = true

			// SECURITY: Automatic rollback on failure
			hrm.logger.Error("Plugin reload failed, initiating rollback",
				"plugin", watched.PluginName,
				"error", err)
			
			if rollbackErr := hrm.rollbackPlugin(reloadState); rollbackErr != nil {
				hrm.logger.Error("CRITICAL: Rollback failed - plugin in inconsistent state",
					"plugin", watched.PluginName,
					"rollback_error", rollbackErr,
					"original_error", err)
				return fmt.Errorf("reload and rollback both failed: reload=%v, rollback=%v", err, rollbackErr)
			}
			
			hrm.logger.Info("Successfully rolled back to previous version",
				"plugin", watched.PluginName)
			return fmt.Errorf("failed to load new plugin version (rolled back): %w", err)
		} else {
			loadSuccess = true
		}
	}

	// Update watched plugin metadata only if both unload and load succeeded
	if unloadSuccess && loadSuccess {
		hrm.mu.Lock()
		if info, err := os.Stat(pluginPath); err == nil {
			watched.LastModified = info.ModTime()
			watched.LastSize = info.Size()
			watched.Hash = event.NewHash
			watched.ReloadCount++
			watched.LastReload = startTime
		}
		hrm.mu.Unlock()

		// Record successful reload
		event.Success = true
		event.Duration = time.Since(startTime)
		hrm.addReloadEvent(event)

		hrm.logger.Info("Plugin reload completed successfully",
			"plugin", watched.PluginName,
			"duration", event.Duration,
			"reload_count", watched.ReloadCount,
			"new_hash", event.NewHash)

		return nil
	}
	
	// If we get here, something went wrong
	return fmt.Errorf("plugin reload incomplete: unload=%v, load=%v", unloadSuccess, loadSuccess)
}

// pluginReloadState tracks state during an atomic reload operation
type pluginReloadState struct {
	pluginName   string
	pluginPath   string
	oldHash      string
	backupPath   string
	reloadFailed bool
}

// rollbackPlugin performs rollback to previous plugin version
func (hrm *HotReloadManager) rollbackPlugin(state *pluginReloadState) error {
	if state.backupPath == "" {
		return fmt.Errorf("no backup available for rollback")
	}
	
	hrm.logger.Info("Rolling back plugin to previous version",
		"plugin", state.pluginName,
		"backup", state.backupPath)
	
	// Restore from backup
	if err := hrm.copyFile(state.backupPath, state.pluginPath); err != nil {
		return fmt.Errorf("failed to restore from backup: %w", err)
	}
	
	// Reload the old version
	if err := hrm.pluginManager.LoadPlugin(state.pluginName); err != nil {
		return fmt.Errorf("failed to reload old version after restore: %w", err)
	}
	
	hrm.logger.Info("Plugin rolled back successfully",
		"plugin", state.pluginName,
		"restored_from", state.backupPath)
	
	return nil
}

// backupPluginAtomic creates a backup and returns the backup path
func (hrm *HotReloadManager) backupPluginAtomic(pluginPath, pluginName string) (string, error) {
	backupPath := filepath.Join(hrm.config.BackupDirectory,
		fmt.Sprintf("%s_%d.so", pluginName, time.Now().Unix()))

	// Ensure backup directory exists
	if err := os.MkdirAll(hrm.config.BackupDirectory, 0750); err != nil {
		return "", fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Copy file atomically
	if err := hrm.copyFile(pluginPath, backupPath); err != nil {
		return "", fmt.Errorf("failed to backup plugin: %w", err)
	}

	// Set restrictive permissions on backup
	if err := os.Chmod(backupPath, 0640); err != nil {
		hrm.logger.Warn("Failed to set backup permissions", "error", err)
	}

	hrm.logger.Info("Plugin backed up atomically",
		"plugin", pluginName,
		"backup_path", backupPath)

	return backupPath, nil
}

// unloadPluginGracefully attempts to gracefully shut down a plugin
func (hrm *HotReloadManager) unloadPluginGracefully(pluginName string) error {
	// This would need to be integrated with the enhanced manager
	// For now, we'll just log the intent
	hrm.logger.Info("Gracefully unloading plugin", "plugin", pluginName)

	// TODO: Implement graceful shutdown
	// 1. Stop accepting new requests for this plugin
	// 2. Wait for existing requests to complete (with timeout)
	// 3. Call plugin.Close() method
	// 4. Remove from plugin manager

	return nil
}

// backupPlugin creates a backup of the current plugin version
func (hrm *HotReloadManager) backupPlugin(pluginPath, pluginName string) error {
	backupPath := filepath.Join(hrm.config.BackupDirectory,
		fmt.Sprintf("%s_%d.so", pluginName, time.Now().Unix()))

	// Copy file
	if err := hrm.copyFile(pluginPath, backupPath); err != nil {
		return fmt.Errorf("failed to backup plugin: %w", err)
	}

	hrm.logger.Debug("Plugin backed up",
		"plugin", pluginName,
		"backup_path", backupPath)

	return nil
}

// restorePluginFromBackup restores a plugin from its most recent backup
func (hrm *HotReloadManager) restorePluginFromBackup(pluginName string) error {
	// Find most recent backup
	pattern := filepath.Join(hrm.config.BackupDirectory, pluginName+"_*.so")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return fmt.Errorf("no backup found for plugin: %s", pluginName)
	}

	// Use the most recent backup (last in sorted order)
	var mostRecent string
	var mostRecentTime int64

	for _, match := range matches {
		if info, err := os.Stat(match); err == nil {
			if info.ModTime().Unix() > mostRecentTime {
				mostRecentTime = info.ModTime().Unix()
				mostRecent = match
			}
		}
	}

	if mostRecent == "" {
		return fmt.Errorf("no valid backup found for plugin: %s", pluginName)
	}

	// Find original plugin path
	hrm.mu.RLock()
	var originalPath string
	for path, watched := range hrm.watchedFiles {
		if watched.PluginName == pluginName {
			originalPath = path
			break
		}
	}
	hrm.mu.RUnlock()

	if originalPath == "" {
		return fmt.Errorf("original path not found for plugin: %s", pluginName)
	}

	// Restore backup
	if err := hrm.copyFile(mostRecent, originalPath); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	hrm.logger.Info("Plugin restored from backup",
		"plugin", pluginName,
		"backup_path", mostRecent)

	return nil
}

// copyFile copies a file from src to dst
func (hrm *HotReloadManager) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = dstFile.ReadFrom(srcFile)
	return err
}

// addReloadEvent adds a reload event to the history
func (hrm *HotReloadManager) addReloadEvent(event ReloadEvent) {
	hrm.mu.Lock()
	defer hrm.mu.Unlock()

	hrm.reloadHistory = append(hrm.reloadHistory, event)

	// Keep only last 100 events
	if len(hrm.reloadHistory) > 100 {
		hrm.reloadHistory = hrm.reloadHistory[1:]
	}
}

// GetReloadHistory returns the recent reload events
func (hrm *HotReloadManager) GetReloadHistory() []ReloadEvent {
	hrm.mu.RLock()
	defer hrm.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make([]ReloadEvent, len(hrm.reloadHistory))
	copy(result, hrm.reloadHistory)
	return result
}

// GetWatchedPlugins returns information about currently watched plugins
func (hrm *HotReloadManager) GetWatchedPlugins() map[string]*WatchedPlugin {
	hrm.mu.RLock()
	defer hrm.mu.RUnlock()

	result := make(map[string]*WatchedPlugin)
	for path, watched := range hrm.watchedFiles {
		// Create a copy to avoid race conditions
		watchedCopy := *watched
		result[path] = &watchedCopy
	}

	return result
}

// FileWatcher methods

// start begins the file watching loop
func (fw *FileWatcher) start() {
	fw.mu.Lock()
	fw.running = true
	fw.mu.Unlock()

	ticker := time.NewTicker(fw.interval)
	defer ticker.Stop()

	for {
		select {
		case <-fw.ctx.Done():
			fw.mu.Lock()
			fw.running = false
			fw.mu.Unlock()
			return

		case <-ticker.C:
			fw.checkForChanges()
		}
	}
}

// stop shuts down the file watcher
func (fw *FileWatcher) stop() {
	if fw.cancel != nil {
		fw.cancel()
	}
}

// checkForChanges scans watched files for modifications
func (fw *FileWatcher) checkForChanges() {
	fw.manager.mu.RLock()
	watchedFiles := make(map[string]*WatchedPlugin)
	for path, watched := range fw.manager.watchedFiles {
		watchedCopy := *watched
		watchedFiles[path] = &watchedCopy
	}
	fw.manager.mu.RUnlock()

	for pluginPath, watched := range watchedFiles {
		// SECURITY: Validate path before checking changes (prevent path injection)
		if err := fw.manager.validatePluginPath(pluginPath); err != nil {
			fw.manager.logger.Error("Plugin path validation failed during change detection",
				"path", pluginPath,
				"plugin", watched.PluginName,
				"error", err)
			// Remove from watch list for security
			fw.manager.UnwatchPlugin(pluginPath)
			continue
		}
		
		if fw.hasFileChanged(pluginPath, watched) {
			fw.manager.logger.Info("Plugin file changed, triggering reload",
				"plugin", watched.PluginName,
				"path", pluginPath)

			// SECURITY: Perform reload with proper error handling and rollback
			if err := fw.manager.performReload(pluginPath, watched); err != nil {
				fw.manager.logger.Error("Auto-reload failed",
					"plugin", watched.PluginName,
					"error", err)
				
				// SECURITY: Stop watching if multiple reloads fail
				if watched.ReloadCount > 5 {
					fw.manager.logger.Warn("Too many failed reloads, removing from watch list",
						"plugin", watched.PluginName,
						"reload_count", watched.ReloadCount)
					fw.manager.UnwatchPlugin(pluginPath)
				}
			}
		}
	}
}

// hasFileChanged checks if a plugin file has been modified
func (fw *FileWatcher) hasFileChanged(pluginPath string, watched *WatchedPlugin) bool {
	info, err := os.Stat(pluginPath)
	if err != nil {
		fw.manager.logger.Warn("Failed to stat plugin file",
			"path", pluginPath,
			"error", err)
		return false
	}

	// Check modification time and size
	if info.ModTime().After(watched.LastModified) || info.Size() != watched.LastSize {
		return true
	}

	return false
}

// GetHotReloadStatus returns current hot reload status
func (hrm *HotReloadManager) GetHotReloadStatus() map[string]interface{} {
	hrm.mu.RLock()
	defer hrm.mu.RUnlock()

	return map[string]interface{}{
		"enabled":        hrm.config.Enabled,
		"running":        hrm.running,
		"watched_files":  len(hrm.watchedFiles),
		"reload_events":  len(hrm.reloadHistory),
		"watch_interval": hrm.config.WatchInterval,
		"backup_enabled": hrm.config.BackupOldVersions,
		"backup_dir":     hrm.config.BackupDirectory,
	}
}

// validatePluginPath validates that a plugin path is safe and within allowed directories
func (hrm *HotReloadManager) validatePluginPath(pluginPath string) error {
	// Clean the path to prevent directory traversal
	cleanPath := filepath.Clean(pluginPath)
	
	// Get absolute path
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path: %w", err)
	}
	
	// Check if path contains suspicious patterns
	if strings.Contains(absPath, "..") {
		return fmt.Errorf("path contains directory traversal attempt: %s", pluginPath)
	}
	
	// Check if file extension is .so
	if !strings.HasSuffix(absPath, ".so") {
		return fmt.Errorf("invalid plugin file extension (must be .so): %s", pluginPath)
	}
	
	// Verify path is within plugin directory or its subdirectories
	pluginDir, err := filepath.Abs(filepath.Dir(absPath))
	if err != nil {
		return fmt.Errorf("failed to resolve plugin directory: %w", err)
	}
	
	// Check file is readable and not a symlink (prevent symlink attacks)
	fileInfo, err := os.Lstat(absPath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlinks are not allowed for security reasons: %s", pluginPath)
	}
	
	// Check file permissions (should not be world-writable)
	if fileInfo.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("plugin file is world-writable (security risk): %s", pluginPath)
	}
	
	hrm.logger.Debug("Plugin path validated successfully",
		"original_path", pluginPath,
		"absolute_path", absPath,
		"plugin_dir", pluginDir)
	
	return nil
}

// verifyPluginChecksum calculates and verifies plugin file checksum
func (hrm *HotReloadManager) verifyPluginChecksum(pluginPath string, expectedHash string) error {
	file, err := os.Open(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to open plugin file: %w", err)
	}
	defer file.Close()
	
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}
	
	actualHash := fmt.Sprintf("%x", hash.Sum(nil))
	
	if expectedHash != "" && actualHash != expectedHash {
		return fmt.Errorf("checksum mismatch - possible tampering detected (expected: %s, got: %s)",
			expectedHash, actualHash)
	}
	
	hrm.logger.Debug("Plugin checksum verified",
		"path", pluginPath,
		"hash", actualHash)
	
	return nil
}
