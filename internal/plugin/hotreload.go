package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

// performReload executes the actual plugin reload process
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
		}
	}

	// Backup old version if enabled
	if hrm.config.BackupOldVersions {
		if err := hrm.backupPlugin(pluginPath, watched.PluginName); err != nil {
			hrm.logger.Warn("Failed to backup plugin",
				"plugin", watched.PluginName,
				"error", err)
		}
	}

	// Unload the existing plugin gracefully
	if err := hrm.unloadPluginGracefully(watched.PluginName); err != nil {
		hrm.logger.Warn("Failed to unload plugin gracefully",
			"plugin", watched.PluginName,
			"error", err)
	}

	// Load the new plugin version
	if err := hrm.pluginManager.LoadPlugin(watched.PluginName); err != nil {
		event.Success = false
		event.Error = fmt.Sprintf("failed to load new version: %v", err)
		event.Duration = time.Since(startTime)
		hrm.addReloadEvent(event)

		// Try to restore from backup if available
		if hrm.config.BackupOldVersions {
			hrm.logger.Warn("Attempting to restore from backup", "plugin", watched.PluginName)
			if restoreErr := hrm.restorePluginFromBackup(watched.PluginName); restoreErr != nil {
				hrm.logger.Error("Failed to restore plugin from backup",
					"plugin", watched.PluginName,
					"error", restoreErr)
			}
		}

		return fmt.Errorf("failed to load new plugin version: %w", err)
	}

	// Update watched plugin metadata
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
		"reload_count", watched.ReloadCount)

	return nil
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
		if fw.hasFileChanged(pluginPath, watched) {
			fw.manager.logger.Info("Plugin file changed, triggering reload",
				"plugin", watched.PluginName,
				"path", pluginPath)

			if err := fw.manager.performReload(pluginPath, watched); err != nil {
				fw.manager.logger.Error("Auto-reload failed",
					"plugin", watched.PluginName,
					"error", err)
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
