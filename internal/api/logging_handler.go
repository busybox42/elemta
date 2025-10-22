package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
)

// LogLevelManager manages runtime log level adjustment
type LogLevelManager struct {
	currentLevel slog.Level
	mu           sync.RWMutex
}

var globalLogLevelManager = &LogLevelManager{
	currentLevel: slog.LevelInfo, // Default to INFO
}

// GetLogLevelManager returns the global log level manager
func GetLogLevelManager() *LogLevelManager {
	return globalLogLevelManager
}

// SetLevel sets the current log level
func (m *LogLevelManager) SetLevel(level slog.Level) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentLevel = level
	slog.SetLogLoggerLevel(level)
}

// GetLevel returns the current log level
func (m *LogLevelManager) GetLevel() slog.Level {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentLevel
}

// LogLevelRequest represents a log level change request
type LogLevelRequest struct {
	Level string `json:"level"`
}

// LogLevelResponse represents a log level response
type LogLevelResponse struct {
	CurrentLevel string `json:"current_level"`
	Message      string `json:"message,omitempty"`
}

// HandleGetLogLevel returns the current log level
func (s *Server) HandleGetLogLevel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	level := globalLogLevelManager.GetLevel()
	levelStr := levelToString(level)

	response := LogLevelResponse{
		CurrentLevel: levelStr,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleSetLogLevel changes the log level at runtime
func (s *Server) HandleSetLogLevel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LogLevelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Parse log level
	level, err := stringToLevel(req.Level)
	if err != nil {
		http.Error(w, "Invalid log level. Valid levels: DEBUG, INFO, WARN, ERROR", http.StatusBadRequest)
		return
	}

	// Set new log level
	globalLogLevelManager.SetLevel(level)

	slog.Info("log level changed",
		"new_level", req.Level,
		"remote_addr", r.RemoteAddr)

	response := LogLevelResponse{
		CurrentLevel: req.Level,
		Message:      "Log level updated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// levelToString converts slog.Level to string
func levelToString(level slog.Level) string {
	switch level {
	case slog.LevelDebug:
		return "DEBUG"
	case slog.LevelInfo:
		return "INFO"
	case slog.LevelWarn:
		return "WARN"
	case slog.LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// stringToLevel converts string to slog.Level
func stringToLevel(levelStr string) (slog.Level, error) {
	switch levelStr {
	case "DEBUG", "debug":
		return slog.LevelDebug, nil
	case "INFO", "info":
		return slog.LevelInfo, nil
	case "WARN", "warn", "WARNING", "warning":
		return slog.LevelWarn, nil
	case "ERROR", "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, http.ErrNotSupported
	}
}

// InitializeLogging initializes logging with the specified level from config
func InitializeLogging(levelStr string) {
	level, err := stringToLevel(levelStr)
	if err != nil {
		slog.Warn("invalid log level in config, defaulting to INFO",
			"configured_level", levelStr)
		level = slog.LevelInfo
	}

	globalLogLevelManager.SetLevel(level)
	
	slog.Info("logging initialized",
		"log_level", levelToString(level))
}

