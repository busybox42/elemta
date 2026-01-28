package api

import (
	"encoding/json"
	"net/http"

	"github.com/busybox42/elemta/internal/logging"
)

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

	level := logging.GetLogLevelManager().GetLevel()
	levelStr := logging.LevelToString(level)

	response := LogLevelResponse{
		CurrentLevel: levelStr,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response) // Best effort
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
	level, err := logging.StringToLevel(req.Level)
	if err != nil {
		http.Error(w, "Invalid log level. Valid levels: DEBUG, INFO, WARN, ERROR", http.StatusBadRequest)
		return
	}

	// Set new log level
	logging.GetLogLevelManager().SetLevel(level)

	response := LogLevelResponse{
		CurrentLevel: req.Level,
		Message:      "Log level updated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response) // Best effort
}
