package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/busybox42/elemta/internal/queue"
	"github.com/gorilla/mux"
)

// Server represents an API server for Elemta
type Server struct {
	httpServer *http.Server
	queueMgr   *queue.Manager
	listenAddr string
	webRoot    string
}

// Config represents API server configuration
type Config struct {
	Enabled    bool   `toml:"enabled" json:"enabled"`
	ListenAddr string `toml:"listen_addr" json:"listen_addr"`
	WebRoot    string `toml:"web_root" json:"web_root"`
}

// NewServer creates a new API server
func NewServer(config *Config, queueDir string) (*Server, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("API server disabled in configuration")
	}

	listenAddr := config.ListenAddr
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8025"
	}

	webRoot := config.WebRoot
	if webRoot == "" {
		webRoot = "./web/static"
	}

	queueMgr := queue.NewManager(queueDir)

	return &Server{
		queueMgr:   queueMgr,
		listenAddr: listenAddr,
		webRoot:    webRoot,
	}, nil
}

// Start starts the API server
func (s *Server) Start() error {
	r := mux.NewRouter()

	// Serve static files for the web interface
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(s.webRoot))))

	// Serve the main dashboard at root
	r.HandleFunc("/", s.handleDashboard).Methods("GET")
	r.HandleFunc("/dashboard", s.handleDashboard).Methods("GET")

	// API routes
	api := r.PathPrefix("/api").Subrouter()

	// Queue management routes - more specific routes first
	api.HandleFunc("/queue/stats", s.handleGetQueueStats).Methods("GET")
	api.HandleFunc("/queue/message/{id}", s.handleGetMessage).Methods("GET")
	api.HandleFunc("/queue/message/{id}", s.handleDeleteMessage).Methods("DELETE")
	api.HandleFunc("/queue/{type}/flush", s.handleFlushQueue).Methods("POST")
	api.HandleFunc("/queue/{type}", s.handleGetQueue).Methods("GET")
	api.HandleFunc("/queue", s.handleGetAllQueues).Methods("GET")

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         s.listenAddr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting API server on %s", s.listenAddr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the API server
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(ctx)
}

// API handlers

// handleGetAllQueues returns all messages in all queues
func (s *Server) handleGetAllQueues(w http.ResponseWriter, r *http.Request) {
	messages, err := s.queueMgr.GetAllMessages()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, messages)
}

// handleGetQueue returns messages in a specific queue
func (s *Server) handleGetQueue(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	qType := vars["type"]

	queueType, err := parseQueueType(qType)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusBadRequest)
		return
	}

	messages, err := s.queueMgr.ListMessages(queueType)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, messages)
}

// handleFlushQueue flushes a specific queue
func (s *Server) handleFlushQueue(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	qType := vars["type"]

	var err error
	if qType == "all" {
		err = s.queueMgr.FlushAllQueues()
	} else {
		queueType, qErr := parseQueueType(qType)
		if qErr != nil {
			http.Error(w, fmt.Sprintf("Error: %v", qErr), http.StatusBadRequest)
			return
		}

		err = s.queueMgr.FlushQueue(queueType)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "success", "message": fmt.Sprintf("Queue %s flushed", qType)})
}

// handleGetMessage returns a specific message
func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	content, err := s.queueMgr.GetMessageContent(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusNotFound)
		return
	}

	// If format=raw is specified, return raw message
	if r.URL.Query().Get("format") == "raw" {
		w.Header().Set("Content-Type", "text/plain")
		n, err := w.Write(content)
		if err != nil || n != len(content) {
			http.Error(w, fmt.Sprintf("Error writing response: %v", err), http.StatusInternalServerError)
		}
		return
	}

	msg, err := s.queueMgr.GetMessage(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusNotFound)
		return
	}

	// Include the content with the message
	type MessageWithContent struct {
		queue.Message
		Content string `json:"content"`
	}

	msgWithContent := MessageWithContent{
		Message: msg,
		Content: string(content),
	}

	writeJSON(w, msgWithContent)
}

// handleDeleteMessage deletes a specific message
func (s *Server) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if err := s.queueMgr.DeleteMessage(id); err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusNotFound)
		return
	}

	writeJSON(w, map[string]string{"status": "success", "message": fmt.Sprintf("Message %s deleted", id)})
}

// handleGetQueueStats returns queue statistics
func (s *Server) handleGetQueueStats(w http.ResponseWriter, r *http.Request) {
	stats := s.queueMgr.GetStats()
	writeJSON(w, stats)
}

// handleDashboard serves the main dashboard page
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, s.webRoot+"/index.html")
}

// Helper functions

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, fmt.Sprintf("Error encoding JSON: %v", err), http.StatusInternalServerError)
	}
}

// parseQueueType converts a string to a QueueType
func parseQueueType(qType string) (queue.QueueType, error) {
	qType = strings.ToLower(qType)

	switch qType {
	case "active":
		return queue.Active, nil
	case "deferred":
		return queue.Deferred, nil
	case "hold":
		return queue.Hold, nil
	case "failed":
		return queue.Failed, nil
	default:
		return "", fmt.Errorf("invalid queue type: %s", qType)
	}
}
