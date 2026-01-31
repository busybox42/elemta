package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// ElasticLogger implements the Logger interface for Elasticsearch output
type ElasticLogger struct {
	config     Config
	level      Level
	fields     []Field
	mu         sync.Mutex
	client     *http.Client
	url        string
	index      string
	bufferSize int
	buffer     []*LogEntry
	connected  bool
	flushTimer *time.Ticker
	stopChan   chan bool
}

// NewElasticLogger creates a new Elasticsearch logger
func NewElasticLogger(config Config) (*ElasticLogger, error) {
	// Set default level if not specified
	if config.Level < Debug || config.Level > Fatal {
		config.Level = Info
	}

	// Ensure output URL is specified
	if config.Output == "" {
		return nil, fmt.Errorf("Elasticsearch URL must be specified")
	}

	// Get index name from options
	index := "logs"
	bufferSize := 100
	flushInterval := 5 * time.Second

	if config.Options != nil {
		if val, ok := config.Options["index"]; ok {
			if idx, ok := val.(string); ok && idx != "" {
				index = idx
			}
		}
		if val, ok := config.Options["bufferSize"]; ok {
			if size, ok := val.(int); ok && size > 0 {
				bufferSize = size
			}
		}
		if val, ok := config.Options["flushInterval"]; ok {
			if interval, ok := val.(time.Duration); ok && interval > 0 {
				flushInterval = interval
			}
		}
	}

	logger := &ElasticLogger{
		config:     config,
		level:      config.Level,
		fields:     []Field{},
		client:     &http.Client{Timeout: 10 * time.Second},
		url:        config.Output,
		index:      index,
		bufferSize: bufferSize,
		buffer:     make([]*LogEntry, 0, bufferSize),
		connected:  false,
		stopChan:   make(chan bool),
	}

	// Start the flush timer
	logger.flushTimer = time.NewTicker(flushInterval)
	go func() {
		for {
			select {
			case <-logger.flushTimer.C:
				if err := logger.Flush(); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to flush logs to Elasticsearch: %v\n", err)
				}
			case <-logger.stopChan:
				logger.flushTimer.Stop()
				return
			}
		}
	}()

	// Test the connection
	if err := logger.testConnection(); err != nil {
		return nil, fmt.Errorf("failed to connect to Elasticsearch: %w", err)
	}

	logger.connected = true
	return logger, nil
}

// testConnection tests the connection to Elasticsearch
func (l *ElasticLogger) testConnection() error {
	req, err := http.NewRequest("GET", l.url, nil)
	if err != nil {
		return err
	}

	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // Ignore error in defer cleanup

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Elasticsearch returned status code %d", resp.StatusCode)
	}

	return nil
}

// Debug logs a message at debug level
func (l *ElasticLogger) Debug(msg string, fields ...Field) {
	if l.level <= Debug {
		l.log(Debug, msg, fields...)
	}
}

// Info logs a message at info level
func (l *ElasticLogger) Info(msg string, fields ...Field) {
	if l.level <= Info {
		l.log(Info, msg, fields...)
	}
}

// Warn logs a message at warn level
func (l *ElasticLogger) Warn(msg string, fields ...Field) {
	if l.level <= Warn {
		l.log(Warn, msg, fields...)
	}
}

// Error logs a message at error level
func (l *ElasticLogger) Error(msg string, fields ...Field) {
	if l.level <= Error {
		l.log(Error, msg, fields...)
	}
}

// Fatal logs a message at fatal level and then exits
func (l *ElasticLogger) Fatal(msg string, fields ...Field) {
	if l.level <= Fatal {
		l.log(Fatal, msg, fields...)
		// Ensure logs are flushed before exiting
		_ = l.Flush() // Ignore error before exit
		os.Exit(1)
	}
}

// WithFields returns a new logger with the given fields added to each log entry
func (l *ElasticLogger) WithFields(fields ...Field) Logger {
	newLogger := &ElasticLogger{
		config:     l.config,
		level:      l.level,
		client:     l.client,
		url:        l.url,
		index:      l.index,
		bufferSize: l.bufferSize,
		buffer:     l.buffer,
		connected:  l.connected,
		flushTimer: l.flushTimer,
		stopChan:   l.stopChan,
	}

	// Combine existing fields with new fields
	newLogger.fields = make([]Field, len(l.fields)+len(fields))
	copy(newLogger.fields, l.fields)
	copy(newLogger.fields[len(l.fields):], fields)

	return newLogger
}

// WithField returns a new logger with the given field added to each log entry
func (l *ElasticLogger) WithField(key string, value interface{}) Logger {
	return l.WithFields(Field{Key: key, Value: value})
}

// SetLevel sets the minimum log level
func (l *ElasticLogger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// GetLevel returns the current minimum log level
func (l *ElasticLogger) GetLevel() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// SetOutput sets the output destination
func (l *ElasticLogger) SetOutput(w io.Writer) {
	// Not applicable for Elasticsearch logger
}

// Close closes the logger and flushes any buffered log entries
func (l *ElasticLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Stop the flush timer
	l.stopChan <- true
	close(l.stopChan)

	// Flush any remaining logs
	return l.flushLocked()
}

// Flush flushes the log buffer to Elasticsearch
func (l *ElasticLogger) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.flushLocked()
}

// flushLocked flushes the log buffer to Elasticsearch (must be called with lock held)
func (l *ElasticLogger) flushLocked() error {
	if len(l.buffer) == 0 {
		return nil
	}

	// Create bulk request
	var buf bytes.Buffer
	for _, entry := range l.buffer {
		// Create action line
		action := map[string]map[string]string{
			"index": {
				"_index": l.index,
			},
		}
		actionBytes, err := json.Marshal(action)
		if err != nil {
			return err
		}
		buf.Write(actionBytes)
		buf.WriteByte('\n')

		// Create document
		doc := map[string]interface{}{
			"@timestamp": entry.Time.Format(time.RFC3339Nano),
			"level":      entry.Level.String(),
			"message":    entry.Message,
		}

		// Add fields
		for _, field := range entry.Fields {
			doc[field.Key] = field.Value
		}

		docBytes, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		buf.Write(docBytes)
		buf.WriteByte('\n')
	}

	// Send bulk request
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/_bulk", l.url), &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // Ignore error in defer cleanup

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Elasticsearch returned status code %d: %s", resp.StatusCode, string(body))
	}

	// Clear buffer
	l.buffer = l.buffer[:0]
	return nil
}

// log adds a log entry to the buffer
func (l *ElasticLogger) log(level Level, msg string, fields ...Field) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.connected {
		return
	}

	// Create log entry
	entry := &LogEntry{
		Time:    time.Now(),
		Level:   level,
		Message: msg,
	}

	// Combine logger fields with entry fields
	if len(l.fields) > 0 || len(fields) > 0 {
		entry.Fields = make([]Field, len(l.fields)+len(fields))
		copy(entry.Fields, l.fields)
		copy(entry.Fields[len(l.fields):], fields)
	}

	// Add to buffer
	l.buffer = append(l.buffer, entry)

	// Flush if buffer is full
	if len(l.buffer) >= l.bufferSize {
		if err := l.flushLocked(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to flush logs to Elasticsearch: %v\n", err)
		}
	}
}
