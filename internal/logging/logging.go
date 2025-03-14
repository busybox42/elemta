package logging

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

// Level represents the severity level of a log message
type Level int

const (
	// Debug level for detailed troubleshooting information
	Debug Level = iota
	// Info level for general operational information
	Info
	// Warn level for non-critical issues
	Warn
	// Error level for errors that should be investigated
	Error
	// Fatal level for critical errors that require immediate attention
	Fatal
)

// String returns the string representation of a log level
func (l Level) String() string {
	switch l {
	case Debug:
		return "DEBUG"
	case Info:
		return "INFO"
	case Warn:
		return "WARN"
	case Error:
		return "ERROR"
	case Fatal:
		return "FATAL"
	default:
		return fmt.Sprintf("LEVEL(%d)", l)
	}
}

// Field represents a key-value pair for structured logging
type Field struct {
	Key   string
	Value interface{}
}

// F creates a new log field
func F(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}

// Logger defines the interface that all logger implementations must satisfy
type Logger interface {
	// Debug logs a message at debug level
	Debug(msg string, fields ...Field)

	// Info logs a message at info level
	Info(msg string, fields ...Field)

	// Warn logs a message at warn level
	Warn(msg string, fields ...Field)

	// Error logs a message at error level
	Error(msg string, fields ...Field)

	// Fatal logs a message at fatal level and then exits
	Fatal(msg string, fields ...Field)

	// WithFields returns a new logger with the given fields added to each log entry
	WithFields(fields ...Field) Logger

	// WithField returns a new logger with the given field added to each log entry
	WithField(key string, value interface{}) Logger

	// SetLevel sets the minimum log level
	SetLevel(level Level)

	// GetLevel returns the current minimum log level
	GetLevel() Level

	// SetOutput sets the output destination
	SetOutput(w io.Writer)

	// Close closes the logger and flushes any buffered log entries
	Close() error
}

// Config represents the configuration for a logger
type Config struct {
	Type      string                 // Type of logger (console, file, elastic, etc.)
	Name      string                 // Name of this logger instance
	Level     Level                  // Minimum log level
	Output    string                 // Output destination (file path, URL, etc.)
	Formatter string                 // Log format (json, text, etc.)
	Options   map[string]interface{} // Additional options specific to the logger type
}

// Factory creates logger instances based on configuration
func Factory(config Config) (Logger, error) {
	switch config.Type {
	case "console":
		return NewConsoleLogger(config), nil
	case "file":
		return NewFileLogger(config)
	case "elastic":
		return NewElasticLogger(config)
	default:
		return nil, errors.New("unsupported logger type: " + config.Type)
	}
}

// Manager manages multiple logger instances
type Manager struct {
	loggers  map[string]Logger
	mu       sync.RWMutex
	default_ Logger
}

// NewManager creates a new logger manager
func NewManager() *Manager {
	// Create a default console logger
	defaultLogger := NewConsoleLogger(Config{
		Type:      "console",
		Name:      "default",
		Level:     Info,
		Formatter: "text",
	})

	return &Manager{
		loggers:  make(map[string]Logger),
		default_: defaultLogger,
	}
}

// Register adds a logger to the manager
func (m *Manager) Register(logger Logger, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.loggers[name]; exists {
		return errors.New("logger with name '" + name + "' already registered")
	}

	m.loggers[name] = logger
	return nil
}

// Get retrieves a logger by name
func (m *Manager) Get(name string) (Logger, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	logger, exists := m.loggers[name]
	return logger, exists
}

// Default returns the default logger
func (m *Manager) Default() Logger {
	return m.default_
}

// SetDefault sets the default logger
func (m *Manager) SetDefault(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logger, exists := m.loggers[name]
	if !exists {
		return errors.New("logger '" + name + "' not found")
	}

	m.default_ = logger
	return nil
}

// List returns all registered loggers
func (m *Manager) List() map[string]Logger {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.loggers
}

// Remove removes a logger from the manager
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logger, exists := m.loggers[name]
	if !exists {
		return errors.New("logger '" + name + "' not found")
	}

	if err := logger.Close(); err != nil {
		return err
	}

	delete(m.loggers, name)
	return nil
}

// CloseAll closes all loggers
func (m *Manager) CloseAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for name, logger := range m.loggers {
		if err := logger.Close(); err != nil {
			errs = append(errs, errors.New("failed to close logger '"+name+"': "+err.Error()))
		}
	}

	if len(errs) > 0 {
		return errors.New("errors closing loggers")
	}

	return nil
}

// Global logger manager instance
var globalManager = NewManager()

// GetManager returns the global logger manager
func GetManager() *Manager {
	return globalManager
}

// Default returns the default logger from the global manager
func Default() Logger {
	return globalManager.Default()
}

// Get retrieves a logger by name from the global manager
func Get(name string) (Logger, bool) {
	return globalManager.Get(name)
}

// Register adds a logger to the global manager
func Register(logger Logger, name string) error {
	return globalManager.Register(logger, name)
}

// SetDefault sets the default logger in the global manager
func SetDefault(name string) error {
	return globalManager.SetDefault(name)
}

// CloseAll closes all loggers in the global manager
func CloseAll() error {
	return globalManager.CloseAll()
}
