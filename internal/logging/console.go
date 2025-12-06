package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// ConsoleLogger implements the Logger interface for console output
type ConsoleLogger struct {
	config    Config
	level     Level
	output    io.Writer
	fields    []Field
	mu        sync.Mutex
	formatter LogFormatter
}

// LogFormatter defines the interface for formatting log entries
type LogFormatter interface {
	Format(entry *LogEntry) ([]byte, error)
}

// LogEntry represents a single log entry
type LogEntry struct {
	Time    time.Time
	Level   Level
	Message string
	Fields  []Field
}

// TextFormatter formats log entries as plain text
type TextFormatter struct {
	TimeFormat string
	Colors     bool
}

// Format formats a log entry as plain text
func (f *TextFormatter) Format(entry *LogEntry) ([]byte, error) {
	var levelColor, resetColor string
	if f.Colors {
		resetColor = "\033[0m"
		switch entry.Level {
		case Debug:
			levelColor = "\033[37m" // White
		case Info:
			levelColor = "\033[32m" // Green
		case Warn:
			levelColor = "\033[33m" // Yellow
		case Error:
			levelColor = "\033[31m" // Red
		case Fatal:
			levelColor = "\033[35m" // Magenta
		}
	}

	timeFormat := f.TimeFormat
	if timeFormat == "" {
		timeFormat = "2006-01-02 15:04:05.000"
	}

	// Format the basic log entry
	logLine := fmt.Sprintf("%s%s%s [%s%s%s] %s",
		levelColor, entry.Time.Format(timeFormat), resetColor,
		levelColor, entry.Level.String(), resetColor,
		entry.Message)

	// Add fields if present
	if len(entry.Fields) > 0 {
		logLine += " "
		for i, field := range entry.Fields {
			if i > 0 {
				logLine += " "
			}
			logLine += fmt.Sprintf("%s=%v", field.Key, field.Value)
		}
	}

	return []byte(logLine + "\n"), nil
}

// JSONFormatter formats log entries as JSON
type JSONFormatter struct {
	TimeFormat string
}

// Format formats a log entry as JSON
func (f *JSONFormatter) Format(entry *LogEntry) ([]byte, error) {
	timeFormat := f.TimeFormat
	if timeFormat == "" {
		timeFormat = time.RFC3339Nano
	}

	data := make(map[string]interface{})
	data["time"] = entry.Time.Format(timeFormat)
	data["level"] = entry.Level.String()
	data["message"] = entry.Message

	// Add fields
	for _, field := range entry.Fields {
		data[field.Key] = field.Value
	}

	serialized, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	return append(serialized, '\n'), nil
}

// NewConsoleLogger creates a new console logger
func NewConsoleLogger(config Config) *ConsoleLogger {
	var formatter LogFormatter

	// Set default formatter if not specified
	if config.Formatter == "" {
		config.Formatter = "text"
	}

	// Create formatter based on configuration
	switch config.Formatter {
	case "json":
		formatter = &JSONFormatter{}
	case "text":
		formatter = &TextFormatter{Colors: true}
	default:
		formatter = &TextFormatter{Colors: true}
	}

	// Set default level if not specified
	if config.Level < Debug || config.Level > Fatal {
		config.Level = Info
	}

	// Set default output if not specified
	output := os.Stdout
	if config.Output != "" && config.Output != "stdout" {
		if config.Output == "stderr" {
			output = os.Stderr
		}
	}

	return &ConsoleLogger{
		config:    config,
		level:     config.Level,
		output:    output,
		fields:    []Field{},
		formatter: formatter,
	}
}

// Debug logs a message at debug level
func (l *ConsoleLogger) Debug(msg string, fields ...Field) {
	if l.level <= Debug {
		l.log(Debug, msg, fields...)
	}
}

// Info logs a message at info level
func (l *ConsoleLogger) Info(msg string, fields ...Field) {
	if l.level <= Info {
		l.log(Info, msg, fields...)
	}
}

// Warn logs a message at warn level
func (l *ConsoleLogger) Warn(msg string, fields ...Field) {
	if l.level <= Warn {
		l.log(Warn, msg, fields...)
	}
}

// Error logs a message at error level
func (l *ConsoleLogger) Error(msg string, fields ...Field) {
	if l.level <= Error {
		l.log(Error, msg, fields...)
	}
}

// Fatal logs a message at fatal level and then exits
func (l *ConsoleLogger) Fatal(msg string, fields ...Field) {
	if l.level <= Fatal {
		l.log(Fatal, msg, fields...)
		os.Exit(1)
	}
}

// WithFields returns a new logger with the given fields added to each log entry
func (l *ConsoleLogger) WithFields(fields ...Field) Logger {
	newLogger := &ConsoleLogger{
		config:    l.config,
		level:     l.level,
		output:    l.output,
		formatter: l.formatter,
	}

	// Combine existing fields with new fields
	newLogger.fields = make([]Field, len(l.fields)+len(fields))
	copy(newLogger.fields, l.fields)
	copy(newLogger.fields[len(l.fields):], fields)

	return newLogger
}

// WithField returns a new logger with the given field added to each log entry
func (l *ConsoleLogger) WithField(key string, value interface{}) Logger {
	return l.WithFields(Field{Key: key, Value: value})
}

// SetLevel sets the minimum log level
func (l *ConsoleLogger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// GetLevel returns the current minimum log level
func (l *ConsoleLogger) GetLevel() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// SetOutput sets the output destination
func (l *ConsoleLogger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

// Close closes the logger and flushes any buffered log entries
func (l *ConsoleLogger) Close() error {
	// Nothing to close for console logger
	return nil
}

// log writes a log entry to the output
func (l *ConsoleLogger) log(level Level, msg string, fields ...Field) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Sanitize message and fields to prevent log injection and sensitive data leaks
	msg = sanitizeMessage(msg)
	fields = sanitizeFields(fields)

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

	// Format the log entry
	formatted, err := l.formatter.Format(entry)
	if err != nil {
		// If formatting fails, use a simple fallback format
		formatted = []byte(fmt.Sprintf("[ERROR FORMATTING LOG] %s [%s] %s\n",
			entry.Time.Format("2006-01-02 15:04:05.000"),
			entry.Level.String(),
			entry.Message))
	}

	// Write to output
	_, _ = l.output.Write(formatted)
}
