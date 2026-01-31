package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// FileLogger implements the Logger interface for file output
type FileLogger struct {
	config    Config
	level     Level
	output    io.Writer
	fields    []Field
	mu        sync.Mutex
	formatter LogFormatter
	file      *os.File
	maxSize   int64
	maxAge    time.Duration
	maxFiles  int
	filePath  string
	fileSize  int64
}

// FileLoggerOption represents an option for configuring a FileLogger
type FileLoggerOption func(*FileLogger)

// WithMaxSize sets the maximum size of a log file before rotation
func WithMaxSize(maxSize int64) FileLoggerOption {
	return func(l *FileLogger) {
		l.maxSize = maxSize
	}
}

// WithMaxAge sets the maximum age of a log file before deletion
func WithMaxAge(maxAge time.Duration) FileLoggerOption {
	return func(l *FileLogger) {
		l.maxAge = maxAge
	}
}

// WithMaxFiles sets the maximum number of log files to keep
func WithMaxFiles(maxFiles int) FileLoggerOption {
	return func(l *FileLogger) {
		l.maxFiles = maxFiles
	}
}

// NewFileLogger creates a new file logger
func NewFileLogger(config Config) (*FileLogger, error) {
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
		formatter = &TextFormatter{Colors: false}
	default:
		formatter = &TextFormatter{Colors: false}
	}

	// Set default level if not specified
	if config.Level < Debug || config.Level > Fatal {
		config.Level = Info
	}

	// Ensure output path is specified
	if config.Output == "" {
		return nil, fmt.Errorf("file path must be specified for file logger")
	}

	// Create directory if it doesn't exist (restrictive permissions)
	dir := filepath.Dir(config.Output)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file with restrictive permissions
	file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Get file info for size
	fileInfo, err := file.Stat()
	if err != nil {
		_ = file.Close() // Ignore error on cleanup in error path
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	// Parse options from config
	maxSize := int64(10 * 1024 * 1024) // Default: 10MB
	maxAge := 7 * 24 * time.Hour       // Default: 7 days
	maxFiles := 10                     // Default: 10 files

	if config.Options != nil {
		if val, ok := config.Options["maxSize"]; ok {
			if size, ok := val.(int64); ok {
				maxSize = size
			}
		}
		if val, ok := config.Options["maxAge"]; ok {
			if age, ok := val.(time.Duration); ok {
				maxAge = age
			}
		}
		if val, ok := config.Options["maxFiles"]; ok {
			if files, ok := val.(int); ok {
				maxFiles = files
			}
		}
	}

	logger := &FileLogger{
		config:    config,
		level:     config.Level,
		output:    file,
		fields:    []Field{},
		formatter: formatter,
		file:      file,
		maxSize:   maxSize,
		maxAge:    maxAge,
		maxFiles:  maxFiles,
		filePath:  config.Output,
		fileSize:  fileInfo.Size(),
	}

	return logger, nil
}

// Debug logs a message at debug level
func (l *FileLogger) Debug(msg string, fields ...Field) {
	if l.level <= Debug {
		l.log(Debug, msg, fields...)
	}
}

// Info logs a message at info level
func (l *FileLogger) Info(msg string, fields ...Field) {
	if l.level <= Info {
		l.log(Info, msg, fields...)
	}
}

// Warn logs a message at warn level
func (l *FileLogger) Warn(msg string, fields ...Field) {
	if l.level <= Warn {
		l.log(Warn, msg, fields...)
	}
}

// Error logs a message at error level
func (l *FileLogger) Error(msg string, fields ...Field) {
	if l.level <= Error {
		l.log(Error, msg, fields...)
	}
}

// Fatal logs a message at fatal level and then exits
func (l *FileLogger) Fatal(msg string, fields ...Field) {
	if l.level <= Fatal {
		l.log(Fatal, msg, fields...)
		os.Exit(1)
	}
}

// WithFields returns a new logger with the given fields added to each log entry
func (l *FileLogger) WithFields(fields ...Field) Logger {
	newLogger := &FileLogger{
		config:    l.config,
		level:     l.level,
		output:    l.output,
		formatter: l.formatter,
		file:      l.file,
		maxSize:   l.maxSize,
		maxAge:    l.maxAge,
		maxFiles:  l.maxFiles,
		filePath:  l.filePath,
		fileSize:  l.fileSize,
	}

	// Combine existing fields with new fields
	newLogger.fields = make([]Field, len(l.fields)+len(fields))
	copy(newLogger.fields, l.fields)
	copy(newLogger.fields[len(l.fields):], fields)

	return newLogger
}

// WithField returns a new logger with the given field added to each log entry
func (l *FileLogger) WithField(key string, value interface{}) Logger {
	return l.WithFields(Field{Key: key, Value: value})
}

// SetLevel sets the minimum log level
func (l *FileLogger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// GetLevel returns the current minimum log level
func (l *FileLogger) GetLevel() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// SetOutput sets the output destination
func (l *FileLogger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

// Close closes the logger and flushes any buffered log entries
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

// log writes a log entry to the output
func (l *FileLogger) log(level Level, msg string, fields ...Field) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Check if we need to rotate the log file
	if l.shouldRotate() {
		if err := l.rotate(); err != nil {
			// If rotation fails, try to log the error
			fmt.Fprintf(os.Stderr, "Failed to rotate log file: %v\n", err)
		}
	}

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
	n, err := l.output.Write(formatted)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write to log file: %v\n", err)
		return
	}

	// Update file size
	l.fileSize += int64(n)
}

// shouldRotate returns true if the log file should be rotated
func (l *FileLogger) shouldRotate() bool {
	return l.maxSize > 0 && l.fileSize >= l.maxSize
}

// rotate rotates the log file
func (l *FileLogger) rotate() error {
	// Close current file
	if err := l.file.Close(); err != nil {
		return err
	}

	// Generate timestamp for rotation
	timestamp := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", l.filePath, timestamp)

	// Rename current file to rotated file
	if err := os.Rename(l.filePath, rotatedPath); err != nil {
		return err
	}

	// Open new file with restrictive permissions
	file, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	// Update logger state
	l.file = file
	l.output = file
	l.fileSize = 0

	// Clean up old log files
	go l.cleanOldLogFiles()

	return nil
}

// cleanOldLogFiles removes old log files based on maxAge and maxFiles
func (l *FileLogger) cleanOldLogFiles() {
	dir := filepath.Dir(l.filePath)
	base := filepath.Base(l.filePath)

	// List all files in the directory
	files, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var logFiles []os.FileInfo
	for _, file := range files {
		// Skip directories
		if file.IsDir() {
			continue
		}

		// Check if the file is a rotated log file
		if filepath.Base(file.Name()) == base || (len(file.Name()) > len(base) && file.Name()[:len(base)] == base && file.Name()[len(base)] == '.') {
			info, err := file.Info()
			if err != nil {
				continue
			}
			logFiles = append(logFiles, info)
		}
	}

	// Sort files by modification time (oldest first)
	sort.Slice(logFiles, func(i, j int) bool {
		return logFiles[i].ModTime().Before(logFiles[j].ModTime())
	})

	// Remove files based on maxAge
	now := time.Now()
	for _, file := range logFiles {
		if l.maxAge > 0 && now.Sub(file.ModTime()) > l.maxAge {
			_ = os.Remove(filepath.Join(dir, file.Name())) // Ignore error on old file cleanup
		}
	}

	// Remove files based on maxFiles
	if l.maxFiles > 0 && len(logFiles) > l.maxFiles {
		for i := 0; i < len(logFiles)-l.maxFiles; i++ {
			_ = os.Remove(filepath.Join(dir, logFiles[i].Name())) // Ignore error on old file cleanup
		}
	}
}
