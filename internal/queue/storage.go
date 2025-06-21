package queue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileStorageBackend implements StorageBackend using the filesystem
type FileStorageBackend struct {
	queueDir string
}

// NewFileStorageBackend creates a new file-based storage backend
func NewFileStorageBackend(queueDir string) *FileStorageBackend {
	return &FileStorageBackend{
		queueDir: queueDir,
	}
}

// Store saves a message to the storage backend
func (fs *FileStorageBackend) Store(msg Message) error {
	// Ensure queue directory exists
	queuePath := filepath.Join(fs.queueDir, string(msg.QueueType))
	if err := os.MkdirAll(queuePath, 0755); err != nil {
		return fmt.Errorf("failed to create queue directory: %w", err)
	}

	// Marshal message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Write to file
	filePath := filepath.Join(queuePath, msg.ID+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write message file: %w", err)
	}

	return nil
}

// Retrieve loads a message from the storage backend
func (fs *FileStorageBackend) Retrieve(id string) (Message, error) {
	// Try to find the message in any queue
	queueTypes := []QueueType{Active, Deferred, Hold, Failed}

	for _, queueType := range queueTypes {
		filePath := filepath.Join(fs.queueDir, string(queueType), id+".json")
		if _, err := os.Stat(filePath); err == nil {
			// File exists, read it
			data, err := os.ReadFile(filePath)
			if err != nil {
				return Message{}, fmt.Errorf("failed to read message file: %w", err)
			}

			// Unmarshal JSON
			var msg Message
			if err := json.Unmarshal(data, &msg); err != nil {
				return Message{}, fmt.Errorf("failed to unmarshal message: %w", err)
			}

			return msg, nil
		}
	}

	return Message{}, fmt.Errorf("message not found: %s", id)
}

// Update saves changes to an existing message
func (fs *FileStorageBackend) Update(msg Message) error {
	// Marshal message to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Write to file
	filePath := filepath.Join(fs.queueDir, string(msg.QueueType), msg.ID+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write message file: %w", err)
	}

	return nil
}

// Delete removes a message from the storage backend
func (fs *FileStorageBackend) Delete(id string) error {
	// Try to find the message in any queue
	queueTypes := []QueueType{Active, Deferred, Hold, Failed}

	for _, queueType := range queueTypes {
		filePath := filepath.Join(fs.queueDir, string(queueType), id+".json")
		if _, err := os.Stat(filePath); err == nil {
			// File exists, delete it
			if err := os.Remove(filePath); err != nil {
				return fmt.Errorf("failed to delete message file: %w", err)
			}
			return nil
		}
	}

	return fmt.Errorf("message not found: %s", id)
}

// List returns all messages in a specific queue
func (fs *FileStorageBackend) List(queueType QueueType) ([]Message, error) {
	queuePath := filepath.Join(fs.queueDir, string(queueType))

	// Check if directory exists
	if _, err := os.Stat(queuePath); os.IsNotExist(err) {
		return []Message{}, nil
	}

	// Read directory
	files, err := os.ReadDir(queuePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read queue directory: %w", err)
	}

	// Load each message
	messages := make([]Message, 0, len(files))
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(queuePath, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue // Skip files that can't be read
		}

		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			continue // Skip files that can't be unmarshaled
		}

		messages = append(messages, msg)
	}

	return messages, nil
}

// Count returns the number of messages in a specific queue
func (fs *FileStorageBackend) Count(queueType QueueType) (int, error) {
	queuePath := filepath.Join(fs.queueDir, string(queueType))

	// Check if directory exists
	if _, err := os.Stat(queuePath); os.IsNotExist(err) {
		return 0, nil
	}

	// Read directory
	files, err := os.ReadDir(queuePath)
	if err != nil {
		return 0, fmt.Errorf("failed to read queue directory: %w", err)
	}

	// Count JSON files
	count := 0
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			count++
		}
	}

	return count, nil
}

// DeleteAll removes all messages from a specific queue
func (fs *FileStorageBackend) DeleteAll(queueType QueueType) error {
	queuePath := filepath.Join(fs.queueDir, string(queueType))

	// Check if directory exists
	if _, err := os.Stat(queuePath); os.IsNotExist(err) {
		return nil // Nothing to delete
	}

	// Read directory
	files, err := os.ReadDir(queuePath)
	if err != nil {
		return fmt.Errorf("failed to read queue directory: %w", err)
	}

	// Delete all JSON files
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			filePath := filepath.Join(queuePath, file.Name())
			if err := os.Remove(filePath); err != nil {
				return fmt.Errorf("failed to delete file %s: %w", filePath, err)
			}
		}
	}

	return nil
}

// Move transfers a message between queues
func (fs *FileStorageBackend) Move(id string, fromQueue, toQueue QueueType) error {
	// Construct file paths
	fromPath := filepath.Join(fs.queueDir, string(fromQueue), id+".json")
	toPath := filepath.Join(fs.queueDir, string(toQueue), id+".json")

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(toPath), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Read message
	data, err := os.ReadFile(fromPath)
	if err != nil {
		return fmt.Errorf("failed to read message file: %w", err)
	}

	// Unmarshal to update queue type
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return fmt.Errorf("failed to unmarshal message: %w", err)
	}

	// Update queue type
	msg.QueueType = toQueue

	// Marshal updated message
	data, err = json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Write to destination
	if err := os.WriteFile(toPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write message file: %w", err)
	}

	// Remove from source
	if err := os.Remove(fromPath); err != nil {
		return fmt.Errorf("failed to remove source file: %w", err)
	}

	return nil
}

// StoreContent saves message content data
func (fs *FileStorageBackend) StoreContent(id string, data []byte) error {
	// Ensure data directory exists
	dataDir := filepath.Join(fs.queueDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Write content to file
	contentPath := filepath.Join(dataDir, id)
	if err := os.WriteFile(contentPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write content file: %w", err)
	}

	return nil
}

// RetrieveContent loads message content data
func (fs *FileStorageBackend) RetrieveContent(id string) ([]byte, error) {
	contentPath := filepath.Join(fs.queueDir, "data", id)

	data, err := os.ReadFile(contentPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read content file: %w", err)
	}

	return data, nil
}

// DeleteContent removes message content data
func (fs *FileStorageBackend) DeleteContent(id string) error {
	contentPath := filepath.Join(fs.queueDir, "data", id)

	if err := os.Remove(contentPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete content file: %w", err)
	}

	return nil
}

// Cleanup removes old messages based on retention policy
func (fs *FileStorageBackend) Cleanup(retentionHours int) (int, error) {
	if retentionHours <= 0 {
		return 0, fmt.Errorf("retention hours must be positive")
	}

	cutoffTime := time.Now().Add(-time.Duration(retentionHours) * time.Hour)
	deletedCount := 0

	// Check all queue types
	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	for _, queueType := range queueTypes {
		messages, err := fs.List(queueType)
		if err != nil {
			continue // Skip on error
		}

		for _, msg := range messages {
			// Check creation time vs cutoff
			if msg.CreatedAt.Before(cutoffTime) {
				if err := fs.Delete(msg.ID); err == nil {
					deletedCount++
				}
				// Also delete content
				fs.DeleteContent(msg.ID)
			}
		}
	}

	return deletedCount, nil
}

// EnsureDirectories creates necessary queue directories
func (fs *FileStorageBackend) EnsureDirectories() error {
	// Create base directory
	if err := os.MkdirAll(fs.queueDir, 0755); err != nil {
		return fmt.Errorf("failed to create base queue directory: %w", err)
	}

	// Create queue subdirectories
	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	for _, qType := range queueTypes {
		qDir := filepath.Join(fs.queueDir, string(qType))
		if err := os.MkdirAll(qDir, 0755); err != nil {
			return fmt.Errorf("failed to create queue directory %s: %w", qDir, err)
		}
	}

	// Create data directory for message contents
	dataDir := filepath.Join(fs.queueDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Create temporary directory for staging
	tmpDir := filepath.Join(fs.queueDir, "tmp")
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create tmp directory: %w", err)
	}

	return nil
}
