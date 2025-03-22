package queue

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Manager handles queue operations
type Manager struct {
	QueueDir string
}

// QueueType represents the type of queue
type QueueType string

const (
	// Active queue for messages ready to be delivered
	Active QueueType = "active"
	// Deferred queue for messages that will be retried later
	Deferred QueueType = "deferred"
	// Hold queue for messages that are manually held
	Hold QueueType = "hold"
	// Failed queue for messages that failed delivery
	Failed QueueType = "failed"
)

// Message represents an email message in the queue
type Message struct {
	ID        string
	QueueType QueueType
	FilePath  string
	From      string
	To        []string
	Subject   string
	Size      int64
}

// NewManager creates a new queue manager
func NewManager(queueDir string) *Manager {
	return &Manager{
		QueueDir: queueDir,
	}
}

// ListMessages lists all messages in the specified queue
func (m *Manager) ListMessages(queueType QueueType) ([]Message, error) {
	queuePath := filepath.Join(m.QueueDir, string(queueType))

	// Check if the directory exists
	if _, err := os.Stat(queuePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("queue directory %s does not exist", queuePath)
	}

	// Get all files in the queue directory
	files, err := ioutil.ReadDir(queuePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read queue directory: %v", err)
	}

	var messages []Message
	for _, file := range files {
		// Skip directories and non-.eml files
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".eml") {
			continue
		}

		// Get the message ID from the filename
		msgID := strings.TrimSuffix(strings.TrimPrefix(file.Name(), "msg-"), ".eml")

		// Read the message file to extract headers
		filePath := filepath.Join(queuePath, file.Name())
		msg, err := m.readMessageHeaders(filePath, msgID, queueType)
		if err != nil {
			log.Printf("Warning: Failed to read message %s: %v", filePath, err)
			continue
		}

		messages = append(messages, msg)
	}

	return messages, nil
}

// readMessageHeaders reads the headers from a message file
func (m *Manager) readMessageHeaders(filePath, msgID string, queueType QueueType) (Message, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return Message{}, fmt.Errorf("failed to read message file: %v", err)
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return Message{}, fmt.Errorf("failed to get file info: %v", err)
	}

	// Create a basic message
	msg := Message{
		ID:        msgID,
		QueueType: queueType,
		FilePath:  filePath,
		Size:      fileInfo.Size(),
	}

	// Parse headers from the data
	lines := strings.Split(string(data), "\n")
	inHeaders := true

	for _, line := range lines {
		// Empty line means end of headers
		if inHeaders && line == "" {
			inHeaders = false
			continue
		}

		if inHeaders {
			// Parse header lines
			if strings.HasPrefix(line, "From:") {
				msg.From = strings.TrimSpace(line[5:])
			} else if strings.HasPrefix(line, "To:") {
				to := strings.TrimSpace(line[3:])
				msg.To = []string{to}
			} else if strings.HasPrefix(line, "Subject:") {
				msg.Subject = strings.TrimSpace(line[8:])
			}
		}
	}

	return msg, nil
}

// GetAllMessages lists all messages across all queue types
func (m *Manager) GetAllMessages() ([]Message, error) {
	var allMessages []Message

	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	for _, qType := range queueTypes {
		messages, err := m.ListMessages(qType)
		if err != nil {
			log.Printf("Warning: Failed to list %s queue: %v", qType, err)
			continue
		}

		allMessages = append(allMessages, messages...)
	}

	return allMessages, nil
}

// GetMessage gets a single message by ID
func (m *Manager) GetMessage(id string) (Message, error) {
	// Check all queue types
	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	for _, qType := range queueTypes {
		queuePath := filepath.Join(m.QueueDir, string(qType))
		filePath := filepath.Join(queuePath, fmt.Sprintf("msg-%s.eml", id))

		if _, err := os.Stat(filePath); err == nil {
			// File exists, read it
			return m.readMessageHeaders(filePath, id, qType)
		}
	}

	return Message{}, fmt.Errorf("message %s not found in any queue", id)
}

// ShowMessage returns the full content of a message
func (m *Manager) ShowMessage(id string) (string, error) {
	// Find the message in any queue
	msg, err := m.GetMessage(id)
	if err != nil {
		return "", err
	}

	// Read the full message content
	data, err := ioutil.ReadFile(msg.FilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read message file: %v", err)
	}

	return string(data), nil
}

// DeleteMessage removes a message from the queue
func (m *Manager) DeleteMessage(id string) error {
	// Find the message in any queue
	msg, err := m.GetMessage(id)
	if err != nil {
		return err
	}

	// Delete the file
	if err := os.Remove(msg.FilePath); err != nil {
		return fmt.Errorf("failed to delete message file: %v", err)
	}

	return nil
}

// FlushQueue removes all messages from the specified queue
func (m *Manager) FlushQueue(queueType QueueType) error {
	queuePath := filepath.Join(m.QueueDir, string(queueType))

	// Check if the directory exists
	if _, err := os.Stat(queuePath); os.IsNotExist(err) {
		return fmt.Errorf("queue directory %s does not exist", queuePath)
	}

	// Get all files in the queue directory
	files, err := ioutil.ReadDir(queuePath)
	if err != nil {
		return fmt.Errorf("failed to read queue directory: %v", err)
	}

	// Delete all .eml files
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".eml") {
			filePath := filepath.Join(queuePath, file.Name())
			if err := os.Remove(filePath); err != nil {
				log.Printf("Warning: Failed to delete %s: %v", filePath, err)
			}
		}
	}

	return nil
}

// FlushAllQueues removes all messages from all queues
func (m *Manager) FlushAllQueues() error {
	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	for _, qType := range queueTypes {
		if err := m.FlushQueue(qType); err != nil {
			log.Printf("Warning: Failed to flush %s queue: %v", qType, err)
		}
	}

	return nil
}

// GetQueueStats returns statistics about the queues
func (m *Manager) GetQueueStats() (map[string]int, error) {
	stats := make(map[string]int)

	queueTypes := []QueueType{Active, Deferred, Hold, Failed}
	for _, qType := range queueTypes {
		messages, err := m.ListMessages(qType)
		if err != nil {
			stats[string(qType)] = 0
			continue
		}

		stats[string(qType)] = len(messages)
	}

	return stats, nil
}
