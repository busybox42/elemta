package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

// Plugin message types
type PluginMessage struct {
	Type      string      `json:"type"`
	ID        string      `json:"id"`
	Command   string      `json:"command,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// Plugin input/output structures (must match the main server definitions)
type SecurePluginInput struct {
	MessageID  string                 `json:"message_id"`
	From       string                 `json:"from"`
	To         []string               `json:"to"`
	Subject    string                 `json:"subject"`
	Headers    map[string]string      `json:"headers"`
	Body       []byte                 `json:"body"`
	Metadata   map[string]interface{} `json:"metadata"`
	Timestamp  time.Time              `json:"timestamp"`
	RemoteAddr string                 `json:"remote_addr"`
	TLSEnabled bool                   `json:"tls_enabled"`
}

type SecurePluginOutput struct {
	Action       string                 `json:"action"`
	Score        float64                `json:"score"`
	Message      string                 `json:"message"`
	Headers      map[string]string      `json:"headers"`
	ModifiedBody []byte                 `json:"modified_body,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
	Errors       []string               `json:"errors,omitempty"`
	Warnings     []string               `json:"warnings,omitempty"`
}

// ExampleAntivirusPlugin represents our secure antivirus plugin
type ExampleAntivirusPlugin struct {
	initialized    bool
	virusPatterns  []*regexp.Regexp
	scanCount      int64
	detectionCount int64
}

// NewExampleAntivirusPlugin creates a new antivirus plugin instance
func NewExampleAntivirusPlugin() *ExampleAntivirusPlugin {
	return &ExampleAntivirusPlugin{
		virusPatterns: []*regexp.Regexp{
			// Example virus signatures (in reality, these would be more sophisticated)
			regexp.MustCompile(`(?i)X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*`), // EICAR test
			regexp.MustCompile(`(?i)malware_signature_example`),
			regexp.MustCompile(`(?i)virus_test_pattern`),
			regexp.MustCompile(`(?i)trojan_horse_signature`),
		},
	}
}

// Initialize initializes the plugin with configuration
func (p *ExampleAntivirusPlugin) Initialize(config map[string]interface{}) error {
	log.Printf("Initializing example antivirus plugin with config: %+v", config)

	// Plugin-specific initialization
	p.initialized = true

	log.Printf("Example antivirus plugin initialized successfully")
	return nil
}

// ProcessMessage processes a message for virus scanning
func (p *ExampleAntivirusPlugin) ProcessMessage(ctx context.Context, input *SecurePluginInput) (*SecurePluginOutput, error) {
	if !p.initialized {
		return nil, fmt.Errorf("plugin not initialized")
	}

	p.scanCount++

	log.Printf("Scanning message %s from %s", input.MessageID, input.From)

	// Simulate virus scanning with timeout protection
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Continue with scanning
	}

	// Scan message body for virus patterns
	virusFound, virusName := p.scanForViruses(input.Body)

	// Scan subject for suspicious patterns
	suspiciousSubject := p.scanSubject(input.Subject)

	output := &SecurePluginOutput{
		Headers:  make(map[string]string),
		Metadata: make(map[string]interface{}),
	}

	// Add scan result headers
	output.Headers["X-Antivirus-Scanned"] = "Yes (Example-AV)"
	output.Headers["X-Antivirus-Engine"] = "Example-AV-1.0.0"

	if virusFound {
		p.detectionCount++

		log.Printf("VIRUS DETECTED in message %s: %s", input.MessageID, virusName)

		output.Action = "reject"
		output.Score = 100.0
		output.Message = fmt.Sprintf("Virus detected: %s", virusName)
		output.Headers["X-Antivirus-Status"] = "Infected"
		output.Headers["X-Antivirus-Threat"] = virusName
		output.Metadata["threat_detected"] = true
		output.Metadata["threat_name"] = virusName
		output.Metadata["scan_time"] = time.Now()

	} else if suspiciousSubject {
		log.Printf("SUSPICIOUS subject in message %s: %s", input.MessageID, input.Subject)

		output.Action = "continue"
		output.Score = 25.0
		output.Message = "Suspicious subject detected"
		output.Headers["X-Antivirus-Status"] = "Suspicious"
		output.Warnings = []string{"Suspicious subject pattern detected"}
		output.Metadata["suspicious_subject"] = true

	} else {
		log.Printf("Message %s is clean", input.MessageID)

		output.Action = "continue"
		output.Score = 0.0
		output.Message = "No threats detected"
		output.Headers["X-Antivirus-Status"] = "Clean"
		output.Metadata["threat_detected"] = false
	}

	// Add scan statistics
	output.Metadata["scan_count"] = p.scanCount
	output.Metadata["detection_count"] = p.detectionCount

	return output, nil
}

// HealthCheck performs a health check
func (p *ExampleAntivirusPlugin) HealthCheck(ctx context.Context) error {
	if !p.initialized {
		return fmt.Errorf("plugin not initialized")
	}

	// Perform basic health checks
	if len(p.virusPatterns) == 0 {
		return fmt.Errorf("no virus patterns loaded")
	}

	log.Printf("Health check passed - %d patterns loaded, %d scans performed, %d detections",
		len(p.virusPatterns), p.scanCount, p.detectionCount)

	return nil
}

// Shutdown shuts down the plugin gracefully
func (p *ExampleAntivirusPlugin) Shutdown() error {
	log.Printf("Shutting down example antivirus plugin - scanned %d messages, detected %d threats",
		p.scanCount, p.detectionCount)

	p.initialized = false
	return nil
}

// scanForViruses scans message body for virus patterns
func (p *ExampleAntivirusPlugin) scanForViruses(body []byte) (bool, string) {
	bodyStr := string(body)

	for i, pattern := range p.virusPatterns {
		if pattern.MatchString(bodyStr) {
			return true, fmt.Sprintf("Virus.Pattern.%d", i+1)
		}
	}

	return false, ""
}

// scanSubject scans email subject for suspicious patterns
func (p *ExampleAntivirusPlugin) scanSubject(subject string) bool {
	suspiciousPatterns := []string{
		"urgent", "winner", "lottery", "congratulations",
		"click here", "act now", "limited time", "free money",
	}

	lowerSubject := strings.ToLower(subject)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerSubject, pattern) {
			return true
		}
	}

	return false
}

// Plugin communication handler
func main() {
	plugin := NewExampleAntivirusPlugin()

	// Set up JSON communication
	encoder := json.NewEncoder(os.Stdout)
	scanner := bufio.NewScanner(os.Stdin)

	// Send ready signal
	readyMsg := PluginMessage{
		Type:      "ready",
		Timestamp: time.Now(),
	}

	if err := encoder.Encode(readyMsg); err != nil {
		log.Fatalf("Failed to send ready message: %v", err)
	}

	log.Printf("Example antivirus plugin started and ready")

	// Main communication loop
	for scanner.Scan() {
		var message PluginMessage
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			log.Printf("Failed to decode message: %v", err)
			continue
		}

		response := PluginMessage{
			Type:      "response",
			ID:        message.ID,
			Timestamp: time.Now(),
		}

		switch message.Type {
		case "command":
			err := handleCommand(plugin, message.Command, message.Data)
			if err != nil {
				response.Error = err.Error()
			}

		case "process_message":
			output, err := handleProcessMessage(plugin, message.Data)
			if err != nil {
				response.Error = err.Error()
			} else {
				response.Data = output
			}

		case "health_check":
			err := plugin.HealthCheck(context.Background())
			if err != nil {
				response.Error = err.Error()
			}

		default:
			response.Error = fmt.Sprintf("unknown message type: %s", message.Type)
		}

		if err := encoder.Encode(response); err != nil {
			log.Printf("Failed to send response: %v", err)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Scanner error: %v", err)
	}

	log.Printf("Example antivirus plugin shutting down")
}

// handleCommand handles plugin commands
func handleCommand(plugin *ExampleAntivirusPlugin, command string, data interface{}) error {
	switch command {
	case "initialize":
		config, ok := data.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid configuration data")
		}
		return plugin.Initialize(config)

	case "shutdown":
		return plugin.Shutdown()

	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

// handleProcessMessage handles message processing
func handleProcessMessage(plugin *ExampleAntivirusPlugin, data interface{}) (*SecurePluginOutput, error) {
	// Convert data to SecurePluginInput
	inputData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input data: %w", err)
	}

	var input SecurePluginInput
	if err := json.Unmarshal(inputData, &input); err != nil {
		return nil, fmt.Errorf("failed to unmarshal input: %w", err)
	}

	// Process the message with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return plugin.ProcessMessage(ctx, &input)
}
