package rule

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/elemta/elemta/internal/common"
	"github.com/elemta/elemta/internal/config"
)

// Phase represents a processing phase in the SMTP transaction
type Phase string

const (
	PhaseConnect  Phase = "connect"
	PhaseHelo     Phase = "helo"
	PhaseMailFrom Phase = "mailfrom"
	PhaseRcptTo   Phase = "rcptto"
	PhaseData     Phase = "data"
	PhaseQueue    Phase = "queue"
	PhaseDeliver  Phase = "deliver"
)

// Action represents an action to take after rule evaluation
type Action string

const (
	ActionAccept     Action = "accept"     // Accept the message and continue processing
	ActionReject     Action = "reject"     // Reject the message with an error
	ActionDiscard    Action = "discard"    // Silently discard the message
	ActionQuarantine Action = "quarantine" // Quarantine the message
	ActionModify     Action = "modify"     // Modify the message and continue processing
)

// Rule represents a rule to be evaluated
type Rule struct {
	Name        string            // Rule name
	Description string            // Rule description
	Phase       Phase             // Phase to run the rule in
	Script      string            // Script to run
	Enabled     bool              // Whether the rule is enabled
	Priority    int               // Rule priority (lower runs first)
	Metadata    map[string]string // Additional metadata
}

// Result represents the result of a rule evaluation
type Result struct {
	RuleName    string            // Name of the rule that produced this result
	Action      Action            // Action to take
	Message     string            // Message to return to the client
	Score       float64           // Score assigned by the rule
	Metadata    map[string]string // Additional metadata
	ElapsedTime time.Duration     // Time taken to evaluate the rule
}

// Context represents the context for rule evaluation
type Context struct {
	Session     *common.Session // SMTP session
	MessageData []byte          // Message data (only available in data phase)
	QueueID     string          // Queue ID (only available in queue phase)
	Results     []*Result       // Results from previous rules
}

// SetMetadata sets a metadata value in the session context
func (c *Context) SetMetadata(key string, value string) {
	if c.Session != nil && c.Session.Context != nil {
		c.Session.Context.Set(key, value)
	}
}

// GetMetadata gets a metadata value from the session context
func (c *Context) GetMetadata(key string) (string, bool) {
	if c.Session != nil && c.Session.Context != nil {
		value, ok := c.Session.Context.GetString(key)
		return value, ok
	}
	return "", false
}

// DeleteMetadata deletes a metadata value from the session context
func (c *Context) DeleteMetadata(key string) {
	if c.Session != nil && c.Session.Context != nil {
		c.Session.Context.Delete(key)
	}
}

// Engine represents the rule engine
type Engine struct {
	config      *config.Config
	rules       map[Phase][]*Rule
	scriptCache map[string]interface{} // Cache for compiled scripts
	mu          sync.RWMutex
}

// NewEngine creates a new rule engine
func NewEngine(cfg *config.Config) (*Engine, error) {
	engine := &Engine{
		config:      cfg,
		rules:       make(map[Phase][]*Rule),
		scriptCache: make(map[string]interface{}),
	}

	// Load rules
	if err := engine.LoadRules(); err != nil {
		return nil, err
	}

	return engine, nil
}

// LoadRules loads rules from the configured rules directory
func (e *Engine) LoadRules() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Clear existing rules
	e.rules = make(map[Phase][]*Rule)

	// Create rules directory if it doesn't exist
	if err := os.MkdirAll(e.config.Rules.Path, 0755); err != nil {
		return fmt.Errorf("failed to create rules directory: %w", err)
	}

	// Walk the rules directory
	err := filepath.Walk(e.config.Rules.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process .yaml files
		if filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml" {
			return nil
		}

		// Load rule
		rule, err := loadRuleFromFile(path)
		if err != nil {
			log.Printf("Failed to load rule from %s: %v", path, err)
			return nil
		}

		// Skip disabled rules
		if !rule.Enabled {
			return nil
		}

		// Add rule to the appropriate phase
		e.rules[rule.Phase] = append(e.rules[rule.Phase], rule)

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk rules directory: %w", err)
	}

	// Sort rules by priority
	for phase := range e.rules {
		sortRulesByPriority(e.rules[phase])
	}

	return nil
}

// loadRuleFromFile loads a rule from a file
func loadRuleFromFile(path string) (*Rule, error) {
	// This is a placeholder. In a real implementation, you would parse the YAML file
	// and return a Rule object.
	return &Rule{
		Name:        "example",
		Description: "Example rule",
		Phase:       PhaseConnect,
		Script:      "return true",
		Enabled:     true,
		Priority:    100,
		Metadata:    make(map[string]string),
	}, nil
}

// sortRulesByPriority sorts rules by priority
func sortRulesByPriority(rules []*Rule) {
	// Sort rules by priority (lower runs first)
	// This is a placeholder. In a real implementation, you would use sort.Slice.
}

// RunConnectRules runs rules for the connect phase
func (e *Engine) RunConnectRules(session *common.Session) error {
	ctx := &Context{
		Session: session,
	}
	return e.runRules(PhaseConnect, ctx)
}

// RunHeloRules runs rules for the HELO/EHLO phase
func (e *Engine) RunHeloRules(session *common.Session) error {
	ctx := &Context{
		Session: session,
	}
	return e.runRules(PhaseHelo, ctx)
}

// RunMailFromRules runs rules for the MAIL FROM phase
func (e *Engine) RunMailFromRules(session *common.Session) error {
	ctx := &Context{
		Session: session,
	}
	return e.runRules(PhaseMailFrom, ctx)
}

// RunRcptToRules runs rules for the RCPT TO phase
func (e *Engine) RunRcptToRules(session *common.Session) error {
	ctx := &Context{
		Session: session,
	}
	return e.runRules(PhaseRcptTo, ctx)
}

// RunDataRules runs rules for the DATA phase
func (e *Engine) RunDataRules(session *common.Session, data []byte) error {
	ctx := &Context{
		Session:     session,
		MessageData: data,
	}
	return e.runRules(PhaseData, ctx)
}

// RunQueueRules runs rules for the queue phase
func (e *Engine) RunQueueRules(session *common.Session, data []byte, queueID string) error {
	ctx := &Context{
		Session:     session,
		MessageData: data,
		QueueID:     queueID,
	}
	return e.runRules(PhaseQueue, ctx)
}

// RunDeliverRules runs rules for the deliver phase
func (e *Engine) RunDeliverRules(session *common.Session, data []byte, queueID string) error {
	ctx := &Context{
		Session:     session,
		MessageData: data,
		QueueID:     queueID,
	}
	return e.runRules(PhaseDeliver, ctx)
}

// runRules runs all rules for a given phase
func (e *Engine) runRules(phase Phase, ctx *Context) error {
	e.mu.RLock()
	rules := e.rules[phase]
	e.mu.RUnlock()

	for _, rule := range rules {
		result, err := e.evaluateRule(rule, ctx)
		if err != nil {
			log.Printf("Error evaluating rule %s: %v", rule.Name, err)
			continue
		}

		// Add result to context
		ctx.Results = append(ctx.Results, result)

		// Handle action
		switch result.Action {
		case ActionReject:
			return errors.New(result.Message)
		case ActionDiscard:
			// Silently discard
			return errors.New("message discarded")
		case ActionQuarantine:
			// Quarantine message
			// This is a placeholder. In a real implementation, you would quarantine the message.
		case ActionModify:
			// Modify message
			// This is a placeholder. In a real implementation, you would modify the message.
		case ActionAccept:
			// Continue processing
		}
	}

	return nil
}

// evaluateRule evaluates a single rule
func (e *Engine) evaluateRule(rule *Rule, ctx *Context) (*Result, error) {
	start := time.Now()

	// This is a placeholder. In a real implementation, you would compile and run the script.
	// For now, we'll just return a default result.
	result := &Result{
		RuleName:    rule.Name,
		Action:      ActionAccept,
		Message:     "",
		Score:       0,
		Metadata:    make(map[string]string),
		ElapsedTime: time.Since(start),
	}

	return result, nil
}

// AddRule adds a rule to the engine
func (e *Engine) AddRule(rule *Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Validate rule
	if rule.Name == "" {
		return errors.New("rule name cannot be empty")
	}
	if rule.Phase == "" {
		return errors.New("rule phase cannot be empty")
	}
	if rule.Script == "" {
		return errors.New("rule script cannot be empty")
	}

	// Add rule to the appropriate phase
	e.rules[rule.Phase] = append(e.rules[rule.Phase], rule)

	// Sort rules by priority
	sortRulesByPriority(e.rules[rule.Phase])

	return nil
}

// RemoveRule removes a rule from the engine
func (e *Engine) RemoveRule(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for phase := range e.rules {
		for i, rule := range e.rules[phase] {
			if rule.Name == name {
				// Remove rule
				e.rules[phase] = append(e.rules[phase][:i], e.rules[phase][i+1:]...)
				return nil
			}
		}
	}

	return fmt.Errorf("rule %s not found", name)
}

// GetRule gets a rule by name
func (e *Engine) GetRule(name string) (*Rule, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for phase := range e.rules {
		for _, rule := range e.rules[phase] {
			if rule.Name == name {
				return rule, nil
			}
		}
	}

	return nil, fmt.Errorf("rule %s not found", name)
}

// GetRules gets all rules for a given phase
func (e *Engine) GetRules(phase Phase) []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]*Rule, len(e.rules[phase]))
	copy(rules, e.rules[phase])
	return rules
}

// GetAllRules gets all rules
func (e *Engine) GetAllRules() map[Phase][]*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make(map[Phase][]*Rule)
	for phase, phaseRules := range e.rules {
		rules[phase] = make([]*Rule, len(phaseRules))
		copy(rules[phase], phaseRules)
	}
	return rules
}
