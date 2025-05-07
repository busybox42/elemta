// Package plugin provides plugin functionality for Elemta
package plugin

import (
	"github.com/busybox42/elemta/internal/message"
)

// ResultType is an alias for PluginAction to maintain compatibility
type ResultType = PluginAction

// Define constants compatible with the existing types
const (
	ResultPass   = ActionContinue
	ResultReject = ActionReject
	ResultHold   = ActionQuarantine
	ResultDrop   = ActionDiscard
)

// StageType is a string representation of the ProcessingStage
type StageType string

// Define string constants for stages
const (
	StagePreQueue  StageType = "pre_queue"  // Before message is queued
	StagePostQueue StageType = "post_queue" // After message is queued
	StageDelivery  StageType = "delivery"   // During message delivery
)

// Result represents the result of a plugin operation
// This version is expanded from PluginResult to maintain backward compatibility
type Result struct {
	Type    ResultType             // Result type (pass, reject, etc)
	Message string                 // Optional message or reason
	Error   error                  // Optional error
	Data    interface{}            // Optional additional data
	Headers map[string]string      // Headers to add to the message
	Tags    []string               // Tags to add to the message
	Scores  map[string]float64     // Scores to add to the message
	Actions map[string]interface{} // Actions to take
}

// NewResult creates a new plugin result
func NewResult(resultType ResultType, message string, err error) *Result {
	return &Result{
		Type:    resultType,
		Message: message,
		Error:   err,
		Headers: make(map[string]string),
		Tags:    make([]string, 0),
		Scores:  make(map[string]float64),
		Actions: make(map[string]interface{}),
	}
}

// HookRegistration represents a plugin hook registration
type HookRegistration struct {
	Name     string                                  // Name of the hook
	Stage    StageType                               // Stage at which the hook is executed
	Priority int                                     // Priority of the hook (lower values run first)
	Func     func(*message.Message) (*Result, error) // Hook function
}
