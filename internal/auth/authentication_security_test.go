package auth

import (
	"log/slog"
	"os"
	"testing"
	"time"
)

// TestSessionStateMachineSecurity tests the security features of the session state machine
func TestSessionStateMachineSecurity(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Test 1: Session state machine creation and basic security
	t.Run("SessionStateMachineCreation", func(t *testing.T) {
		ssm, err := NewSessionStateMachine(nil, "192.168.1.1:1234", "test-client", logger)
		if err != nil {
			t.Fatalf("Failed to create session state machine: %v", err)
		}

		// Verify initial state
		if ssm.GetCurrentState() != SessionStateInitial {
			t.Errorf("Expected initial state, got %v", ssm.GetCurrentState())
		}

		// Verify session ID is generated
		sessionID := ssm.GetSessionID()
		if sessionID == "" {
			t.Error("Session ID should not be empty")
		}

		// Verify session is not expired
		if ssm.IsExpired() {
			t.Error("New session should not be expired")
		}

		// Verify session is not locked
		if ssm.IsLockedOut() {
			t.Error("New session should not be locked")
		}
	})

	// Test 2: State transition validation
	t.Run("StateTransitionValidation", func(t *testing.T) {
		ssm, err := NewSessionStateMachine(nil, "192.168.1.1:1234", "test-client", logger)
		if err != nil {
			t.Fatalf("Failed to create session state machine: %v", err)
		}

		// Test valid transition: Initial -> Authenticating
		if err := ssm.TransitionTo(SessionStateAuthenticating, "test"); err != nil {
			t.Errorf("Valid transition should succeed: %v", err)
		}

		// Test invalid transition: Authenticating -> Initial
		if err := ssm.TransitionTo(SessionStateInitial, "test"); err == nil {
			t.Error("Invalid transition should fail")
		}

		// Test invalid transition: Authenticating -> Authenticated (without username)
		if err := ssm.TransitionTo(SessionStateAuthenticated, "test"); err == nil {
			t.Error("Transition to authenticated without username should fail")
		}
	})

	// Test 3: Session fixation protection
	t.Run("SessionFixationProtection", func(t *testing.T) {
		ssm, err := NewSessionStateMachine(nil, "192.168.1.1:1234", "test-client", logger)
		if err != nil {
			t.Fatalf("Failed to create session state machine: %v", err)
		}

		originalSessionID := ssm.GetSessionID()

		// Regenerate session ID
		if err := ssm.RegenerateSessionID(); err != nil {
			t.Errorf("Failed to regenerate session ID: %v", err)
		}

		newSessionID := ssm.GetSessionID()
		if newSessionID == originalSessionID {
			t.Error("Session ID should be different after regeneration")
		}
	})

	// Test 4: Failure count and lockout
	t.Run("FailureCountAndLockout", func(t *testing.T) {
		config := &SessionStateMachineConfig{
			MaxAge:            30 * time.Minute,
			MaxFailures:       3,
			LockoutDuration:   1 * time.Minute,
			MaxStateHistory:   10,
		}

		ssm, err := NewSessionStateMachine(config, "192.168.1.1:1234", "test-client", logger)
		if err != nil {
			t.Fatalf("Failed to create session state machine: %v", err)
		}

		// Transition to authenticating
		if err := ssm.TransitionTo(SessionStateAuthenticating, "test"); err != nil {
			t.Fatalf("Failed to transition to authenticating: %v", err)
		}

		// Simulate multiple failures
		for i := 0; i < 3; i++ {
			if err := ssm.TransitionTo(SessionStateFailed, "auth_failed"); err != nil {
				t.Errorf("Failed to transition to failed state: %v", err)
			}
			// Transition back to authenticating for next attempt
			if i < 2 {
				if err := ssm.TransitionTo(SessionStateAuthenticating, "retry"); err != nil {
					t.Errorf("Failed to transition back to authenticating: %v", err)
				}
			}
		}

		// Should now be locked
		if !ssm.IsLockedOut() {
			t.Error("Session should be locked after max failures")
		}

		// Try to transition to authenticated (should fail)
		if err := ssm.TransitionTo(SessionStateAuthenticated, "test"); err == nil {
			t.Error("Should not be able to transition to authenticated when locked")
		}
	})

	// Test 5: Session expiration
	t.Run("SessionExpiration", func(t *testing.T) {
		config := &SessionStateMachineConfig{
			MaxAge:            100 * time.Millisecond, // Very short expiration
			MaxFailures:       5,
			LockoutDuration:   1 * time.Minute,
			MaxStateHistory:   10,
		}

		ssm, err := NewSessionStateMachine(config, "192.168.1.1:1234", "test-client", logger)
		if err != nil {
			t.Fatalf("Failed to create session state machine: %v", err)
		}

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Should be expired
		if !ssm.IsExpired() {
			t.Error("Session should be expired")
		}

		// Try to transition (should fail)
		if err := ssm.TransitionTo(SessionStateAuthenticating, "test"); err == nil {
			t.Error("Should not be able to transition when expired")
		}
	})

	// Test 6: RBAC context
	t.Run("RBACContext", func(t *testing.T) {
		ssm, err := NewSessionStateMachine(nil, "192.168.1.1:1234", "test-client", logger)
		if err != nil {
			t.Fatalf("Failed to create session state machine: %v", err)
		}

		// Transition to authenticating first
		if err := ssm.TransitionTo(SessionStateAuthenticating, "test"); err != nil {
			t.Fatalf("Failed to transition to authenticating: %v", err)
		}

		// Set username (this should work in authenticating state)
		if err := ssm.SetUsername("testuser"); err != nil {
			t.Errorf("Failed to set username: %v", err)
		}

		// Now transition to authenticated
		if err := ssm.TransitionTo(SessionStateAuthenticated, "test"); err != nil {
			t.Fatalf("Failed to transition to authenticated: %v", err)
		}

		// Set RBAC context
		rbacContext := &RBACContext{
			Username:   "testuser",
			Roles:      []string{"user", "admin"},
			Permissions: []Permission{PermissionSMTPAuth, PermissionSMTPSend},
			LastCheck:  time.Now(),
		}

		if err := ssm.SetRBACContext(rbacContext); err != nil {
			t.Errorf("Failed to set RBAC context: %v", err)
		}

		// Check permissions
		if !ssm.HasPermission(PermissionSMTPAuth) {
			t.Error("Should have SMTP auth permission")
		}

		if !ssm.HasPermission(PermissionSMTPSend) {
			t.Error("Should have SMTP send permission")
		}

		if ssm.HasPermission(PermissionSystemAdmin) {
			t.Error("Should not have system admin permission")
		}
	})
}

// TestConstantTimeAuthentication tests constant-time authentication comparisons
func TestConstantTimeAuthentication(t *testing.T) {
	// Test 1: Constant-time string comparison
	t.Run("ConstantTimeStringComparison", func(t *testing.T) {
		// Test equal strings
		if !ConstantTimeStringCompare("test", "test") {
			t.Error("Equal strings should compare as equal")
		}

		// Test different strings
		if ConstantTimeStringCompare("test", "different") {
			t.Error("Different strings should not compare as equal")
		}

		// Test empty strings
		if !ConstantTimeStringCompare("", "") {
			t.Error("Empty strings should compare as equal")
		}

		// Test one empty string
		if ConstantTimeStringCompare("test", "") {
			t.Error("Non-empty and empty strings should not compare as equal")
		}
	})

	// Test 2: Secure password comparison
	t.Run("SecurePasswordComparison", func(t *testing.T) {
		// Test bcrypt comparison
		hashedPassword := "$2a$10$N9qo8uLOickgx2ZMRZoMye.IjdQjOj8Qj8Qj8Qj8Qj8Qj8Qj8Qj8Q"
		plainPassword := "testpassword"

		// This should not panic and should return an error (invalid hash)
		err := ComparePasswordsSecure(hashedPassword, plainPassword)
		if err == nil {
			t.Error("Invalid bcrypt hash should return error")
		}

		// Test SHA-1 comparison
		sha1Hash := "{SHA}qvTGHdzF6KLavt4PO0gs2a6pQ00=" // "hello" in SHA-1
		if err := ComparePasswordsSecure(sha1Hash, "hello"); err != nil {
			t.Errorf("Valid SHA-1 hash should succeed: %v", err)
		}

		if err := ComparePasswordsSecure(sha1Hash, "wrong"); err == nil {
			t.Error("Invalid password should fail")
		}

		// Test plain text comparison
		if err := ComparePasswordsSecure("test", "test"); err != nil {
			t.Errorf("Valid plain text should succeed: %v", err)
		}

		if err := ComparePasswordsSecure("test", "wrong"); err == nil {
			t.Error("Invalid plain text should fail")
		}
	})
}

// TestAuthenticationBypassPrevention tests that authentication bypasses are prevented
func TestAuthenticationBypassPrevention(t *testing.T) {
	// Test 1: Session state consistency
	t.Run("SessionStateConsistency", func(t *testing.T) {
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelError,
		}))

		ssm, err := NewSessionStateMachine(nil, "192.168.1.1:1234", "test-client", logger)
		if err != nil {
			t.Fatalf("Failed to create session state machine: %v", err)
		}

		// Test that we can't bypass authentication by directly setting state
		// (This would require access to private fields, which we can't do)
		// Instead, test that invalid transitions are rejected

		// Try to go directly from initial to authenticated (should fail)
		if err := ssm.TransitionTo(SessionStateAuthenticated, "bypass_attempt"); err == nil {
			t.Error("Should not be able to bypass authentication")
		}
	})

	// Test 2: Session invalidation
	t.Run("SessionInvalidation", func(t *testing.T) {
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelError,
		}))

		ssm, err := NewSessionStateMachine(nil, "192.168.1.1:1234", "test-client", logger)
		if err != nil {
			t.Fatalf("Failed to create session state machine: %v", err)
		}

		// Invalidate session
		if err := ssm.Invalidate("security_concern"); err != nil {
			t.Errorf("Failed to invalidate session: %v", err)
		}

		// Should not be able to transition from invalidated state
		if err := ssm.TransitionTo(SessionStateAuthenticating, "test"); err == nil {
			t.Error("Should not be able to transition from invalidated state")
		}
	})

	// Test 3: State history tracking
	t.Run("StateHistoryTracking", func(t *testing.T) {
		logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelError,
		}))

		ssm, err := NewSessionStateMachine(nil, "192.168.1.1:1234", "test-client", logger)
		if err != nil {
			t.Fatalf("Failed to create session state machine: %v", err)
		}

		// Make several transitions
		ssm.TransitionTo(SessionStateAuthenticating, "test1")
		ssm.TransitionTo(SessionStateFailed, "test2")
		ssm.TransitionTo(SessionStateAuthenticating, "test3")

		// Check state history
		history := ssm.GetStateHistory()
		if len(history) < 3 {
			t.Errorf("Expected at least 3 state transitions, got %d", len(history))
		}

		// Verify history contains expected transitions
		found := false
		for _, transition := range history {
			if transition.FromState == SessionStateInitial && transition.ToState == SessionStateAuthenticating {
				found = true
				break
			}
		}
		if !found {
			t.Error("State history should contain initial to authenticating transition")
		}
	})
}
