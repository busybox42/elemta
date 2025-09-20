package smtp

import (
	"context"
	"fmt"
)

// test_helpers.go contains functions that are only used for testing purposes

// HandleXDEBUGForTesting provides a way for tests to access the XDEBUG command handler
// This allows tests to directly call the XDEBUG command handler through the command handler
func HandleXDEBUGForTesting(session *Session, command string) error {
	if session.commandHandler == nil {
		return fmt.Errorf("command handler not initialized")
	}
	return session.commandHandler.HandleXDEBUG(context.Background(), command)
}
