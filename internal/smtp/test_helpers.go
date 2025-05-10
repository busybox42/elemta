package smtp

// test_helpers.go contains functions that are only used for testing purposes

// HandleXDEBUGForTesting provides a way for tests to access the private handleXDEBUG method
// This allows tests to directly call the XDEBUG command handler without having to
// go through the normal SMTP command processing flow
func HandleXDEBUGForTesting(session *Session, command string) {
	session.handleXDEBUG(command)
}
