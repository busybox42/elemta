package smtp

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDSNInEHLO tests that DSN is advertised in EHLO response
func TestDSNInEHLO(t *testing.T) {
	config := createTestConfig(t)
	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start() }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n') // greeting

	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)

	var responses []string
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		responses = append(responses, line)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	allResponses := strings.Join(responses, "")
	assert.Contains(t, allResponses, "DSN", "EHLO should advertise DSN")
}

// TestREQUIRETLSNotInEHLOWithoutTLS tests that REQUIRETLS is NOT advertised without TLS
func TestREQUIRETLSNotInEHLOWithoutTLS(t *testing.T) {
	config := createTestConfig(t)
	server, err := NewServer(config)
	require.NoError(t, err)
	defer func() { _ = server.Close() }()

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Start() }()
	time.Sleep(100 * time.Millisecond)

	conn, err := net.Dial("tcp", server.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n') // greeting

	_, err = conn.Write([]byte("EHLO test.example.com\r\n"))
	require.NoError(t, err)

	var responses []string
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		responses = append(responses, line)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	allResponses := strings.Join(responses, "")
	assert.NotContains(t, allResponses, "REQUIRETLS",
		"REQUIRETLS should NOT be advertised without active TLS")
}

// TestDSNMailFromRETFull tests MAIL FROM with RET=FULL
func TestDSNMailFromRETFull(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	addr, _, err := ch.parseMailFrom(ctx, "FROM:<user@example.com> RET=FULL")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", addr)

	dsnParams := state.GetDSNParams()
	require.NotNil(t, dsnParams)
	assert.Equal(t, DSNReturnFull, dsnParams.Return)
}

// TestDSNMailFromRETHdrs tests MAIL FROM with RET=HDRS
func TestDSNMailFromRETHdrs(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	addr, _, err := ch.parseMailFrom(ctx, "FROM:<user@example.com> RET=HDRS")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", addr)

	dsnParams := state.GetDSNParams()
	require.NotNil(t, dsnParams)
	assert.Equal(t, DSNReturnHeaders, dsnParams.Return)
}

// TestDSNMailFromRETInvalid tests MAIL FROM with invalid RET value
func TestDSNMailFromRETInvalid(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	_, _, err := ch.parseMailFrom(ctx, "FROM:<user@example.com> RET=INVALID")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "501")
	assert.Contains(t, err.Error(), "RET")
}

// TestDSNMailFromENVID tests MAIL FROM with ENVID parameter
func TestDSNMailFromENVID(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	addr, _, err := ch.parseMailFrom(ctx, "FROM:<user@example.com> ENVID=abc123")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", addr)

	dsnParams := state.GetDSNParams()
	require.NotNil(t, dsnParams)
	assert.Equal(t, "abc123", dsnParams.EnvID)
}

// TestDSNMailFromENVIDTooLong tests MAIL FROM with ENVID exceeding max length
func TestDSNMailFromENVIDTooLong(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	longEnvID := strings.Repeat("x", 101)
	_, _, err := ch.parseMailFrom(ctx, "FROM:<user@example.com> ENVID="+longEnvID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "501")
	assert.Contains(t, err.Error(), "ENVID")
}

// TestDSNMailFromCombinedParams tests MAIL FROM with multiple DSN params
func TestDSNMailFromCombinedParams(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	addr, size, err := ch.parseMailFrom(ctx, "FROM:<user@example.com> SIZE=5000 RET=FULL ENVID=test-env-123")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", addr)
	assert.Equal(t, int64(5000), size)

	dsnParams := state.GetDSNParams()
	require.NotNil(t, dsnParams)
	assert.Equal(t, DSNReturnFull, dsnParams.Return)
	assert.Equal(t, "test-env-123", dsnParams.EnvID)
}

// TestDSNRcptToNOTIFYSuccess tests RCPT TO with NOTIFY=SUCCESS
func TestDSNRcptToNOTIFYSuccess(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	addr, err := ch.parseRcptTo(ctx, "TO:<user@example.com> NOTIFY=SUCCESS")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", addr)

	rcptParams := state.GetAllDSNRecipientParams()
	require.NotNil(t, rcptParams)
	require.Contains(t, rcptParams, "user@example.com")
	assert.Contains(t, rcptParams["user@example.com"].Notify, DSNNotifySuccess)
}

// TestDSNRcptToNOTIFYNever tests RCPT TO with NOTIFY=NEVER
func TestDSNRcptToNOTIFYNever(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	addr, err := ch.parseRcptTo(ctx, "TO:<user@example.com> NOTIFY=NEVER")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", addr)

	rcptParams := state.GetAllDSNRecipientParams()
	require.NotNil(t, rcptParams)
	assert.Contains(t, rcptParams["user@example.com"].Notify, DSNNotifyNever)
}

// TestDSNRcptToNOTIFYNeverCombined tests that NOTIFY=NEVER,SUCCESS is rejected
func TestDSNRcptToNOTIFYNeverCombined(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	_, err := ch.parseRcptTo(ctx, "TO:<user@example.com> NOTIFY=NEVER,SUCCESS")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "501")
	assert.Contains(t, err.Error(), "NEVER")
}

// TestDSNRcptToNOTIFYMultiple tests RCPT TO with NOTIFY=SUCCESS,FAILURE,DELAY
func TestDSNRcptToNOTIFYMultiple(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	addr, err := ch.parseRcptTo(ctx, "TO:<user@example.com> NOTIFY=SUCCESS,FAILURE,DELAY")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", addr)

	rcptParams := state.GetAllDSNRecipientParams()
	require.NotNil(t, rcptParams)
	params := rcptParams["user@example.com"]
	assert.Len(t, params.Notify, 3)
	assert.Contains(t, params.Notify, DSNNotifySuccess)
	assert.Contains(t, params.Notify, DSNNotifyFailure)
	assert.Contains(t, params.Notify, DSNNotifyDelay)
}

// TestDSNRcptToORCPT tests RCPT TO with ORCPT parameter
func TestDSNRcptToORCPT(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	addr, err := ch.parseRcptTo(ctx, "TO:<user@example.com> ORCPT=rfc822;orig@example.com")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", addr)

	rcptParams := state.GetAllDSNRecipientParams()
	require.NotNil(t, rcptParams)
	assert.Equal(t, "rfc822;orig@example.com", rcptParams["user@example.com"].ORCPT)
}

// TestDSNRcptToInvalidNOTIFY tests RCPT TO with invalid NOTIFY value
func TestDSNRcptToInvalidNOTIFY(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	_, err := ch.parseRcptTo(ctx, "TO:<user@example.com> NOTIFY=INVALID")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "501")
}

// TestDSNRSETClearsState tests that RSET clears DSN state
func TestDSNRSETClearsState(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	state := NewSessionState(logger)

	// Set some DSN state
	state.SetDSNParams(ctx, &DSNParams{Return: DSNReturnFull, EnvID: "test123"})
	state.SetDSNRecipientParams(ctx, "user@example.com", &DSNRecipientParams{
		Notify: []DSNNotifyType{DSNNotifySuccess},
		ORCPT:  "rfc822;orig@example.com",
	})
	state.SetRequireTLS(ctx, true)

	// Verify state is set
	assert.NotNil(t, state.GetDSNParams())
	assert.NotNil(t, state.GetAllDSNRecipientParams())
	assert.True(t, state.IsRequireTLS())

	// Reset
	state.Reset(ctx)

	// Verify state is cleared
	assert.Nil(t, state.GetDSNParams())
	assert.Nil(t, state.GetAllDSNRecipientParams())
	assert.False(t, state.IsRequireTLS())
}

// TestREQUIRETLSWithoutTLS tests that REQUIRETLS in MAIL FROM fails without TLS
func TestREQUIRETLSWithoutTLS(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	// TLS is not active by default
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	_, _, err := ch.parseMailFrom(ctx, "FROM:<user@example.com> REQUIRETLS")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "530")
	assert.Contains(t, err.Error(), "5.7.4")
}

// TestREQUIRETLSWithTLS tests that REQUIRETLS in MAIL FROM succeeds with TLS
func TestREQUIRETLSWithTLS(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	// Simulate TLS being active
	state.SetTLSActive(ctx, true)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	addr, _, err := ch.parseMailFrom(ctx, "FROM:<user@example.com> REQUIRETLS")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", addr)
	assert.True(t, state.IsRequireTLS())
}

// TestDSNRcptToCombinedParams tests RCPT TO with both NOTIFY and ORCPT
func TestDSNRcptToCombinedParams(t *testing.T) {
	ctx := context.Background()
	config := createTestConfig(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	session := &Session{config: config, logger: logger, sessionID: "test", remoteAddr: "127.0.0.1:12345"}
	state := NewSessionState(logger)
	ch := NewCommandHandler(session, state, nil, nil, config, nil, logger)

	addr, err := ch.parseRcptTo(ctx, "TO:<user@example.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;orig@example.com")
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", addr)

	rcptParams := state.GetAllDSNRecipientParams()
	require.NotNil(t, rcptParams)
	params := rcptParams["user@example.com"]
	assert.Len(t, params.Notify, 2)
	assert.Contains(t, params.Notify, DSNNotifySuccess)
	assert.Contains(t, params.Notify, DSNNotifyFailure)
	assert.Equal(t, "rfc822;orig@example.com", params.ORCPT)
}
