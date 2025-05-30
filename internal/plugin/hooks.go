package plugin

import (
	"context"
	"net"
	"time"
)

// HookContext provides comprehensive context for plugin execution
type HookContext struct {
	Context    context.Context
	MessageID  string
	SessionID  string
	RemoteAddr net.Addr
	LocalAddr  net.Addr
	Timestamp  time.Time
	Phase      ProcessingStage
	Data       map[string]interface{} // Shared data between plugins
}

// NewHookContext creates a new hook context
func NewHookContext(ctx context.Context, sessionID, messageID string, remoteAddr, localAddr net.Addr, phase ProcessingStage) *HookContext {
	return &HookContext{
		Context:    ctx,
		MessageID:  messageID,
		SessionID:  sessionID,
		RemoteAddr: remoteAddr,
		LocalAddr:  localAddr,
		Timestamp:  time.Now(),
		Phase:      phase,
		Data:       make(map[string]interface{}),
	}
}

// Set stores data in the hook context
func (hc *HookContext) Set(key string, value interface{}) {
	hc.Data[key] = value
}

// Get retrieves data from the hook context
func (hc *HookContext) Get(key string) (interface{}, bool) {
	value, exists := hc.Data[key]
	return value, exists
}

// ConnectionHook is called when a new connection is established
type ConnectionHook interface {
	OnConnect(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error)
	OnDisconnect(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error)
}

// SMTPCommandHook is called for SMTP command processing
type SMTPCommandHook interface {
	OnHelo(ctx *HookContext, hostname string) (*PluginResult, error)
	OnEhlo(ctx *HookContext, hostname string) (*PluginResult, error)
	OnAuth(ctx *HookContext, mechanism, username string) (*PluginResult, error)
	OnStartTLS(ctx *HookContext) (*PluginResult, error)
}

// MailTransactionHook is called during mail transaction processing
type MailTransactionHook interface {
	OnMailFrom(ctx *HookContext, sender string, params map[string]string) (*PluginResult, error)
	OnRcptTo(ctx *HookContext, recipient string, params map[string]string) (*PluginResult, error)
	OnData(ctx *HookContext) (*PluginResult, error)
}

// MessageProcessingHook is called during message content processing
type MessageProcessingHook interface {
	OnHeaders(ctx *HookContext, headers map[string][]string) (*PluginResult, error)
	OnBody(ctx *HookContext, body []byte) (*PluginResult, error)
	OnMessageComplete(ctx *HookContext, rawMessage []byte) (*PluginResult, error)
}

// QueueHook is called during queue operations
type QueueHook interface {
	OnEnqueue(ctx *HookContext, queueID string) (*PluginResult, error)
	OnDequeue(ctx *HookContext, queueID string) (*PluginResult, error)
	OnQueueRetry(ctx *HookContext, queueID string, attempt int) (*PluginResult, error)
}

// DeliveryHook is called during message delivery
type DeliveryHook interface {
	OnPreDelivery(ctx *HookContext, recipient string) (*PluginResult, error)
	OnDeliveryAttempt(ctx *HookContext, recipient string, attempt int) (*PluginResult, error)
	OnDeliverySuccess(ctx *HookContext, recipient string) (*PluginResult, error)
	OnDeliveryFailure(ctx *HookContext, recipient string, err error) (*PluginResult, error)
}

// SecurityHook is called for security-related events
type SecurityHook interface {
	OnRateLimitCheck(ctx *HookContext, remoteAddr net.Addr) (*PluginResult, error)
	OnGreylistCheck(ctx *HookContext, sender, recipient string, remoteAddr net.Addr) (*PluginResult, error)
	OnReputationCheck(ctx *HookContext, remoteAddr net.Addr, domain string) (*PluginResult, error)
}

// ContentFilterHook is called for content filtering
type ContentFilterHook interface {
	OnAntivirusScan(ctx *HookContext, content []byte) (*PluginResult, error)
	OnAntispamScan(ctx *HookContext, content []byte) (*PluginResult, error)
	OnContentFilter(ctx *HookContext, content []byte) (*PluginResult, error)
}

// AuthenticationHook is called for email authentication
type AuthenticationHook interface {
	OnSPFCheck(ctx *HookContext, sender string, remoteAddr net.IP) (*PluginResult, error)
	OnDKIMVerify(ctx *HookContext, content []byte) (*PluginResult, error)
	OnDMARCCheck(ctx *HookContext, sender string, spfResult, dkimResult string) (*PluginResult, error)
}

// MetricsHook is called for metrics collection
type MetricsHook interface {
	OnMetricsCollect(ctx *HookContext, event string, data map[string]interface{}) error
}

// ErrorHook is called when errors occur
type ErrorHook interface {
	OnError(ctx *HookContext, err error, phase ProcessingStage) (*PluginResult, error)
	OnRecovery(ctx *HookContext, recovered interface{}, phase ProcessingStage) (*PluginResult, error)
}

// HookRegistry manages all registered hooks
type HookRegistry struct {
	connectionHooks     []ConnectionHook
	commandHooks        []SMTPCommandHook
	transactionHooks    []MailTransactionHook
	processingHooks     []MessageProcessingHook
	queueHooks          []QueueHook
	deliveryHooks       []DeliveryHook
	securityHooks       []SecurityHook
	contentFilterHooks  []ContentFilterHook
	authenticationHooks []AuthenticationHook
	metricsHooks        []MetricsHook
	errorHooks          []ErrorHook
}

// NewHookRegistry creates a new hook registry
func NewHookRegistry() *HookRegistry {
	return &HookRegistry{
		connectionHooks:     make([]ConnectionHook, 0),
		commandHooks:        make([]SMTPCommandHook, 0),
		transactionHooks:    make([]MailTransactionHook, 0),
		processingHooks:     make([]MessageProcessingHook, 0),
		queueHooks:          make([]QueueHook, 0),
		deliveryHooks:       make([]DeliveryHook, 0),
		securityHooks:       make([]SecurityHook, 0),
		contentFilterHooks:  make([]ContentFilterHook, 0),
		authenticationHooks: make([]AuthenticationHook, 0),
		metricsHooks:        make([]MetricsHook, 0),
		errorHooks:          make([]ErrorHook, 0),
	}
}

// RegisterConnectionHook registers a connection hook
func (hr *HookRegistry) RegisterConnectionHook(hook ConnectionHook) {
	hr.connectionHooks = append(hr.connectionHooks, hook)
}

// RegisterCommandHook registers a command hook
func (hr *HookRegistry) RegisterCommandHook(hook SMTPCommandHook) {
	hr.commandHooks = append(hr.commandHooks, hook)
}

// RegisterTransactionHook registers a transaction hook
func (hr *HookRegistry) RegisterTransactionHook(hook MailTransactionHook) {
	hr.transactionHooks = append(hr.transactionHooks, hook)
}

// RegisterProcessingHook registers a processing hook
func (hr *HookRegistry) RegisterProcessingHook(hook MessageProcessingHook) {
	hr.processingHooks = append(hr.processingHooks, hook)
}

// RegisterQueueHook registers a queue hook
func (hr *HookRegistry) RegisterQueueHook(hook QueueHook) {
	hr.queueHooks = append(hr.queueHooks, hook)
}

// RegisterDeliveryHook registers a delivery hook
func (hr *HookRegistry) RegisterDeliveryHook(hook DeliveryHook) {
	hr.deliveryHooks = append(hr.deliveryHooks, hook)
}

// RegisterSecurityHook registers a security hook
func (hr *HookRegistry) RegisterSecurityHook(hook SecurityHook) {
	hr.securityHooks = append(hr.securityHooks, hook)
}

// RegisterContentFilterHook registers a content filter hook
func (hr *HookRegistry) RegisterContentFilterHook(hook ContentFilterHook) {
	hr.contentFilterHooks = append(hr.contentFilterHooks, hook)
}

// RegisterAuthenticationHook registers an authentication hook
func (hr *HookRegistry) RegisterAuthenticationHook(hook AuthenticationHook) {
	hr.authenticationHooks = append(hr.authenticationHooks, hook)
}

// RegisterMetricsHook registers a metrics hook
func (hr *HookRegistry) RegisterMetricsHook(hook MetricsHook) {
	hr.metricsHooks = append(hr.metricsHooks, hook)
}

// RegisterErrorHook registers an error hook
func (hr *HookRegistry) RegisterErrorHook(hook ErrorHook) {
	hr.errorHooks = append(hr.errorHooks, hook)
}

// GetConnectionHooks returns all connection hooks
func (hr *HookRegistry) GetConnectionHooks() []ConnectionHook {
	return hr.connectionHooks
}

// GetCommandHooks returns all command hooks
func (hr *HookRegistry) GetCommandHooks() []SMTPCommandHook {
	return hr.commandHooks
}

// GetTransactionHooks returns all transaction hooks
func (hr *HookRegistry) GetTransactionHooks() []MailTransactionHook {
	return hr.transactionHooks
}

// GetProcessingHooks returns all processing hooks
func (hr *HookRegistry) GetProcessingHooks() []MessageProcessingHook {
	return hr.processingHooks
}

// GetQueueHooks returns all queue hooks
func (hr *HookRegistry) GetQueueHooks() []QueueHook {
	return hr.queueHooks
}

// GetDeliveryHooks returns all delivery hooks
func (hr *HookRegistry) GetDeliveryHooks() []DeliveryHook {
	return hr.deliveryHooks
}

// GetSecurityHooks returns all security hooks
func (hr *HookRegistry) GetSecurityHooks() []SecurityHook {
	return hr.securityHooks
}

// GetContentFilterHooks returns all content filter hooks
func (hr *HookRegistry) GetContentFilterHooks() []ContentFilterHook {
	return hr.contentFilterHooks
}

// GetAuthenticationHooks returns all authentication hooks
func (hr *HookRegistry) GetAuthenticationHooks() []AuthenticationHook {
	return hr.authenticationHooks
}

// GetMetricsHooks returns all metrics hooks
func (hr *HookRegistry) GetMetricsHooks() []MetricsHook {
	return hr.metricsHooks
}

// GetErrorHooks returns all error hooks
func (hr *HookRegistry) GetErrorHooks() []ErrorHook {
	return hr.errorHooks
}
