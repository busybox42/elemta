package plugin

// PluginInfo contains information about a plugin
type PluginInfo struct {
	Name        string
	Description string
	Version     string
	Type        string
	Author      string
}

// PluginTypes
const (
	PluginTypeAntivirus  = "antivirus"
	PluginTypeAntispam   = "antispam"
	PluginTypeCache      = "cache"
	PluginTypeQueue      = "queue"
	PluginTypeRule       = "rule"
	PluginTypeAuth       = "auth"       // Authentication plugins
	PluginTypeDKIM       = "dkim"       // DKIM signing/verification
	PluginTypeSPF        = "spf"        // SPF verification
	PluginTypeDMARC      = "dmarc"      // DMARC verification
	PluginTypeARC        = "arc"        // ARC signing/verification
	PluginTypeRateLimit  = "ratelimit"  // Rate limiting
	PluginTypeGreylist   = "greylist"   // Greylisting
	PluginTypeReputation = "reputation" // IP/domain reputation
	PluginTypeSecurity   = "security"   // Security plugins (rate limiting, greylisting, etc.)
	PluginTypeArchive    = "archive"    // Message archiving
	PluginTypeFilter     = "filter"     // Content filtering
	PluginTypeRouting    = "routing"    // Message routing
	PluginTypeMetrics    = "metrics"    // Metrics collection
)

// ProcessingStage defines when a plugin should be executed in the email processing pipeline
type ProcessingStage int

const (
	// Connection stages
	StageConnect ProcessingStage = iota
	StageHelo
	StageAuth

	// Envelope stages
	StageMailFrom
	StageRcptTo

	// Data stages
	StageDataBegin
	StageDataHeaders
	StageDataBody
	StageDataComplete

	// Post-processing stages
	StageQueued
	StagePreDelivery
	StagePostDelivery

	// Special stages
	StageDisconnect
	StageError
)

// PluginPriority defines the execution order of plugins within the same stage
type PluginPriority int

const (
	PriorityHighest PluginPriority = 100
	PriorityHigh    PluginPriority = 75
	PriorityNormal  PluginPriority = 50
	PriorityLow     PluginPriority = 25
	PriorityLowest  PluginPriority = 0
)

// RateLimitPlugin interface for rate limiting plugins
type RateLimitPlugin interface {
	Plugin
	SecurityHook
	ConnectionHook
	SMTPCommandHook
	MailTransactionHook
	MessageProcessingHook

	// Rate limiting specific methods
	GetMetrics() map[string]interface{}
	UpdateConfig(config map[string]interface{}) error
	AddToWhitelist(item string) error
	AddToBlacklist(item string) error
	RemoveFromWhitelist(item string) error
	RemoveFromBlacklist(item string) error
}

// PluginResult represents the result of a plugin execution
type PluginResult struct {
	Action      PluginAction
	Message     string
	Score       float64
	Annotations map[string]string
}

// PluginAction defines what action should be taken after plugin execution
type PluginAction int

const (
	ActionContinue   PluginAction = iota // Continue processing
	ActionReject                         // Reject the message
	ActionDiscard                        // Silently discard the message
	ActionQuarantine                     // Quarantine the message
	ActionDefer                          // Defer/retry later
	ActionModify                         // Modify the message and continue
)

// Plugin is the base interface that all plugins must implement
type Plugin interface {
	GetInfo() PluginInfo
	Init(config map[string]interface{}) error
	Close() error
}

// StagePlugin is an interface for plugins that can be executed at specific stages
type StagePlugin interface {
	Plugin
	GetStages() []ProcessingStage
	GetPriority() PluginPriority
}
