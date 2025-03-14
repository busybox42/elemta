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
	PluginTypeAntivirus = "antivirus"
	PluginTypeAntispam  = "antispam"
	PluginTypeCache     = "cache"
	PluginTypeQueue     = "queue"
	PluginTypeRule      = "rule"
)
