package main

import (
	"github.com/busybox42/elemta/internal/plugin"
)

// Plugin is the exported plugin instance
// The internal RateLimiterPlugin already implements all required interfaces:
// - Plugin (GetInfo, Init, Close)
// - SecurityHook (OnRateLimitCheck, OnGreylistCheck, OnReputationCheck)
// - ConnectionHook (OnConnect, OnDisconnect)
// - SMTPCommandHook (OnHelo, OnEhlo, OnAuth, OnStartTLS)
// - MailTransactionHook (OnMailFrom, OnRcptTo, OnData)
// - MessageProcessingHook (OnHeaders, OnBody, OnMessageComplete)
var Plugin = plugin.NewRateLimiterPlugin()

// PluginInfo is required for the plugin system
var PluginInfo = &plugin.PluginInfo{
	Name:        "rate_limiter",
	Version:     "1.0.0",
	Description: "Enterprise-grade rate limiting with Valkey backend for distributed multinode deployment",
	Author:      "Elemta Team",
	Type:        plugin.PluginTypeRateLimit,
}
