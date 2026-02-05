package smtp

import (
	"net"
	"testing"
)

func TestParseNetwork(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{
			name:    "valid IPv4 CIDR",
			cidr:    "192.168.1.0/24",
			wantErr: false,
		},
		{
			name:    "valid IPv6 CIDR",
			cidr:    "2001:db8::/32",
			wantErr: false,
		},
		{
			name:    "invalid CIDR - no prefix",
			cidr:    "192.168.1.0",
			wantErr: true,
		},
		{
			name:    "invalid CIDR - bad format",
			cidr:    "not-a-cidr",
			wantErr: true,
		},
		{
			name:    "invalid CIDR - bad prefix",
			cidr:    "192.168.1.0/99",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, err := parseNetwork(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseNetwork(%q) error = %v, wantErr %v", tt.cidr, err, tt.wantErr)
				return
			}
			if !tt.wantErr && network == nil {
				t.Errorf("parseNetwork(%q) returned nil network without error", tt.cidr)
			}
		})
	}
}

func TestInitPrivateNetworks(t *testing.T) {
	networks, err := initPrivateNetworks()
	if err != nil {
		t.Fatalf("initPrivateNetworks() failed: %v", err)
	}

	if len(networks) != 8 {
		t.Errorf("Expected 8 private networks, got %d", len(networks))
	}

	// Verify some expected networks are present
	expectedCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
	}

	for _, cidr := range expectedCIDRs {
		found := false
		_, expectedNet, _ := net.ParseCIDR(cidr)
		for _, network := range networks {
			if network.String() == expectedNet.String() {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected network %s not found in initialized networks", cidr)
		}
	}
}

func TestIsPrivateNetwork(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"IPv4 private Class A", "10.0.0.1", true},
		{"IPv4 private Class B", "172.16.0.1", true},
		{"IPv4 private Class C", "192.168.1.1", true},
		{"IPv4 loopback", "127.0.0.1", true},
		{"IPv4 link-local", "169.254.1.1", true},
		{"IPv4 public", "8.8.8.8", false},
		{"IPv6 loopback", "::1", true},
		{"IPv6 unique local", "fc00::1", true},
		{"IPv6 link-local", "fe80::1", true},
		{"IPv6 public", "2001:4860:4860::8888", false},
		{"nil IP", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip net.IP
			if tt.ip != "" {
				ip = net.ParseIP(tt.ip)
			}
			result := IsPrivateNetwork(ip)
			if result != tt.expected {
				t.Errorf("IsPrivateNetwork(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsAllowedRelay(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		allowedRelays []string
		expected      bool
	}{
		{
			name:          "exact IP match",
			ip:            "203.0.113.1",
			allowedRelays: []string{"203.0.113.1"},
			expected:      true,
		},
		{
			name:          "CIDR match",
			ip:            "203.0.113.5",
			allowedRelays: []string{"203.0.113.0/24"},
			expected:      true,
		},
		{
			name:          "invalid CIDR skipped, private network allowed",
			ip:            "10.0.0.1",
			allowedRelays: []string{"invalid-cidr"},
			expected:      true, // Private network still allowed
		},
		{
			name:          "public IP not in allowed list",
			ip:            "8.8.8.8",
			allowedRelays: []string{},
			expected:      false,
		},
		{
			name:          "private network always allowed",
			ip:            "192.168.1.1",
			allowedRelays: []string{},
			expected:      true,
		},
		{
			name:          "nil IP",
			ip:            "",
			allowedRelays: []string{"203.0.113.0/24"},
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip net.IP
			if tt.ip != "" {
				ip = net.ParseIP(tt.ip)
			}
			result := IsAllowedRelay(ip, tt.allowedRelays)
			if result != tt.expected {
				t.Errorf("IsAllowedRelay(%s, %v) = %v, want %v", tt.ip, tt.allowedRelays, result, tt.expected)
			}
		})
	}
}

func TestIsAllowedRelayAddr(t *testing.T) {
	tests := []struct {
		name          string
		addr          string
		allowedRelays []string
		expected      bool
	}{
		{
			name:          "IP with port",
			addr:          "10.0.0.1:25",
			allowedRelays: []string{},
			expected:      true, // Private network
		},
		{
			name:          "IP without port",
			addr:          "203.0.113.1",
			allowedRelays: []string{"203.0.113.1"},
			expected:      true,
		},
		{
			name:          "invalid address",
			addr:          "not-an-ip",
			allowedRelays: []string{},
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAllowedRelayAddr(tt.addr, tt.allowedRelays)
			if result != tt.expected {
				t.Errorf("IsAllowedRelayAddr(%s, %v) = %v, want %v", tt.addr, tt.allowedRelays, result, tt.expected)
			}
		})
	}
}
