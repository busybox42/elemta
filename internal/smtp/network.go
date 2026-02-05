package smtp

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
)

// Private network ranges as defined in RFC 1918 and RFC 4193
var privateNetworks []*net.IPNet

func init() {
	networks, err := initPrivateNetworks()
	if err != nil {
		slog.Error("Failed to initialize private networks", "error", err)
		privateNetworks = []*net.IPNet{}
		return
	}
	privateNetworks = networks
}

func initPrivateNetworks() ([]*net.IPNet, error) {
	cidrs := []string{
		// IPv4 private networks
		"10.0.0.0/8",     // Class A private
		"172.16.0.0/12",  // Class B private
		"192.168.0.0/16", // Class C private
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local

		// IPv6 private networks
		"::1/128",   // IPv6 loopback
		"fc00::/7",  // IPv6 unique local addresses
		"fe80::/10", // IPv6 link-local
	}

	networks := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		network, err := parseNetwork(cidr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", cidr, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func parseNetwork(cidr string) (*net.IPNet, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation %q: %w", cidr, err)
	}
	return network, nil
}

// IsPrivateNetwork checks if an IP address is in a private network range
func IsPrivateNetwork(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check against all private network ranges
	for _, network := range privateNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// IsPrivateNetworkAddr checks if an address string represents a private network IP
func IsPrivateNetworkAddr(addr string) bool {
	// Extract IP from address (remove port if present)
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port, use the address as is
		host = addr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return IsPrivateNetwork(ip)
}

// IsInternalConnection checks if a connection is from an internal/private network
func IsInternalConnection(conn net.Conn) bool {
	if conn == nil {
		return false
	}

	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return false
	}

	return IsPrivateNetworkAddr(remoteAddr.String())
}

// GetClientIP extracts the client IP address from a connection
func GetClientIP(conn net.Conn) net.IP {
	if conn == nil {
		return nil
	}

	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return nil
	}

	switch addr := remoteAddr.(type) {
	case *net.TCPAddr:
		return addr.IP
	case *net.UDPAddr:
		return addr.IP
	default:
		// Try to parse the string representation
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			host = addr.String()
		}
		return net.ParseIP(host)
	}
}

// IsAllowedRelay checks if an IP is allowed to relay messages
// This includes both explicit allowed relays and internal networks
func IsAllowedRelay(ip net.IP, allowedRelays []string) bool {
	if ip == nil {
		return false
	}

	ipStr := ip.String()

	// Check explicit allowed relays first
	for _, relay := range allowedRelays {
		// Support both IP addresses and CIDR notation
		if strings.Contains(relay, "/") {
			// CIDR notation
			_, network, err := net.ParseCIDR(relay)
			if err != nil {
				slog.Warn("Invalid CIDR in allowed relays", "cidr", relay, "error", err)
				continue // Skip invalid instead of crashing
			}
			if network.Contains(ip) {
				return true
			}
		} else {
			// Direct IP comparison
			if relay == ipStr {
				return true
			}
		}
	}

	// Always allow internal/private networks
	return IsPrivateNetwork(ip)
}

// IsAllowedRelayAddr checks if an address string is allowed to relay
func IsAllowedRelayAddr(addr string, allowedRelays []string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		// Try to extract IP from host:port format
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return false
		}
		ip = net.ParseIP(host)
		if ip == nil {
			return false
		}
	}

	return IsAllowedRelay(ip, allowedRelays)
}
