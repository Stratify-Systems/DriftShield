package tests

import (
	"strings"
	"testing"

	"github.com/SuryaTK2007/DriftShield/internal/display"
)

func TestGetPortDescription(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		fromPort int32
		toPort   int32
		expected string
	}{
		{"All traffic (-1)", "-1", 0, 0, "All Traffic"},
		{"All traffic (all)", "all", 0, 0, "All Traffic"},
		{"All TCP ports", "tcp", 0, 65535, "All TCP Ports (0-65535)"},
		{"SSH known port", "tcp", 22, 22, "SSH (22)"},
		{"HTTP known port", "tcp", 80, 80, "HTTP (80)"},
		{"HTTPS known port", "tcp", 443, 443, "HTTPS (443)"},
		{"MySQL known port", "tcp", 3306, 3306, "MySQL (3306)"},
		{"PostgreSQL known port", "tcp", 5432, 5432, "PostgreSQL (5432)"},
		{"Unknown single port", "tcp", 8081, 8081, "TCP Port 8081"},
		{"Empty protocol single port", "", 9000, 9000, "TCP Port 9000"},
		{"UDP protocol single port", "udp", 53, 53, "DNS (53)"},
		{"Port range", "tcp", 8000, 9000, "TCP Ports 8000-9000"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := display.GetPortDescription(tc.protocol, tc.fromPort, tc.toPort)
			if got != tc.expected {
				t.Errorf("GetPortDescription(%q, %d, %d) = %q; want %q",
					tc.protocol, tc.fromPort, tc.toPort, got, tc.expected)
			}
		})
	}
}

func TestStatusPrefixes(t *testing.T) {
	prefixes := map[string]string{
		"OK":      display.OK(),
		"DRIFT":   display.DRIFT(),
		"NEW":     display.NEW(),
		"DELETED": display.DELETED(),
		"FIXED":   display.FIXED(),
		"FAILED":  display.FAILED(),
		"SKIP":    display.SKIP(),
		"INFO":    display.INFO(),
	}

	for name, prefix := range prefixes {
		if prefix == "" {
			t.Errorf("Prefix %s returned empty string", name)
		}
		if !strings.Contains(prefix, name) {
			t.Errorf("Prefix %s does not contain text %q: got %q", name, name, prefix)
		}
	}
}

func TestPrintBannerMuted(t *testing.T) {
	origMute := display.MuteBanner
	defer func() { display.MuteBanner = origMute }()

	display.MuteBanner = true
	// Should not panic or crash
	display.PrintBanner("Test Title")
}
