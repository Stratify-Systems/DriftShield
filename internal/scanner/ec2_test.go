package scanner

import (
	"testing"
)

func TestIsOpenCIDR(t *testing.T) {
	tests := []struct {
		cidr     string
		expected bool
	}{
		{"0.0.0.0/0", true},
		{"::/0", true},
		{"10.0.0.0/8", false},
		{"192.168.1.1/32", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.cidr, func(t *testing.T) {
			if got := isOpenCIDR(tc.cidr); got != tc.expected {
				t.Errorf("isOpenCIDR(%q) = %v; want %v", tc.cidr, got, tc.expected)
			}
		})
	}
}

func TestIsRiskyRule(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		fromPort int32
		toPort   int32
		expected bool
	}{
		{"All traffic", "-1", 0, 0, true},
		{"All ports TCP", "tcp", 0, 65535, true},
		{"SSH port", "tcp", 22, 22, true},
		{"RDP port", "tcp", 3389, 3389, true},
		{"MySQL port", "tcp", 3306, 3306, true},
		{"PostgreSQL port", "tcp", 5432, 5432, true},
		{"Range including SSH", "tcp", 20, 25, true},
		{"Safe HTTP port", "tcp", 80, 80, false},
		{"Safe HTTPS port", "tcp", 443, 443, false},
		{"Custom high port", "tcp", 8080, 8080, false},
		{"Range of safe ports", "tcp", 8000, 9000, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsRiskyRule(tc.protocol, tc.fromPort, tc.toPort); got != tc.expected {
				t.Errorf("IsRiskyRule(%q, %d, %d) = %v; want %v", tc.protocol, tc.fromPort, tc.toPort, got, tc.expected)
			}
		})
	}
}

func TestFormatRuleDescription(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		fromPort int32
		toPort   int32
		source   string
		expected string
	}{
		{"All traffic", "-1", 0, 0, "0.0.0.0/0", "All Traffic from 0.0.0.0/0"},
		{"All ports", "tcp", 0, 65535, "0.0.0.0/0", "All tcp Ports (0-65535) from 0.0.0.0/0"},
		{"Known risky port (SSH)", "tcp", 22, 22, "0.0.0.0/0", "SSH (22) from 0.0.0.0/0"},
		{"Known risky port (RDP)", "tcp", 3389, 3389, "::/0", "RDP (3389) from ::/0"},
		{"Unknown single port", "tcp", 80, 80, "0.0.0.0/0", "tcp Port 80 from 0.0.0.0/0"},
		{"Port range", "tcp", 8000, 9000, "10.0.0.0/8", "tcp Ports 8000-9000 from 10.0.0.0/8"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatRuleDescription(tc.protocol, tc.fromPort, tc.toPort, tc.source); got != tc.expected {
				t.Errorf("FormatRuleDescription(...) = %q; want %q", got, tc.expected)
			}
		})
	}
}
