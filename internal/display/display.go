// Package display provides CLI output formatting utilities.
package display

import (
	"fmt"
	"strings"

	"github.com/SuryaTK2007/DriftShield/internal/config"
)

// PortServices maps well-known ports to service names.
var PortServices = map[int32]string{
	22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
	445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
	995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
	3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
	5439: "Redshift", 5900: "VNC", 6379: "Redis",
	8080: "HTTP-Alt", 8443: "HTTPS-Alt",
	9200: "Elasticsearch", 27017: "MongoDB",
}

// PrintBanner prints a formatted banner with the given title.
func PrintBanner(title string) {
	fmt.Println()
	fmt.Println("+" + strings.Repeat("-", 58) + "+")
	fmt.Printf("|%-58s|\n", "")
	fmt.Printf("|  %-56s|\n", "DRIFTSHIELD - "+title)
	fmt.Printf("|  %-56s|\n", "Version "+config.Version)
	fmt.Printf("|%-58s|\n", "")
	fmt.Println("+" + strings.Repeat("-", 58) + "+")
	fmt.Println()
}

// GetPortDescription returns a human-readable description for a port range.
func GetPortDescription(protocol string, fromPort, toPort int32) string {
	if protocol == "-1" || protocol == "all" {
		return "All Traffic"
	}

	proto := strings.ToUpper(protocol)
	if proto == "" {
		proto = "TCP"
	}

	if fromPort == 0 && toPort == 65535 {
		return fmt.Sprintf("All %s Ports (0-65535)", proto)
	}

	if fromPort == toPort {
		if svc, ok := PortServices[fromPort]; ok {
			return fmt.Sprintf("%s (%d)", svc, fromPort)
		}
		return fmt.Sprintf("%s Port %d", proto, fromPort)
	}

	return fmt.Sprintf("%s Ports %d-%d", proto, fromPort, toPort)
}
