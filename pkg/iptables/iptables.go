package iptables

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
)

// IPTablesManager manages iptables rules for raw socket TCP
type IPTablesManager struct {
	rules []string
	mu    sync.Mutex
}

// NewIPTablesManager creates a new iptables manager
func NewIPTablesManager() *IPTablesManager {
	return &IPTablesManager{
		rules: make([]string, 0),
	}
}

// CleanupStaleRulesForPort removes any leftover iptables rules from previous runs for a specific port
// This prevents rule accumulation from crashes or kill -9
// Should be called before adding new rules for the port
func CleanupStaleRulesForPort(port uint16) error {
	log.Printf("Cleaning up any stale iptables rules for port %d from previous runs...", port)
	
	// List all OUTPUT rules
	cmd := exec.Command("iptables", "-S", "OUTPUT")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to list iptables rules: %v", err)
	}
	
	lines := strings.Split(string(output), "\n")
	removedCount := 0
	
	for _, line := range lines {
		// Look for RST drop rules for this port
		// Match both sport and dport rules
		if strings.Contains(line, fmt.Sprintf("--sport %d", port)) ||
		   strings.Contains(line, fmt.Sprintf("--dport %d", port)) {
			if strings.Contains(line, "tcp-flags RST RST") && strings.Contains(line, "-j DROP") {
				// This is our rule, remove it
				// Convert from -S format to -D format
				// -A OUTPUT ... becomes -D OUTPUT ...
				ruleStr := strings.TrimPrefix(line, "-A ")
				if ruleStr == line {
					continue // Not an -A rule, skip
				}
				
				// Delete the rule
				args := []string{"-D"}
				args = append(args, strings.Split(ruleStr, " ")...)
				
				delCmd := exec.Command("iptables", args...)
				if err := delCmd.Run(); err != nil {
					log.Printf("Warning: failed to remove stale rule '%s': %v", line, err)
				} else {
					removedCount++
					log.Printf("Removed stale iptables rule: %s", line)
				}
			}
		}
	}
	
	if removedCount > 0 {
		log.Printf("Cleaned up %d stale iptables rule(s) for port %d", removedCount, port)
	} else {
		log.Printf("No stale iptables rules found for port %d", port)
	}
	
	return nil
}

// AddRuleForPort adds an iptables rule to drop RST packets for a specific port
// This is essential for raw socket TCP to work properly
func (m *IPTablesManager) AddRuleForPort(port uint16, isServer bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var rule string
	if isServer {
		// Server: drop RST packets sent by kernel for incoming connections on this port
		rule = fmt.Sprintf("OUTPUT -p tcp --tcp-flags RST RST --sport %d -j DROP", port)
	} else {
		// Client: drop RST packets sent by kernel for outgoing connections on this port
		rule = fmt.Sprintf("OUTPUT -p tcp --tcp-flags RST RST --sport %d -j DROP", port)
	}

	// Check if rule already exists
	if m.ruleExists(rule) {
		log.Printf("iptables rule already exists: %s", rule)
		return nil
	}

	// Add the rule
	args := strings.Split(rule, " ")
	args = append([]string{"-A"}, args...)
	
	cmd := exec.Command("iptables", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add iptables rule: %v, output: %s", err, output)
	}

	m.rules = append(m.rules, rule)
	log.Printf("Added iptables rule: iptables -A %s", rule)
	return nil
}

// AddRuleForConnection adds iptables rules for a specific connection (both directions)
func (m *IPTablesManager) AddRuleForConnection(localIP string, localPort uint16, remoteIP string, remotePort uint16, isServer bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var rules []string
	
	if isServer {
		// Server: drop RST for this specific connection
		rules = []string{
			fmt.Sprintf("OUTPUT -p tcp --tcp-flags RST RST -s %s --sport %d -d %s --dport %d -j DROP", 
				localIP, localPort, remoteIP, remotePort),
		}
	} else {
		// Client: drop RST for this specific connection
		rules = []string{
			fmt.Sprintf("OUTPUT -p tcp --tcp-flags RST RST -s %s --sport %d -d %s --dport %d -j DROP", 
				localIP, localPort, remoteIP, remotePort),
		}
	}

	for _, rule := range rules {
		// Check if rule already exists
		if m.ruleExists(rule) {
			log.Printf("iptables rule already exists: %s", rule)
			continue
		}

		// Add the rule
		args := strings.Split(rule, " ")
		args = append([]string{"-A"}, args...)
		
		cmd := exec.Command("iptables", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to add iptables rule: %v, output: %s", err, output)
		}

		m.rules = append(m.rules, rule)
		log.Printf("Added iptables rule: iptables -A %s", rule)
	}

	return nil
}

// RemoveAllRules removes all iptables rules added by this manager
func (m *IPTablesManager) RemoveAllRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errors []string
	
	for _, rule := range m.rules {
		args := strings.Split(rule, " ")
		args = append([]string{"-D"}, args...)
		
		cmd := exec.Command("iptables", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to remove rule '%s': %v, output: %s", rule, err, output))
			continue
		}
		
		log.Printf("Removed iptables rule: iptables -D %s", rule)
	}

	m.rules = make([]string, 0)

	if len(errors) > 0 {
		return fmt.Errorf("errors removing rules: %s", strings.Join(errors, "; "))
	}

	return nil
}

// ruleExists checks if an iptables rule already exists
func (m *IPTablesManager) ruleExists(rule string) bool {
	args := strings.Split(rule, " ")
	args = append([]string{"-C"}, args...)
	
	cmd := exec.Command("iptables", args...)
	err := cmd.Run()
	return err == nil
}

// GenerateRule generates an iptables rule string without adding it
func GenerateRule(port uint16, isServer bool) string {
	if isServer {
		return fmt.Sprintf("iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport %d -j DROP", port)
	}
	return fmt.Sprintf("iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport %d -j DROP", port)
}

// CheckIPTablesAvailable checks if iptables is available
func CheckIPTablesAvailable() error {
	cmd := exec.Command("iptables", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables not available: %v, output: %s", err, output)
	}
	return nil
}

// ClearAllRules removes all rules (static method for cleanup)
func ClearAllRules(port uint16) error {
	rules := []string{
		fmt.Sprintf("OUTPUT -p tcp --tcp-flags RST RST --sport %d -j DROP", port),
		fmt.Sprintf("OUTPUT -p tcp --tcp-flags RST RST --dport %d -j DROP", port),
	}

	var errors []string
	for _, rule := range rules {
		// Try to remove the rule (ignore errors if it doesn't exist)
		args := strings.Split(rule, " ")
		args = append([]string{"-D"}, args...)
		
		cmd := exec.Command("iptables", args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// Ignore "No chain/target/match by that name" errors
			if !strings.Contains(string(output), "No chain/target/match") {
				errors = append(errors, fmt.Sprintf("failed to remove rule '%s': %v", rule, err))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors clearing rules: %s", strings.Join(errors, "; "))
	}

	return nil
}

// MonitorAndReAdd monitors iptables and automatically re-adds rules if they are removed
func (m *IPTablesManager) MonitorAndReAdd(stopCh <-chan struct{}) {
	// This is a placeholder for future implementation
	// Can periodically check if rules still exist and re-add them if necessary
	<-stopCh
}

// GetRules returns all active rules managed by this manager
func (m *IPTablesManager) GetRules() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	rules := make([]string, len(m.rules))
	copy(rules, m.rules)
	return rules
}

// AddCustomRule adds a custom iptables rule
func (m *IPTablesManager) AddCustomRule(rule string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.ruleExists(rule) {
		return nil
	}

	args := strings.Split(rule, " ")
	args = append([]string{"-A"}, args...)
	
	cmd := exec.Command("iptables", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add custom rule: %v, output: %s", err, output)
	}

	m.rules = append(m.rules, rule)
	return nil
}
