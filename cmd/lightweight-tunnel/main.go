package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/openbmx/lightweight-tunnel/internal/config"
	"github.com/openbmx/lightweight-tunnel/pkg/tunnel"
)

var (
	version                  = "1.0.0"
	defaultServiceConfigPath = "/etc/lightweight-tunnel/config.json"
	serviceDir               = "/etc/systemd/system"
)

const systemdUnitTemplate = `[Unit]
Description=Lightweight Tunnel Service (%q)
After=network-online.target
Wants=network-online.target

[Service]
# Root privileges are required to create and manage TUN devices
Type=simple
ExecStart=%s -c %s
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=read-only
ProtectSystem=full

[Install]
WantedBy=multi-user.target
`

type commandRunner func(name string, args ...string) ([]byte, error)

func main() {
	// Command line flags
	configFile := flag.String("c", "", "Configuration file path")
	mode := flag.String("m", "server", "Mode: server or client")
	localAddr := flag.String("l", "0.0.0.0:9000", "Local address to listen on")
	remoteAddr := flag.String("r", "", "Remote address to connect to (client mode)")
	tunnelAddr := flag.String("t", "10.0.0.1/24", "Tunnel IP address and netmask")
	mtu := flag.Int("mtu", 1400, "MTU size")
	fecData := flag.Int("fec-data", 10, "FEC data shards")
	fecParity := flag.Int("fec-parity", 3, "FEC parity shards")
	sendQueueSize := flag.Int("send-queue", 1000, "Send queue buffer size")
	recvQueueSize := flag.Int("recv-queue", 1000, "Receive queue buffer size")
	multiClient := flag.Bool("multi-client", true, "Enable multi-client support (server mode)")
	maxClients := flag.Int("max-clients", 100, "Maximum number of concurrent clients (server mode)")
	clientIsolation := flag.Bool("client-isolation", false, "Enable client isolation mode (clients cannot communicate with each other)")
	p2pEnabled := flag.Bool("p2p", true, "Enable P2P direct connections")
	p2pPort := flag.Int("p2p-port", 0, "UDP port for P2P connections (0 = auto)")
	enableMeshRouting := flag.Bool("mesh-routing", true, "Enable mesh routing through other clients")
	maxHops := flag.Int("max-hops", 3, "Maximum hops for mesh routing")
	routeUpdateInterval := flag.Int("route-update", 30, "Route quality check interval in seconds")
	tunName := flag.String("tun", "", "TUN device name (empty = auto assign)")
	advertisedRoutes := flag.String("routes", "", "Comma-separated CIDR ranges that should be reachable through this node (forwarded to peers via server)")
	showVersion := flag.Bool("v", false, "Show version")
	generateConfig := flag.String("g", "", "Generate example config file")
	serviceAction := flag.String("service", "", "Manage systemd service: install|uninstall|start|stop|restart|status")
	serviceName := flag.String("service-name", "lightweight-tunnel", "Systemd service name")
	serviceConfig := flag.String("service-config", defaultServiceConfigPath, "Config file to bind with the system service (defaults to /etc/lightweight-tunnel/config.json)")
	tlsEnabled := flag.Bool("tls", false, "Enable TLS encryption")
	tlsCertFile := flag.String("tls-cert", "", "TLS certificate file (server mode)")
	tlsKeyFile := flag.String("tls-key", "", "TLS private key file (server mode)")
	tlsSkipVerify := flag.Bool("tls-skip-verify", false, "Skip TLS certificate verification (client mode, insecure)")
	key := flag.String("k", "", "Encryption key for tunnel traffic (required for secure communication)")

	flag.Parse()

	// Show version
	if *showVersion {
		fmt.Printf("lightweight-tunnel version %s\n", version)
		return
	}

	// Generate config file
	if *generateConfig != "" {
		if err := generateConfigFile(*generateConfig); err != nil {
			log.Fatalf("Failed to generate config: %v", err)
		}
		fmt.Printf("Generated config file: %s\n", *generateConfig)
		return
	}

	// Manage system service
	if *serviceAction != "" {
		targetConfig := *configFile
		if targetConfig == "" {
			targetConfig = *serviceConfig
		}

		if targetConfig == "" {
			log.Fatalf("Service config not provided. Use -c or -service-config to specify the config file.")
		}

		if err := manageService(*serviceAction, *serviceName, targetConfig); err != nil {
			log.Fatalf("Service action failed: %v", err)
		}
		return
	}

	// Load configuration
	var cfg *config.Config
	var err error

	if *configFile != "" {
		cfg, err = config.LoadConfig(*configFile)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	} else {
		// Use command line arguments
		cfg = &config.Config{
			Mode:                *mode,
			LocalAddr:           *localAddr,
			RemoteAddr:          *remoteAddr,
			TunnelAddr:          *tunnelAddr,
			MTU:                 *mtu,
			FECDataShards:       *fecData,
			FECParityShards:     *fecParity,
			Timeout:             30,
			KeepaliveInterval:   10,
			SendQueueSize:       *sendQueueSize,
			RecvQueueSize:       *recvQueueSize,
			TunName:             *tunName,
			AdvertisedRoutes:    splitAndCleanList(*advertisedRoutes),
			Key:                 *key,
			TLSEnabled:          *tlsEnabled,
			TLSCertFile:         *tlsCertFile,
			TLSKeyFile:          *tlsKeyFile,
			TLSSkipVerify:       *tlsSkipVerify,
			MultiClient:         *multiClient,
			MaxClients:          *maxClients,
			ClientIsolation:     *clientIsolation,
			P2PEnabled:          *p2pEnabled,
			P2PPort:             *p2pPort,
			EnableMeshRouting:   *enableMeshRouting,
			MaxHops:             *maxHops,
			RouteUpdateInterval: *routeUpdateInterval,
			P2PTimeout:          5,
		}
	}

	// Validate configuration
	if err := validateConfig(cfg); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Print configuration
	log.Println("=== Lightweight Tunnel ===")
	log.Printf("Version: %s", version)
	log.Printf("Mode: %s", cfg.Mode)
	log.Printf("Local Address: %s", cfg.LocalAddr)
	if cfg.Mode == "client" {
		log.Printf("Remote Address: %s", cfg.RemoteAddr)
	}
	log.Printf("Tunnel Address: %s", cfg.TunnelAddr)
	log.Printf("MTU: %d", cfg.MTU)
	log.Printf("FEC: %d data + %d parity shards", cfg.FECDataShards, cfg.FECParityShards)
	log.Printf("Send Queue Size: %d", cfg.SendQueueSize)
	log.Printf("Receive Queue Size: %d", cfg.RecvQueueSize)
	if cfg.Mode == "server" {
		log.Printf("Multi-client: %v (max: %d)", cfg.MultiClient, cfg.MaxClients)
		log.Printf("Client Isolation: %v", cfg.ClientIsolation)
	}
	if cfg.Key != "" {
		log.Println("🔐  Encryption: Enabled (AES-256-GCM)")
	} else {
		log.Println("⚠️  WARNING: No encryption key set (-k) - traffic is NOT encrypted")
		log.Println("⚠️  Anyone can connect to this tunnel without authentication")
		log.Println("⚠️  Use -k <key> to enable encryption and prevent unauthorized access")
	}

	// Create tunnel
	tun, err := tunnel.NewTunnel(cfg)
	if err != nil {
		log.Fatalf("Failed to create tunnel: %v", err)
	}

	// Start tunnel
	if err := tun.Start(); err != nil {
		log.Fatalf("Failed to start tunnel: %v", err)
	}

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	log.Println("Tunnel running. Press Ctrl+C to stop.")
	<-sigCh

	// Stop tunnel
	log.Println("Shutting down...")
	tun.Stop()
	log.Println("Shutdown complete")
}

func validateConfig(cfg *config.Config) error {
	if cfg.Mode != "server" && cfg.Mode != "client" {
		return fmt.Errorf("mode must be 'server' or 'client'")
	}

	if cfg.Mode == "client" && cfg.RemoteAddr == "" {
		return fmt.Errorf("remote address required in client mode")
	}

	if cfg.TunnelAddr == "" {
		return fmt.Errorf("tunnel address required")
	}

	if len(cfg.TunName) > 15 {
		return fmt.Errorf("TUN name too long (max 15 characters)")
	}

	if cfg.MTU < 500 || cfg.MTU > 9000 {
		return fmt.Errorf("MTU must be between 500 and 9000")
	}

	if cfg.FECDataShards < 1 || cfg.FECParityShards < 1 {
		return fmt.Errorf("FEC shards must be positive")
	}

	// TLS validation
	if cfg.TLSEnabled && cfg.Mode == "server" {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return fmt.Errorf("TLS enabled in server mode but certificate or key file not specified")
		}
	}

	return nil
}

func generateConfigFile(filename string) error {
	// Generate server config with all features
	serverCfg := config.DefaultConfig()
	serverCfg.Mode = "server"
	serverCfg.LocalAddr = "0.0.0.0:9000"
	serverCfg.TunnelAddr = "10.0.0.1/24"
	serverCfg.Key = "CHANGE-THIS-TO-YOUR-SECRET-KEY" // Example key
	serverCfg.AdvertisedRoutes = []string{}

	if err := config.SaveConfig(filename, serverCfg); err != nil {
		return err
	}

	// Generate client config example with all features
	clientFilename := filename + ".client"
	clientCfg := config.DefaultConfig()
	clientCfg.Mode = "client"
	clientCfg.RemoteAddr = "SERVER_IP:9000"
	clientCfg.TunnelAddr = "10.0.0.2/24"
	clientCfg.Key = "CHANGE-THIS-TO-YOUR-SECRET-KEY"        // Must match server key
	clientCfg.AdvertisedRoutes = []string{"192.168.1.0/24"} // Example: expose local LAN via tunnel

	if err := config.SaveConfig(clientFilename, clientCfg); err != nil {
		return err
	}

	fmt.Printf("Also generated client config example: %s\n", clientFilename)
	return nil
}

func manageService(action, serviceName, configPath string) error {
	return manageServiceWithRunner(action, serviceName, configPath, serviceDir, defaultCommandRunner)
}

func splitAndCleanList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	clean := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			clean = append(clean, p)
		}
	}
	if len(clean) == 0 {
		return nil
	}
	return clean
}

func manageServiceWithRunner(action, serviceName, configPath, dir string, runner commandRunner) error {
	if runner == nil {
		runner = defaultCommandRunner
	}

	if serviceName == "" {
		return fmt.Errorf("service name is required")
	}

	unitName := normalizeServiceName(serviceName)
	unitFile := filepath.Join(dir, unitName)

	switch action {
	case "install":
		if configPath == "" {
			return fmt.Errorf("config file path is required for install")
		}

		absConfig, err := filepath.Abs(configPath)
		if err != nil {
			return fmt.Errorf("failed to resolve config path: %w", err)
		}

		if _, err := os.Stat(absConfig); err != nil {
			return fmt.Errorf("config file not found: %w", err)
		}

		binPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to locate binary: %w", err)
		}
		quotedBin := strconv.Quote(binPath)
		quotedConfig := strconv.Quote(absConfig)

		unitContent := fmt.Sprintf(systemdUnitTemplate, serviceName, quotedBin, quotedConfig)

		if err := os.WriteFile(unitFile, []byte(unitContent), 0640); err != nil {
			return fmt.Errorf("failed to write service file: %w", err)
		}

		commands := [][]string{
			{"systemctl", "daemon-reload"},
			{"systemctl", "enable", unitName},
			{"systemctl", "start", unitName},
		}
		return runCommands(runner, commands)

	case "uninstall":
		logSystemctlWarning(runner, "stop", unitName)
		logSystemctlWarning(runner, "disable", unitName)
		if err := os.Remove(unitFile); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove service file: %w", err)
		}
		_, err := runner("systemctl", "daemon-reload")
		return err

	case "start", "stop", "restart", "status":
		out, err := runner("systemctl", action, unitName)
		if err != nil {
			return fmt.Errorf("systemctl %s failed: %v: %s", action, err, string(out))
		}
		if len(out) > 0 {
			fmt.Print(string(out))
		}
		return nil
	default:
		return fmt.Errorf("unknown service action: %s", action)
	}
}

func normalizeServiceName(name string) string {
	if strings.HasSuffix(name, ".service") {
		return name
	}
	return name + ".service"
}

func runCommands(runner commandRunner, commands [][]string) error {
	for _, cmd := range commands {
		out, err := runner(cmd[0], cmd[1:]...)
		if err != nil {
			return fmt.Errorf("%s %s failed: %v (output: %s)", cmd[0], strings.Join(cmd[1:], " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func logSystemctlWarning(runner commandRunner, action, unitName string) {
	if out, err := runner("systemctl", action, unitName); err != nil {
		log.Printf("Warning: systemctl %s %s failed: %v (output: %s)", action, unitName, err, strings.TrimSpace(string(out)))
	}
}

func defaultCommandRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}
