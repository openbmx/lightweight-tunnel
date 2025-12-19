package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/openbmx/lightweight-tunnel/internal/config"
	"github.com/openbmx/lightweight-tunnel/pkg/tunnel"
)

var (
	version = "1.0.0"
)

func main() {
	// Command line flags
	configFile := flag.String("c", "", "Configuration file path")
	mode := flag.String("m", "server", "Mode: server or client")
	// Transport mode is now fixed to rawtcp only
	// transport flag removed - always use rawtcp mode for true TCP disguise
	localAddr := flag.String("l", "0.0.0.0:9000", "Local address to listen on")
	remoteAddr := flag.String("r", "", "Remote address to connect to (client mode)")
	tunnelAddr := flag.String("t", "10.0.0.1/24", "Tunnel IP address and netmask")
	mtu := flag.Int("mtu", 1400, "MTU size")
	fecData := flag.Int("fec-data", 10, "FEC data shards")
	fecParity := flag.Int("fec-parity", 3, "FEC parity shards")
	sendQueueSize := flag.Int("send-queue", 5000, "Send queue buffer size (increased default for better performance)")
	recvQueueSize := flag.Int("recv-queue", 5000, "Receive queue buffer size (increased default for better performance)")
	multiClient := flag.Bool("multi-client", true, "Enable multi-client support (server mode)")
	maxClients := flag.Int("max-clients", 100, "Maximum number of concurrent clients (server mode)")
	clientIsolation := flag.Bool("client-isolation", false, "Enable client isolation mode (clients cannot communicate with each other)")
	p2pEnabled := flag.Bool("p2p", true, "Enable P2P direct connections")
	p2pPort := flag.Int("p2p-port", 0, "UDP port for P2P connections (0 = auto)")
	enableMeshRouting := flag.Bool("mesh-routing", true, "Enable mesh routing through other clients")
	maxHops := flag.Int("max-hops", 3, "Maximum hops for mesh routing")
	routeUpdateInterval := flag.Int("route-update", 30, "Route quality check interval in seconds")
	enableNATDetection := flag.Bool("nat-detection", true, "Enable automatic NAT type detection")
	showVersion := flag.Bool("v", false, "Show version")
	generateConfig := flag.String("g", "", "Generate example config file")
	// TLS flags removed: TLS over the UDP fake-TCP transport is not supported.
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
			Mode:              *mode,
			Transport:         "rawtcp", // Fixed to rawtcp mode only
			LocalAddr:         *localAddr,
			RemoteAddr:        *remoteAddr,
			TunnelAddr:        *tunnelAddr,
			MTU:               *mtu,
			FECDataShards:     *fecData,
			FECParityShards:   *fecParity,
			Timeout:           30,
			KeepaliveInterval: 10,
			SendQueueSize:     *sendQueueSize,
			RecvQueueSize:     *recvQueueSize,
			Key:               *key,
			// TLS configuration is available via config file only; CLI flags were removed
			MultiClient:         *multiClient,
			MaxClients:          *maxClients,
			ClientIsolation:     *clientIsolation,
			P2PEnabled:          *p2pEnabled,
			P2PPort:             *p2pPort,
			EnableMeshRouting:   *enableMeshRouting,
			MaxHops:             *maxHops,
			RouteUpdateInterval: *routeUpdateInterval,
			EnableNATDetection:  *enableNATDetection,
			P2PTimeout:          5,
		}
	}

	// Normalize client tunnel address when running without explicit config file
	if err := normalizeTunnelAddr(cfg, *configFile != ""); err != nil {
		log.Fatalf("Failed to normalize tunnel address: %v", err)
	}

	// Validate configuration
	if err := validateConfig(cfg); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Print configuration
	log.Println("=== Lightweight Tunnel ===")
	log.Printf("Version: %s", version)
	log.Printf("Mode: %s", cfg.Mode)
	log.Printf("Transport: rawtcp (true TCP disguise)")
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

	if cfg.MTU < 500 || cfg.MTU > 9000 {
		return fmt.Errorf("MTU must be between 500 and 9000")
	}

	if cfg.FECDataShards < 1 || cfg.FECParityShards < 1 {
		return fmt.Errorf("FEC shards must be positive")
	}

	return nil
}

func generateConfigFile(filename string) error {
	// Generate minimalist server config with only essential parameters
	serverCfg := &config.Config{
		Mode:       "server",
		LocalAddr:  "0.0.0.0:9000",
		TunnelAddr: "10.0.0.1/24",
		Key:        "请修改为您的强密钥",
		MTU:        0, // 0 = auto-detect
	}

	if err := config.SaveConfig(filename, serverCfg); err != nil {
		return err
	}

	// Generate minimalist client config example with only essential parameters
	clientFilename := filename + ".client"
	clientCfg := &config.Config{
		Mode:       "client",
		RemoteAddr: "服务器IP:9000",
		TunnelAddr: "10.0.0.2/24",
		Key:        "请修改为您的强密钥",
		MTU:        0, // 0 = auto-detect
	}

	if err := config.SaveConfig(clientFilename, clientCfg); err != nil {
		return err
	}

	fmt.Printf("✅ 已生成服务端配置: %s\n", filename)
	fmt.Printf("✅ 已生成客户端配置: %s\n", clientFilename)
	fmt.Printf("\n📝 配置说明:\n")
	fmt.Printf("   - mode: 运行模式 (server/client)\n")
	fmt.Printf("   - local_addr: 服务端监听地址\n")
	fmt.Printf("   - remote_addr: 客户端连接的服务器地址\n")
	fmt.Printf("   - tunnel_addr: 虚拟网络IP地址\n")
	fmt.Printf("   - key: 加密密钥（必须设置且双方一致）\n")
	fmt.Printf("   - mtu: 最大传输单元 (0=自动检测)\n")
	fmt.Printf("\n⚠️  重要: 请修改配置文件中的密钥为强密码！\n")
	return nil
}

// normalizeTunnelAddr ensures the client does not reuse the default server tunnel IP
// when no explicit configuration file is provided. This prevents IP conflicts like
// both ends using 10.0.0.1/24, which makes the server tunnel unreachable.
func normalizeTunnelAddr(cfg *config.Config, configFromFile bool) error {
	if configFromFile || cfg == nil || cfg.Mode != "client" {
		return nil
	}

	const defaultServerTunnel = "10.0.0.1/24"
	if cfg.TunnelAddr == "" {
		return fmt.Errorf("tunnel address is required in client mode")
	}
	if cfg.TunnelAddr == defaultServerTunnel {
		peerAddr, err := tunnel.GetPeerIP(cfg.TunnelAddr)
		if err != nil {
			return fmt.Errorf("failed to derive peer tunnel IP: %w", err)
		}
		log.Printf("Client tunnel address %s conflicts with server default; auto-switching to %s", cfg.TunnelAddr, peerAddr)
		cfg.TunnelAddr = peerAddr
	}
	return nil
}
