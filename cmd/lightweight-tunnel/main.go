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
	localAddr := flag.String("l", "0.0.0.0:9000", "Local address to listen on")
	remoteAddr := flag.String("r", "", "Remote address to connect to (client mode)")
	tunnelAddr := flag.String("t", "10.0.0.1/24", "Tunnel IP address and netmask")
	mtu := flag.Int("mtu", 1400, "MTU size")
	fecData := flag.Int("fec-data", 10, "FEC data shards")
	fecParity := flag.Int("fec-parity", 3, "FEC parity shards")
	showVersion := flag.Bool("v", false, "Show version")
	generateConfig := flag.String("g", "", "Generate example config file")
	tlsEnabled := flag.Bool("tls", false, "Enable TLS encryption")
	tlsCertFile := flag.String("tls-cert", "", "TLS certificate file (server mode)")
	tlsKeyFile := flag.String("tls-key", "", "TLS private key file (server mode)")
	tlsSkipVerify := flag.Bool("tls-skip-verify", false, "Skip TLS certificate verification (client mode, insecure)")

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
			LocalAddr:         *localAddr,
			RemoteAddr:        *remoteAddr,
			TunnelAddr:        *tunnelAddr,
			MTU:               *mtu,
			FECDataShards:     *fecData,
			FECParityShards:   *fecParity,
			Timeout:           30,
			KeepaliveInterval: 10,
			TLSEnabled:        *tlsEnabled,
			TLSCertFile:       *tlsCertFile,
			TLSKeyFile:        *tlsKeyFile,
			TLSSkipVerify:     *tlsSkipVerify,
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
	log.Printf("TLS Encryption: %v", cfg.TLSEnabled)
	if !cfg.TLSEnabled {
		log.Println("⚠️  WARNING: TLS disabled - traffic will be sent in PLAINTEXT")
		log.Println("⚠️  ISPs and network operators can view and log all tunnel content")
		log.Println("⚠️  Enable TLS with -tls flag for secure communication")
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

	// TLS validation
	if cfg.TLSEnabled && cfg.Mode == "server" {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return fmt.Errorf("TLS enabled in server mode but certificate or key file not specified")
		}
	}

	return nil
}

func generateConfigFile(filename string) error {
	// Generate server config
	serverCfg := config.DefaultConfig()
	serverCfg.Mode = "server"
	serverCfg.LocalAddr = "0.0.0.0:9000"
	serverCfg.TunnelAddr = "10.0.0.1/24"

	if err := config.SaveConfig(filename, serverCfg); err != nil {
		return err
	}

	// Generate client config example
	clientFilename := filename + ".client"
	clientCfg := config.DefaultConfig()
	clientCfg.Mode = "client"
	clientCfg.RemoteAddr = "SERVER_IP:9000"
	clientCfg.TunnelAddr = "10.0.0.2/24"

	if err := config.SaveConfig(clientFilename, clientCfg); err != nil {
		return err
	}

	fmt.Printf("Also generated client config example: %s\n", clientFilename)
	return nil
}
