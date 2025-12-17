# Quick Start Guide

## Installation

```bash
# Clone the repository
git clone https://github.com/openbmx/lightweight-tunnel.git
cd lightweight-tunnel

# Build using Makefile
make build

# Or build manually
go build -o bin/lightweight-tunnel ./cmd/lightweight-tunnel
```

## Basic Usage

### ⚠️ Security First

**IMPORTANT**: By default, tunnel traffic is **NOT encrypted**. ISPs and network operators can view all content.

**For secure communication, always use TLS:**
```bash
# Server with TLS
sudo ./bin/lightweight-tunnel -m server -tls -tls-cert server.crt -tls-key server.key

# Client with TLS  
sudo ./bin/lightweight-tunnel -m client -r SERVER_IP:9000 -tls
```

See [examples/TLS-GUIDE.md](examples/TLS-GUIDE.md) for detailed TLS setup instructions.

### Server Setup

**Without TLS (insecure):**
```bash
# Start server (requires root for TUN device)
sudo ./bin/lightweight-tunnel -m server -l 0.0.0.0:9000 -t 10.0.0.1/24
```

**With TLS (recommended):**
```bash
# Generate test certificates first
./examples/generate-certs.sh

# Start server with TLS
sudo ./bin/lightweight-tunnel -m server -l 0.0.0.0:9000 -t 10.0.0.1/24 \
  -tls -tls-cert certs/server.crt -tls-key certs/server.key
```

### Client Setup

**Without TLS (insecure):**
```bash
# Start client (replace SERVER_IP with your server's IP)
sudo ./bin/lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.2/24
```

**With TLS (recommended):**
```bash
# With self-signed certificates (testing)
sudo ./bin/lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.2/24 -tls -tls-skip-verify

# With valid certificates (production)
sudo ./bin/lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.2/24 -tls
```

### Test Connection

After both server and client are running:

```bash
# On server, ping client
ping 10.0.0.2

# On client, ping server
ping 10.0.0.1
```

## Using Configuration Files

### Generate Example Configs

```bash
./bin/lightweight-tunnel -g config.json
# This creates config.json (server) and config.json.client (client)
```

### Edit and Use

```bash
# Edit the config files with your settings
nano config.json

# Run with config file
sudo ./bin/lightweight-tunnel -c config.json
```

## Using Helper Scripts

```bash
# Server
cd examples
sudo bash start-server.sh

# Client (edit script first to set SERVER_IP)
nano start-client.sh
sudo bash start-client.sh
```

## Common Issues

### Permission Denied

**Problem**: `failed to open /dev/net/tun: permission denied`

**Solution**: Run with sudo/root privileges
```bash
sudo ./bin/lightweight-tunnel ...
```

### Module Not Found

**Problem**: `/dev/net/tun: no such file or directory`

**Solution**: Load TUN module
```bash
sudo modprobe tun
```

### Connection Refused

**Problem**: Client cannot connect to server

**Solutions**:
1. Check server is running: `netstat -tlnp | grep 9000`
2. Check firewall: `sudo ufw allow 9000/tcp`
3. Verify server IP address is correct
4. Check network connectivity: `ping SERVER_IP`

### Address Already in Use

**Problem**: `bind: address already in use`

**Solution**: Kill existing process or use different port
```bash
# Find process using port
sudo lsof -i :9000
# Kill the process
sudo kill -9 PID
```

## Performance Tuning

### For High-Speed Networks

```bash
# Increase MTU
sudo ./bin/lightweight-tunnel -mtu 8000 ...

# Reduce FEC overhead
sudo ./bin/lightweight-tunnel -fec-data 20 -fec-parity 2 ...
```

### For Lossy Networks

```bash
# Increase FEC redundancy
sudo ./bin/lightweight-tunnel -fec-data 10 -fec-parity 5 ...

# Reduce MTU
sudo ./bin/lightweight-tunnel -mtu 1200 ...
```

## Firewall Configuration

### Using UFW (Ubuntu/Debian)

```bash
# Allow tunnel port
sudo ufw allow 9000/tcp

# Enable forwarding
sudo ufw default allow routed
```

### Using firewalld (CentOS/RHEL)

```bash
# Allow tunnel port
sudo firewall-cmd --permanent --add-port=9000/tcp
sudo firewall-cmd --reload

# Enable masquerading
sudo firewall-cmd --permanent --add-masquerade
sudo firewall-cmd --reload
```

### Using iptables

```bash
# Allow tunnel port
sudo iptables -A INPUT -p tcp --dport 9000 -j ACCEPT

# Enable forwarding
sudo iptables -A FORWARD -i tun0 -j ACCEPT
sudo iptables -A FORWARD -o tun0 -j ACCEPT
```

## Advanced Usage

### Running as Systemd Service

Create `/etc/systemd/system/lightweight-tunnel.service`:

```ini
[Unit]
Description=Lightweight Tunnel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/lightweight-tunnel
ExecStart=/opt/lightweight-tunnel/bin/lightweight-tunnel -c /etc/lightweight-tunnel/config.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable lightweight-tunnel
sudo systemctl start lightweight-tunnel
sudo systemctl status lightweight-tunnel
```

### Routing Through Tunnel

```bash
# On client, route specific network through tunnel
sudo ip route add 192.168.1.0/24 via 10.0.0.1 dev tun0

# Route all traffic through tunnel (be careful!)
sudo ip route add default via 10.0.0.1 dev tun0 metric 100
```

### Monitoring

```bash
# Check TUN device
ip addr show tun0

# Monitor traffic
sudo tcpdump -i tun0

# Check connection
ss -tnp | grep 9000
```

## Troubleshooting Commands

```bash
# Check if TUN module is loaded
lsmod | grep tun

# Load TUN module if not loaded
sudo modprobe tun

# Check TUN device permissions
ls -l /dev/net/tun

# View tunnel process logs
journalctl -u lightweight-tunnel -f

# Test network connectivity
ping -I tun0 10.0.0.2

# Check routing table
ip route show

# Monitor bandwidth
iftop -i tun0
```

## Next Steps

- Read [ARCHITECTURE.md](ARCHITECTURE.md) for implementation details
- Check [README.md](README.md) for full documentation
- Review example configurations in `examples/` directory
- Consider adding encryption for production use
