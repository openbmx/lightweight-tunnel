# Lightweight Tunnel (轻量级内网隧道)

一个使用 Go 语言开发的轻量级内网隧道工具，支持 TCP 伪装和 FEC 纠错功能。适用于在两个低配置服务器之间建立安全的内网连接。

A lightweight intranet tunnel tool developed in Go, supporting TCP disguise and FEC (Forward Error Correction). Suitable for establishing secure intranet connections between two low-spec servers.

## Features (特性)

- 🚀 **轻量级设计** - 占用资源少，适合低配置服务器
- 🔒 **TCP 伪装** - UDP 数据包伪装成 TCP 连接，绕过防火墙限制
- 🔐 **TLS 加密** - 可选的 TLS 加密保护数据不被 ISP 检查
- 🛡️ **FEC 纠错** - Forward Error Correction 提供数据包丢失恢复能力
- 🌐 **TUN 设备** - 基于 TUN 设备的第三层网络隧道
- ⚡ **高性能** - 使用 Go 协程实现并发处理
- 🎯 **简单易用** - 命令行参数或配置文件两种配置方式

## Quick Start (快速开始)

### Prerequisites (前置要求)

- Linux 系统 (需要 TUN 设备支持)
- Root 权限 (用于创建和配置 TUN 设备)
- Go 1.19+ (仅编译时需要)

## ⚠️ Security Notice (安全提醒)

**English**: By default, this tunnel transmits data in **plaintext** without encryption. ISPs and network operators can view and log all tunnel content. **For secure communication, always enable TLS encryption** using the `-tls` flag. See [SECURITY.md](SECURITY.md) for details.

**中文**: 默认情况下，此隧道以**明文**传输数据，不进行加密。运营商和网络设备可以查看和记录所有隧道内容。**要进行安全通信，请始终使用 `-tls` 标志启用 TLS 加密**。详见 [SECURITY.md](SECURITY.md)。

### Installation (安装)

```bash
# Clone the repository
git clone https://github.com/openbmx/lightweight-tunnel.git
cd lightweight-tunnel

# Build
go build -o lightweight-tunnel ./cmd/lightweight-tunnel

# Or install directly
go install ./cmd/lightweight-tunnel
```

### Usage (使用方法)

#### Server Side (服务端)

**Without TLS (insecure - traffic visible to ISPs):**
```bash
# Run as server with default settings
sudo ./lightweight-tunnel -m server -l 0.0.0.0:9000 -t 10.0.0.1/24
```

**With TLS (recommended - encrypted traffic):**
```bash
# Generate certificates first (for testing only)
./examples/generate-certs.sh

# Run server with TLS
sudo ./lightweight-tunnel -m server -l 0.0.0.0:9000 -t 10.0.0.1/24 -tls -tls-cert certs/server.crt -tls-key certs/server.key
```

#### Client Side (客户端)

**Without TLS (insecure):**
```bash
# Run as client
sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.2/24
```

**With TLS (recommended):**
```bash
# With self-signed certificates (testing only)
sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.2/24 -tls -tls-skip-verify

# With valid certificates (production)
sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.2/24 -tls
```

### Configuration File (配置文件)

Generate example configuration files:

```bash
./lightweight-tunnel -g config.json
```

This creates `config.json` (server) and `config.json.client` (client).

Example server configuration:

```json
{
  "mode": "server",
  "local_addr": "0.0.0.0:9000",
  "remote_addr": "",
  "tunnel_addr": "10.0.0.1/24",
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3,
  "timeout": 30,
  "keepalive": 10
}
```

Example client configuration:

```json
{
  "mode": "client",
  "local_addr": "0.0.0.0:9000",
  "remote_addr": "SERVER_IP:9000",
  "tunnel_addr": "10.0.0.2/24",
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3,
  "timeout": 30,
  "keepalive": 10
}
```

## Command Line Options (命令行选项)

```
  -c string
        Configuration file path
  -m string
        Mode: server or client (default "server")
  -l string
        Local address to listen on (default "0.0.0.0:9000")
  -r string
        Remote address to connect to (client mode)
  -t string
        Tunnel IP address and netmask (default "10.0.0.1/24")
  -mtu int
        MTU size (default 1400)
  -fec-data int
        FEC data shards (default 10)
  -fec-parity int
        FEC parity shards (default 3)
  -tls
        Enable TLS encryption (recommended for security)
  -tls-cert string
        TLS certificate file (server mode)
  -tls-key string
        TLS private key file (server mode)
  -tls-skip-verify
        Skip TLS certificate verification (client mode, insecure)
  -v    Show version
  -g string
        Generate example config file
```

## Architecture (架构)

```
┌─────────────┐         TCP (disguised)         ┌─────────────┐
│   Server    │ ◄─────────────────────────────► │   Client    │
│  (10.0.0.1) │    with FEC error correction    │  (10.0.0.2) │
└──────┬──────┘                                  └──────┬──────┘
       │                                                │
       │ TUN Device                            TUN Device │
       │                                                │
  ┌────▼────┐                                      ┌────▼────┐
  │ App/Svc │                                      │ App/Svc │
  └─────────┘                                      └─────────┘
```

## How It Works (工作原理)

1. **TUN Device**: Creates a virtual network interface for Layer 3 (IP) traffic
2. **TCP Disguise**: Wraps UDP-like packets in TCP connections to bypass firewalls
3. **TLS Encryption**: Optional end-to-end encryption to protect data from ISP inspection
4. **FEC**: Adds redundant data shards for packet loss recovery
5. **Keepalive**: Maintains connection with periodic heartbeat packets

## Testing (测试)

After establishing the tunnel, you can test connectivity:

```bash
# On server side, ping client
ping 10.0.0.2

# On client side, ping server
ping 10.0.0.1

# Test with iperf
# Server: iperf -s
# Client: iperf -c 10.0.0.1
```

## Performance Tuning (性能调优)

- **MTU**: Adjust based on your network (default: 1400)
- **FEC Shards**: More parity shards = better loss recovery but more overhead
- **Keepalive**: Shorter interval = faster detection of disconnection

## Limitations (限制)

- Currently supports only IPv4
- Single client per server instance
- Requires root/admin privileges for TUN device
- Linux only (uses Linux TUN/TAP interfaces)
- **No encryption by default** - enable TLS for secure communication

## Security (安全)

For detailed security information, including:
- ISP visibility and Deep Packet Inspection (DPI)
- TLS encryption setup
- GFW and network monitoring considerations
- Threat model and best practices

Please read [SECURITY.md](SECURITY.md)

## References (参考项目)

- [udp2raw](https://github.com/wangyu-/udp2raw) - UDP to TCP converter
- [tinyfecvpn](https://github.com/wangyu-/tinyfecVPN) - VPN with FEC

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
