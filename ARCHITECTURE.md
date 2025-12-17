# Architecture and Design

## Overview

Lightweight Tunnel is a Go-based network tunnel implementation that provides secure, reliable communication between two endpoints using TCP disguise and Forward Error Correction (FEC).

## Design Goals

1. **Lightweight**: Minimal resource usage suitable for low-spec servers
2. **Reliable**: FEC error correction for packet loss recovery
3. **Stealthy**: TCP disguise to bypass firewall restrictions
4. **Simple**: Easy to deploy and configure

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                        Application Layer                       │
│                     (User Applications)                        │
└───────────────────┬───────────────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────────────┐
│                      TUN Device (tun0)                         │
│                   Virtual Network Interface                     │
└───────────────────┬───────────────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────────────┐
│                     Tunnel Processing                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ TUN Reader  │  │   Packet    │  │ TUN Writer  │          │
│  │  Goroutine  │  │   Queues    │  │  Goroutine  │          │
│  └──────┬──────┘  └──────┬──────┘  └──────▲──────┘          │
│         │                │                 │                   │
│         ▼                ▼                 │                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ FEC Encoder │  │  Send/Recv  │  │ FEC Decoder │          │
│  │  (Optional) │  │   Queues    │  │  (Optional) │          │
│  └──────┬──────┘  └──────┬──────┘  └──────▲──────┘          │
│         │                │                 │                   │
│         ▼                ▼                 │                   │
│  ┌─────────────┐                   ┌─────────────┐           │
│  │ Net Writer  │                   │ Net Reader  │           │
│  │  Goroutine  │                   │  Goroutine  │           │
│  └──────┬──────┘                   └──────▲──────┘           │
└─────────┼──────────────────────────────────┼─────────────────┘
          │                                  │
          ▼                                  │
┌───────────────────────────────────────────────────────────────┐
│                    TCP Disguise Layer                          │
│          (Wraps UDP-like packets in TCP stream)               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Length Prefix (4 bytes) │ Packet Type (1 byte) │ Data  │ │
│  └─────────────────────────────────────────────────────────┘ │
└───────────────────┬───────────────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────────────┐
│                    TCP Connection                              │
│                (Actual Network Transport)                      │
└───────────────────────────────────────────────────────────────┘
```

## Components

### 1. TUN Device (`pkg/tunnel/tun.go`)

- Creates a virtual network interface (Layer 3)
- Captures IP packets from the operating system
- Injects received packets back into the OS network stack
- Uses Linux TUN/TAP interface via `/dev/net/tun`

**Key Functions:**
- `CreateTUN()`: Creates and configures TUN device
- `Read()`: Reads IP packets from TUN device
- `Write()`: Writes IP packets to TUN device

### 2. TCP Disguise Layer (`pkg/tcp_disguise/tcp_disguise.go`)

Wraps UDP-like packet semantics in a TCP connection:

- **Packet Framing**: Each packet is prefixed with a 4-byte length header
- **Reliable Stream**: Uses TCP for underlying transport
- **Packet Boundaries**: Maintains packet boundaries unlike raw TCP

**Packet Format:**
```
┌──────────────┬──────────────┬──────────────────┐
│   Length     │     Type     │      Payload     │
│  (4 bytes)   │   (1 byte)   │   (variable)     │
└──────────────┴──────────────┴──────────────────┘
```

**Packet Types:**
- `0x01`: Data packet (IP packet from TUN)
- `0x02`: Keepalive packet (maintain connection)

### 3. FEC (Forward Error Correction) (`pkg/fec/fec.go`)

Implements error correction using XOR-based parity shards:

- **Data Shards**: Original data split into N pieces
- **Parity Shards**: M redundant pieces for recovery
- **Recovery**: Can recover up to M lost data shards

**Algorithm:**
- Simple XOR-based FEC for lightweight implementation
- For production, consider Reed-Solomon codes (more robust)

### 4. Tunnel Management (`pkg/tunnel/tunnel.go`)

Coordinates all components:

**Goroutines:**
1. **TUN Reader**: Reads packets from TUN device → Send queue
2. **TUN Writer**: Receive queue → Writes to TUN device
3. **Network Reader**: TCP connection → Receive queue
4. **Network Writer**: Send queue → TCP connection
5. **Keepalive**: Periodic heartbeat packets

**Packet Flow:**

```
Outbound:
App → TUN Device → TUN Reader → Send Queue → Net Writer → TCP → Network

Inbound:
Network → TCP → Net Reader → Receive Queue → TUN Writer → TUN Device → App
```

### 5. Configuration (`internal/config/config.go`)

JSON-based configuration with sensible defaults:

```json
{
  "mode": "server|client",
  "local_addr": "0.0.0.0:9000",
  "remote_addr": "server_ip:9000",
  "tunnel_addr": "10.0.0.1/24",
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3,
  "timeout": 30,
  "keepalive": 10
}
```

## Operating Modes

### Server Mode

1. Creates TUN device with configured IP
2. Listens on specified port for TCP connection
3. Accepts first client connection
4. Closes listener (single client only)
5. Starts packet processing

### Client Mode

1. Creates TUN device with configured IP
2. Connects to server via TCP
3. Establishes connection
4. Starts packet processing

## Security Considerations

### Current Implementation

- **TCP Disguise**: Helps bypass simple firewall rules that block UDP
- **TLS Encryption**: Optional TLS 1.2+ encryption for data confidentiality
- **No Authentication**: Pre-shared key auth not yet implemented (coming soon)

### Recommendations for Production

1. **✅ Enable TLS/SSL**: Always use TLS encryption in production
2. **Authentication**: Use certificate-based authentication
3. **Rate Limiting**: Prevent DoS attacks
4. **Connection Limits**: Limit number of connections per IP
5. **Packet Validation**: Validate packet sizes and types

## Performance Characteristics

### Throughput

- **Best Case**: Near line-rate with low overhead
- **FEC Overhead**: ~30% for 10 data + 3 parity configuration
- **TCP Overhead**: Standard TCP header (~40 bytes per packet)

### Latency

- **Additional Latency**: ~1-2ms for packet processing
- **TCP Latency**: Standard TCP latency characteristics
- **Queue Depth**: 100 packets (configurable)

### Resource Usage

- **Memory**: ~10-20 MB per connection
- **CPU**: Low (<5% on modern systems)
- **Goroutines**: 5 per tunnel instance

## Limitations

1. **IPv4 Only**: No IPv6 support currently
2. **Linux Only**: Uses Linux-specific TUN/TAP interfaces
3. **No NAT Traversal**: Requires direct connectivity or port forwarding
4. **Simple FEC**: XOR-based FEC is less robust than Reed-Solomon
5. **Centralized Routing**: All traffic flows through server (potential bottleneck)

## Multi-Client Architecture (NEW)

### Hub Mode

```
                       Server
                         │
                   ┌─────┼─────┐
                   │     │     │
               Client1 Client2 Client3
                   │     │     │
                   └─────┴─────┘
              Clients can communicate
```

### Components for Multi-Client

1. **Client Connection Pool**: Map of client IP → connection
2. **Packet Router**: Routes packets between clients based on destination IP
3. **Dynamic Registration**: Clients register their IP on first packet
4. **IP Conflict Detection**: Warns and handles IP conflicts

### Packet Flow (Multi-Client)

**Client-to-Client:**
```
Client1 → Server → Routing Decision → Client2
```

**Client-to-Server:**
```
Client1 → Server → TUN Device → Server App
```

## Future Enhancements

1. ✅ **Multi-client Support**: Server accepts multiple clients (DONE)
2. **IPv6 Support**: Add IPv6 packet handling
3. **Pre-shared Key Auth**: Implement PSK authentication
4. **Certificate-based Auth**: Mutual TLS authentication
5. **Better FEC**: Implement proper Reed-Solomon codes
6. **NAT Traversal**: Add UDP hole punching or relay support
7. **Bandwidth Management**: QoS and rate limiting
8. **Statistics**: Real-time connection statistics and monitoring
9. **Cross-platform**: Support for macOS and Windows
10. **Traffic Obfuscation**: Additional obfuscation beyond TLS

## Testing Strategy

### Unit Tests

- FEC encoding/decoding
- TCP packet framing
- Configuration parsing

### Integration Tests

- End-to-end tunnel connectivity
- Packet loss recovery with FEC
- Connection failure handling

### Performance Tests

- Throughput benchmarks
- Latency measurements
- Resource usage profiling

## References

- [TUN/TAP Documentation](https://www.kernel.org/doc/Documentation/networking/tuntap.txt)
- [Reed-Solomon FEC](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)
- [udp2raw Project](https://github.com/wangyu-/udp2raw)
- [tinyfecVPN Project](https://github.com/wangyu-/tinyfecVPN)
