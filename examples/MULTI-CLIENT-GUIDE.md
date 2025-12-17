# Multi-Client Setup Guide

This guide demonstrates how to set up a multi-client tunnel network where multiple clients can connect to a server and communicate with each other.

## Scenario

We'll create a virtual network with:
- 1 Server (10.0.0.1)
- 3 Clients (10.0.0.2, 10.0.0.3, 10.0.0.4)

All clients will be able to communicate with each other through the server hub.

## Prerequisites

- Linux system with TUN/TAP support
- Root/sudo access on all machines
- Network connectivity between clients and server
- `lightweight-tunnel` binary built and ready

## Step 1: Start the Server

On the server machine:

```bash
# Without TLS (for testing only - traffic is visible to ISPs)
sudo ./lightweight-tunnel -m server -l 0.0.0.0:9000 -t 10.0.0.1/24

# With TLS (recommended for production)
sudo ./lightweight-tunnel -m server -l 0.0.0.0:9000 -t 10.0.0.1/24 \
    -tls -tls-cert server.crt -tls-key server.key
```

Expected output:
```
=== Lightweight Tunnel ===
Version: 1.0.0
Mode: server
Local Address: 0.0.0.0:9000
Tunnel Address: 10.0.0.1/24
Multi-client: true (max: 100)
Client Isolation: false
Created TUN device: tun0
Configured tun0 with IP 10.0.0.1/24, MTU 1400
Listening on 0.0.0.0:9000...
Multi-client mode enabled (max: 100 clients)
Tunnel running. Press Ctrl+C to stop.
```

## Step 2: Connect Client 1

On the first client machine:

```bash
# Without TLS
sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.2/24

# With TLS (self-signed cert)
sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.2/24 \
    -tls -tls-skip-verify

# With TLS (valid cert)
sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.2/24 -tls
```

Expected output:
```
=== Lightweight Tunnel ===
Version: 1.0.0
Mode: client
Remote Address: SERVER_IP:9000
Tunnel Address: 10.0.0.2/24
Created TUN device: tun0
Configured tun0 with IP 10.0.0.2/24, MTU 1400
Connecting to server at SERVER_IP:9000...
Connected to server: 10.0.0.2:12345 -> SERVER_IP:9000
Tunnel running. Press Ctrl+C to stop.
```

Server output:
```
Client connected: CLIENT1_IP:12345
Client registered with IP: 10.0.0.2 (total clients: 1)
```

## Step 3: Connect Client 2

On the second client machine:

```bash
sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.3/24 -tls -tls-skip-verify
```

Server output:
```
Client connected: CLIENT2_IP:23456
Client registered with IP: 10.0.0.3 (total clients: 2)
```

## Step 4: Connect Client 3

On the third client machine:

```bash
sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.4/24 -tls -tls-skip-verify
```

Server output:
```
Client connected: CLIENT3_IP:34567
Client registered with IP: 10.0.0.4 (total clients: 3)
```

## Step 5: Test Connectivity

### Test 1: Ping from Client 1 to Server

On Client 1:
```bash
ping 10.0.0.1
```

Expected output:
```
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=2.5 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=2.3 ms
```

### Test 2: Ping from Client 1 to Client 2

On Client 1:
```bash
ping 10.0.0.3
```

Expected output:
```
PING 10.0.0.3 (10.0.0.3) 56(84) bytes of data.
64 bytes from 10.0.0.3: icmp_seq=1 ttl=64 time=5.2 ms
64 bytes from 10.0.0.3: icmp_seq=2 ttl=64 time=4.8 ms
```

### Test 3: Ping from Client 2 to Client 3

On Client 2:
```bash
ping 10.0.0.4
```

Expected output:
```
PING 10.0.0.4 (10.0.0.4) 56(84) bytes of data.
64 bytes from 10.0.0.4: icmp_seq=1 ttl=64 time=5.5 ms
64 bytes from 10.0.0.4: icmp_seq=2 ttl=64 time=5.1 ms
```

### Test 4: SSH from Client 1 to Client 3

On Client 3, make sure SSH is running:
```bash
sudo systemctl start sshd
```

On Client 1:
```bash
ssh user@10.0.0.4
```

### Test 5: HTTP Service Access

On Client 2, start a simple HTTP server:
```bash
python3 -m http.server 8080 --bind 10.0.0.3
```

On Client 1, access the HTTP server:
```bash
curl http://10.0.0.3:8080
```

### Test 6: Check Tunnel Status

On the server, you can check connected clients by looking at the logs:
```
Client registered with IP: 10.0.0.2 (total clients: 3)
Client registered with IP: 10.0.0.3 (total clients: 3)
Client registered with IP: 10.0.0.4 (total clients: 3)
```

## Advanced Configuration

### Using Configuration File

Server (`server-config.json`):
```json
{
  "mode": "server",
  "local_addr": "0.0.0.0:9000",
  "tunnel_addr": "10.0.0.1/24",
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3,
  "timeout": 30,
  "keepalive": 10,
  "send_queue_size": 1000,
  "recv_queue_size": 1000,
  "multi_client": true,
  "max_clients": 100,
  "client_isolation": false,
  "tls_enabled": true,
  "tls_cert_file": "server.crt",
  "tls_key_file": "server.key"
}
```

Start server with config:
```bash
sudo ./lightweight-tunnel -c server-config.json
```

### Client Isolation Mode

If you want clients to only communicate with the server (not with each other):

```bash
sudo ./lightweight-tunnel -m server -l 0.0.0.0:9000 -t 10.0.0.1/24 \
    -client-isolation -tls -tls-cert server.crt -tls-key server.key
```

In this mode:
- ✅ Client 1 can ping/access Server (10.0.0.1)
- ✅ Client 2 can ping/access Server (10.0.0.1)
- ❌ Client 1 cannot ping/access Client 2 (10.0.0.3)
- ❌ Client 2 cannot ping/access Client 3 (10.0.0.4)

### Limiting Maximum Clients

To limit the number of concurrent clients:

```bash
sudo ./lightweight-tunnel -m server -l 0.0.0.0:9000 -t 10.0.0.1/24 \
    -max-clients 10 -tls -tls-cert server.crt -tls-key server.key
```

## Troubleshooting

### Client Cannot Connect

1. **Check firewall rules** on server:
   ```bash
   sudo ufw allow 9000/tcp
   # or
   sudo iptables -A INPUT -p tcp --dport 9000 -j ACCEPT
   ```

2. **Verify server is listening**:
   ```bash
   netstat -tuln | grep 9000
   # or
   ss -tuln | grep 9000
   ```

3. **Test network connectivity**:
   ```bash
   telnet SERVER_IP 9000
   ```

### Clients Cannot Communicate with Each Other

1. **Check client isolation is disabled**:
   - Make sure `-client-isolation` flag is NOT set on server

2. **Verify client IPs are different**:
   - Each client must have a unique IP address in the same subnet

3. **Check routing**:
   ```bash
   # On client, check routing table
   ip route show | grep tun0
   
   # Should see something like:
   # 10.0.0.0/24 dev tun0 proto kernel scope link src 10.0.0.2
   ```

### IP Address Conflicts

If you see warnings like:
```
Warning: IP conflict detected for 10.0.0.2, closing old connection
```

This means two clients are using the same IP address. Make sure each client has a unique IP.

### Performance Issues

1. **Increase queue sizes**:
   ```bash
   sudo ./lightweight-tunnel -m server -l 0.0.0.0:9000 -t 10.0.0.1/24 \
       -send-queue 5000 -recv-queue 5000
   ```

2. **Check server CPU usage**:
   ```bash
   top
   # Look for lightweight-tunnel process
   ```

3. **Monitor network traffic**:
   ```bash
   # On server
   iftop -i tun0
   ```

### TLS Certificate Errors

If clients cannot connect with TLS:

1. **For testing, use self-signed certificates**:
   ```bash
   # Generate test certificates
   ./examples/generate-certs.sh
   
   # Use -tls-skip-verify on clients (INSECURE - testing only)
   sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -t 10.0.0.2/24 \
       -tls -tls-skip-verify
   ```

2. **For production, use valid certificates** (e.g., from Let's Encrypt)

## Use Cases

### Remote Office Network

Connect multiple remote offices to a central hub:
```
Office A (10.0.0.2) ──┐
                      │
Office B (10.0.0.3) ──┼─── Central Server (10.0.0.1)
                      │
Office C (10.0.0.4) ──┘
```

### Development Team Collaboration

Create a shared development environment:
```
Developer 1 (10.0.0.2) ──┐
                         │
Developer 2 (10.0.0.3) ──┼─── Build Server (10.0.0.1)
                         │
Developer 3 (10.0.0.4) ──┘
```

### Gaming LAN Party

Create a virtual LAN for gaming:
```
Player 1 (10.0.0.2) ──┐
                      │
Player 2 (10.0.0.3) ──┼─── Game Host (10.0.0.1)
                      │
Player 3 (10.0.0.4) ──┘
```

## Performance Benchmarks

With 4-core CPU server:

| Clients | Total Throughput | Avg Latency | CPU Usage |
|---------|------------------|-------------|-----------|
| 1       | ~350 Mbps        | ~2 ms       | ~60%      |
| 3       | ~650 Mbps        | ~4 ms       | ~80%      |
| 5       | ~800 Mbps        | ~5 ms       | ~85%      |
| 10      | ~1000 Mbps       | ~8 ms       | ~95%      |

Note: Performance depends on server hardware, network conditions, and configuration.

## Security Best Practices

1. **Always use TLS in production**:
   - Never use `-tls-skip-verify` in production
   - Use valid certificates from a trusted CA

2. **Use client isolation when appropriate**:
   - Enable `-client-isolation` if clients shouldn't communicate

3. **Limit maximum clients**:
   - Set `-max-clients` to a reasonable number for your use case

4. **Monitor connections**:
   - Regularly check server logs for unauthorized connections

5. **Use firewall rules**:
   - Only allow connections from trusted IP addresses

## Stopping the Tunnel

To stop the tunnel gracefully on any machine:

```bash
# Press Ctrl+C in the terminal where lightweight-tunnel is running
```

Or send SIGTERM:
```bash
sudo pkill -SIGTERM lightweight-tunnel
```

Server will automatically clean up all client connections.

## Summary

You now have a fully functional multi-client tunnel network where:
- ✅ Multiple clients can connect to the server simultaneously
- ✅ Clients can communicate with each other through the server
- ✅ All traffic can be encrypted with TLS
- ✅ Client isolation mode available for security
- ✅ Configurable connection limits

For more information, see [IMPLEMENTATION.md](../IMPLEMENTATION.md) for technical details.
