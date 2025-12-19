# TLS 加密使用指南 / TLS Encryption Usage Guide

[中文](#中文指南) | [English](#english-guide)

---

## 中文指南

### 快速开始：启用 TLS 加密

#### 第一步：生成证书（测试用）

```bash
# 运行证书生成脚本
cd examples
./generate-certs.sh

# 或手动生成
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
```

#### 第二步：启动服务器（启用 TLS）

```bash
# 使用命令行参数
sudo ./bin/lightweight-tunnel \
  -m server \
  -l 0.0.0.0:9000 \
  -t 10.0.0.1/24 \
  -tls \
  -tls-cert certs/server.crt \
  -tls-key certs/server.key

# 或使用配置文件
sudo ./bin/lightweight-tunnel -c examples/server-tls.json
```

#### 第三步：连接客户端（启用 TLS）

```bash
# 使用自签名证书（测试）
sudo ./bin/lightweight-tunnel \
  -m client \
  -r SERVER_IP:9000 \
  -t 10.0.0.2/24 \
  -tls \
  -tls-skip-verify

# 使用有效证书（生产环境）
sudo ./bin/lightweight-tunnel \
  -m client \
  -r SERVER_IP:9000 \
  -t 10.0.0.2/24 \
  -tls
```

### 在中国使用（GFW 场景）

#### ⚠️ 重要提醒

1. **必须启用 TLS**
   - 不启用 TLS，所有流量都是明文
   - 运营商（ISP）可以看到所有数据内容
   - GFW 可以检测和阻止您的流量

2. **生产环境配置**
   ```bash
   # 服务器（境外）
   sudo ./bin/lightweight-tunnel \
     -m server \
     -l 0.0.0.0:9000 \
     -t 10.0.0.1/24 \
     -tls \
     -tls-cert /etc/lightweight-tunnel/server.crt \
     -tls-key /etc/lightweight-tunnel/server.key
   
   # 客户端（境内）
   sudo ./bin/lightweight-tunnel \
     -m client \
     -r YOUR_VPS_IP:9000 \
     -t 10.0.0.2/24 \
     -tls
   ```

3. **额外安全建议**
   - 结合 `-obfs` 与 `-obfs-padding`（默认 16）开启 TLS 记录混淆，流量特征更接近常规 HTTPS
   - 使用非标准端口（避免 443、1194 等常见端口）
   - 考虑使用 CDN 或域前置技术
   - 结合其他混淆工具使用
   - 定期更换服务器 IP

#### 风险评估

| 配置 | ISP 可见性 | DPI 检测 | 内容安全 | 推荐 |
|------|----------|---------|---------|------|
| 无 TLS | ✅ 完全可见 | ✅ 易检测 | ❌ 无保护 | ❌ 不推荐 |
| 使用 TLS | ❌ 加密 | ⚠️ 可能检测模式 | ✅ 加密保护 | ✅ 推荐 |
| TLS + 混淆 | ❌ 加密 | ⚠️ 较难检测 | ✅ 加密保护 | ✅✅ 强烈推荐 |

### 生产环境证书

**不要在生产环境使用自签名证书！** 获取正规证书的方法：

1. **Let's Encrypt（免费）**
   ```bash
   # 安装 certbot
   sudo apt-get install certbot
   
   # 获取证书（需要域名）
   sudo certbot certonly --standalone -d your-domain.com
   
   # 证书位置
   # /etc/letsencrypt/live/your-domain.com/fullchain.pem
   # /etc/letsencrypt/live/your-domain.com/privkey.pem
   
   # 使用证书
   sudo ./bin/lightweight-tunnel \
     -m server \
     -tls \
     -tls-cert /etc/letsencrypt/live/your-domain.com/fullchain.pem \
     -tls-key /etc/letsencrypt/live/your-domain.com/privkey.pem
   ```

2. **自己的证书颁发机构**
   - 如果您有组织的 CA，使用组织签发的证书
   - 确保客户端信任该 CA

### 配置文件示例

**服务器配置（使用 TLS）：**
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
  "tls_enabled": true,
  "tls_cert_file": "/etc/letsencrypt/live/your-domain.com/fullchain.pem",
  "tls_key_file": "/etc/letsencrypt/live/your-domain.com/privkey.pem"
}
```

**客户端配置（使用 TLS）：**
```json
{
  "mode": "client",
  "remote_addr": "your-domain.com:9000",
  "tunnel_addr": "10.0.0.2/24",
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3,
  "timeout": 30,
  "keepalive": 10,
  "tls_enabled": true,
  "tls_skip_verify": false
}
```

### 故障排除

#### 问题：TLS 握手失败

**症状**：
```
Network read error: remote error: tls: bad certificate
```

**解决方案**：
1. 检查证书文件路径是否正确
2. 确保证书未过期
3. 客户端使用 `-tls-skip-verify`（仅用于测试自签名证书）

#### 问题：连接被拒绝

**症状**：
```
Failed to connect as client: dial tcp: connection refused
```

**解决方案**：
1. 确保服务器正在运行
2. 检查防火墙规则
3. 验证 IP 地址和端口

#### 问题：证书验证失败

**症状**：
```
x509: certificate signed by unknown authority
```

**解决方案**：
- 使用自签名证书时添加 `-tls-skip-verify`
- 或使用 Let's Encrypt 等受信任的证书

### 性能优化

启用 TLS 后的性能影响：

- **CPU 使用**：增加 5-10%
- **延迟**：增加 1-2ms
- **吞吐量**：在现代硬件上影响很小

优化建议：
1. 使用硬件加速（如果可用）
2. 调整 MTU 以减少碎片
3. 使用较快的加密算法（自动选择）

---

## English Guide

### Quick Start: Enable TLS Encryption

#### Step 1: Generate Certificates (for testing)

```bash
# Run certificate generation script
cd examples
./generate-certs.sh

# Or manually generate
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
```

#### Step 2: Start Server (with TLS)

```bash
# Using command-line flags
sudo ./bin/lightweight-tunnel \
  -m server \
  -l 0.0.0.0:9000 \
  -t 10.0.0.1/24 \
  -tls \
  -tls-cert certs/server.crt \
  -tls-key certs/server.key

# Or using config file
sudo ./bin/lightweight-tunnel -c examples/server-tls.json
```

#### Step 3: Connect Client (with TLS)

```bash
# With self-signed certificates (testing)
sudo ./bin/lightweight-tunnel \
  -m client \
  -r SERVER_IP:9000 \
  -t 10.0.0.2/24 \
  -tls \
  -tls-skip-verify

# With valid certificates (production)
sudo ./bin/lightweight-tunnel \
  -m client \
  -r SERVER_IP:9000 \
  -t 10.0.0.2/24 \
  -tls
```

### Using in China (GFW Scenario)

#### ⚠️ Important Notes

1. **TLS is MANDATORY**
   - Without TLS, all traffic is plaintext
   - ISPs can see all data content
   - GFW can detect and block your traffic

2. **Production Configuration**
   ```bash
   # Server (outside China)
   sudo ./bin/lightweight-tunnel \
     -m server \
     -l 0.0.0.0:9000 \
     -t 10.0.0.1/24 \
     -tls \
     -tls-cert /etc/lightweight-tunnel/server.crt \
     -tls-key /etc/lightweight-tunnel/server.key
   
   # Client (inside China)
   sudo ./bin/lightweight-tunnel \
     -m client \
     -r YOUR_VPS_IP:9000 \
     -t 10.0.0.2/24 \
     -tls
   ```

3. **Additional Security Recommendations**
   - Use non-standard ports (avoid 443, 1194, etc.)
   - Consider using CDN or domain fronting
   - Combine with other obfuscation tools
   - Regularly rotate server IPs

#### Risk Assessment

| Configuration | ISP Visibility | DPI Detection | Content Security | Recommended |
|--------------|----------------|---------------|------------------|-------------|
| No TLS | ✅ Fully visible | ✅ Easy to detect | ❌ No protection | ❌ Not recommended |
| With TLS | ❌ Encrypted | ⚠️ May detect patterns | ✅ Encrypted | ✅ Recommended |
| TLS + Obfuscation | ❌ Encrypted | ⚠️ Harder to detect | ✅ Encrypted | ✅✅ Highly recommended |

### Production Certificates

**DO NOT use self-signed certificates in production!** Ways to obtain proper certificates:

1. **Let's Encrypt (Free)**
   ```bash
   # Install certbot
   sudo apt-get install certbot
   
   # Obtain certificate (requires domain)
   sudo certbot certonly --standalone -d your-domain.com
   
   # Certificate location
   # /etc/letsencrypt/live/your-domain.com/fullchain.pem
   # /etc/letsencrypt/live/your-domain.com/privkey.pem
   
   # Use certificates
   sudo ./bin/lightweight-tunnel \
     -m server \
     -tls \
     -tls-cert /etc/letsencrypt/live/your-domain.com/fullchain.pem \
     -tls-key /etc/letsencrypt/live/your-domain.com/privkey.pem
   ```

2. **Your Own Certificate Authority**
   - If you have an organizational CA, use certificates issued by it
   - Ensure clients trust the CA

### Configuration File Examples

**Server Config (with TLS):**
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
  "tls_enabled": true,
  "tls_cert_file": "/etc/letsencrypt/live/your-domain.com/fullchain.pem",
  "tls_key_file": "/etc/letsencrypt/live/your-domain.com/privkey.pem"
}
```

**Client Config (with TLS):**
```json
{
  "mode": "client",
  "remote_addr": "your-domain.com:9000",
  "tunnel_addr": "10.0.0.2/24",
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3,
  "timeout": 30,
  "keepalive": 10,
  "tls_enabled": true,
  "tls_skip_verify": false
}
```

### Troubleshooting

#### Issue: TLS handshake failure

**Symptoms:**
```
Network read error: remote error: tls: bad certificate
```

**Solutions:**
1. Check certificate file paths are correct
2. Ensure certificate has not expired
3. Use `-tls-skip-verify` on client (only for testing self-signed certs)

#### Issue: Connection refused

**Symptoms:**
```
Failed to connect as client: dial tcp: connection refused
```

**Solutions:**
1. Ensure server is running
2. Check firewall rules
3. Verify IP address and port

#### Issue: Certificate verification failed

**Symptoms:**
```
x509: certificate signed by unknown authority
```

**Solutions:**
- Add `-tls-skip-verify` when using self-signed certificates
- Or use trusted certificates like Let's Encrypt

### Performance Optimization

Performance impact with TLS enabled:

- **CPU Usage**: +5-10%
- **Latency**: +1-2ms
- **Throughput**: Minimal impact on modern hardware

Optimization tips:
1. Use hardware acceleration (if available)
2. Adjust MTU to reduce fragmentation
3. Use faster cipher suites (automatically selected)

---

## Reference

For more security information, see [SECURITY.md](../SECURITY.md)
