# Security Considerations

[English](#english) | [中文](#中文)

---

## English

### Can ISP Equipment View Tunnel Content?

**Short Answer**: 
- **Without TLS (current default)**: YES - ISPs and network operators can see your tunnel traffic in plaintext
- **With TLS enabled**: NO - Traffic is encrypted and protected from inspection

### Current Security Status

#### What is Protected ✅
- **TCP Disguise**: UDP-like packets are wrapped in TCP connections, making them appear as regular TCP traffic
- **Firewall Bypass**: Helps bypass simple firewall rules that block UDP traffic
- **Packet Loss Recovery**: FEC (Forward Error Correction) helps recover lost packets

#### What is NOT Protected ❌
- **No Encryption by Default**: All data is transmitted in plaintext over TCP
- **No Authentication**: No verification of peer identity
- **Vulnerable to DPI**: Deep Packet Inspection (DPI) can easily read packet contents
- **Visible to ISPs**: Internet Service Providers can monitor and log all tunnel traffic

### ISP and GFW Considerations

#### In Countries with Network Monitoring (e.g., China's GFW)

**Without TLS Encryption:**
- 🔴 **High Risk**: ISPs and government monitoring equipment can:
  - Read all packet contents in plaintext
  - Identify tunnel traffic patterns
  - Log and analyze all transmitted data
  - Block or throttle the connection based on content
  - Use Deep Packet Inspection (DPI) to detect and filter traffic

**With TLS Encryption (Recommended):**
- 🟢 **Better Protection**: 
  - Data is encrypted end-to-end
  - ISPs see only encrypted TLS traffic (looks like HTTPS)
  - Content is protected from inspection
  - Harder to detect as tunnel traffic
  - Note: Connection metadata (IP addresses, timing, packet sizes) is still visible

### Security Recommendations

#### For Production Use

1. **✅ ALWAYS Enable TLS Encryption**
   ```bash
   # Server with TLS
   sudo ./lightweight-tunnel -m server -tls -tls-cert server.crt -tls-key server.key
   
   # Client with TLS
   sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -tls
   ```

2. **✅ Use Strong Certificates**
   - Generate proper TLS certificates (not self-signed for production)
   - Keep private keys secure
   - Rotate certificates regularly

3. **✅ Additional Security Layers**
   - Use in combination with VPN for defense in depth
   - Consider obfuscation techniques for traffic pattern hiding
   - Implement rate limiting and connection filtering

4. **✅ Monitor and Audit**
   - Keep logs for security analysis
   - Monitor for unusual connection patterns
   - Regularly update software for security patches

#### For High-Risk Environments (GFW, etc.)

If you're in an environment with active Deep Packet Inspection:

1. **Must Enable TLS**: Without encryption, your traffic WILL be visible
2. **Consider Traffic Obfuscation**: Even with TLS, traffic patterns may be detectable
3. **Use Unpredictable Ports**: Avoid common VPN ports (443, 1194, etc.)
4. **Combine with Other Tools**: Consider using this tunnel with:
   - Domain fronting
   - Traffic obfuscation plugins
   - Multiple layers of encryption

### TLS Configuration

#### Generating Certificates

**Self-signed certificates (for testing only):**
```bash
# Generate server certificate
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"

# Generate client certificate (optional, for mutual TLS)
openssl req -x509 -newkey rsa:4096 -keyout client.key -out client.crt -days 365 -nodes -subj "/CN=client"
```

**Production certificates:**
- Use Let's Encrypt for free, trusted certificates
- Use your organization's certificate authority
- Never use self-signed certificates in production

#### Configuration File with TLS

**Server config:**
```json
{
  "mode": "server",
  "local_addr": "0.0.0.0:9000",
  "tunnel_addr": "10.0.0.1/24",
  "tls_enabled": true,
  "tls_cert_file": "/path/to/server.crt",
  "tls_key_file": "/path/to/server.key",
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3
}
```

**Client config:**
```json
{
  "mode": "client",
  "remote_addr": "SERVER_IP:9000",
  "tunnel_addr": "10.0.0.2/24",
  "tls_enabled": true,
  "tls_skip_verify": false,
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3
}
```

### Threat Model

#### What TLS Protects Against
- ✅ Passive eavesdropping by ISPs
- ✅ Content inspection (DPI)
- ✅ Man-in-the-middle attacks (with proper certificate validation)
- ✅ Data tampering

#### What TLS Does NOT Protect Against
- ❌ Traffic analysis (packet timing, sizes, patterns)
- ❌ Connection metadata (source/destination IPs)
- ❌ Active blocking by IP address or port
- ❌ Endpoint security (if server/client is compromised)

### Performance Impact

- **TLS Encryption Overhead**: ~5-10% CPU usage increase
- **Latency Impact**: +1-2ms per packet
- **Throughput**: Minimal impact on modern hardware
- **Memory**: +2-5MB per connection for TLS buffers

### Compliance and Legal Considerations

⚠️ **Important**: 
- Using encryption may be restricted or illegal in some jurisdictions
- Bypassing network restrictions may violate terms of service or local laws
- Understand your local regulations before deploying
- This tool is provided for legitimate use cases only

---

## 中文

### 运营商设备能否查看隧道内容？

**简短回答**：
- **不使用 TLS（当前默认设置）**：能 - 运营商和网络设备可以看到您的隧道流量明文内容
- **启用 TLS**：不能 - 流量已加密，防止被检查

### 当前安全状态

#### 受保护的内容 ✅
- **TCP 伪装**：类 UDP 数据包被包装在 TCP 连接中，看起来像普通 TCP 流量
- **绕过防火墙**：帮助绕过阻止 UDP 流量的简单防火墙规则
- **数据包丢失恢复**：FEC（前向纠错）帮助恢复丢失的数据包

#### 未受保护的内容 ❌
- **默认无加密**：所有数据通过 TCP 以明文形式传输
- **无身份验证**：无对等方身份验证
- **易受 DPI 攻击**：深度包检测（DPI）可以轻松读取数据包内容
- **运营商可见**：互联网服务提供商可以监控和记录所有隧道流量

### 运营商和 GFW 注意事项

#### 在有网络监控的国家（如中国的 GFW）

**不使用 TLS 加密：**
- 🔴 **高风险**：运营商和政府监控设备可以：
  - 以明文形式读取所有数据包内容
  - 识别隧道流量模式
  - 记录和分析所有传输的数据
  - 根据内容阻止或限制连接
  - 使用深度包检测（DPI）检测和过滤流量

**使用 TLS 加密（推荐）：**
- 🟢 **更好的保护**：
  - 数据端到端加密
  - 运营商只能看到加密的 TLS 流量（看起来像 HTTPS）
  - 内容受保护不被检查
  - 更难被检测为隧道流量
  - 注意：连接元数据（IP 地址、时间、数据包大小）仍然可见

### 安全建议

#### 用于生产环境

1. **✅ 始终启用 TLS 加密**
   ```bash
   # 使用 TLS 的服务器
   sudo ./lightweight-tunnel -m server -tls -tls-cert server.crt -tls-key server.key
   
   # 使用 TLS 的客户端
   sudo ./lightweight-tunnel -m client -r SERVER_IP:9000 -tls
   ```

2. **✅ 使用强证书**
   - 生成正确的 TLS 证书（生产环境不要使用自签名证书）
   - 保护私钥安全
   - 定期轮换证书

3. **✅ 额外的安全层**
   - 与 VPN 结合使用以实现纵深防御
   - 考虑流量混淆技术以隐藏流量模式
   - 实施速率限制和连接过滤

4. **✅ 监控和审计**
   - 保留日志以进行安全分析
   - 监控异常连接模式
   - 定期更新软件以获取安全补丁

#### 用于高风险环境（GFW 等）

如果您处于有主动深度包检测的环境：

1. **必须启用 TLS**：没有加密，您的流量将会被看到
2. **考虑流量混淆**：即使有 TLS，流量模式也可能被检测到
3. **使用不可预测的端口**：避免常见的 VPN 端口（443、1194 等）
4. **与其他工具结合**：考虑将此隧道与以下工具结合使用：
   - 域前置
   - 流量混淆插件
   - 多层加密

### TLS 配置

#### 生成证书

**自签名证书（仅用于测试）：**
```bash
# 生成服务器证书
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"

# 生成客户端证书（可选，用于双向 TLS）
openssl req -x509 -newkey rsa:4096 -keyout client.key -out client.crt -days 365 -nodes -subj "/CN=client"
```

**生产环境证书：**
- 使用 Let's Encrypt 获取免费、可信的证书
- 使用您组织的证书颁发机构
- 生产环境中绝不使用自签名证书

#### 带 TLS 的配置文件

**服务器配置：**
```json
{
  "mode": "server",
  "local_addr": "0.0.0.0:9000",
  "tunnel_addr": "10.0.0.1/24",
  "tls_enabled": true,
  "tls_cert_file": "/path/to/server.crt",
  "tls_key_file": "/path/to/server.key",
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3
}
```

**客户端配置：**
```json
{
  "mode": "client",
  "remote_addr": "SERVER_IP:9000",
  "tunnel_addr": "10.0.0.2/24",
  "tls_enabled": true,
  "tls_skip_verify": false,
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3
}
```

### 威胁模型

#### TLS 防护的威胁
- ✅ 运营商的被动窃听
- ✅ 内容检查（DPI）
- ✅ 中间人攻击（使用正确的证书验证）
- ✅ 数据篡改

#### TLS 不能防护的威胁
- ❌ 流量分析（数据包时间、大小、模式）
- ❌ 连接元数据（源/目标 IP）
- ❌ 通过 IP 地址或端口的主动阻止
- ❌ 端点安全（如果服务器/客户端被攻破）

### 性能影响

- **TLS 加密开销**：CPU 使用率增加约 5-10%
- **延迟影响**：每个数据包 +1-2ms
- **吞吐量**：在现代硬件上影响最小
- **内存**：每个连接 +2-5MB 用于 TLS 缓冲区

### 合规性和法律考虑

⚠️ **重要**：
- 在某些司法管辖区，使用加密可能受到限制或非法
- 绕过网络限制可能违反服务条款或当地法律
- 在部署之前了解您当地的法规
- 此工具仅供合法使用

---

## Reporting Security Issues

If you discover a security vulnerability, please report it by creating a private security advisory on GitHub or by opening an issue with the `security` label.

**Do not** include exploit details in public issues - use GitHub's security advisory feature for sensitive reports.

## 报告安全问题

如果您发现安全漏洞，请通过在 GitHub 上创建私有安全公告或创建带有 `security` 标签的 issue 来报告。

**不要**在公开 issue 中包含漏洞利用详情 - 使用 GitHub 的安全公告功能报告敏感信息。
