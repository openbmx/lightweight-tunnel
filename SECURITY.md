# Security Considerations

[English](#english) | [中文](#中文)

---

## English

### Can ISP Equipment View Tunnel Content?

**Short Answer**: 
- **Without encryption (-k)**: YES - ISPs and network operators can see your tunnel traffic in plaintext
- **With encryption enabled (-k)**: NO - Traffic is encrypted with AES-256-GCM

### Current Security Status

#### What is Protected ✅
- **AES-256-GCM Encryption**: Use `-k` flag to enable strong encryption
- **TCP Disguise**: UDP-like packets are wrapped in TCP connections, making them appear as regular TCP traffic (main tunnel only)
- **Firewall Bypass**: Helps bypass simple firewall rules that block UDP traffic
- **Packet Loss Recovery**: FEC (Forward Error Correction) helps recover lost packets
- **Access Control**: Clients with wrong key cannot connect

#### What is NOT Protected ❌ (without -k flag)
- **No Encryption by Default**: All data is transmitted in plaintext
- **No Authentication**: Anyone can connect without a key
- **Vulnerable to DPI**: Deep Packet Inspection (DPI) can easily read packet contents
- **Visible to ISPs**: Internet Service Providers can monitor and log all tunnel traffic

### Security Recommendations

#### For Production Use

1. **✅ ALWAYS Use Encryption Key**
   ```bash
   # Server with encryption
   sudo ./lightweight-tunnel -m server -k "your-strong-secret-key" -l 0.0.0.0:9000 -t 10.0.0.1/24
   
   # Client with same key
   sudo ./lightweight-tunnel -m client -k "your-strong-secret-key" -r SERVER_IP:9000 -t 10.0.0.2/24
   ```

2. **✅ Use Strong Keys**
   - Use long, random keys (16+ characters recommended)
   - Include letters, numbers, and special characters
   - Avoid dictionary words or simple patterns
   - Consider using a password manager to generate keys

3. **✅ Additional Security Layers**
   - Use in combination with VPN for defense in depth
   - Enable TLS record obfuscation (`-obfs` with optional `-obfs-padding`) to make traffic resemble HTTPS and resist DPI/GFW detection
   - Implement rate limiting and connection filtering

4. **✅ Monitor and Audit**
   - Keep logs for security analysis
   - Monitor for unusual connection patterns
   - Regularly update software for security patches

### ISP and GFW Considerations

#### In Countries with Network Monitoring (e.g., China's GFW)

**Without Encryption (-k flag):**
- 🔴 **High Risk**: ISPs and government monitoring equipment can:
  - Read all packet contents in plaintext
  - Identify tunnel traffic patterns
  - Log and analyze all transmitted data
  - Block or throttle the connection based on content
  - Use Deep Packet Inspection (DPI) to detect and filter traffic

**With Encryption (-k flag):**
- 🟢 **Better Protection**: 
  - Data is encrypted end-to-end with AES-256-GCM
  - ISPs see only encrypted traffic
  - Content is protected from inspection
  - Unauthorized users cannot connect
  - Note: Connection metadata (IP addresses, timing, packet sizes) is still visible

#### For High-Risk Environments (GFW, etc.)

If you're in an environment with active Deep Packet Inspection:

1. **Must Enable Encryption**: Use `-k` flag to enable AES-256-GCM encryption
2. **Consider Traffic Obfuscation**: Even with encryption, traffic patterns may be detectable
3. **Use Unpredictable Ports**: Avoid common VPN ports (443, 1194, etc.)
4. **Combine with Other Tools**: Consider using this tunnel with:
   - Traffic obfuscation plugins
   - Multiple layers of encryption

### Encryption Configuration

#### Using -k Flag (Recommended)

```bash
# Server with encryption
sudo ./lightweight-tunnel -m server -k "strong-random-key-here" -l 0.0.0.0:9000 -t 10.0.0.1/24

# Client with same key
sudo ./lightweight-tunnel -m client -k "strong-random-key-here" -r SERVER_IP:9000 -t 10.0.0.2/24
```

#### Configuration File with Encryption

**Server config:**
```json
{
  "mode": "server",
  "local_addr": "0.0.0.0:9000",
  "tunnel_addr": "10.0.0.1/24",
  "key": "strong-random-key-here",
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
  "key": "strong-random-key-here",
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3
}
```

### Threat Model

#### What Encryption (-k) Protects Against
- ✅ Passive eavesdropping by ISPs
- ✅ Content inspection (DPI)
- ✅ Man-in-the-middle attacks
- ✅ Data tampering
- ✅ Unauthorized access (wrong key = cannot connect)

#### What Encryption Does NOT Protect Against
- ❌ Traffic analysis (packet timing, sizes, patterns)
- ❌ Connection metadata (source/destination IPs)
- ❌ Active blocking by IP address or port
- ❌ Endpoint security (if server/client is compromised)

### Performance Impact

- **AES-256-GCM Overhead**: ~28 bytes per packet (12-byte nonce + 16-byte tag)
- **CPU Impact**: Minimal on modern hardware with AES-NI support
- **Latency Impact**: Negligible
- **Throughput**: Minimal impact on modern hardware

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
- **不使用加密（-k 参数）**：能 - 运营商和网络设备可以看到您的隧道流量明文内容
- **启用加密（-k 参数）**：不能 - 流量使用 AES-256-GCM 加密

### 当前安全状态

#### 受保护的内容 ✅
- **AES-256-GCM 加密**：使用 `-k` 参数启用强加密
- **TCP 伪装**：类 UDP 数据包被包装在 TCP 连接中，看起来像普通 TCP 流量（仅主隧道）
- **绕过防火墙**：帮助绕过阻止 UDP 流量的简单防火墙规则
- **数据包丢失恢复**：FEC（前向纠错）帮助恢复丢失的数据包
- **访问控制**：密钥不正确的客户端无法连接

#### 未受保护的内容 ❌（不使用 -k 参数时）
- **默认无加密**：所有数据以明文形式传输
- **无身份验证**：任何人都可以连接
- **易受 DPI 攻击**：深度包检测（DPI）可以轻松读取数据包内容
- **运营商可见**：互联网服务提供商可以监控和记录所有隧道流量

### 安全建议

#### 用于生产环境

1. **✅ 始终使用加密密钥**
   ```bash
   # 使用加密的服务器
   sudo ./lightweight-tunnel -m server -k "your-strong-secret-key" -l 0.0.0.0:9000 -t 10.0.0.1/24
   
   # 使用相同密钥的客户端
   sudo ./lightweight-tunnel -m client -k "your-strong-secret-key" -r SERVER_IP:9000 -t 10.0.0.2/24
   ```

2. **✅ 使用强密钥**
   - 使用长随机密钥（建议 16 个字符以上）
   - 包含字母、数字和特殊字符
   - 避免使用字典单词或简单模式
   - 考虑使用密码管理器生成密钥

3. **✅ 额外的安全层**
   - 与 VPN 结合使用以实现纵深防御
   - 启用 TLS 记录混淆（`-obfs` 与可选 `-obfs-padding`）让流量更像常规 HTTPS，降低 DPI/GFW 检测概率
   - 实施速率限制和连接过滤

4. **✅ 监控和审计**
   - 保留日志以进行安全分析
   - 监控异常连接模式
   - 定期更新软件以获取安全补丁

### 运营商和 GFW 注意事项

#### 在有网络监控的国家（如中国的 GFW）

**不使用加密（-k 参数）：**
- 🔴 **高风险**：运营商和政府监控设备可以：
  - 以明文形式读取所有数据包内容
  - 识别隧道流量模式
  - 记录和分析所有传输的数据
  - 根据内容阻止或限制连接
  - 使用深度包检测（DPI）检测和过滤流量

**使用加密（-k 参数）：**
- 🟢 **更好的保护**：
  - 数据使用 AES-256-GCM 端到端加密
  - 运营商只能看到加密流量
  - 内容受保护不被检查
  - 未授权用户无法连接
  - 注意：连接元数据（IP 地址、时间、数据包大小）仍然可见

#### 用于高风险环境（GFW 等）

如果您处于有主动深度包检测的环境：

1. **必须启用加密**：使用 `-k` 参数启用 AES-256-GCM 加密
2. **考虑流量混淆**：即使有加密，流量模式也可能被检测到
3. **使用不可预测的端口**：避免常见的 VPN 端口（443、1194 等）
4. **与其他工具结合**：考虑将此隧道与以下工具结合使用：
   - 流量混淆插件
   - 多层加密

### 加密配置

#### 使用 -k 参数（推荐）

```bash
# 使用加密的服务器
sudo ./lightweight-tunnel -m server -k "strong-random-key-here" -l 0.0.0.0:9000 -t 10.0.0.1/24

# 使用相同密钥的客户端
sudo ./lightweight-tunnel -m client -k "strong-random-key-here" -r SERVER_IP:9000 -t 10.0.0.2/24
```

#### 使用配置文件

**服务器配置：**
```json
{
  "mode": "server",
  "local_addr": "0.0.0.0:9000",
  "tunnel_addr": "10.0.0.1/24",
  "key": "strong-random-key-here",
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
  "key": "strong-random-key-here",
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3
}
```

### 威胁模型

#### 加密（-k）防护的威胁
- ✅ 运营商的被动窃听
- ✅ 内容检查（DPI）
- ✅ 中间人攻击
- ✅ 数据篡改
- ✅ 未授权访问（密钥错误无法连接）

#### 加密不能防护的威胁
- ❌ 流量分析（数据包时间、大小、模式）
- ❌ 连接元数据（源/目标 IP）
- ❌ 通过 IP 地址或端口的主动阻止
- ❌ 端点安全（如果服务器/客户端被攻破）

### 性能影响

- **AES-256-GCM 开销**：每个数据包约 28 字节（12 字节 nonce + 16 字节标签）
- **CPU 影响**：在支持 AES-NI 的现代硬件上影响最小
- **延迟影响**：可忽略不计
- **吞吐量**：在现代硬件上影响最小

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
