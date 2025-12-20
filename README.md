# Lightweight Tunnel - 轻量级隧道

<div align="center">

**高性能、低延迟的内网穿透隧道工具**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.19+-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-green.svg)](https://www.linux.org/)

[功能特性](#-功能特性) • [快速开始](#-快速开始) • [使用说明](#-使用说明) • [常见问题](#-常见问题)

</div>

---

## 📖 项目简介

Lightweight Tunnel 是一个使用 Go 语言开发的轻量级内网穿透隧道工具，专注于提供**真正的 TCP 伪装**能力。

### 核心特点

- 🔥 **真实 TCP 伪装**：使用 Raw Socket 构造完整的 TCP/IP 数据包，完美绕过防火墙检测
- 🚀 **高性能设计**：基于 UDP 传输避免 TCP-over-TCP 问题，延迟低、吞吐量高
- 🔐 **内置加密**：AES-256-GCM 军用级加密，保护所有隧道流量
- 🌐 **P2P 直连**：支持 NAT 穿透，客户端间可建立点对点连接
- 🛠️ **智能适配**：自动 MTU 检测，自适应网络环境
- 📦 **简单易用**：极简配置，开箱即用

### 适用场景

- 🏢 **企业内网互联** - 在多个分支机构之间建立安全的虚拟局域网
- 🏠 **家庭服务器访问** - 从外网安全访问家中的 NAS、服务器等设备
- 🎮 **游戏联机** - 为局域网游戏建立低延迟的虚拟局域网
- 🔧 **开发测试** - 在不同网络环境中快速建立开发测试网络
- 🌐 **多点互联** - 支持多个客户端组成 Hub 网络，任意节点间可直接通信
- 🔥 **突破封锁** - 真正伪装成 TCP 流量，绕过严格的防火墙和 DPI 检测

---

## ✨ 功能特性

### 🔥 真实 TCP 伪装（Raw Socket 模式）

本项目的核心特性是**真正的 TCP 流量伪装**，类似于 udp2raw：

- ✅ 使用 Raw Socket 构造完整的 IP/TCP 数据包
- ✅ 在网络层就是真实的 TCP 协议（IP 协议号 = 6）
- ✅ 实现完整的 TCP 三次握手（SYN、SYN-ACK、ACK）
- ✅ 维护真实的 TCP 序列号和确认号
- ✅ 包含完整的 TCP 选项（MSS、SACK、Window Scale、Timestamp）
- ✅ 正确计算 TCP 校验和和 IP 校验和
- ✅ 自动管理 iptables 规则，阻止内核发送 RST 包
- ✅ **可完美绕过严格的 TCP-only 防火墙和 DPI 检测**

**技术原理**：
```
传统方式（容易被识别）:
UDP 包 → [UDP Header + TCP 伪头 + 数据]

本项目（完美伪装）:
TCP 包 → [IP Header (协议=6, TCP) + TCP Header + 数据]
```

**注意**：Raw Socket 模式需要 **root 权限**运行。

### 🚀 高性能架构

#### 避免 TCP-over-TCP 问题

```
问题场景：
应用层 TCP → 隧道层 TCP → 网络传输
         ↓         ↓
      重传机制   重传机制
      拥塞控制   拥塞控制
         ↓
      性能崩溃！

本项目方案：
应用层流量 → FEC 纠错 → Raw TCP 伪装 → 网络传输
           ↓
       无需重传，延迟更低
```

#### 性能优势

- **低延迟**：避免双重重传，延迟更稳定
- **高吞吐**：FEC 主动纠错，无需等待重传
- **适合实时应用**：游戏、VoIP、视频会议等场景表现优秀
- **智能队列管理**：5000 大小的发送/接收队列（可配置），防止队列溢出
- **自动重连**：客户端断线后自动重连，无需人工干预

### 🔄 可靠性保障

#### 自动重连机制

客户端内置智能重连功能，确保连接稳定性：

- ✅ **自动检测断线**：实时监测连接状态，快速发现问题
- ✅ **指数退避重试**：1s → 2s → 4s → 8s → 16s → 32s（最大间隔）
- ✅ **无限期重试**：持续尝试重连，直到成功或用户手动停止
- ✅ **透明恢复**：重连成功后立即恢复数据传输，应用层无感知
- ✅ **日志完善**：详细记录重连过程，便于问题诊断

**适用场景**：
- 🔧 服务器临时维护重启
- 🌐 网络波动或临时中断
- 🔥 防火墙规则临时调整
- 📡 移动网络在不同基站间切换

### 🔐 安全加密

- **算法**：AES-256-GCM（Galois/Counter Mode）
- **密钥派生**：SHA-256 哈希用户提供的密钥字符串
- **随机 Nonce**：每个数据包使用独立的随机 nonce
- **认证标签**：16 字节的认证标签确保数据完整性
- **端到端加密**：包括 P2P 直连在内的所有流量均被加密

### 🌐 智能路由与 P2P

#### P2P 直连机制

```
第 1 步：客户端注册到服务器
第 2 步：服务器协调 NAT 打洞
第 3 步：双方同时发送 UDP 打洞包
第 4 步：P2P 直连建立
```

#### 路由优先级

1. 🥇 **本地网络直连** - 如果在同一局域网，直接使用内网 IP
2. 🥈 **P2P 公网直连** - 通过 NAT 打洞建立的点对点连接
3. 🥉 **服务器中转** - P2P 失败时自动回退到服务器转发

#### NAT 兼容性

| NAT 类型 | P2P 成功率 | 说明 |
|---------|-----------|------|
| 完全锥形 (Full Cone) | ✅ 99% | 任何外部主机都可连接 |
| 限制锥形 (Restricted Cone) | ✅ 95% | 只有通信过的 IP 可连接 |
| 端口限制锥形 (Port Restricted) | ✅ 90% | 只有通信过的 IP:Port 可连接 |
| 对称型 (Symmetric) | ⚠️ 30% | 自动回退到服务器中转 |

### 🛠️ 智能适配

#### 自动 MTU 检测

设置 `mtu: 0` 启用自动 MTU 检测：

1. **网络类型识别**：自动识别 Ethernet、PPPoE、WiFi、移动网络等
2. **推荐值选择**：根据网络类型选择最优 MTU
3. **路径 MTU 探测**：客户端模式下进行实际路径 MTU 测试
4. **自动调整**：考虑加密和协议开销，确保不会分片

**推荐 MTU 值**：

| 网络类型 | MTU | 说明 |
|---------|-----|------|
| 以太网 | 1371 | 标准以太网 |
| PPPoE | 1343 | PPPoE 连接（DSL 等） |
| 移动网络 | 1200 | 保守配置，适应性强 |
| WiFi | 1371 | 通常与以太网相同 |
| VPN | 1300 | 考虑 VPN 额外开销 |

### 📦 FEC 前向纠错

使用 FEC（Forward Error Correction）技术在弱网环境下保证传输质量：

```
原始数据：10 个数据分片
FEC 编码：+ 3 个校验分片
接收端：即使丢失 3 个分片，仍可恢复完整数据
```

**参数选择**：

| 网络环境 | fec_data | fec_parity | 可恢复丢包率 | 带宽开销 |
|---------|----------|------------|-------------|---------|
| 低丢包 (<1%) | 20 | 2 | 9% | 10% |
| 标准 (1-3%) | 10 | 3 | 23% | 30% |
| 高丢包 (3-10%) | 10 | 5 | 33% | 50% |
| 极端 (>10%) | 8 | 6 | 43% | 75% |

---

## 🚀 快速开始

### 系统要求

- **操作系统**：Linux (内核 2.6+)
- **权限**：Root（必需，用于 Raw Socket）
- **内存**：最低 64MB，推荐 128MB+
- **网络**：至少一台设备需要公网 IP 或端口转发

### 安装

#### 方式 1：从源码编译（推荐）

```bash
# 1. 克隆仓库
git clone https://github.com/openbmx/lightweight-tunnel.git
cd lightweight-tunnel

# 2. 安装依赖
go mod download

# 3. 编译
go build -o lightweight-tunnel ./cmd/lightweight-tunnel

# 4. （可选）安装到系统路径
sudo cp lightweight-tunnel /usr/local/bin/

# 5. 验证安装
./lightweight-tunnel -v
```

#### 方式 2：使用 Makefile

```bash
# 编译
make build

# 编译后的二进制文件位于：bin/lightweight-tunnel
```

#### 方式 3：注册为 systemd 服务（可自定义服务名与配置路径）

```bash
# 先构建
make build

# 安装为 systemd 服务，指定配置文件路径与服务名
sudo make install-service CONFIG_PATH=/etc/lightweight-tunnel/config-server.json SERVICE_NAME=lightweight-tunnel-server
# CONFIG_PATH 必填，服务默认以 lightweight-tunnel 系统用户运行（自动创建），请确保配置文件对该用户可读
# systemd 单元仅授予 CAP_NET_ADMIN 与 CAP_NET_RAW（创建 TUN 与 Raw TCP 伪装所需），其余权限受限
# 需要访问网络，因此 PrivateNetwork 保持为 no，同时启用了 PrivateTmp/ProtectHome 等隔离设置
# CAP_NET_RAW 是构造原始 TCP 报文所必需的能力，请勿移除
# 配置文件权限示例：
sudo chown root:lightweight-tunnel /etc/lightweight-tunnel/config-server.json
sudo chmod 640 /etc/lightweight-tunnel/config-server.json

# 启动与查看状态
sudo systemctl start lightweight-tunnel-server
sudo systemctl status lightweight-tunnel-server

# （可选）一键更新：在仓库根目录执行，自动 git pull + make build，并替换 /usr/local/bin/lightweight-tunnel
./mupdate
# 如果服务正在运行，更新后请重启对应的 systemd 服务，例如：sudo systemctl restart lightweight-tunnel（自定义 SERVICE_NAME 的请替换为实际服务名，如 lightweight-tunnel-server）
```

---

## 📖 使用说明

### 基础使用

#### 场景 1：最简单的加密隧道（推荐新手）

**服务端**（需要公网 IP）：
```bash
sudo ./lightweight-tunnel \
  -m server \
  -l 0.0.0.0:9000 \
  -t 10.0.0.1/24 \
  -k "my-secret-password-2024"
```

**客户端**：
```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器公网IP>:9000 \
  -t 10.0.0.2/24 \
  -k "my-secret-password-2024"
```

**测试连接**：
```bash
# 在客户端执行
ping 10.0.0.1    # ping 服务器的虚拟 IP
```

#### 场景 2：多客户端 Hub 网络

**服务端**：
```bash
sudo ./lightweight-tunnel \
  -m server \
  -l 0.0.0.0:9000 \
  -t 10.0.0.1/24 \
  -k "company-key-2024"
```

**客户端 A**（北京）：
```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.10/24 \
  -k "company-key-2024"
```

**客户端 B**（上海）：
```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.20/24 \
  -k "company-key-2024"
```

现在客户端 A 可以直接访问客户端 B：
```bash
# 在客户端 A 上
ping 10.0.0.20
ssh user@10.0.0.20
```

#### 场景 3：启用 P2P 直连（低延迟）

**服务端**：
```bash
sudo ./lightweight-tunnel \
  -m server \
  -l 0.0.0.0:9000 \
  -t 10.0.0.1/24 \
  -k "gaming-2024"
```

**客户端**（默认启用 P2P）：
```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.2/24 \
  -k "gaming-2024" \
  -p2p \
  -p2p-port 19000
```

程序会自动尝试建立 P2P 连接，成功后流量不经过服务器。

### 使用配置文件

#### 生成配置模板

```bash
./lightweight-tunnel -g config.json
```

这会生成两个文件：
- `config.json` - 服务端配置
- `config.json.client` - 客户端配置

#### 服务端配置示例

**config-server.json**：
```json
{
  "mode": "server",
  "local_addr": "0.0.0.0:9000",
  "tunnel_addr": "10.0.0.1/24",
  "key": "请修改为您的强密钥",
  "mtu": 0,
  "tun_name": "tun0",
  "routes": [
    "10.10.0.0/16",
    "10.20.0.0/16"
  ],
  "config_push_interval": 600
}
```

**配置说明**：
- `mode`: 运行模式（server 或 client）
- `local_addr`: 服务端监听地址
- `tunnel_addr`: 虚拟网络 IP 地址
- `key`: 加密密钥（**必须设置且双方一致**）
- `mtu`: 最大传输单元（0 = 自动检测）
- `tun_name`: 可选，指定 TUN 设备名称（冲突或非法时自动回退）
- `routes`: 可选，宣告给服务端/对端的 CIDR 路由列表
- `config_push_interval`: 可选，服务端定期下发新配置/密钥的间隔（秒，0=关闭）

#### 客户端配置示例

**config-client.json**：
```json
{
  "mode": "client",
  "remote_addr": "服务器IP:9000",
  "tunnel_addr": "10.0.0.2/24",
  "key": "请修改为您的强密钥",
  "mtu": 0,
  "tun_name": "tun1",
  "routes": [
    "10.10.0.0/16",
    "10.20.0.0/16"
  ]
}
```

#### 使用配置文件运行

```bash
# 服务端
sudo ./lightweight-tunnel -c config-server.json

# 客户端
sudo ./lightweight-tunnel -c config-client.json
```

### 命令行参数说明

```
必需参数：
  -m string
        运行模式：server（服务端）或 client（客户端）
  -l string
        监听地址（仅服务端，格式：IP:端口，默认：0.0.0.0:9000）
  -r string
        远程服务器地址（仅客户端，格式：IP:端口）
  -t string
        隧道虚拟 IP 地址（格式：IP/CIDR，如：10.0.0.2/24）
  -k string
        加密密钥（强烈推荐设置，双方必须相同）

可选参数：
  -mtu int
        最大传输单元（默认：1400，设置为 0 启用自动检测）
  -tun-name string
        指定 TUN 网卡名称（默认自动分配，如 tun0、tun1）
  -routes string
        以逗号分隔的 CIDR 路由列表，自动宣告给对端
  -config-push-interval int
        服务端定期下发新配置/密钥的间隔（秒，0=关闭）
  -send-queue int
        发送队列大小（默认：5000）
  -recv-queue int
        接收队列大小（默认：5000）
  -p2p
        启用 P2P 直连（默认：true）
  -p2p-port int
        P2P UDP 监听端口（默认：0，自动分配）

服务端专用：
  -multi-client
        启用多客户端支持（默认：true）
  -max-clients int
        最大客户端数（默认：100）
  -client-isolation
        启用客户端隔离（默认：false）

其他：
  -c string
        从 JSON 文件加载配置
  -g string
        生成示例配置文件
  -v
        显示版本信息
```

### 动态密钥轮换与路由宣告

- **动态密钥下发**：服务端通过 `-config-push-interval` 定期生成新密钥并推送给客户端，客户端自动切换新密钥并重连，旧密钥立即失效。
- **配置文件自动持久化**：若通过 `-c config.json` 启动，服务端下发/客户端接收的新密钥会自动写回该配置文件（0600 权限），重启后沿用最新密钥。若未使用配置文件（纯命令行），仍仅在内存中生效。
- **路由宣告**：使用 `-routes "10.10.0.0/16,10.20.0.0/16"` 将本端可达网段宣告给对端；服务端和客户端会自动安装/清理这些路由，需为合法 CIDR。
- **多 TUN/多配置**：可用 `-tun-name tunX` 指定网卡名称；若名称冲突或非法会自动退回系统分配的名称，便于多配置并行（tun0、tun1 等）。

---

## ⚙️ 高级配置

### 性能调优

#### 高速内网环境

```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.2/24 \
  -k "my-key" \
  -mtu 1371 \
  -send-queue 10000 \
  -recv-queue 10000
```

- 大队列处理突发流量
- MTU 保持默认或略高

#### 弱网环境（高丢包）

```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.2/24 \
  -k "my-key" \
  -mtu 1200
```

- 小 MTU 降低单包丢失影响
- 默认队列大小已足够

#### 移动网络

```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.2/24 \
  -k "my-key" \
  -mtu 0  # 自动检测
```

- 启用自动 MTU 检测适应网络变化

### 安全配置

#### 生成强密钥

```bash
# 使用 OpenSSL 生成随机密钥
openssl rand -base64 32

# 或使用密码管理器生成
# 推荐长度：16-64 字符
# 包含：大小写字母、数字、特殊字符
```

#### 配置文件权限

```bash
# 创建配置文件
sudo nano config.json

# 设置权限（仅 root 可读）
sudo chmod 600 config.json
sudo chown root:root config.json
```

#### 防火墙配置

```bash
# Ubuntu/Debian
sudo ufw allow 9000/tcp
sudo ufw allow 9000/udp

# CentOS/RHEL
sudo firewall-cmd --add-port=9000/tcp --permanent
sudo firewall-cmd --add-port=9000/udp --permanent
sudo firewall-cmd --reload
```

---

## 🔍 常见问题

### Q1: 权限错误 "permission denied"

**错误信息**：
```
Raw Socket模式需要root权限运行
```

**解决方案**：
```bash
# 使用 sudo 运行
sudo ./lightweight-tunnel -m server ...
```

### Q2: TUN 设备不存在

**错误信息**：
```
/dev/net/tun: no such file or directory
```

**解决方案**：
```bash
# 加载 TUN 模块
sudo modprobe tun

# 验证
ls -l /dev/net/tun

# 设置开机自动加载
echo "tun" | sudo tee -a /etc/modules
```

### Q3: 客户端无法连接服务器

**排查步骤**：

1. **检查服务端是否运行**：
```bash
sudo netstat -tulnp | grep 9000
```

2. **检查防火墙**：
```bash
sudo ufw status
sudo ufw allow 9000
```

3. **测试连通性**：
```bash
ping <服务器IP>
telnet <服务器IP> 9000
```

### Q4: 密钥不匹配

**错误信息**：
```
Decryption error (wrong key?)
```

**解决方案**：
- 确保服务端和客户端使用**完全相同**的 `-k` 参数
- 密钥区分大小写
- 注意空格和特殊字符
- 使用引号包裹密钥

### Q5: MTU 应该设置多少？

**推荐配置**：
```bash
# 最简单：自动检测（推荐）
-mtu 0

# 标准网络
-mtu 1371

# 移动网络/弱网
-mtu 1200

# PPPoE 网络
-mtu 1343
```

### Q6: 发送队列满错误

**解决方案**：

从新版本开始，默认队列已增加到 5000，并实现了超时等待机制。如果仍然出现队列满：

```bash
# 增大队列
sudo ./lightweight-tunnel \
  -send-queue 10000 \
  -recv-queue 10000 \
  ...
```

### Q7: P2P 连接失败

**可能原因**：
- 双方都是对称 NAT（程序会自动回退到服务器中转）
- 防火墙阻止 UDP（检查并开放 P2P 端口）
- P2P 端口被占用（指定不同端口）

**不影响使用**：P2P 失败时会自动使用服务器中转。

### Q8: 客户端掉线后会自动重连吗？

**是的！** 客户端具有自动重连功能：

**工作原理**：
- 客户端检测到连接断开后，会自动尝试重新连接服务器
- 使用指数退避策略：1秒、2秒、4秒、8秒、16秒、最多32秒
- 客户端会持续重连，直到成功或用户手动停止程序
- 重连成功后，隧道立即恢复正常工作

**日志示例**：
```
Network read error: connection refused, attempting reconnection...
Attempting to reconnect to server at 1.2.3.4:9000 (backoff 1s)
Reconnect attempt failed: connection refused
Attempting to reconnect to server at 1.2.3.4:9000 (backoff 2s)
Reconnected to server: 10.0.0.2:54321 -> 1.2.3.4:9000
Reconnection successful, resuming packet reception
```

**常见场景**：
- ✅ 服务器临时重启 → 客户端自动重连
- ✅ 网络临时中断 → 客户端等待网络恢复后自动重连
- ✅ 防火墙临时阻断 → 客户端持续尝试直到恢复
- ✅ 长时间断线 → 客户端以32秒间隔持续重试

**无需手动操作**：客户端会一直运行，无需手动重启程序。

### Q9: 如何查看运行状态？

程序会输出详细日志：

```
=== Lightweight Tunnel ===
Version: 1.0.0
Mode: client
Transport: rawtcp (true TCP disguise)
✅ 使用 Raw Socket 模式
🔐 Encryption: Enabled (AES-256-GCM)
MTU: 1371
```

使用系统工具监控：
```bash
# 查看网卡流量
sudo iftop -i tun0

# 查看网卡统计
ip -s link show tun0
```

---

## 🔒 安全声明

### 重要提示

1. **生产环境务必启用加密**（`-k` 参数）
2. **使用强密码** - 16+ 字符，包含大小写、数字、特殊字符
3. **定期更换密钥** - 建议每 3-6 个月更换一次
4. **保护配置文件** - 设置适当的文件权限（600）
5. **监控异常流量** - 及时发现潜在的安全问题

### 威胁模型

- ✅ 防止 ISP 查看流量内容（加密）
- ✅ 防止 DPI 识别协议类型（TCP 伪装）
- ✅ 防止未授权连接（密钥认证）
- ⚠️ 不能防止高级流量分析（行为特征）
- ⚠️ 不能防止端点被入侵

---

## 🛠️ 开发与贡献

### 项目结构

```
lightweight-tunnel/
├── cmd/lightweight-tunnel/    # 程序入口
├── internal/config/           # 配置管理
├── pkg/
│   ├── crypto/               # AES-256-GCM 加密
│   ├── faketcp/              # TCP 伪装（Raw Socket）
│   ├── fec/                  # FEC 前向纠错
│   ├── p2p/                  # P2P 连接管理
│   ├── routing/              # 路由表
│   └── tunnel/               # 隧道主逻辑
└── README.md                 # 本文档
```

### 编译和测试

```bash
# 安装依赖
go mod download

# 编译
make build

# 运行测试
make test

# 或直接
go test -v ./...
```

### 贡献指南

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

---

## 📚 技术细节

### 为什么使用 Raw Socket 而非 UDP？

**Raw Socket 模式**：
- ✅ 真正的 TCP 协议（IP 协议号 = 6）
- ✅ 可以绕过 TCP-only 防火墙
- ✅ 更难被 DPI 检测
- ⚠️ 需要 root 权限

**对比其他方案**：
```
UDP + 假 TCP 头：
[UDP Header] [假 TCP 头] [数据]
└─ 协议号 = 17 (UDP)，容易被识别

Raw Socket + 真 TCP 包：
[IP Header (协议=6)] [TCP Header] [数据]
└─ 协议号 = 6 (TCP)，真实 TCP 流量
```

### 为什么基于 UDP 而非 TCP？

避免 **TCP-over-TCP 问题**：

- TCP 隧道中的 TCP 应用会导致双重重传
- 在丢包环境下性能急剧下降
- 延迟变化大，不适合实时应用

**本项目方案**：
- 使用 UDP（伪装成 TCP）作为传输层
- FEC 主动纠错代替重传
- 延迟低且稳定

### FEC 工作原理

```
编码：
原始数据 [D1][D2][D3][D4][D5][D6][D7][D8][D9][D10]
         ↓ FEC 编码（10 数据 + 3 校验）
发送包   [D1][D2][D3][D4][D5][D6][D7][D8][D9][D10][P1][P2][P3]

接收：
收到包   [D1][  ][D3][D4][D5][D6][  ][D8][D9][D10][P1][P2][P3]
         ↓ FEC 解码
恢复数据 [D1][D2][D3][D4][D5][D6][D7][D8][D9][D10]
```

---

## 📄 开源协议

本项目采用 [MIT License](LICENSE) 开源协议。

```
MIT License

Copyright (c) 2024 openbmx

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 📞 联系方式

- **GitHub Issues**: [提交问题或建议](https://github.com/openbmx/lightweight-tunnel/issues)
- **Pull Requests**: [贡献代码](https://github.com/openbmx/lightweight-tunnel/pulls)

---

## 🙏 致谢

本项目的设计灵感和技术方案参考了以下优秀开源项目：

- **[udp2raw](https://github.com/wangyu-/udp2raw)** - UDP 流量伪装为 TCP 的先驱项目
- **[tinyfecVPN](https://github.com/wangyu-/tinyfecVPN)** - 轻量级 FEC VPN 实现

---

<div align="center">

**感谢使用 Lightweight Tunnel！**

如果这个项目对您有帮助，请给我们一个 ⭐ Star！

Made with ❤️ by the Lightweight Tunnel Team

[⬆ 返回顶部](#lightweight-tunnel---轻量级隧道)

</div>
