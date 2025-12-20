# Lightweight Tunnel - 轻量级隧道

<div align="center">

**基于 Go 语言开发的高性能、低延迟内网穿透工具**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.19+-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-green.svg)](https://www.linux.org/)

[功能特性](#-功能特性) • [快速开始](#-快速开始) • [使用指南](#-使用指南) • [技术架构](#-技术架构) • [常见问题](#-常见问题)

</div>

---

## 📖 项目简介

Lightweight Tunnel 是一个专业的内网穿透和虚拟组网工具，采用 Go 语言开发。项目的核心目标是提供**真正的 TCP 伪装能力**，通过 Raw Socket 技术构造完整的 TCP/IP 数据包，在保持高性能的同时，有效绕过防火墙和深度包检测（DPI）。

### 核心特点

- 🔥 **真实 TCP 伪装**：使用 Raw Socket 技术，构造完整的 TCP/IP 数据包，实现协议层面的真实伪装
- 🚀 **高性能设计**：基于 UDP 核心避免 TCP-over-TCP 问题，配合 FEC 前向纠错保证传输质量
- 🔐 **军用级加密**：AES-256-GCM 端到端加密，所有隧道流量均得到保护
- 🌐 **智能 P2P 直连**：支持 NAT 穿透，客户端间可建立点对点连接，降低延迟
- 🛠️ **自适应网络**：自动 MTU 检测，智能识别网络类型并优化参数
- 🔄 **自动重连机制**：客户端断线后自动重连，无需人工干预
- 📦 **简单易用**：极简配置，支持命令行和配置文件两种方式

### 适用场景

- 🏢 **企业内网互联** - 在多个分支机构之间建立安全的虚拟局域网
- 🏠 **家庭服务器访问** - 从外网安全访问家中的 NAS、服务器等设备
- 🎮 **游戏联机** - 为局域网游戏建立低延迟的虚拟局域网
- 🔧 **开发测试** - 在不同网络环境中快速建立开发测试网络
- 🌐 **多点互联** - 支持多个客户端组成 Mesh 网络，任意节点间可直接通信
- 🔥 **突破封锁** - 真正伪装成 TCP 流量，绕过严格的防火墙和 DPI 检测

---

## ✨ 功能特性

### 🔥 真实 TCP 伪装（Raw Socket 模式）

本项目最核心的特性是**真正的 TCP 流量伪装**，技术实现类似 udp2raw：

#### 技术实现

- ✅ 使用 Raw Socket 构造完整的 IP/TCP 数据包
- ✅ 在网络层就是真实的 TCP 协议（IP 协议号 = 6）
- ✅ 实现完整的 TCP 三次握手（SYN、SYN-ACK、ACK）
- ✅ 维护真实的 TCP 序列号和确认号
- ✅ 包含完整的 TCP 选项（MSS、SACK、Window Scale、Timestamp）
- ✅ 正确计算 TCP 校验和和 IP 校验和
- ✅ 自动管理 iptables 规则，阻止内核发送 RST 包
- ✅ **可完美绕过严格的 TCP-only 防火墙和 DPI 检测**

#### 对比传统方案

```
传统 UDP 假装 TCP（容易被识别）:
UDP 包 → [UDP Header (协议=17) + 伪造的 TCP 头 + 数据]
         ↓
      防火墙检测到协议号是 UDP，容易识别

本项目（完美伪装）:
Raw Socket → [IP Header (协议=6) + 真实 TCP Header + 数据]
             ↓
          在网络层就是标准 TCP 流量，无法区分
```

**注意**：Raw Socket 模式需要 **root 权限**运行。

### 🚀 高性能架构

#### 避免 TCP-over-TCP 问题

TCP-over-TCP 是隧道技术中的经典问题：

```
问题场景：
应用层 TCP → 隧道层 TCP → 网络传输
         ↓         ↓
      重传机制   重传机制      → 双重重传导致性能崩溃
      拥塞控制   拥塞控制      → 拥塞控制相互干扰

本项目方案：
应用层流量 → FEC 前向纠错 → Raw TCP 伪装 → 网络传输
            ↓
        主动纠错，无重传开销，延迟更低更稳定
```

#### 性能优势

- **低延迟**：避免双重重传，延迟更稳定
- **高吞吐**：FEC 主动纠错，无需等待重传
- **适合实时应用**：游戏、VoIP、视频会议等场景表现优秀
- **智能队列管理**：默认 5000 大小的发送/接收队列，防止队列溢出
- **自动重连**：客户端断线后自动重连，无需人工干预

### 🔄 可靠性保障

#### 自动重连机制

客户端内置智能重连功能，确保连接稳定性：

- ✅ **自动检测断线**：实时监测连接状态，快速发现问题
- ✅ **指数退避重试**：1s → 2s → 4s → 8s → 16s → 32s（最大间隔）
- ✅ **无限期重试**：持续尝试重连，直到成功或用户手动停止
- ✅ **透明恢复**：重连成功后立即恢复数据传输，应用层无感知
- ✅ **完善日志**：详细记录重连过程，便于问题诊断

适用场景：
- 🔧 服务器临时维护重启
- 🌐 网络波动或临时中断
- 🔥 防火墙规则临时调整
- 📡 移动网络在不同基站间切换

### 🔐 安全加密

- **算法**：AES-256-GCM（Galois/Counter Mode）
- **密钥派生**：SHA-256 哈希用户提供的密钥字符串
- **随机 Nonce**：每个数据包使用独立的随机 nonce，确保安全性
- **认证标签**：16 字节的认证标签确保数据完整性和真实性
- **端到端加密**：包括 P2P 直连在内的所有流量均被加密
- **密钥轮换**：服务端支持定期自动轮换密钥，提升安全性

### 🌐 智能路由与 P2P

#### P2P 直连机制

```
第 1 步：客户端注册到服务器，获取公网地址
第 2 步：服务器协调 NAT 打洞，广播对等节点信息
第 3 步：双方同时发送 UDP 打洞包建立连接
第 4 步：P2P 直连建立成功，后续流量不经过服务器
```

#### 路由优先级

1. 🥇 **本地网络直连** - 如果在同一局域网，直接使用内网 IP
2. 🥈 **P2P 公网直连** - 通过 NAT 打洞建立的点对点连接
3. 🥉 **服务器中转** - P2P 失败时自动回退到服务器转发

#### NAT 类型兼容性

| NAT 类型 | P2P 成功率 | 说明 |
|---------|-----------|------|
| 完全锥形 (Full Cone) | ✅ 99% | 任何外部主机都可连接 |
| 限制锥形 (Restricted Cone) | ✅ 95% | 只有通信过的 IP 可连接 |
| 端口限制锥形 (Port Restricted) | ✅ 90% | 只有通信过的 IP:Port 可连接 |
| 对称型 (Symmetric) | ⚠️ 30% | 自动回退到服务器中转 |

#### NAT 类型检测

- **自动检测**：启动时自动检测本地 NAT 类型
- **智能决策**：根据双方 NAT 类型决定是否尝试 P2P
- **优先级策略**：NAT 类型较好的一方主动发起连接

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
FEC 编码：+ 3 个校验分片 = 13 个总分片
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
- **权限**：Root（必需，用于 Raw Socket 和 TUN 设备）
- **内存**：最低 64MB，推荐 128MB+
- **网络**：至少一台设备需要公网 IP 或端口转发
- **Go 版本**（编译需要）：Go 1.19+

### 安装方式

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

# 安装依赖
make install

# 运行测试
make test
```

#### 方式 3：注册为 systemd 服务

```bash
# 先构建
make build

# 安装为 systemd 服务，指定配置文件路径与服务名
sudo make install-service \
  CONFIG_PATH=/etc/lightweight-tunnel/config-server.json \
  SERVICE_NAME=lightweight-tunnel-server

# 说明：
# - CONFIG_PATH 必填，必须是绝对路径
# - 服务默认以 lightweight-tunnel 系统用户运行（自动创建）
# - systemd 单元仅授予 CAP_NET_ADMIN 与 CAP_NET_RAW 权限
# - 启用了 PrivateTmp/ProtectHome 等安全隔离设置

# 配置文件权限示例：
sudo mkdir -p /etc/lightweight-tunnel
sudo chown root:lightweight-tunnel /etc/lightweight-tunnel/*.json
sudo chmod 640 /etc/lightweight-tunnel/*.json

# 启动服务
sudo systemctl start lightweight-tunnel-server

# 查看状态
sudo systemctl status lightweight-tunnel-server

# 开机自启（已自动配置）
sudo systemctl enable lightweight-tunnel-server

# 查看日志
sudo journalctl -u lightweight-tunnel-server -f
```

#### 方式 4：一键更新脚本

```bash
# 在仓库根目录执行
./mupdate

# 功能：
# - 自动 git pull 拉取最新代码
# - 自动 make build 编译
# - 自动替换 /usr/local/bin/lightweight-tunnel

# 注意：如果服务正在运行，更新后请重启对应的 systemd 服务
sudo systemctl restart lightweight-tunnel-server
```

---

## 📖 使用指南

### 基础使用场景

#### 场景 1：最简单的点对点隧道（推荐新手）

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

# 在服务端执行
ping 10.0.0.2    # ping 客户端的虚拟 IP
```

#### 场景 2：多客户端 Hub 网络

**服务端**：

```bash
sudo ./lightweight-tunnel \
  -m server \
  -l 0.0.0.0:9000 \
  -t 10.0.0.1/24 \
  -k "company-key-2024" \
  -multi-client \
  -max-clients 100
```

**客户端 A**（北京办公室）：

```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.10/24 \
  -k "company-key-2024"
```

**客户端 B**（上海办公室）：

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

程序会自动尝试建立 P2P 连接，成功后流量不经过服务器，延迟更低。

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
  "config_push_interval": 600,
  "multi_client": true,
  "max_clients": 100,
  "client_isolation": false
}
```

**配置说明**：

| 参数 | 说明 | 默认值 |
|-----|------|--------|
| `mode` | 运行模式（server 或 client） | 必填 |
| `local_addr` | 服务端监听地址 | 0.0.0.0:9000 |
| `tunnel_addr` | 虚拟网络 IP 地址（CIDR 格式） | 必填 |
| `key` | 加密密钥（双方必须一致） | 空（不加密） |
| `mtu` | 最大传输单元（0=自动检测） | 1400 |
| `tun_name` | TUN 设备名称（空=自动） | 自动 |
| `routes` | 宣告给对端的 CIDR 路由列表 | [] |
| `config_push_interval` | 服务端定期下发新配置/密钥的间隔（秒，0=关闭） | 0 |
| `multi_client` | 启用多客户端支持 | true |
| `max_clients` | 最大客户端数 | 100 |
| `client_isolation` | 客户端隔离（客户端间不能通信） | false |

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
    "192.168.1.0/24"
  ],
  "p2p_enabled": true,
  "p2p_port": 19000,
  "enable_nat_detection": true
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
        服务端定期下发新配置/密钥的间隔（秒，0=关闭，默认：0）
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

### 高级功能

#### 动态密钥轮换

服务端可以定期自动生成新密钥并推送给所有客户端，提升安全性：

```bash
# 服务端启用密钥轮换（每 10 分钟轮换一次）
sudo ./lightweight-tunnel \
  -m server \
  -l 0.0.0.0:9000 \
  -t 10.0.0.1/24 \
  -k "initial-key-2024" \
  -config-push-interval 600
```

特性：
- 服务端自动生成随机密钥并推送给所有客户端
- 客户端自动切换到新密钥并重连
- 旧密钥在 15 秒的宽限期后失效
- 如果使用配置文件启动，新密钥会自动写回配置文件

#### 路由宣告

可以向对端宣告本地可达的网段，自动建立路由：

```bash
# 客户端宣告本地网段
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.2/24 \
  -k "my-key" \
  -routes "192.168.1.0/24,192.168.2.0/24"
```

服务端会自动接收并安装这些路由，发往这些网段的流量会通过隧道转发给该客户端。

#### 指定 TUN 设备名称

默认情况下，系统会自动分配 TUN 设备名称（tun0、tun1 等）。你可以手动指定：

```bash
sudo ./lightweight-tunnel \
  -m server \
  -t 10.0.0.1/24 \
  -tun-name mytun0
```

注意：如果名称冲突或非法，会自动退回系统分配的名称。

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

优化点：
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

优化点：
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

优化点：
- 启用自动 MTU 检测适应网络变化

### 安全配置

#### 生成强密钥

```bash
# 使用 OpenSSL 生成随机密钥
openssl rand -base64 32

# 或使用 /dev/urandom
head -c 32 /dev/urandom | base64

# 推荐长度：32-64 字符
# 包含：大小写字母、数字、特殊字符
```

#### 配置文件权限

```bash
# 创建配置文件
sudo nano /etc/lightweight-tunnel/config.json

# 设置权限（仅 root 可读）
sudo chmod 600 /etc/lightweight-tunnel/config.json
sudo chown root:root /etc/lightweight-tunnel/config.json
```

#### 防火墙配置

```bash
# Ubuntu/Debian (使用 ufw)
sudo ufw allow 9000/tcp
sudo ufw allow 9000/udp

# CentOS/RHEL (使用 firewalld)
sudo firewall-cmd --add-port=9000/tcp --permanent
sudo firewall-cmd --add-port=9000/udp --permanent
sudo firewall-cmd --reload

# 或直接使用 iptables
sudo iptables -A INPUT -p tcp --dport 9000 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 9000 -j ACCEPT
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

# 或者给予二进制文件 CAP_NET_RAW 和 CAP_NET_ADMIN 权限
sudo setcap cap_net_raw,cap_net_admin=eip ./lightweight-tunnel
./lightweight-tunnel -m server ...
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
# 或
sudo ss -tulnp | grep 9000
```

2. **检查防火墙**：
```bash
sudo ufw status
sudo ufw allow 9000
```

3. **测试连通性**：
```bash
# 测试网络连通性
ping <服务器IP>

# 测试端口连通性
telnet <服务器IP> 9000
# 或
nc -zv <服务器IP> 9000
```

4. **检查日志**：
```bash
# 服务端日志
sudo journalctl -u lightweight-tunnel-server -n 50

# 客户端运行时日志
sudo ./lightweight-tunnel -m client ... # 查看输出
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
- 使用引号包裹密钥：`-k "my key with spaces"`
- 检查配置文件中的密钥是否一致

### Q5: MTU 应该设置多少？

**推荐配置**：

```bash
# 最简单：自动检测（推荐）
-mtu 0

# 标准网络（以太网）
-mtu 1371

# 移动网络/弱网
-mtu 1200

# PPPoE 网络
-mtu 1343

# 如果不确定，使用自动检测
-mtu 0
```

### Q6: 发送队列满错误

**错误信息**：
```
Send queue full, dropping packet
```

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
- P2P 端口被占用（指定不同端口：`-p2p-port 19001`）
- 网络环境不支持 UDP 打洞

**不影响使用**：P2P 失败时会自动使用服务器中转，功能不受影响。

### Q8: 客户端掉线后会自动重连吗？

**是的！** 客户端具有自动重连功能：

**工作原理**：
- 客户端检测到连接断开后，会自动尝试重新连接服务器
- 使用指数退避策略：1秒、2秒、4秒、8秒、16秒、最多32秒
- 客户端会持续重连，直到成功或用户手动停止程序
- 重连成功后，隧道立即恢复正常工作
- P2P 连接也会自动重新建立

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
Routing stats: 2 peers, 1 direct, 0 relay, 1 server
```

使用系统工具监控：

```bash
# 查看网卡流量
sudo iftop -i tun0

# 查看网卡统计
ip -s link show tun0

# 查看路由表
ip route

# 查看进程状态
ps aux | grep lightweight-tunnel

# 查看 systemd 服务状态
sudo systemctl status lightweight-tunnel-server
```

### Q10: 如何测试 P2P 是否成功建立？

查看日志中的路由统计信息：

```bash
# 在客户端日志中查找
Routing stats: X peers, Y direct, Z relay, W server
  Peer 10.0.0.X: route=P2P-DIRECT quality=100 status=connected
```

- `P2P-DIRECT`：P2P 直连成功
- `SERVER-RELAY`：通过服务器中转
- `status=connected`：连接已建立

---

## 🔒 安全声明

### 重要提示

1. **生产环境务必启用加密**（`-k` 参数）
2. **使用强密码** - 32+ 字符，包含大小写、数字、特殊字符
3. **定期更换密钥** - 建议每 3-6 个月更换一次，或使用自动轮换功能
4. **保护配置文件** - 设置适当的文件权限（600 或 640）
5. **监控异常流量** - 及时发现潜在的安全问题
6. **限制服务器访问** - 使用防火墙规则限制只有授权 IP 可以连接

### 威胁模型

**项目可以防御**：
- ✅ 防止 ISP 查看流量内容（通过加密）
- ✅ 防止 DPI 识别协议类型（通过 TCP 伪装）
- ✅ 防止未授权连接（通过密钥认证）
- ✅ 防止中间人攻击（通过 GCM 认证加密）

**项目不能防御**：
- ⚠️ 不能防止高级流量分析（行为特征、流量模式）
- ⚠️ 不能防止端点被入侵
- ⚠️ 不能防止密钥泄露后的攻击
- ⚠️ 不能完全隐藏正在使用 VPN/隧道的事实

### 最佳安全实践

1. **密钥管理**：
   - 使用密码管理器生成和存储密钥
   - 不要在命令行中直接输入密钥（使用配置文件）
   - 使用自动密钥轮换功能

2. **网络隔离**：
   - 服务端放在专用的 VPS 或服务器上
   - 使用防火墙限制只允许必要的端口和 IP

3. **监控和日志**：
   - 定期检查日志文件
   - 监控异常连接和流量模式
   - 使用 systemd 的日志功能

4. **更新维护**：
   - 定期更新到最新版本
   - 关注安全公告
   - 使用 `./mupdate` 脚本快速更新

---

## 🛠️ 技术架构

### 项目结构

```
lightweight-tunnel/
├── cmd/                        # 应用程序入口
│   └── lightweight-tunnel/     # 主程序
│       └── main.go            # 主函数，命令行参数解析
├── internal/                   # 内部包（不对外暴露）
│   └── config/                # 配置管理
│       ├── config.go          # 配置结构和加载/保存
│       └── config_test.go     # 配置测试
├── pkg/                        # 公共包（可被外部引用）
│   ├── crypto/                # 加密模块
│   │   ├── crypto.go          # AES-256-GCM 实现
│   │   └── crypto_test.go     # 加密测试
│   ├── faketcp/               # TCP 伪装模块
│   │   ├── faketcp.go         # 接口定义
│   │   ├── faketcp_raw.go     # Raw Socket 实现
│   │   ├── adapter.go         # 适配器接口
│   │   └── *_test.go          # 测试文件
│   ├── rawsocket/             # 原始套接字
│   │   └── rawsocket.go       # 底层 Raw Socket 操作
│   ├── fec/                   # FEC 前向纠错
│   │   └── fec.go             # Reed-Solomon 编码
│   ├── iptables/              # iptables 规则管理
│   │   └── iptables.go        # 添加/删除 iptables 规则
│   ├── p2p/                   # P2P 连接管理
│   │   ├── manager.go         # P2P 管理器
│   │   ├── peer.go            # 对等节点信息
│   │   └── *_test.go          # 测试文件
│   ├── nat/                   # NAT 类型检测
│   │   ├── nat.go             # NAT 类型检测实现
│   │   └── nat_test.go        # NAT 测试
│   ├── routing/               # 路由表管理
│   │   ├── table.go           # 智能路由表
│   │   └── table_test.go      # 路由测试
│   └── tunnel/                # 隧道核心逻辑
│       ├── tunnel.go          # 隧道主逻辑
│       ├── tun.go             # TUN 设备管理
│       ├── mtu_discovery.go   # MTU 自动检测
│       └── *_test.go          # 测试文件
├── docs/                       # 文档目录
│   ├── N2N_ANALYSIS.md        # N2N 架构分析
│   ├── P2P_FIXES_SUMMARY.md   # P2P 修复总结
│   └── P2P_OPTIMIZATION.md    # P2P 优化文档
├── Makefile                    # 构建脚本
├── go.mod                      # Go 模块定义
├── README.md                   # 本文档
├── SECURITY.md                 # 安全政策
├── LICENSE                     # MIT 许可证
└── mupdate                     # 一键更新脚本
```

### 核心模块说明

#### 1. crypto 模块
- 实现 AES-256-GCM 加密
- 提供加密/解密接口
- 自动生成随机 nonce
- 包含认证标签验证

#### 2. faketcp 模块
- 提供 TCP 伪装的统一接口
- Raw Socket 模式实现真正的 TCP 伪装
- 实现 TCP 三次握手和状态管理
- 自动管理 iptables 规则

#### 3. rawsocket 模块
- 底层 Raw Socket 操作
- 构造和解析 IP/TCP 数据包
- 计算校验和
- 发送和接收原始数据包

#### 4. fec 模块
- Reed-Solomon 纠错码实现
- 支持可配置的数据/校验分片比例
- 在弱网环境下提供可靠传输

#### 5. p2p 模块
- P2P 连接管理和维护
- NAT 打洞实现
- 对等节点信息管理
- 自动重连机制

#### 6. nat 模块
- NAT 类型检测（Full Cone、Restricted、Port Restricted、Symmetric）
- 基于 STUN 协议
- 为 P2P 连接提供决策依据

#### 7. routing 模块
- 智能路由表管理
- 支持直连、中转、服务器转发三种路由类型
- 路由质量评估和自动切换
- 网格路由支持

#### 8. tunnel 模块
- 隧道核心逻辑
- TUN 设备管理
- 数据包路由和转发
- 多客户端管理
- 自动重连
- MTU 自动检测

### 技术细节

#### 为什么使用 Raw Socket 而非 UDP？

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

#### 为什么基于 UDP 核心而非 TCP？

避免 **TCP-over-TCP 问题**：

- TCP 隧道中的 TCP 应用会导致双重重传
- 在丢包环境下性能急剧下降
- 延迟变化大，不适合实时应用
- 拥塞控制相互干扰

**本项目方案**：
- 使用 UDP 语义作为传输核心（伪装成 TCP）
- FEC 主动纠错代替重传
- 延迟低且稳定
- 适合实时应用

#### FEC 工作原理

```
编码过程：
原始数据 [D1][D2][D3][D4][D5][D6][D7][D8][D9][D10]
         ↓ Reed-Solomon 编码（10 数据 + 3 校验）
发送包   [D1][D2][D3][D4][D5][D6][D7][D8][D9][D10][P1][P2][P3]

解码过程：
收到包   [D1][  ][D3][D4][D5][D6][  ][D8][D9][D10][P1][P2][P3]
         ↓ Reed-Solomon 解码（丢失 2 个可恢复）
恢复数据 [D1][D2][D3][D4][D5][D6][D7][D8][D9][D10]
```

优点：
- 无需等待重传，降低延迟
- 可以抵抗一定比例的丢包
- 适合实时应用

#### P2P 连接建立过程

```
步骤 1：客户端 A 和 B 连接到服务器
   A --> [Server] <-- B

步骤 2：服务器告知 A 和 B 对方的公网地址
   A <-- [Server] --> B
   (收到对方的 IP:Port)

步骤 3：A 和 B 同时向对方发送 UDP 打洞包
   A --UDP--> [NAT A] ---> [NAT B] <--UDP-- B
            (打洞包)      (打洞包)

步骤 4：NAT 被打开，P2P 连接建立
   A <--P2P直连--> B
   (后续流量不经过服务器)
```

NAT 类型对 P2P 的影响：
- Full Cone NAT：最容易打洞
- Restricted Cone NAT：较容易打洞
- Port Restricted Cone NAT：可以打洞
- Symmetric NAT：双方都是时无法打洞，需要服务器中转

---

## 🧪 开发与测试

### 编译和测试

```bash
# 克隆仓库
git clone https://github.com/openbmx/lightweight-tunnel.git
cd lightweight-tunnel

# 安装依赖
go mod download

# 编译
make build

# 运行所有测试
make test

# 或直接使用 go test
go test -v ./...

# 运行特定包的测试
go test -v ./pkg/crypto
go test -v ./pkg/p2p

# 运行性能测试
go test -bench=. ./pkg/crypto
```

### 贡献指南

我们欢迎所有形式的贡献！

1. **报告问题**：
   - 在 GitHub Issues 中提交 bug 报告
   - 提供详细的错误信息和重现步骤
   - 包含系统环境信息

2. **提交代码**：
   - Fork 本仓库
   - 创建特性分支 (`git checkout -b feature/AmazingFeature`)
   - 编写清晰的提交信息
   - 确保所有测试通过
   - 提交 Pull Request

3. **代码规范**：
   - 遵循 Go 语言标准格式（使用 `gofmt`）
   - 为新功能添加测试
   - 更新相关文档

### 开发环境设置

```bash
# 安装 Go（版本 >= 1.19）
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# 验证安装
go version

# 配置 Go 代理（中国大陆用户）
go env -w GOPROXY=https://goproxy.cn,direct

# 安装开发工具
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

---

## 📚 参考资源

### 相关项目

本项目的设计灵感和技术方案参考了以下优秀开源项目：

- **[udp2raw](https://github.com/wangyu-/udp2raw)** - UDP 流量伪装为 TCP 的先驱项目，本项目 Raw Socket 实现的灵感来源
- **[tinyfecVPN](https://github.com/wangyu-/tinyfecVPN)** - 轻量级 FEC VPN 实现，FEC 模块参考
- **[n2n](https://github.com/ntop/n2n)** - 去中心化的 P2P VPN，P2P 架构参考

### 技术文档

- [Go 语言官方文档](https://go.dev/doc/)
- [Linux 网络编程](https://man7.org/linux/man-pages/man7/raw.7.html)
- [TCP/IP 协议详解](https://www.rfc-editor.org/rfc/rfc793)
- [Reed-Solomon 纠错码](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)
- [STUN 协议](https://www.rfc-editor.org/rfc/rfc5389)

### 学习资源

- [Go 网络编程](https://www.golang-book.com/books/intro)
- [Linux Raw Socket 编程](https://man7.org/linux/man-pages/man7/raw.7.html)
- [NAT 穿透技术](https://en.wikipedia.org/wiki/NAT_traversal)

---

## 📄 开源协议

本项目采用 [MIT License](LICENSE) 开源协议。

```
MIT License

Copyright (c) 2024 openbmx

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 📞 联系方式

- **GitHub Issues**: [提交问题或建议](https://github.com/openbmx/lightweight-tunnel/issues)
- **Pull Requests**: [贡献代码](https://github.com/openbmx/lightweight-tunnel/pulls)
- **Discussions**: [讨论区](https://github.com/openbmx/lightweight-tunnel/discussions)

---

## 🙏 致谢

感谢以下开源项目和贡献者：

- **udp2raw** - 提供了 TCP 伪装的实现思路
- **tinyfecVPN** - FEC 实现参考
- **n2n** - P2P 网络架构参考
- 所有为本项目贡献代码和建议的开发者

---

## 📝 更新日志

### v1.0.0 (最新版本)

**新功能**：
- ✨ 实现 Raw Socket 真实 TCP 伪装
- ✨ 支持多客户端 Hub 模式
- ✨ P2P 直连和 NAT 穿透
- ✨ AES-256-GCM 加密
- ✨ 自动 MTU 检测
- ✨ FEC 前向纠错
- ✨ 自动重连机制
- ✨ 动态密钥轮换
- ✨ 路由宣告功能
- ✨ systemd 服务支持

**改进**：
- 🚀 优化队列管理，默认队列从 1000 增加到 5000
- 🚀 改进 P2P 连接逻辑和 NAT 类型检测
- 🚀 增强错误处理和日志记录
- 🚀 优化重连策略

**修复**：
- 🐛 修复队列满导致的丢包问题
- 🐛 修复 P2P 连接建立的时序问题
- 🐛 修复加密数据包分片问题

---

<div align="center">

**感谢使用 Lightweight Tunnel！**

如果这个项目对您有帮助，请给我们一个 ⭐ Star！

Made with ❤️ by the Lightweight Tunnel Team

[⬆ 返回顶部](#lightweight-tunnel---轻量级隧道)

</div>
