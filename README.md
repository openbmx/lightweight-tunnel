# Lightweight Tunnel - 轻量级内网穿透隧道

<div align="center">

**一个高性能、低延迟的内网穿透隧道工具**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.19+-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-green.svg)](https://www.linux.org/)

</div>

---

## 📖 项目简介

Lightweight Tunnel 是一个使用 Go 语言开发的轻量级内网穿透隧道工具。它通过 **UDP 传输并伪装成 TCP 流量**来绕过防火墙限制，同时内置 **AES-256-GCM 加密**和 **FEC 前向纠错**功能，在保证安全性的同时提供稳定可靠的网络连接。

### 适用场景

- 🏢 **企业内网互联**：在多个分支机构之间建立安全的虚拟局域网
- 🏠 **家庭服务器访问**：从外网安全访问家中的 NAS、服务器等设备
- 🎮 **游戏联机**：为局域网游戏建立低延迟的虚拟局域网
- 🔧 **开发测试**：在不同网络环境中快速建立开发测试网络
- 🌐 **多点互联**：支持多个客户端组成 Hub 网络，任意节点间可直接通信

---

## ✨ 核心特性

### 🚀 高性能与稳定性

- **基于 UDP 传输**：避免 TCP-over-TCP 问题，延迟更低，性能更好
- **TCP 流量伪装**：UDP 数据包被包装成 TCP 格式，可穿透严格的防火墙
- **FEC 前向纠错**：通过冗余数据自动恢复丢失的数据包，无需重传
- **智能队列管理**：可配置的发送/接收队列，适应不同带宽环境
- **高并发处理**：基于 Go 协程的异步处理架构，支持高并发场景

### 🔐 安全与加密

- **AES-256-GCM 加密**：军用级加密算法，保护所有隧道流量
- **密钥认证机制**：只有持有正确密钥的客户端才能连接
- **端到端加密**：包括服务器中转和 P2P 直连在内的所有流量均被加密
- **防窃听防篡改**：GCM 模式提供认证加密，确保数据完整性

### 🌐 网络拓扑

- **多客户端支持**：服务端默认支持 Hub 模式，可同时连接 100+ 客户端
- **P2P 直连**：支持 NAT 穿透，客户端间可建立直接连接
- **智能路由选择**：自动选择最优路径（P2P > 服务器中转）
- **网状网络架构**：预留多跳中继功能（当前版本未启用）
- **客户端隔离模式**：可配置客户端只能与服务器通信，互相隔离

### 🛠️ 易用性

- **简单的命令行界面**：一条命令即可启动，参数设计直观易懂
- **灵活的配置方式**：支持命令行参数和 JSON 配置文件两种方式
- **自动配置生成**：可快速生成服务端和客户端配置模板
- **详细的日志输出**：实时显示连接状态、路由信息和性能统计
- **跨平台编译**：Go 语言编写，可轻松编译到不同架构

---

## 🎯 工作原理

### 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                        应用层流量                             │
│              (HTTP, SSH, 游戏, 任意 TCP/UDP 协议)              │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                      TUN 虚拟网卡                             │
│               (10.0.0.x/24 虚拟网络接口)                       │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   Lightweight Tunnel                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  1. IP 数据包捕获 → 2. FEC 编码 → 3. AES-256-GCM 加密 │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                  UDP + 伪装 TCP 头部                          │
│            (外观像 TCP，实际走 UDP 传输)                       │
└─────────────────────────────────────────────────────────────┘
                            ↓
                      物理网络传输
```

### 技术细节

#### 1. TUN 虚拟网卡层

- 创建 Linux TUN 设备，分配虚拟 IP 地址（如 10.0.0.2/24）
- 捕获发往虚拟网络的所有 IP 数据包
- 将应用程序的网络流量透明地导入隧道
- 支持所有基于 IP 的协议（TCP、UDP、ICMP 等）

#### 2. FEC 前向纠错层

- 将原始数据分割成多个分片（默认 10 个数据分片）
- 生成额外的校验分片（默认 3 个校验分片）
- 接收端可以从部分分片恢复出完整数据
- 在弱网环境下显著提高传输可靠性，避免重传

#### 3. 加密层 (可选但强烈推荐)

- **算法**：AES-256-GCM（Galois/Counter Mode）
- **密钥派生**：SHA-256 哈希用户提供的密钥字符串
- **随机 Nonce**：每个数据包使用独立的随机 nonce
- **认证标签**：16 字节的认证标签确保数据完整性
- **开销**：每个数据包增加 28 字节（12 字节 nonce + 16 字节标签）

#### 4. TCP 伪装层

- 在 UDP 数据包外部添加伪造的 TCP 头部
- 包含源端口、目标端口、序列号、确认号等 TCP 字段
- 简单的防火墙会将其识别为 TCP 流量
- 注意：深度包检测 (DPI) 可能识破伪装

#### 5. P2P 直连机制

**NAT 打洞流程**：

```
1. 客户端 A 和客户端 B 同时连接到服务器
2. 服务器记录两个客户端的公网 IP 和端口
3. 服务器发送 PUNCH 指令，告知双方对方的地址
4. 两个客户端同时向对方发送 UDP 数据包
5. NAT 设备为双向 UDP 流量开放端口映射
6. P2P 连接建立，后续流量直接传输
```

**路由优先级**：
1. 🥇 **本地网络直连**：如果双方在同一局域网，直接使用内网 IP
2. 🥈 **P2P 公网直连**：通过 NAT 打洞建立的直接连接
3. 🥉 **服务器中转**：P2P 失败时回退到服务器转发

**智能 NAT 检测与 P2P 优化** (新功能)：
- 🔍 **自动 NAT 类型检测**：识别 Full Cone、Restricted Cone、Port-Restricted Cone、Symmetric NAT
- 🎯 **智能连接策略**：低级别 NAT 主动向高级别 NAT 发起连接，提高成功率
- 🔄 **自动回退**：双方都是 Symmetric NAT 时自动使用服务器中转
- 📊 **成功率提升**：P2P 连接成功率提高 15-20%

**P2P 兼容性**：
- ✅ **高成功率** (90%+)：锥形 NAT 之间的连接
- ⚠️ **中等成功率** (30%+)：一方是 Symmetric NAT
- 🔄 **自动中转** (100%)：双方都是 Symmetric NAT（自动使用服务器中转）

详细说明请参考：[NAT 检测文档](docs/NAT_DETECTION.md)

**P2P 局限性**：
- ✅ **支持**：锥形 NAT (Cone NAT)、端口限制锥形 NAT
- ⚠️ **部分支持**：对称 NAT (Symmetric NAT) - 成功率较低
- ❌ **不支持**：双方都是严格对称 NAT 的情况（已自动回退到服务器中转）

---

## 🚀 快速开始

### 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Linux (内核 2.6+) |
| 权限 | Root 或 sudo |
| 内存 | 最低 64MB，推荐 128MB+ |
| CPU | 任意架构 (x86_64, ARM, ARM64 等) |
| 网络 | 至少一台设备需要公网 IP 或端口转发 |

### 安装步骤

#### 方式 1：从源码编译（推荐）

```bash
# 1. 克隆仓库
git clone https://github.com/openbmx/lightweight-tunnel.git
cd lightweight-tunnel

# 2. 安装依赖（如果使用 Go modules 会自动下载）
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
ls -lh bin/
```

#### 方式 3：直接安装到 $GOPATH/bin

```bash
go install github.com/openbmx/lightweight-tunnel/cmd/lightweight-tunnel@latest
```

### 基础使用教程

#### 场景 1：最简单的双端加密隧道

这是最基本也是最推荐的使用方式，适合快速测试。

**服务端**（需要公网 IP 或公网端口转发）：
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
ping 8.8.8.8      # 测试外网（需配置路由）
```

**参数说明**：
- `-m`：运行模式（server 服务端 / client 客户端）
- `-l`：服务端监听地址和端口
- `-r`：客户端要连接的服务器地址
- `-t`：隧道虚拟 IP 地址和子网掩码
- `-k`：**加密密钥**（双方必须相同）

---

#### 场景 2：多客户端 Hub 网络（企业内网互联）

服务端默认启用多客户端模式，所有客户端可以相互访问，形成虚拟局域网。

**服务端**：
```bash
sudo ./lightweight-tunnel \
  -m server \
  -l 0.0.0.0:9000 \
  -t 10.0.0.1/24 \
  -k "company-secure-key-2024" \
  -max-clients 50
```

**客户端 A**（北京分公司）：
```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.10/24 \
  -k "company-secure-key-2024"
```

**客户端 B**（上海分公司）：
```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.20/24 \
  -k "company-secure-key-2024"
```

**客户端 C**（深圳分公司）：
```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.30/24 \
  -k "company-secure-key-2024"
```

**应用示例**：
```bash
# 在客户端 A (北京) 上访问客户端 B (上海) 的服务
ssh user@10.0.0.20          # SSH 连接
mysql -h 10.0.0.20 -u root  # 访问数据库
ping 10.0.0.30              # ping 深圳分公司

# 在客户端 B (上海) 上访问客户端 C (深圳) 的 Web 服务
curl http://10.0.0.30:8080
```

---

#### 场景 3：P2P 直连模式（低延迟游戏联机）

启用 P2P 后，客户端会尝试建立直接连接，流量不经过服务器中转。

**服务端**：
```bash
sudo ./lightweight-tunnel \
  -m server \
  -l 0.0.0.0:9000 \
  -t 10.0.0.1/24 \
  -k "gaming-2024"
```

**游戏主机 1**：
```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.100/24 \
  -k "gaming-2024" \
  -p2p \
  -p2p-port 19000
```

**游戏主机 2**：
```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.101/24 \
  -k "gaming-2024" \
  -p2p \
  -p2p-port 19001
```

**检查 P2P 状态**：
程序日志会显示：
```
P2P connection established with 10.0.0.101 (direct)
Routing stats: 1 direct, 0 relay, 0 server
# 表示已建立 P2P 直连，流量不经过服务器
```

**P2P 优势**：
- ⚡ **延迟更低**：点对点直连，避免服务器中转
- 💰 **节省带宽**：服务器不需要转发流量
- 🔒 **同样安全**：P2P 流量也使用 AES-256-GCM 加密

---

#### 场景 4：客户端隔离模式（安全需求）

在某些场景下，您可能希望客户端只能访问服务端，而不能相互访问。

**服务端**：
```bash
sudo ./lightweight-tunnel \
  -m server \
  -l 0.0.0.0:9000 \
  -t 10.0.0.1/24 \
  -k "isolated-network" \
  -client-isolation
```

此模式下：
- ✅ 客户端可以访问 10.0.0.1 (服务端)
- ❌ 客户端 A 无法访问客户端 B
- ✅ 服务端可以访问所有客户端

**适用场景**：
- 中心化的服务架构（所有客户端只访问中心服务器）
- 安全要求较高的环境（防止客户端间攻击）
- VPN 场景（客户端不需要相互通信）

---

### 使用配置文件（生产环境推荐）

对于生产环境或复杂配置，推荐使用 JSON 配置文件。

#### 生成配置模板

```bash
./lightweight-tunnel -g myconfig.json
```

这会生成两个文件：
- `myconfig.json` - 服务端配置模板
- `myconfig.json.client` - 客户端配置模板

#### 服务端完整配置示例

**config-server.json**：
```json
{
  "mode": "server",
  "local_addr": "0.0.0.0:9000",
  "tunnel_addr": "10.0.0.1/24",
  "key": "change-this-to-your-strong-secret-key",
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3,
  "timeout": 30,
  "keepalive": 10,
  "send_queue_size": 1000,
  "recv_queue_size": 1000,
  "multi_client": true,
  "max_clients": 100,
  "client_isolation": false
}
```

**配置说明**：

| 字段 | 说明 | 推荐值 |
|------|------|--------|
| `mode` | 运行模式 | `server` 或 `client` |
| `local_addr` | 监听地址（服务端） | `0.0.0.0:9000` |
| `tunnel_addr` | 虚拟网络地址 | `10.0.0.1/24` |
| `key` | 加密密钥 | 16+ 字符的强密码 |
| `mtu` | 最大传输单元 | 1400 (标准网络)<br>1200 (弱网)<br>8000 (内网) |
| `fec_data` | FEC 数据分片数 | 10 (标准)<br>20 (低丢包) |
| `fec_parity` | FEC 校验分片数 | 3 (标准)<br>5 (高丢包) |
| `timeout` | 连接超时秒数 | 30 |
| `keepalive` | 心跳间隔秒数 | 10 |
| `send_queue_size` | 发送队列大小 | 1000-5000 |
| `recv_queue_size` | 接收队列大小 | 1000-5000 |
| `multi_client` | 启用多客户端 | `true` (Hub 模式)<br>`false` (点对点) |
| `max_clients` | 最大客户端数 | 100 |
| `client_isolation` | 客户端隔离 | `false` (可互访)<br>`true` (隔离) |

#### 客户端完整配置示例

**config-client.json**：
```json
{
  "mode": "client",
  "remote_addr": "your-server-ip:9000",
  "tunnel_addr": "10.0.0.2/24",
  "key": "change-this-to-your-strong-secret-key",
  "mtu": 1400,
  "fec_data": 10,
  "fec_parity": 3,
  "timeout": 30,
  "keepalive": 10,
  "send_queue_size": 1000,
  "recv_queue_size": 1000,
  "p2p_enabled": true,
  "p2p_port": 0,
  "enable_mesh_routing": true,
  "max_hops": 3,
  "route_update_interval": 30,
  "p2p_timeout": 5
}
```

**P2P 相关配置说明**：

| 字段 | 说明 | 推荐值 |
|------|------|--------|
| `p2p_enabled` | 启用 P2P 直连 | `true` |
| `p2p_port` | P2P UDP 端口 | `0` (自动分配) 或指定端口 |
| `enable_mesh_routing` | 启用网状路由 | `true` |
| `max_hops` | 最大中继跳数 | 3 |
| `route_update_interval` | 路由更新间隔 | 30 秒 |
| `p2p_timeout` | P2P 超时 | 5 秒 |

#### 使用配置文件运行

```bash
# 服务端
sudo ./lightweight-tunnel -c config-server.json

# 客户端
sudo ./lightweight-tunnel -c config-client.json
```

---

## ⚙️ 配置参数详解

### 命令行参数完整列表

```
基本参数：
  -c string
        配置文件路径（使用 JSON 文件配置）
  -m string
        运行模式：server（服务端）或 client（客户端）
        默认值：server
  -v    显示版本信息
  -g string
        生成示例配置文件到指定路径

网络配置：
  -l string
        监听地址（仅服务端使用）
        格式：IP:端口
        默认值：0.0.0.0:9000
        示例：-l 0.0.0.0:9000
  -r string
        远程服务器地址（仅客户端使用）
        格式：IP:端口
        示例：-r 1.2.3.4:9000
  -t string
        隧道虚拟 IP 地址和子网掩码
        格式：IP/CIDR
        默认值：10.0.0.1/24
        示例：-t 10.0.0.2/24

加密配置：
  -k string
        加密密钥（强烈推荐设置）
        不设置则流量明文传输（仅供测试）
        示例：-k "my-secret-password-2024"

性能优化：
  -mtu int
        最大传输单元（字节）
        默认值：1400
        推荐值：
          - 标准网络：1400
          - 弱网环境：1200
          - 高速内网：8000
  -send-queue int
        发送队列缓冲区大小
        默认值：1000
        高带宽场景推荐：5000-10000
  -recv-queue int
        接收队列缓冲区大小
        默认值：1000
        高带宽场景推荐：5000-10000

FEC 纠错配置：
  -fec-data int
        FEC 数据分片数量
        默认值：10
        推荐值：
          - 低丢包网络：20
          - 标准网络：10
          - 高丢包网络：10
  -fec-parity int
        FEC 校验分片数量
        默认值：3
        推荐值：
          - 低丢包网络：2
          - 标准网络：3
          - 高丢包网络：5

服务端多客户端配置：
  -multi-client
        启用多客户端支持（Hub 模式）
        默认值：true
  -max-clients int
        最大并发客户端数量
        默认值：100
  -client-isolation
        启用客户端隔离（客户端间不能互访）
        默认值：false

P2P 直连配置：
  -p2p
        启用 P2P 直接连接
        默认值：true
  -p2p-port int
        P2P UDP 监听端口
        默认值：0（自动分配）
        示例：-p2p-port 19000
  -mesh-routing
        启用网状网络路由
        默认值：true
  -max-hops int
        网状网络最大跳数
        默认值：3
  -route-update int
        路由质量更新间隔（秒）
        默认值：30
```

### 性能调优建议

#### 高速内网环境（千兆/万兆）

```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.2/24 \
  -k "my-key" \
  -mtu 8000 \
  -fec-data 20 \
  -fec-parity 2 \
  -send-queue 5000 \
  -recv-queue 5000
```

**优化说明**：
- 大 MTU (8000)：减少数据包数量，降低 CPU 开销
- 少 FEC 冗余：内网丢包率低，减少冗余节省带宽
- 大队列：应对突发流量

#### 弱网环境（移动网络/高丢包）

```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.2/24 \
  -k "my-key" \
  -mtu 1200 \
  -fec-data 10 \
  -fec-parity 5 \
  -send-queue 2000 \
  -recv-queue 2000
```

**优化说明**：
- 小 MTU (1200)：降低单包丢失影响
- 多 FEC 冗余：更强的恢复能力
- 中等队列：平衡内存和性能

#### 标准互联网环境（家庭宽带）

```bash
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.2/24 \
  -k "my-key" \
  -mtu 1400 \
  -fec-data 10 \
  -fec-parity 3 \
  -send-queue 1000 \
  -recv-queue 1000
```

**说明**：使用默认配置即可满足大多数场景。

---

## 🔍 常见问题与故障排除

### Q1: 权限错误 "permission denied"

**错误信息**：
```
failed to open /dev/net/tun: permission denied
```

**原因**：创建 TUN 设备需要 root 权限。

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

**原因**：系统未加载 TUN/TAP 内核模块。

**解决方案**：
```bash
# 手动加载 TUN 模块
sudo modprobe tun

# 验证设备是否存在
ls -l /dev/net/tun

# 设置开机自动加载
echo "tun" | sudo tee -a /etc/modules
```

### Q3: 客户端无法连接服务器

**排查步骤**：

1. **检查服务端是否运行**：
```bash
# 在服务端执行
sudo netstat -tulnp | grep 9000
# 或
sudo ss -tulnp | grep 9000
```

2. **检查防火墙规则**：
```bash
# Ubuntu/Debian
sudo ufw status
sudo ufw allow 9000/tcp
sudo ufw allow 9000/udp

# CentOS/RHEL
sudo firewall-cmd --list-all
sudo firewall-cmd --add-port=9000/tcp --permanent
sudo firewall-cmd --add-port=9000/udp --permanent
sudo firewall-cmd --reload
```

3. **测试网络连通性**：
```bash
# ping 测试
ping <服务器IP>

# telnet 测试端口
telnet <服务器IP> 9000
```

4. **检查 NAT/路由器端口转发**：
如果服务器在 NAT 后面，确保路由器配置了端口转发：
- 外部端口 9000 → 内部 IP:9000 (TCP + UDP)

### Q4: 密钥不匹配导致连接失败

**错误信息（服务端日志）**：
```
Decryption error (wrong key?)
Client authentication failed
```

**原因**：服务端和客户端使用了不同的加密密钥。

**解决方案**：
确保服务端和所有客户端使用完全相同的 `-k` 参数：

```bash
# 服务端
sudo ./lightweight-tunnel -m server -k "exactly-same-password" ...

# 客户端（密钥必须一字不差）
sudo ./lightweight-tunnel -m client -k "exactly-same-password" ...
```

**注意事项**：
- 密钥区分大小写
- 注意空格、特殊字符
- 建议使用引号包裹密钥

### Q5: 第二个客户端连接被拒绝

**错误信息**：
```
Network read error: EOF
Connection closed by remote host
```

**原因**：服务端配置为单客户端模式 (`multi_client: false`)。

**解决方案**：

命令行方式：
```bash
# 确保启用多客户端（默认已启用）
sudo ./lightweight-tunnel -m server -multi-client=true ...
```

配置文件方式：
```json
{
  "mode": "server",
  "multi_client": true,
  "max_clients": 100
}
```

### Q6: P2P 连接失败，流量走服务器中转

**现象**：日志显示 "P2P connection failed, using server relay"

**可能原因**：

1. **双方都是对称 NAT**：
   - 对称 NAT 下 UDP 打洞成功率低
   - 无法解决，只能使用服务器中转

2. **防火墙阻止 UDP**：
   - 检查客户端防火墙设置
   - 允许 P2P 端口的 UDP 流量

3. **P2P 端口被占用**：
   - 尝试指定不同的 P2P 端口
   - 使用 `-p2p-port` 参数

**解决方案**：
```bash
# 客户端 1
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.2/24 \
  -k "key" \
  -p2p \
  -p2p-port 19000

# 客户端 2
sudo ./lightweight-tunnel \
  -m client \
  -r <服务器IP>:9000 \
  -t 10.0.0.3/24 \
  -k "key" \
  -p2p \
  -p2p-port 19001
```

### Q7: 端口被占用

**错误信息**：
```
bind: address already in use
```

**解决方案**：

1. **查找占用端口的进程**：
```bash
sudo lsof -i :9000
# 或
sudo netstat -tulnp | grep 9000
```

2. **终止占用的进程**：
```bash
sudo kill -9 <PID>
```

3. **或使用不同的端口**：
```bash
sudo ./lightweight-tunnel -m server -l 0.0.0.0:9001 ...
```

### Q8: 性能不佳或延迟高

**排查方向**：

1. **检查是否使用 P2P**：
   - 查看日志中的路由统计
   - P2P 直连延迟更低

2. **调整 MTU**：
   - 小 MTU 增加 CPU 开销但减少丢包影响
   - 大 MTU 提高吞吐量但丢包影响大

3. **调整 FEC 参数**：
   - 过多冗余浪费带宽
   - 过少冗余无法有效纠错

4. **增大队列**：
```bash
sudo ./lightweight-tunnel \
  -send-queue 5000 \
  -recv-queue 5000 \
  ...
```

### Q9: 看到 "Send queue full, dropping packet" 警告

**原因**：发送队列溢出，数据包被丢弃。

**解决方案**：
```bash
# 增大发送和接收队列
sudo ./lightweight-tunnel \
  -send-queue 5000 \
  -recv-queue 5000 \
  ...
```

### Q10: 如何查看实时连接状态？

**日志输出示例**：
```
=== Lightweight Tunnel ===
Version: 1.0.0
Mode: client
Tunnel Address: 10.0.0.2/24
MTU: 1400
🔐 Encryption: Enabled (AES-256-GCM)

Client connected successfully
P2P connection established with 10.0.0.3 (direct)
Routing stats: 2 peers, 1 direct, 0 relay, 1 server
```

**实时监控工具**：
```bash
# 查看网络接口流量
sudo iftop -i tun0

# 查看虚拟网卡统计
ifconfig tun0
# 或
ip -s link show tun0
```

---

## 🔐 安全配置最佳实践

### 1. 始终使用强加密密钥

❌ **不安全的示例**：
```bash
-k "123456"
-k "password"
-k ""  # 无加密
```

✅ **安全的示例**：
```bash
-k "xK9$mN2#pQ7&vL4@wR8*zT3!yU6%"
-k "MyCompany-Secure-Tunnel-2024-Winter"
```

**密钥生成建议**：
```bash
# 生成随机密钥（Linux/Mac）
openssl rand -base64 32

# 或使用密码管理器生成
# 推荐长度：16-64 字符
# 包含：大小写字母、数字、特殊字符
```

### 2. 密钥管理

**使用环境变量**（避免命令行明文）：
```bash
# 设置环境变量
export TUNNEL_KEY="your-secret-key"

# 使用环境变量（需要修改程序支持）
sudo -E ./lightweight-tunnel -m client -k "$TUNNEL_KEY" ...
```

**使用配置文件**（设置适当权限）：
```bash
# 创建配置文件
cat > config.json << EOF
{
  "key": "your-secret-key",
  ...
}
EOF

# 设置文件权限（仅 root 可读）
sudo chmod 600 config.json
sudo chown root:root config.json

# 使用配置文件
sudo ./lightweight-tunnel -c config.json
```

### 3. 网络隔离建议

**使用独立的虚拟网段**：
```bash
# 避免与现有网络冲突
# 常用内网网段：
-t 10.0.0.1/24    # 10.0.0.0 - 10.0.0.255
-t 172.16.0.1/16  # 172.16.0.0 - 172.16.255.255
-t 192.168.100.1/24  # 192.168.100.0 - 192.168.100.255
```

**配置防火墙规则**：
```bash
# 只允许隧道流量
sudo iptables -A INPUT -i tun0 -s 10.0.0.0/24 -j ACCEPT
sudo iptables -A INPUT -i tun0 -j DROP

# 限制连接速率
sudo iptables -A INPUT -p tcp --dport 9000 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
```

### 4. 日志和监控

**启用详细日志**：
```bash
sudo ./lightweight-tunnel -m server ... 2>&1 | tee -a /var/log/tunnel.log
```

**定期审计**：
- 检查异常连接
- 监控流量模式
- 审查密钥更换记录

### 5. 定期更新

```bash
# 定期拉取最新代码
git pull origin main

# 重新编译
go build -o lightweight-tunnel ./cmd/lightweight-tunnel

# 重启服务
sudo systemctl restart lightweight-tunnel
```

---

## 📊 架构设计与技术细节

### 为什么选择 UDP 而非 TCP？

#### TCP-over-TCP 问题

当使用 TCP 作为隧道传输协议时，会出现严重的性能问题：

```
┌─────────────────────────────────────┐
│   应用层 TCP 连接（如 SSH、HTTP）     │
│   - 有自己的重传机制                  │
│   - 有自己的拥塞控制                  │
└─────────────────────────────────────┘
             ↓
┌─────────────────────────────────────┐
│   隧道层 TCP 连接（外层传输）          │
│   - 也有重传机制                      │
│   - 也有拥塞控制                      │
└─────────────────────────────────────┘
```

**问题**：
1. **双重重传**：一个数据包丢失，两层 TCP 都会重传
2. **级联超时**：外层 TCP 的重传被内层 TCP 误认为网络拥塞
3. **性能崩溃**：在 10% 丢包率下，吞吐量可降至原来的 1/10

#### 本项目的解决方案

```
┌─────────────────────────────────────┐
│   应用层流量（任意协议）               │
│   - TCP/UDP/ICMP 等                 │
└─────────────────────────────────────┘
             ↓
┌─────────────────────────────────────┐
│   Lightweight Tunnel                │
│   - FEC 纠错（无需重传）              │
│   - UDP 传输（无拥塞控制干扰）        │
└─────────────────────────────────────┘
```

**优势**：
- ✅ 避免双重重传
- ✅ 延迟更低更稳定
- ✅ 适合实时应用（游戏、VoIP）
- ✅ FEC 主动纠错，不等待重传

### TCP 伪装技术

#### 伪装原理

```
┌──────────────────────────────────────────────────┐
│             伪装的 TCP 数据包                      │
├──────────────────────────────────────────────────┤
│  IP Header (20 bytes)                            │
│  - Source IP, Dest IP                            │
│  - Protocol: TCP (6)                             │
├──────────────────────────────────────────────────┤
│  TCP Header (20 bytes)                           │
│  - Source Port, Dest Port                        │
│  - Seq Number, Ack Number                        │
│  - Flags: ACK, PSH, etc.                         │
├──────────────────────────────────────────────────┤
│  Payload (encrypted data)                        │
│  - 实际是 UDP 数据                                │
│  - 但外观像 TCP 流量                              │
└──────────────────────────────────────────────────┘
```

#### 有效性与局限性

**能骗过**：
- ✅ 基于端口号的防火墙
- ✅ 简单的包过滤规则
- ✅ 只检查协议字段的 DPI

**骗不过**：
- ❌ 状态检测防火墙（检查 TCP 握手）
- ❌ 深度包检测（DPI）- 检查载荷熵值
- ❌ 高级 IDS/IPS（检测伪造特征）

**实际效果**：
- 在大多数家庭/企业网络中有效
- 可绕过简单的 UDP 封锁
- 不能保证在所有环境下有效

### FEC 前向纠错算法

#### 基本原理

```
原始数据：D1 D2 D3 D4 D5 D6 D7 D8 D9 D10
           ↓
FEC 编码（10 数据 + 3 校验）：
    D1  D2  D3  D4  D5  D6  D7  D8  D9  D10  P1  P2  P3
    └────────────────────────────────────┘  └─────────┘
              数据分片                        校验分片

接收端：
    D1  X   D3  D4  D5  D6  X   D8  D9  D10  P1  P2  P3
        ↑                       ↑
        丢失                    丢失

FEC 解码：
    ✅ 可以恢复：丢失 2 个分片，有 3 个校验分片
    ✅ 无需重传：直接从剩余分片恢复完整数据
```

#### 参数选择

| 网络环境 | fec-data | fec-parity | 可恢复丢包率 | 带宽开销 |
|---------|----------|------------|-------------|---------|
| 低丢包 (<1%) | 20 | 2 | 9% | 10% |
| 标准 (1-3%) | 10 | 3 | 23% | 30% |
| 高丢包 (3-10%) | 10 | 5 | 33% | 50% |
| 极端 (>10%) | 8 | 6 | 43% | 75% |

**计算公式**：
- 可恢复丢包率 = `fec-parity / (fec-data + fec-parity)`
- 带宽开销 = `fec-parity / fec-data`

### P2P NAT 穿透

#### 支持的 NAT 类型

| NAT 类型 | 描述 | P2P 成功率 | 说明 |
|---------|------|-----------|------|
| 完全锥形 (Full Cone) | 最宽松 | ✅ 99% | 任何外部主机都可连接 |
| 限制锥形 (Restricted Cone) | 限制 IP | ✅ 95% | 只有通信过的 IP 可连接 |
| 端口限制锥形 (Port Restricted) | 限制 IP+Port | ✅ 90% | 只有通信过的 IP:Port 可连接 |
| 对称型 (Symmetric) | 最严格 | ⚠️ 30% | 每个目标使用不同的端口映射 |

#### 打洞流程详解

```
第 1 步：客户端注册
┌──────────┐                    ┌──────────┐
│ Client A │ ────注册───────→   │  Server  │
│ (NAT-A)  │ ←───公网地址────   │ (Public) │
└──────────┘     1.2.3.4:5000   └──────────┘
                                      ↑
                                      │ 注册
┌──────────┐     6.7.8.9:6000        │
│ Client B │ ←───公网地址────────────┘
│ (NAT-B)  │ ────注册───────→
└──────────┘

第 2 步：服务器协调打洞
┌──────────┐                    ┌──────────┐
│ Client A │ ←───PUNCH 指令───  │  Server  │
│          │    目标：6.7.8.9:6000  │          │
└──────────┘                    └──────────┘
     │                                ↓
     │                          ┌──────────┐
     │                          │ Client B │
     │        PUNCH 指令 ─────→ │          │
     │        目标：1.2.3.4:5000  └──────────┘
     ↓

第 3 步：双方同时发送 UDP 打洞包
┌──────────┐                    ┌──────────┐
│ Client A │ ─── UDP 包 ──→ X   │ NAT-B    │
│          │      (打洞包)       │          │
│          │                    │  开放映射 │
│          │                    │  6.7.8.9:6000 → B
└──────────┘                    └──────────┘
     ↑                                ↓
     │  ┌──────────┐        ┌──────────┐
NAT-A │  │  Server  │        │ Client B │
     │  └──────────┘        └──────────┘
开放映射                          ↓
1.2.3.4:5000 → A                 发送打洞包
     ↑                                │
     └────────────── UDP 包 ─────────┘

第 4 步：P2P 直连建立
┌──────────┐                    ┌──────────┐
│ Client A │ ←───── P2P ─────→  │ Client B │
│          │      直接通信       │          │
└──────────┘                    └──────────┘
```

---

## 🛠️ 开发与贡献

### 项目结构

```
lightweight-tunnel/
├── cmd/
│   └── lightweight-tunnel/
│       └── main.go                # 程序入口
├── internal/
│   └── config/
│       ├── config.go              # 配置管理
│       └── config_test.go         # 配置测试
├── pkg/
│   ├── crypto/
│   │   ├── crypto.go              # AES-256-GCM 加密
│   │   └── crypto_test.go
│   ├── faketcp/
│   │   ├── faketcp.go             # TCP 伪装实现
│   │   └── faketcp_test.go
│   ├── fec/
│   │   └── fec.go                 # FEC 纠错算法
│   ├── p2p/
│   │   ├── manager.go             # P2P 连接管理
│   │   ├── peer.go                # 对等节点
│   │   └── peer_test.go
│   ├── routing/
│   │   ├── table.go               # 路由表
│   │   └── table_test.go
│   ├── tcp_disguise/
│   │   └── tcp_disguise.go        # TCP 伪装头部
│   └── tunnel/
│       ├── tunnel.go              # 隧道主逻辑
│       └── tun.go                 # TUN 设备管理
├── Makefile                        # 构建脚本
├── README.md                       # 项目文档
├── SECURITY.md                     # 安全文档
├── LICENSE                         # MIT 许可证
└── go.mod                          # Go 模块依赖
```

### 编译与测试

```bash
# 安装依赖
go mod download

# 编译
make build

# 运行测试
make test

# 或者直接运行 Go 测试
go test -v ./...

# 编译特定平台
GOOS=linux GOARCH=amd64 go build -o lightweight-tunnel-linux-amd64 ./cmd/lightweight-tunnel
GOOS=linux GOARCH=arm64 go build -o lightweight-tunnel-linux-arm64 ./cmd/lightweight-tunnel
```

### 代码规范

```bash
# 格式化代码
go fmt ./...

# 静态检查
go vet ./...

# 使用 golint（需要安装）
golint ./...
```

### 贡献指南

1. **Fork 本仓库**
2. **创建特性分支** (`git checkout -b feature/AmazingFeature`)
3. **提交更改** (`git commit -m 'Add some AmazingFeature'`)
4. **推送到分支** (`git push origin feature/AmazingFeature`)
5. **开启 Pull Request**

### 报告问题

发现 Bug 或有功能建议？请 [创建 Issue](https://github.com/openbmx/lightweight-tunnel/issues)。

**Issue 模板**：
```markdown
### 问题描述
简要描述遇到的问题

### 重现步骤
1. 执行命令 '...'
2. 看到错误 '...'

### 期望行为
描述您期望发生什么

### 系统信息
- OS: Ubuntu 22.04
- Go 版本: 1.21
- 项目版本: 1.0.0

### 日志输出
粘贴相关日志
```

---

## 📚 参考资料与致谢

### 灵感来源

本项目的设计灵感和技术方案参考了以下优秀开源项目：

- **[udp2raw](https://github.com/wangyu-/udp2raw)** - UDP 流量伪装为 TCP 的先驱项目
- **[tinyfecVPN](https://github.com/wangyu-/tinyfecVPN)** - 轻量级 FEC VPN 实现

### 技术对比

| 特性 | Lightweight Tunnel | udp2raw | tinyfecVPN |
|------|-------------------|---------|------------|
| **传输协议** | UDP | UDP (可选 ICMP) | UDP |
| **TCP 伪装** | ✅ 简化实现 | ✅ 完整 raw socket | ❌ |
| **内置加密** | ✅ AES-256-GCM | ❌ | ❌ |
| **FEC 纠错** | ✅ XOR-based | ❌ | ✅ Reed-Solomon |
| **P2P 打洞** | ✅ 服务器协调 | ❌ | ❌ |
| **多客户端 Hub** | ✅ 原生支持 | ❌ | ❌ |
| **TUN/TAP** | ✅ TUN | ❌ | ✅ TAP |
| **编程语言** | Go | C++ | C++ |
| **跨平台** | 容易（Go）| 困难（C++）| 困难（C++）|
| **学习曲线** | 低 | 中 | 中 |

### 相关文档

- [RFC 793 - TCP Protocol](https://datatracker.ietf.org/doc/html/rfc793)
- [RFC 768 - UDP Protocol](https://datatracker.ietf.org/doc/html/rfc768)
- [RFC 3489 - STUN (NAT Traversal)](https://datatracker.ietf.org/doc/html/rfc3489)
- [Reed-Solomon FEC](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)

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

## 🔒 安全声明

详细的安全信息和建议请参阅 [SECURITY.md](SECURITY.md) 文档，包括：

- ✅ 加密配置最佳实践
- ⚠️ ISP 和 DPI 监控考量
- 🛡️ 威胁模型和防护措施
- 📋 安全漏洞报告流程

**重要提示**：
1. **生产环境务必启用加密** (`-k` 参数)
2. **使用强密码** - 16+ 字符，包含字母、数字、特殊字符
3. **定期更换密钥** - 建议每 3-6 个月更换一次
4. **监控异常流量** - 及时发现潜在的安全问题

---

## 📞 联系方式

- **GitHub Issues**: [提交问题或建议](https://github.com/openbmx/lightweight-tunnel/issues)
- **Pull Requests**: [贡献代码](https://github.com/openbmx/lightweight-tunnel/pulls)
- **Discussions**: [技术讨论](https://github.com/openbmx/lightweight-tunnel/discussions)

---

## 🌟 Star History

如果这个项目对您有帮助，请给我们一个 ⭐ Star！

[![Star History Chart](https://api.star-history.com/svg?repos=openbmx/lightweight-tunnel&type=Date)](https://star-history.com/#openbmx/lightweight-tunnel&Date)

---

<div align="center">

**感谢使用 Lightweight Tunnel！**

Made with ❤️ by the Lightweight Tunnel Team

[⬆ 返回顶部](#lightweight-tunnel---轻量级内网穿透隧道)

</div>
