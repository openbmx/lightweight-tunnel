# 项目结构说明（中文）

## 概述

本文档详细说明 Lightweight Tunnel 项目的目录结构和各模块的功能。

## 目录结构

```
lightweight-tunnel/
├── cmd/                        # 应用程序入口
│   └── lightweight-tunnel/     # 主程序
│       └── main.go            # 主函数，命令行参数解析，程序启动逻辑
│
├── internal/                   # 内部包（仅供项目内部使用）
│   └── config/                # 配置管理
│       ├── config.go          # 配置结构定义、加载和保存
│       └── config_test.go     # 配置功能测试
│
├── pkg/                        # 公共包（可被外部项目引用）
│   ├── crypto/                # 加密模块
│   │   ├── crypto.go          # AES-256-GCM 加密/解密实现
│   │   └── crypto_test.go     # 加密功能测试
│   │
│   ├── faketcp/               # TCP 伪装模块
│   │   ├── faketcp.go         # 接口定义和基础实现
│   │   ├── faketcp_raw.go     # Raw Socket 实现（真正的TCP伪装）
│   │   ├── adapter.go         # 适配器接口，统一不同传输模式
│   │   └── *_test.go          # 测试文件
│   │
│   ├── rawsocket/             # 原始套接字模块
│   │   └── rawsocket.go       # 底层 Raw Socket 操作，构造/解析 TCP/IP 包
│   │
│   ├── fec/                   # FEC 前向纠错模块
│   │   └── fec.go             # Reed-Solomon 编码实现
│   │
│   ├── iptables/              # iptables 规则管理
│   │   └── iptables.go        # 自动添加/删除 iptables 规则
│   │
│   ├── p2p/                   # P2P 连接管理模块
│   │   ├── manager.go         # P2P 管理器，处理 NAT 打洞和连接维护
│   │   ├── peer.go            # 对等节点信息和状态管理
│   │   └── *_test.go          # 测试文件
│   │
│   ├── nat/                   # NAT 类型检测模块
│   │   ├── nat.go             # NAT 类型检测实现（STUN 协议）
│   │   └── nat_test.go        # NAT 检测测试
│   │
│   ├── routing/               # 路由表管理模块
│   │   ├── table.go           # 智能路由表，选择最优路径
│   │   └── table_test.go      # 路由功能测试
│   │
│   └── tunnel/                # 隧道核心逻辑模块
│       ├── tunnel.go          # 隧道主逻辑，数据包处理和转发
│       ├── tun.go             # TUN 设备管理
│       ├── mtu_discovery.go   # MTU 自动检测
│       └── *_test.go          # 测试文件
│
├── docs/                       # 文档目录
│   ├── N2N_ANALYSIS.md        # N2N 架构分析（英文技术文档）
│   ├── P2P_FIXES_SUMMARY.md   # P2P 修复总结（英文技术文档）
│   ├── P2P_OPTIMIZATION.md    # P2P 优化文档（英文技术文档）
│   └── PROJECT_STRUCTURE_CN.md # 项目结构说明（本文档）
│
├── Makefile                    # 构建脚本
├── go.mod                      # Go 模块定义
├── go.sum                      # 依赖校验和
├── README.md                   # 项目主文档（中文）
├── SECURITY.md                 # 安全政策
├── LICENSE                     # MIT 许可证
├── .gitignore                  # Git 忽略规则
└── mupdate                     # 一键更新脚本
```

## 模块详解

### 1. cmd/lightweight-tunnel

**功能**：应用程序入口点

**主要职责**：
- 解析命令行参数
- 加载配置文件
- 初始化隧道实例
- 处理系统信号（优雅退出）

**关键代码**：
- `main.go`：主函数，程序启动流程

### 2. internal/config

**功能**：配置管理

**主要职责**：
- 定义配置结构（Config）
- 从 JSON 文件加载配置
- 保存配置到 JSON 文件
- 配置验证和默认值设置
- 支持动态密钥更新

**关键代码**：
- `Config` 结构体：包含所有配置项
- `LoadConfig()`：加载配置文件
- `SaveConfig()`：保存配置文件
- `UpdateConfigKey()`：更新密钥

### 3. pkg/crypto

**功能**：AES-256-GCM 加密

**主要职责**：
- 提供加密和解密接口
- 使用 SHA-256 派生密钥
- 自动生成随机 nonce
- 提供认证标签验证

**技术细节**：
- 算法：AES-256-GCM
- 密钥长度：256 位
- Nonce 长度：12 字节（随机生成）
- 认证标签：16 字节

**关键代码**：
- `NewCipher()`：创建加密器
- `Encrypt()`：加密数据
- `Decrypt()`：解密数据
- `Overhead()`：获取加密开销大小

### 4. pkg/faketcp

**功能**：TCP 伪装

**主要职责**：
- 使用 Raw Socket 构造真实的 TCP/IP 数据包
- 实现 TCP 三次握手
- 维护 TCP 连接状态
- 自动管理 iptables 规则（阻止内核 RST）
- 提供统一的连接接口

**技术细节**：
- 使用 Raw Socket（需要 root 权限）
- IP 协议号 = 6（TCP）
- 完整的 TCP 选项（MSS、SACK、Window Scale、Timestamp）
- 正确计算 TCP/IP 校验和

**关键代码**：
- `faketcp.go`：接口定义
- `faketcp_raw.go`：Raw Socket 实现
- `adapter.go`：适配器模式

### 5. pkg/rawsocket

**功能**：原始套接字操作

**主要职责**：
- 创建和管理 Raw Socket
- 构造 IP 和 TCP 头部
- 计算校验和
- 发送和接收原始数据包

**技术细节**：
- 使用 syscall 直接操作 socket
- 设置 IP_HDRINCL 选项
- 构造完整的 IP/TCP 数据包

**关键代码**：
- `NewRawSocket()`：创建原始套接字
- `BuildIPHeader()`：构造 IP 头部
- `BuildTCPHeader()`：构造 TCP 头部
- `CalculateChecksum()`：计算校验和
- `SendPacket()`：发送数据包
- `RecvPacket()`：接收数据包

### 6. pkg/fec

**功能**：FEC 前向纠错

**主要职责**：
- 使用 Reed-Solomon 编码
- 提供数据分片和校验分片
- 从部分分片恢复完整数据

**技术细节**：
- Reed-Solomon 纠错码
- 可配置的数据/校验分片比例
- 支持丢包恢复

**关键代码**：
- `NewFEC()`：创建 FEC 编码器
- `Encode()`：编码数据
- `Decode()`：解码数据

### 7. pkg/iptables

**功能**：iptables 规则管理

**主要职责**：
- 自动添加 iptables 规则
- 阻止内核发送 RST 包
- 程序退出时自动清理规则

**技术细节**：
- 使用 `iptables` 命令
- 添加 DROP 规则
- 跟踪已添加的规则

**关键代码**：
- `NewIPTablesManager()`：创建管理器
- `AddDropRSTRule()`：添加 RST 阻止规则
- `Cleanup()`：清理规则

### 8. pkg/p2p

**功能**：P2P 连接管理

**主要职责**：
- NAT 打洞（UDP hole punching）
- P2P 连接建立和维护
- 对等节点信息管理
- 连接质量监控
- 自动重连和保活

**技术细节**：
- UDP 打洞协议
- 20 次握手尝试 + 3 次重试阶段
- 15 秒保活间隔
- RTT 测量和质量评分
- 端口预测（对称 NAT）

**关键代码**：
- `Manager`：P2P 管理器
- `PeerInfo`：对等节点信息
- `ConnectToPeer()`：建立 P2P 连接
- `SendPacket()`：通过 P2P 发送数据

### 9. pkg/nat

**功能**：NAT 类型检测

**主要职责**：
- 检测本地 NAT 类型
- 判断 P2P 连接可行性
- 决定连接策略

**NAT 类型**：
- None：无 NAT（公网 IP）
- Full Cone：完全锥形 NAT（最宽松）
- Restricted Cone：限制锥形 NAT
- Port Restricted Cone：端口限制锥形 NAT
- Symmetric：对称 NAT（最严格）

**关键代码**：
- `NATType` 枚举
- `DetectNATType()`：检测 NAT 类型
- `CanTraverseWith()`：判断能否穿透
- `ShouldInitiateConnection()`：决定谁发起连接

### 10. pkg/routing

**功能**：智能路由表

**主要职责**：
- 管理到各个对等节点的路由
- 选择最优路径（直连/中转/服务器）
- 监控路由质量
- 自动故障转移

**路由类型**：
- **RouteDirect**：P2P 直连（最优）
- **RouteRelay**：通过其他节点中转
- **RouteServer**：通过服务器中转（回退方案）

**质量评分**：
- 基于延迟、丢包率、连接类型
- 分数范围：0-150
- 自动选择最高分路由

**关键代码**：
- `RoutingTable`：路由表
- `AddPeer()`：添加对等节点
- `GetRoute()`：获取最优路由
- `UpdateRoutes()`：更新路由质量
- `GetRouteStats()`：获取路由统计

### 11. pkg/tunnel

**功能**：隧道核心逻辑

**主要职责**：
- 创建和管理 TUN 设备
- 数据包路由和转发
- 多客户端管理（服务端）
- 自动重连（客户端）
- MTU 自动检测
- 密钥轮换
- 路由宣告

**工作流程**：

**客户端模式**：
1. 创建 TUN 设备
2. 连接到服务器
3. 启动 P2P 管理器（如果启用）
4. 开始数据包收发循环
5. 自动重连（如果断开）

**服务端模式**：
1. 创建 TUN 设备
2. 监听客户端连接
3. 管理多个客户端
4. 转发数据包
5. 定期推送配置（如果启用密钥轮换）

**关键代码**：
- `Tunnel` 结构体：隧道主体
- `NewTunnel()`：创建隧道
- `Start()`：启动隧道
- `Stop()`：停止隧道
- `tunReader()`：读取 TUN 设备
- `tunWriter()`：写入 TUN 设备
- `netReader()`：读取网络数据
- `netWriter()`：写入网络数据
- `reconnectToServer()`：自动重连

## 数据流程

### 客户端发送数据

```
应用程序
    ↓
TUN 设备 (10.0.0.2)
    ↓
tunReader() 读取 IP 数据包
    ↓
sendPacketWithRouting() 智能路由
    ├─→ P2P 直连（如果可用）
    │   ↓
    │   加密 → UDP 发送到对等节点
    │
    └─→ 服务器中转（回退）
        ↓
        加密 → Raw TCP 发送到服务器
            ↓
        服务器转发
            ↓
        目标客户端接收
```

### 客户端接收数据

```
网络连接（Raw TCP 或 P2P UDP）
    ↓
netReader() / handleP2PPacket()
    ↓
解密数据包
    ↓
recvQueue 接收队列
    ↓
tunWriter() 写入 TUN 设备
    ↓
TUN 设备 (10.0.0.2)
    ↓
应用程序
```

### P2P 连接建立

```
客户端 A                  服务器                  客户端 B
    |                       |                       |
    |--- 连接 + 注册 ----→  |  ←---- 连接 + 注册 ---|
    |                       |                       |
    |  ←-- 公网地址 --------  |  ----→ 公网地址 --→  |
    |                       |                       |
    |  ←-- B 的信息 --------  |  ----→ A 的信息 --→  |
    |                       |                       |
    |--- UDP 打洞包 ----------------→ UDP 打洞包 ---|
    |                                               |
    |  ←---------- P2P 直连建立 -----------------→  |
```

## 测试覆盖

### 单元测试

- **config**: 5 个测试（配置加载、保存、验证）
- **crypto**: 7 个测试（加密、解密、密钥验证）
- **faketcp**: 测试 Raw Socket 实现
- **nat**: 6 个测试（NAT 类型检测、判断）
- **p2p**: 9 个测试（对等节点管理、连接）
- **routing**: 11 个测试（路由选择、质量评分）
- **tunnel**: 6 个测试（隧道逻辑、MTU 调整）

### 运行测试

```bash
# 运行所有测试
make test

# 或
go test -v ./...

# 运行特定包的测试
go test -v ./pkg/crypto
go test -v ./pkg/p2p
```

## 构建和部署

### 构建

```bash
# 使用 Makefile
make build

# 或直接使用 go build
go build -o lightweight-tunnel ./cmd/lightweight-tunnel
```

### 部署

```bash
# 安装为 systemd 服务
sudo make install-service \
  CONFIG_PATH=/etc/lightweight-tunnel/config.json \
  SERVICE_NAME=lightweight-tunnel

# 启动服务
sudo systemctl start lightweight-tunnel

# 查看状态
sudo systemctl status lightweight-tunnel
```

## 开发建议

### 添加新功能

1. **选择合适的包**：根据功能归属选择在哪个包中实现
2. **编写测试**：为新功能编写单元测试
3. **更新文档**：更新相关的文档
4. **运行测试**：确保所有测试通过

### 调试技巧

1. **启用详细日志**：程序默认输出详细日志
2. **使用 tcpdump**：抓包分析网络流量
3. **检查 iptables**：查看防火墙规则
4. **查看路由表**：`ip route` 查看系统路由

### 代码规范

- 遵循 Go 语言标准格式（使用 `gofmt`）
- 为导出的函数和结构体添加文档注释
- 使用有意义的变量和函数名
- 保持函数简短和单一职责

## 性能优化

### 关键性能参数

- **队列大小**：默认 5000，可配置
- **FEC 参数**：根据网络质量调整
- **MTU 大小**：自动检测或手动设置
- **P2P 保活**：15 秒间隔

### 性能监控

- 查看路由统计：程序日志中定期输出
- 监控网卡流量：`iftop -i tun0`
- 检查连接状态：查看 P2P 连接质量

## 常见问题

详见主 README.md 文件的"常见问题"章节。

## 参考资料

- [Go 语言官方文档](https://go.dev/doc/)
- [Linux 网络编程](https://man7.org/linux/man-pages/man7/raw.7.html)
- [TCP/IP 协议详解](https://www.rfc-editor.org/rfc/rfc793)
- [Reed-Solomon 纠错码](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)
- [STUN 协议](https://www.rfc-editor.org/rfc/rfc5389)

---

**最后更新**：2024-12-20

**维护者**：Lightweight Tunnel Team
