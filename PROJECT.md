# Flux 项目决策、架构、进度与验收

状态：核心后端和两节点 Beta 链路已完成实机复验。单 Controller、SQLite、Noise/AES-256-GCM、Owner/租户 RBAC、Agent systemd、nftables、tc/IFB、WireGuard、域名目标和节点级协议拦截均已实现。Go 全量测试、React 29 项测试和前端生产构建已在 Ubuntu 24.04 VM 通过。

最后更新：2026-08-01

## 1. 产品定位

Flux 是面向个人和小社区的 Linux 自托管四层转发平台。

它只处理 TCP/UDP 端口转发和跨节点路径。用户业务流量始终由 Linux 内核转发，不进入 Go 用户态复制。Go Controller 和 Agent 只负责身份、期望状态、规则、计量、限速、健康与调度。

首发运行边界：

- 始终只有一个 Controller，不做多 Controller、leader election 或分布式数据库。
- 采用本地 SQLite，目标规模是 1～10 个 Linux 节点和约 1000 条转发；这不是代码许可证或硬上限。
- 首发只有 Owner 与 Tenant 两种角色：唯一 Owner 管理机器、租户和授权；租户只能管理自己且仍在 Owner 分配范围内的转发。不引入企业组织、部门和自定义角色矩阵。
- 不做公开注册、支付、套餐商城、发票和代理商系统。
- 前端位于 `web/`，使用 React/TypeScript，可由 Controller 同源托管；权限裁决始终在 Controller 后端完成，前端隐藏按钮不构成安全边界。
- Linux Agent 支持 Ubuntu 20.04、22.04、24.04 等发行版；面板并不绑定 Ubuntu 24.04。真正的兼容边界是内核及 nft、tc、ip、conntrack、WireGuard 工具能力。

明确不做：

- Xray、GOST 或其他用户态代理作为核心数据面。
- 不提供 SOCKS/HTTP 代理服务，也不提供 TLS/WSS/gRPC/QUIC/KCP 伪装隧道。节点级协议拦截只是访问控制，不会代理这些协议。
- 不解析 SNI、HTTP Host 或正文，不做完整 DPI 和 L7 路由。
- 用户态 TCP/UDP 数据复制。
- Windows/macOS 节点。
- NAT 穿透和自动替业务流量加密。

## 2. 冻结架构

    Web Console（React / TypeScript，独立项目）
             |
             | 管理 API
             v
    单个 Flux Controller
      - SQLite 唯一事实来源
      - Owner、租户、节点、转发、配额
      - Desired State / generation
      - 调度、审计、用量聚合
      - 单实例文件锁
             |
             | Noise + AES-256-GCM 长连接
             | Protobuf / gRPC 应用协议
             v
    Linux Node Agent
      - nftables：NAT、过滤、计数
      - tc / IFB：上下行整形
      - route / policy rule：跨节点路径
      - WireGuard / direct L3 / GRE：节点 Fabric
      - conntrack：连接保持与强制删除

Controller 停机或链路断开不会清空节点规则。Agent 保留 last-known-good 数据面，并在重连或重启后继续对账。

### 2.1 单 Controller 是硬约束

Controller 启动时获取数据库旁的独占锁。相同状态目录中的第二个实例会直接失败，避免两个进程同时消费 outbox 或发布 generation。

数据库层只使用一个打开连接，写操作在单 Controller 内串行化。代码中保留的 outbox lease 仅用于进程崩溃后的任务恢复，不表示高可用或多 Controller。

这项锁只能约束共享同一状态文件的进程。禁止把数据库复制到另一台机器后同时启动两个独立 Controller。

### 2.2 SQLite

SQLite 是 Controller 的唯一持久化数据库：

- WAL journal。
- foreign_keys 开启。
- busy_timeout 为 10 秒。
- synchronous=FULL。
- schema 迁移由 Controller 自行执行。
- 不需要 PostgreSQL、Redis、Kafka 或外部分布式锁。

SQLite 文件格式可跨机器迁移，但在线运行时不能只复制 flux.db，因为尚未 checkpoint 的数据可能还在 WAL。项目提供单文件备份归档，在线和离线迁移都统一走 backup / restore。

归档包含：

- 一致性的 SQLite 快照。
- Controller Noise 静态身份密钥。
- manifest 和每个文件的 SHA-256 校验值。

Controller 密钥必须和数据库一起迁移，否则现有 Agent 会把新 Controller 视为未知身份并拒绝连接。

### 2.3 非 TLS 的 AES 安全通道

Controller-Agent 运行环境不允许 TLS，因此注册与控制通道不使用 TLS、mTLS、X.509 或证书续期。浏览器管理面与此约束分离：公网面板仍应在同机反向代理终止常规 HTTPS，再转发到 Controller 的 loopback HTTP 监听。

也不自行设计“一个 AES 密码直接加密 TCP”的协议。控制通道采用标准 Noise Protocol Framework：

- 正常控制连接：Noise_IK_25519_AESGCM_SHA256。
- 首次注册：Noise_NK_25519_AESGCM_SHA256。
- 密钥协商和身份：X25519 静态密钥。
- 记录加密与完整性：AES-256-GCM。
- 握手哈希：SHA-256。
- 加密记录按固定计数自动 rekey。

Controller 私钥只存于 Controller 本地。Agent 私钥在节点本地生成并保存。Controller 公钥通过一次性注册包带到 Agent 并固定；以后握手必须匹配该公钥。

首次注册时，Noise NK 先认证 Controller 并加密请求，一次性、短时、绑定 NodeID 的 token 再认证尚未被信任的新节点公钥。注册完成后，正常控制连接使用 Noise IK 双向认证静态密钥。

线上承载仍保留 Protobuf/gRPC 的流控和消息模型，但 HTTP/2/gRPC 字节位于 AES-GCM 加密记录内部，网络上没有 TLS ClientHello、证书或 TLS record。

这不是伪装协议：

- 不模仿 HTTPS、SSH、WebSocket 或任何其他协议。
- 不提供域前置、SNI 或流量形态伪装。
- 它只是一个长度分帧的认证密文通道。
- 如果网络策略禁止的是“所有未知 TCP 协议”而不只是 TLS，它仍可能被阻断；Flux 不绕过这种白名单策略。

### 2.4 可配置周期

不同数据有不同实时性和开销，不能只用一个全局上报周期。

Agent 参数：

| 参数 | 默认值 | 含义 |
| --- | ---: | --- |
| --heartbeat-interval | 25s | Agent 状态心跳 |
| --usage-interval | 10s | 读取计数并写入本地 durable outbox |
| --health-interval | 1s | 调度已到期的健康探测 |
| --policy-interval | 1s | 本地到期、暂停、drain 策略检查 |
| --reconcile-interval | 15s | 内核漂移与 last-known-good 对账 |

Controller 参数：

| 参数 | 默认值 | 含义 |
| --- | ---: | --- |
| --snapshot-poll-interval | 5s | Desired State 兜底轮询 |
| --ping-interval | 30s | Controller 主动 ping |
| --auth-check-interval | 30s | 已连接节点密钥吊销复查 |
| --heartbeat-timeout | 95s | Agent 静默断线阈值 |

所有周期均可由部署者指定 time.Duration，例如 500ms、10s、2m。它们改变正常维护频率，不做随机延迟、流量整形或协议伪装。

约束建议：

- heartbeat-timeout 至少为 heartbeat-interval 的三倍并留出网络抖动余量。
- usage-interval 越短，计量越及时，但 SQLite、nft 读取和网络消息越多。
- auth-check-interval 决定已连接节点被吊销后的最长继续在线窗口。
- health-interval 只是调度 tick，具体目标的探测周期仍由 Desired State 决定。

### 2.5 网页按需诊断与节点维护

网页诊断只在用户点击“检查 TCP”时执行一次，不进入定时任务，也不保存为长期健康状态：

- 直连转发由入口节点连接目标 TCP 端口。
- 隧道转发由出口节点连接目标 TCP 端口。
- 检查只完成一次 TCP 建连并立即关闭，显示是否可连接和建连耗时；不发送业务数据、不做带宽测速。
- UDP-only 转发不执行 TCP 检查。
- 原有 Agent 心跳和 Desired State 后端健康探测保持不变。

Owner 可在节点详情发起在线升级或卸载。升级只接受 Controller 启动参数预设的 HTTPS 发行包地址，Agent 同时校验归档 SHA-256 和归档内 Agent 二进制清单，安装后执行 `flux-agent version`；验证失败会恢复旧二进制。首次安装会同时写入受限的 systemd 一次性维护单元，因此旧版 Agent 需要先手动升级一次才能使用网页维护。

网页卸载仅允许在线、配置已同步且不再承载入口或出口转发的节点。Controller 先把节点移出转发配置并等待 Agent 确认内核状态已经清空，同时阻止新转发再次选中该节点；随后 Agent 删除程序和 systemd 单元，Controller 确认收到结果并永久吊销节点身份后，Agent 才停止自身并删除本地身份。若结果传输时断线，Controller 仍会吊销已移出配置的节点，并提示管理员用卸载脚本确认本地文件。最后一个节点也可以安全卸载。诊断、升级和卸载都是内存中的一次性命令，Controller 重启后不会主动重放命令。

## 3. 数据面语义

### 3.1 直连

    Client
      -> Ingress public IP:Port
      -> nftables DNAT
      -> Target IP:Port
      -> nftables SNAT

### 3.2 跨节点

    Client
      -> Ingress nftables
      -> Service VIP
      -> WireGuard / direct L3 / GRE Fabric
      -> Exit nftables
      -> Target

业务 Tunnel 与物理 Fabric 解耦。每个用户不会创建独立 WireGuard 接口。公网或不可信网络默认 WireGuard；GRE 只允许显式用于可信网络，不作为公网默认。

跨节点服务使用 Controller 管理的 Service VIP 和策略路由，确保回程仍经过原入口。service CIDR 必须由部署者显式配置并做冲突检查。

### 3.3 nftables

Agent 只管理：

    table inet flux

禁止：

- flush ruleset。
- 修改 Docker、firewalld 或其他软件管理的 table。
- 每条转发执行一次 shell 命令。
- Controller 断线后清空规则。

TCP 与 UDP 使用独立 map：

    tcp_dnat: listen_ipv4 . listen_port -> target_ipv4 . target_port
    udp_dnat: listen_ipv4 . listen_port -> target_ipv4 . target_port

规则先预检查，再按 generation 整批提交。nft 单批次原子；nft、tc、route、WireGuard 之间不存在共同的内核事务，因此跨子系统使用 preflight、pending、依赖顺序 apply、verify、commit 和失败补偿。

Owner 可以给每个节点独立开启 HTTP、HTTPS、SOCKS 和 TLS 拦截。规则只作用于该节点承载的 Flux TCP 转发，并在 nftables 内核链中检查连接开头：HTTP 匹配请求方法，SOCKS 匹配 4/5 握手，TLS 匹配 ClientHello，HTTPS 匹配 CONNECT 或 ClientHello 前 256 字节内的 HTTP ALPN。它不按 80/443 等端口或“高熵”特征封禁，因此随机 AES 数据不会仅因端口或密文形态被拦截。

这是轻量首包识别，不是不可绕过的完整 DPI：刻意拆包、修改握手或没有 ALPN 的 HTTPS 可能漏过；启用策略前已建立的加密会话也不会被追溯识别。该功能适合管理员减少常见代理/网页协议使用，不能宣传为合规审查或绝对协议封锁。

生命周期：

- active：接受新连接并维持已有连接。
- paused：立即阻断新旧流量，但不删除 conntrack；恢复后旧连接可能继续。
- draining：拒绝新连接，已有连接继续；UDP 必须有截止时间。
- force delete：先放置阻断 tombstone，再精确清理关联 conntrack，ACK 后删除对象。

### 3.4 tc 限速

nft 写入 Flux 所有的 mark，tc 按 mark 分类：

- 上传：公网接口 ingress 分类，重定向到 Flux IFB，再做 HTB + fq_codel。
- 下载：公网接口 egress 使用 HTB + fq_codel。
- 默认平滑排队，不使用 nft limit 代替带宽整形。

只有同时提供 --public-interface 和 --allow-tc-root-replace 时，Agent 才启用 tc.rate-limit。这表示部署者明确允许 Flux 管理该公网接口的 root qdisc 和 clsact。

用户级限速是 Controller 分配到节点的预算，不宣传为跨节点逐包强一致。

### 3.5 流量口径

计量值为节点转发钩子看到的 L3 bytes，包括 IP 头与重传，不等于应用 payload。

每条转发只在入口节点生成可计费用量计数，跨节点出口不会重复计费。租户级与转发级配额按 Controller 中保留的全部入口节点历史增量累计；节点迁移不会重置额度。

Agent 使用 node_id、counter_epoch、sequence 作为幂等键，将增量先保存到本地 durable outbox，再发给 Controller。Agent 重启、计数器重建或 epoch 变化不会产生负增量。

Controller 离线时优先维持数据面可用，因此当前配额是软配额，可能出现一个“采集间隔 + 重连 + generation 应用”的超额窗口。

## 4. 业务模型

业务输入不直接绑定物理 WireGuard/GRE：

    ForwardIntent
      - id
      - user_id
      - protocols: tcp / udp
      - ingress_node_id
      - listen_ip / listen_port
      - path_mode: direct / via_exit
      - optional exit_node_id
      - target_ip_or_hostname / target_port
      - snat_mode
      - ingress / egress rate
      - traffic quota
      - expires_at
      - lifecycle
      - resource_version

    Placement
      - 调度后的入口、出口和路径

    FabricLink
      - transport: wireguard / direct_l3 / gre
      - trust_domain
      - addresses / routes / mtu
      - health

    NodeDesiredState
      - node_id
      - generation
      - checksum
      - 完整节点配置

resource_version 用于业务对象乐观并发；generation 是单节点严格单调的期望状态版本。相同 generation 但 checksum 不同属于协议错误。

首发为 IPv4、具体监听 IP、IPv4 或域名目标和单目标。域名由 Controller 解析为一个稳定 IPv4 后再下发；每 60 秒刷新，解析失败保留上次可用 IP，租户的新解析结果仍需通过目标网段策略。多个 DNS A 记录不用于负载均衡或健康故障切换。IPv6 与多目标负载均衡后置。未实现字段必须返回 unsupported，不允许静默忽略。

## 5. 当前代码进度

### Phase 1：本机数据面——完成

- TCP/UDP 单目标 DNAT/SNAT。
- 固定规则骨架和动态 map/set。
- active、pause、resume、基础删除。
- conntrack 行为与 nft counter。
- pending / last-known-good 和重启恢复。
- network namespace 验收脚本。

### Phase 2：Controller 与 Agent——完成并通过 VM 复验

- SQLite migration 和 Desired State 持久化。
- generation/checksum、完整 snapshot、ACK/NACK、重试。
- Agent 幂等 reconcile 和断线保留数据面。
- Noise/AES-256-GCM 注册及长期双向认证控制流。
- 节点密钥授权和定期吊销复查。
- 可配置心跳与 Controller 静默超时。

### Phase 3：策略——核心完成

- 用户/转发配额模型。
- tc/IFB 上下行限速计划。
- 到期、pause、drain、force delete。
- durable usage outbox、幂等聚合与审计。
- 健康探测调度。

### Phase 4：跨节点——核心完成

- 共享 WireGuard Fabric。
- direct L3 和显式 GRE 计划。
- 入口 Service VIP、出口二次 DNAT/SNAT、策略回程。
- MTU、MSS clamp、rp_filter 预检查与回读验证。
- 节点本地 WireGuard 私钥。

### Phase 5：社区发布能力——部分完成

已完成：

- 节点标签、调度、集群计划、分阶段 rollout 和 rollback 后端。
- 单 Controller 独占锁。
- SQLite 在线一致性备份、校验和安全恢复。
- Linux amd64/arm64 构建目标。
- 唯一 Owner、Tenant 账号、Argon2id 密码、会话 Cookie、CSRF、登录限流与管理审计。
- Owner 可分配入口/出口节点、监听 IP/端口、协议、目标 CIDR、转发数、限速、配额和到期时间；租户转发写入时由后端强制复核。
- Tenant 被禁用、到期或策略收紧后，Controller worker 会把既有不合规转发改成 paused；策略放宽不会自动恢复，必须人工复核后 Resume。
- 管理 API 的转发创建、查询、修改、Pause/Resume、Drain/Force 删除，并接入 cluster plan、Desired State、ACK 与最终清理。
- 节点列表和一次性安装命令 API；Agent 可原子安装自身、固定 Controller 公钥、注册并写入 systemd 服务。
- React/TypeScript 管理界面、真实 API 适配、Owner/Tenant 导航裁剪、用量页、系统状态和在线备份。
- 当前账号密码修改、Owner 重置 Tenant 密码；密码变化会撤销该账号全部现有会话。
- 节点监听 IP 作为 cluster plan 清单管理，面板只允许从对应节点的清单内选择。
- 租户级总限速/总配额会同步为 Desired State 用户策略；单条转发可选择更严格的独立限制，但不必重复填写租户总限制。
- Owner 可永久吊销节点身份和未使用注册 token；面板安装命令默认启用 Flux Fabric 能力。
- Controller 受限 systemd 单元、同机 Nginx 反向代理样例、Linux Beta 打包脚本和 amd64/arm64 SHA-256 清单。
- 注册请求严格拒绝未知字段及尾随 JSON，并限制同时握手连接数；登录端同时限制 Argon2 计算并为来源窗口设置内存上限。节点吊销覆盖旧密钥、未使用 token 和已连接节点的定期重鉴权。
- Owner 可按节点独立拦截 HTTP、HTTPS、SOCKS 和 TLS；Tenant 看不到设置且后端拒绝其修改。规则不按端口封禁，随机 AES 流量已在 network namespace 中验证可正常通过。
- Owner/Tenant 可对自己有权查看的 TCP 转发手动执行一次 tcping，显示建连耗时；没有点击时 Agent 不产生诊断连接，也不会执行带宽测速。
- Owner 可从节点详情在线升级或安全卸载 Agent；卸载会检查同步状态和转发占用，先完成空配置 ACK，再删除 Agent 并永久吊销节点身份。

未完成：

- Webhook 告警和正式 OpenAPI 契约。
- 发行包独立签名；当前升级链路已完成 HTTPS、外层 SHA-256、归档内清单和失败回滚。按需诊断不保存历史。
- IPv6、多目标 failover。
- 高 PPS/CPS/吞吐与长时间稳定性验收。
- 与旧 Flux Panel 的剩余产品差距：单向/双向计费切换与流量倍率、可复用的命名隧道套餐。

多 Controller 已从目标中删除，不属于任何后续阶段。

### 2026-07-23 两 VM Beta 验收——完成

- 环境：`192.168.121.135`（Controller + node-a）和 `192.168.121.136`（node-b），Ubuntu 24.04.3 LTS，Linux 6.8。
- 安装：Owner 登录后由管理 API 生成一次性 Agent 安装命令；两个节点均完成 Noise 注册、systemd enable/start、能力和独立 WireGuard 公钥上报。
- 数据面：namespace 自动验收通过；真实 VM 的直连和 WireGuard 跨节点 TCP/UDP 均通过。最终计划 revision 16、0 告警，node-a generation `17/17`、node-b `1/1`。
- 生命周期：Pause 同时阻断已有和新增连接；Resume 恢复；Drain 保留旧连接到截止时间并拒绝新连接；Force 重置旧连接、清理 conntrack，最终无残留规则或 tc class。
- 离线恢复：Controller 停止时四条既有 TCP/UDP 路径继续工作；两个 Agent 重启后分别从 generation 17 和 1 的 last-known-good 恢复并自动重连。
- 计量与限速：Controller 聚合 L3 TCP/UDP 用量；临时 veth 上的 1 Mbit 双向 HTB/IFB 实测 512 KiB 用时 4.752 秒，删除后 HTB class 清空。
- 安全：9443 抓包未发现 TLS ClientHello；一次性 token 复用失败，已吊销节点不能重新签发；8080 仅 loopback；Controller、Agent 和 WireGuard 私钥文件均为 0600。

### 2026-08-01 节点协议拦截验收——完成

- 管理面：Owner 节点详情提供 HTTP、HTTPS、SOCKS、TLS 四个开关；Tenant API 修改返回 403，节点列表也不向 Tenant 暴露策略。
- 数据面：Ubuntu 24.04、Linux 6.8、nftables 1.0.9 的隔离 network namespace 实测通过。HTTP、HTTPS CONNECT/ALPN、SOCKS4/5 和 TLS ClientHello 分别被拦截；相同节点策略下的随机 AES 样本全部正常转发。
- 工程验证：Go 全量测试通过；React 9 个测试文件共 29 项通过；TypeScript 与 Vite 生产构建通过。
- 管理面：真实 Owner/Tenant RBAC、授权内转发、越权 403、SQLite 在线备份与隔离恢复、单 Controller 独占锁、SPA 同源静态资源均通过。
- 构建：Linux VM 内全量 `go test ./...` 通过，Linux amd64/arm64 Controller 和 Agent 静态交叉构建通过，Web 生产构建通过。
- 本轮修复：Controller identity store 的 Go 编译错误；Ubuntu 24.04 `tc -force` 对幂等 qdisc 清理错误和 HTB warning 的兼容处理。修复后未出现新的 Agent ERROR。
- 节点维护：HTTPS 下载与双层 SHA-256、升级成功/回滚、卸载清理、systemd 单元校验和最后节点退出计划均有 Linux 自动化覆盖。

## 6. 仓库结构

    cmd/flux-controller/          Controller CLI
    cmd/flux-agent/               Linux Agent CLI
    proto/flux/control/v1/        Protobuf 控制协议
    gen/control/v1/               生成的 Go gRPC 类型
    internal/securechannel/       Noise、X25519、AES-GCM 记录层
    internal/controller/store/    SQLite、migration、outbox、计划状态
    internal/controller/archive/  单文件一致性备份与恢复
    internal/controller/instance/ 单 Controller 独占锁
    internal/controller/iam/      Owner/Tenant、Argon2id、授权策略
    internal/controller/management/ 管理 HTTP API、Cookie/CSRF、审计
    internal/controller/enrollment/ 节点注册服务
    internal/controller/control/  gRPC 流、snapshot、ACK、用量
    internal/agent/enrollment/    节点密钥生成、注册和身份固定
    internal/agent/serviceinstall/ Agent 原子复制与 systemd 单元
    internal/agent/controlclient/ 出站控制流、重连和定期上报
    internal/agent/               reconcile、pending、LKG
    internal/dataplane/nft/       nft 编译、预检查、原子提交
    internal/dataplane/tc/        tc、HTB、fq_codel、IFB
    internal/dataplane/fabric/    WireGuard/L3/GRE 和策略路由
    internal/dataplane/conntrack/ force delete 清理
    internal/meter/               counter baseline 和增量
    internal/health/              健康探测引擎
    internal/cluster/             调度、rollout 和 rollback
    web/                          React、shadcn/ui、TypeScript 管理界面
    deploy/                       Controller systemd、环境变量和 Nginx 样例
    examples/                     Desired State 和 cluster plan 示例
    hack/netns-test.sh            Linux namespace 手动验收
    hack/build-release.sh         Linux 测试、双架构构建和 Beta 打包

### 6.1 管理 API（当前实现）

所有响应使用 `{"data": ...}` 或 `{"error":{"code":"...","message":"..."}}`。登录后使用 HttpOnly `flux_session` Cookie；写操作还必须把可读的 `flux_csrf` Cookie 值放进 `X-CSRF-Token` 请求头。Web Console 必须与 API 同源并为 fetch 开启 credentials。

- `POST /api/v1/auth/login`、`POST /api/v1/auth/logout`、`GET /api/v1/auth/me`
- `POST /api/v1/auth/password`
- `GET/POST /api/v1/tenants`
- `GET/PATCH /api/v1/tenants/{tenantID}`
- `POST /api/v1/tenants/{tenantID}/password-reset`（Owner only）
- `GET/PATCH /api/v1/tenants/{tenantID}/policy`
- `GET/POST /api/v1/forwards`
- `GET/PATCH/DELETE /api/v1/forwards/{forwardID}`
- `POST /api/v1/forwards/{forwardID}/tcp-check`（按需执行一次 TCP 连通检查）
- `GET /api/v1/nodes`
- `POST /api/v1/nodes/install-command`（Owner only）
- `DELETE /api/v1/nodes/{nodeID}`（Owner only，仅删除从未接入的待处理节点）
- `PATCH /api/v1/nodes/{nodeID}/protocol-blocks`（Owner only）
- `POST /api/v1/nodes/{nodeID}/revoke`（Owner only，不可逆吊销节点身份）
- `POST /api/v1/nodes/{nodeID}/upgrade`、`POST /api/v1/nodes/{nodeID}/uninstall`（Owner only）
- `GET /api/v1/usage`
- `GET /api/v1/audit`（Owner only）
- `GET /api/v1/system/status`、`POST /api/v1/system/backup`、`POST /api/v1/system/backup/download`（Owner only）

Tenant 看不到其他租户的转发，节点列表也只返回 Owner 分配给它的入口/出口节点。创建或修改转发时，Controller 后端重新检查所有授权字段，随后创建不可变 plan revision；前端的路由守卫和按钮显隐只用于体验。

节点 revoke 会立即阻止新的注册/控制连接，并在下一次授权复查时断开已有控制连接；它不能远程擦除一台已经离线或被攻陷主机上的 last-known-good 内核规则。发生主机失陷时仍需同时从 plan 移除节点，并在云防火墙或交换网络层隔离该机器。

## 7. 首次部署与手动验证

下面以 192.168.121.132 同时运行单 Controller 和 node-a Agent，192.168.121.134 运行 node-b Agent 为例。测试 VM 可使用 Ubuntu 20.04.6；后续也要在更新发行版补兼容矩阵。

### 一键安装（推荐）

发布版本时，把以下三个文件放在同一个 HTTPS 下载目录：

- `install.sh`
- `flux-版本号.tar.gz`
- `flux-版本号.tar.gz.sha256`

`hack/build-release.sh 版本号` 会生成这些文件。安装器只接受 HTTPS 下载地址，先校验发行包 SHA-256，再安装程序；安装中途失败会恢复原有二进制、systemd 单元和配置。SQLite 数据库、Controller 密钥和 Agent 身份默认不会被覆盖或删除。

安装 Controller：

    RELEASE_BASE=https://github.com/你的仓库/releases/download/v1.0.0
    curl -fsSL "$RELEASE_BASE/install.sh" | sudo bash -s -- controller \
      --release-url "$RELEASE_BASE/flux-v1.0.0.tar.gz" \
      --public-host controller.example.com \
      --initial-node-id node-a \
      --initial-node-ip 10.0.0.10

安装器会安装 Controller、Web 控制台和 systemd 服务，初始化 SQLite、唯一管理员及第一台节点配置。未提供密码文件时会生成高强度初始密码并只显示一次。管理页面仍只监听 `127.0.0.1:8080`，先通过输出中的 SSH 隧道访问。

安装 Agent 有两种等价方式：

1. 推荐：在面板“节点 → 添加节点”中复制完整命令，粘贴到目标 Linux 主机。命令会自动识别 amd64/arm64、下载安装包、校验并完成一次性接入。
2. 单独启动安装器：运行下面命令，再粘贴面板里的“接入码”。

       RELEASE_BASE=https://github.com/你的仓库/releases/download/v1.0.0
       curl -fsSL "$RELEASE_BASE/install.sh" | sudo bash -s -- agent \
         --release-url "$RELEASE_BASE/flux-v1.0.0.tar.gz" \
         --enable-fabric

运行 `bash install.sh doctor` 可检查依赖和服务状态。卸载默认保留数据；只有同时使用 `--purge --yes` 才会清除 SQLite 或节点身份。卸载 Agent 前应先在面板移除其转发并等待同步；为保证 Controller 断线时继续转发，单纯停止 Agent 不会主动清空 last-known-good 内核规则。

### 7.1 Linux 前置条件

- root 或等价的 CAP_NET_ADMIN。
- nftables、iproute2、conntrack、wireguard-tools。
- 已开启 IPv4 forwarding。
- 测试机防火墙允许 Controller TCP 8443 和 9443。
- 若测试跨节点 WireGuard，允许所选 UDP 端口。

Controller 不是 Linux 数据面时可以运行在其他受支持环境，但正式自托管建议仍放在专用 Linux 主机或其中一台节点上。

### 7.2 初始化 Controller

在 192.168.121.132：

    sudo mkdir -p /var/lib/flux-controller
    sudo flux-controller key-init --dir /var/lib/flux-controller
    sudo flux-controller migrate \
      --database /var/lib/flux-controller/flux.db

创建唯一 Owner。密码文件只放一行，完成后删除：

    sudo install -m 600 /dev/null /tmp/flux-owner-password
    sudo nano /tmp/flux-owner-password
    sudo flux-controller owner-init \
      --database /var/lib/flux-controller/flux.db \
      --username owner \
      --display-name Owner \
      --password-file /tmp/flux-owner-password
    sudo rm -f /tmp/flux-owner-password

启动：

    sudo flux-controller serve \
      --database /var/lib/flux-controller/flux.db \
      --controller-key /var/lib/flux-controller/controller-noise.key \
      --enroll-address :8443 \
      --control-address :9443 \
      --public-enroll-address 192.168.121.132:8443 \
      --public-control-address 192.168.121.132:9443 \
      --management-address 127.0.0.1:8080 \
      --management-plan-id edge-prod \
      --management-backup-directory /var/lib/flux-controller/backups \
      --web-root /opt/flux/web \
      --snapshot-poll-interval 5s \
      --ping-interval 30s \
      --auth-check-interval 30s \
      --heartbeat-timeout 95s

先在 `web/` 执行 `corepack pnpm install --frozen-lockfile && pnpm build`，再把 `web/dist` 的内容放到上例 `/opt/flux/web`。`--web-root` 会让 Controller 在同一个管理监听端口提供 SPA 和 `/api/v1`；也可以不传该参数，继续由同机可信反向代理单独托管静态文件。管理监听仍限定 loopback。反向代理应覆盖并发送可信的 `X-Forwarded-For` 或 `X-Real-IP`；Controller 只在直连来源为 loopback 时采用这些头。正式浏览器访问保留 Secure Cookie；只有本机纯 HTTP 开发时才使用 `--management-cookie-secure=false`。

`--management-plan-id` 必须与要由面板管理的 cluster plan ID 一致。示例 `examples/cluster-plan.json` 的 ID 是 `edge-prod`；首次使用转发 API 前先按 7.5 发布该 plan。

第二个使用相同数据库/锁文件的 Controller 必须启动失败。

正式常驻部署可直接使用：

- `deploy/systemd/flux-controller.service`
- `deploy/flux-controller.env.example`
- `deploy/nginx/flux.conf.example`

先把环境样例复制为 `/etc/flux-controller/flux-controller.env` 并修改 Controller 可达地址和 plan ID，再安装 systemd 单元。Controller 服务账户只需要读写 `/var/lib/flux-controller` 和 `/run/flux-controller`；8443/9443 都是非特权端口，不需要 root。Nginx 只反代到 `127.0.0.1:8080`，并覆盖来源 IP 请求头。Nginx 的 HTTPS 只服务浏览器管理面，Agent 的 8443/9443 仍是 Noise/AES 密文而不是 TLS。

### 7.3 为节点生成一次性注册包

在 Controller 上分别执行：

    sudo flux-controller token \
      --database /var/lib/flux-controller/flux.db \
      --controller-key /var/lib/flux-controller/controller-noise.key \
      --node-id node-a \
      --enroll-address 192.168.121.132:8443 \
      --control-address 192.168.121.132:9443 \
      --out /tmp/node-a.enroll.json

    sudo flux-controller token \
      --database /var/lib/flux-controller/flux.db \
      --controller-key /var/lib/flux-controller/controller-noise.key \
      --node-id node-b \
      --enroll-address 192.168.121.132:8443 \
      --control-address 192.168.121.132:9443 \
      --out /tmp/node-b.enroll.json

注册包包含敏感的一次性 token，应通过可信方式分别复制到对应节点并在注册成功后删除。

正式面板流程更短：Owner 调用 `POST /api/v1/nodes/install-command`，Controller 返回一条短时、单次的完整安装命令。只需在 Linux 节点粘贴，脚本会下载并校验对应架构的 Agent，然后执行：

    flux-agent install --bundle-base64 '面板返回的值' --enable-fabric

Controller 需要配置 `--node-installer-url` 和 `--node-release-url`（systemd 环境变量为 `FLUX_NODE_INSTALLER_URL`、`FLUX_NODE_RELEASE_URL`）才能生成完整的一键命令。安装器会原子复制二进制到 `/usr/local/bin/flux-agent`，固定 Controller Noise 公钥，完成一次性注册，写入 `/etc/systemd/system/flux-agent.service`，然后 enable/start。面板命令默认加入 `--enable-fabric`，允许 Agent 按 Controller 的 Desired State 管理 Flux 自有的 WG/L3/GRE 接口和路由；它不会自动允许接管公网接口的 tc root qdisc。命令含有短时 token，可能进入 shell history；只在可信 root 终端粘贴，注册完成后 token 即失效。

### 7.4 注册并运行 Agent

node-a：

    sudo flux-agent enroll \
      --token-file /tmp/node-a.enroll.json \
      --identity-dir /var/lib/flux-agent/identity

    sudo flux-agent run \
      --controller 192.168.121.132:9443 \
      --node-id node-a \
      --identity-dir /var/lib/flux-agent/identity \
      --state-dir /var/lib/flux-agent \
      --heartbeat-interval 25s \
      --usage-interval 10s \
      --reconcile-interval 15s

node-b 使用 node-b 注册包和 NodeID。需要跨节点时显式加 --enable-fabric；需要限速时再提供公网接口并显式允许 Flux 接管 root qdisc：

    --public-interface ens33 --allow-tc-root-replace

不要在不了解现有 qdisc 所有权时开启该选项。

### 7.5 发布测试状态

面板管理 API 修改的是一个完整 cluster plan。先把示例中的节点、`listen_ips`、地址、Fabric 和目标改成实际值，再建立初始 plan：

    flux-controller plan-validate --file examples/cluster-plan.json
    flux-controller plan-apply \
      --database /var/lib/flux-controller/flux.db \
      --file examples/cluster-plan.json \
      --actor owner:bootstrap

Controller 的 `--management-plan-id` 必须与该文件的 `id` 相同。此后 Owner/Tenant 通过管理 API 创建的单目标转发会生成新 plan revision，并沿用现有 rollout/ACK/rollback 链路。

先在任意机器验证示例：

    flux-agent validate --file examples/direct-desired.json
    flux-agent render --file examples/direct-desired.json

发布时由 Controller 分配 generation：

    flux-controller publish \
      --database /var/lib/flux-controller/flux.db \
      --file examples/direct-desired.json

示例中的 node_id、监听 IP、目标 IP 和接口必须先改成测试网络实际值。

### 7.6 Linux 验收点

- nft list table inet flux 只看到 Flux 自己的 table。
- TCP 和 UDP 都能通过监听地址访问目标。
- Pause 后新连接和已有连接都在目标时间内阻断。
- Resume 后新连接恢复。
- Drain 不再接受新连接，已有 TCP 连接能继续到截止时间。
- Force delete 后规则、conntrack、tc class 和路由无残留。
- 停止 Controller 后，已有数据面继续工作。
- 重启 Agent 后，从 last-known-good 自动恢复并重新连接。
- 篡改 Agent 固定的 Controller 公钥后，握手必须失败。
- 撤销节点密钥后，最迟在 auth-check-interval 后连接终止。
- 抓包不得出现 TLS ClientHello 或 X.509 证书；负载应是 Flux Noise 握手和 AES-GCM 密文，但不把这一点当作伪装能力。
- 跨节点验证 WireGuard 路径、MTU/MSS、回程和节点掉线恢复。

自动 namespace 数据面验收：

    sudo bash hack/netns-test.sh

真实 VM 验收按上面步骤执行；当前收尾阶段遵循约束，Windows 只做源码编辑和静态检查，不在 Windows 执行构建、测试或数据面运行。

在 Linux 构建机生成 Beta 目录和归档：

    bash hack/build-release.sh beta.1

脚本会先运行 Go 与 Web 自动化测试，再构建 Linux amd64/arm64 Controller 和 Agent、打包已构建 Web、部署样例与本文档，并生成二进制及归档 SHA-256。输出已存在时脚本会拒绝覆盖。

## 8. 备份和无损迁移

在线创建单文件备份：

    flux-controller backup \
      --database /var/lib/flux-controller/flux.db \
      --controller-key /var/lib/flux-controller/controller-noise.key \
      --out /backup/flux-2026-07-22.tar.gz

将该 tar.gz 复制到新机器。为保证始终只有一个 Controller，先停止旧 Controller，再恢复：

    flux-controller restore \
      --in /backup/flux-2026-07-22.tar.gz \
      --database /var/lib/flux-controller/flux.db \
      --controller-key /var/lib/flux-controller/controller-noise.key

restore 会：

- 拒绝覆盖已存在的数据库或密钥。
- 校验 manifest 和文件 SHA-256。
- 校验 Controller X25519 密钥对。
- 打开 SQLite 并验证/迁移 schema。
- 只有验证成功才安装目标文件。

恢复后用原 Controller key 启动新机器，因此 Agent 不需要重新注册。把 Controller 地址切到新机器后再关闭迁移窗口。

若 Controller 已完全停止且确认数据库已正常关闭，直接复制完整状态目录通常也可行；产品标准流程仍是 backup / restore，因为它能处理在线快照、密钥绑定和完整性检查。

## 9. 安全与人工 Review

上线公网前建议进行一次独立安全 review，重点不是重新发明密码算法，而是检查实现边界：

- Noise 握手模式、方向密钥和 rekey 同步是否正确。
- Controller 公钥注册包的线下分发方式。
- 节点私钥、Controller 私钥和备份文件权限。
- token 生命周期、单次消费和重放。
- Argon2id 密码参数、登录限流、会话吊销、Cookie 属性和 CSRF 双提交校验。
- Owner/Tenant 对象级授权、目标 CIDR/端口/节点限制，以及策略变更后的既有转发处置。
- Agent 安装命令在 shell history 中的短时 token 暴露、二进制发行签名和升级回滚。
- 长度分帧、异常输入、资源耗尽和连接并发限制。
- 节点撤销、Controller 密钥轮换及灾难恢复流程。
- nft、tc、路由、conntrack 所有权边界。

当前采用标准 Noise + AES-GCM，而不是自定义裸 AES，这是必要的安全底线。它提供机密性、完整性和身份认证，但不代替主机安全、磁盘加密、密钥备份和防火墙。

## 10. 下一步

按当前产品定位，后续顺序为：

1. 生成正式 Beta 归档，并在公有云做一次全新安装验收。
2. 补创建请求的持久化幂等键和正式 OpenAPI 契约。
3. 为发行包增加独立签名，并保留当前 SHA-256 与安装回滚校验。
4. 补旧 Flux 用户需要的计费方向、流量倍率和可复用隧道套餐模型。
5. 做 TCP/UDP、长连接、小包、PPS、CPS、吞吐和 p99 压测，并补 Ubuntu 20.04/22.04 兼容矩阵。

自定义 RBAC、多 Controller、企业告警矩阵不是本产品当前方向。IPv6 和多目标 failover 属于明确的后续功能，不阻塞小范围开源发布。
