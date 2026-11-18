# capgo 实施计划

> 版本：v1.0
> 状态：已确认方向，待按阶段实施
> 更新：2026-11-18

## 1. 项目定位

`capgo` 是一个使用 Go 编写的、可独立部署的 Cap 工作量证明（PoW）人机验证服务。它参考官方 [tiagozip/cap](https://github.com/tiagozip/cap) / `capd` 的协议、管理模型和 WebUI 信息架构，但不复制整个官方 dashboard。

目标部署形态：

```text
Caddy / Nginx
      ↓
capgo 单个静态二进制
      ├── SQLite：站点、密钥、会话、事件
      └── 内存：短期 challenge / verification token
```

首要使用场景是 Homepage 的 Twikoo 评论区，同时保留给登录、表单和其他服务复用的能力。

## 2. 已确认的产品决策

- **主语言：Go**。
- **WebUI：轻量核心版**，使用 Go `html/template`、原生 JavaScript/CSS 和 `go:embed`，不移植官方的 Svelte/Vite dashboard。
- **协议目标：完整 Cap v4 协议能力**，包括：
  - legacy format-1；
  - format-2；
  - SHA-256 PoW；
  - HashWX；
  - RSW time-lock puzzle；
  - instrumentation / 行为校验所需的服务端协议。
- **协议实现：自行实现**。官方 `@cap.js/server`、`capjs-core` 和 `capd` 只作为规范、测试 oracle 和互操作对象，不作为运行时服务端依赖。
- **部署边界：单实例优先**。v1 不依赖 Docker、Node、Redis 或 Valkey；不承诺多副本 HA。
- **持久化：** SQLite 保存长期数据；challenge、verification token 和短期限流状态留在进程内存中，并通过锁保证一次性消费的原子性。
- **密钥：** 站点 secret 可以在 WebUI 中恢复展示，使用独立的 `CAPGO_MASTER_KEY` 加密后存入 SQLite。
- **版本策略：** 所有官方 widget、WASM、协议 oracle 和测试依赖必须固定版本，不使用 `latest`。

### 2.1 “完整 Cap v4”的边界

这里的“完整”指 **Cap 协议和验证能力完整**，不指 capd 的所有产品功能完整。

v1 不追求以下 capd 功能对等：

- 世界地图、ASN/GeoIP、复杂流量画像；
- ClickHouse 多节点分析；
- Valkey 分布式限流和多副本状态；
- Webhook、share links、完整规则 DSL；
- Cloudflare Workers 等平台适配器；
- 官方 capd 的 269 个 Svelte dashboard 组件。

如果 format-2 的某个高级协议尚未通过官方 widget 的真实浏览器互操作测试，不得在 WebUI 中标记为稳定功能；可以先作为隐藏的实验功能保留。

## 3. 兼容性目标

| 对象 | 固定/目标版本 | 验收要求 |
|---|---:|---|
| `@cap.js/widget` | 0.1.63 | 使用未修改的 widget 完成 challenge → solve → redeem |
| `@cap.js/wasm` | 0.0.8 | 本地同源加载，不能依赖 jsDelivr |
| `@cap.js/server` | 4.0.5 | format-1 双向互操作；官方生成的 challenge 能由 capgo redeem，反之亦然 |
| `capjs-core` | 0.1.18 | format-2、HashWX、RSW、instrumentation 使用官方 oracle 做互操作测试 |
| capd | 4.0.15 作为参考基线 | 对照其 endpoint、site key、secret、策略和错误语义；不承诺 dashboard/API 全量兼容 |
| Twikoo | 2.0.17 | 外接模式可用：`CAPTCHA_PROVIDER=Cap`、`CAP_API_ENDPOINT`、`CAP_SECRET_KEY` |

### 3.1 对外 HTTP 协议

每个站点使用一个 slug，例如 `twikoo`。建议公开 endpoint 为：

```text
https://cap.example.com/twikoo/
```

widget 会追加路径：

```http
POST /twikoo/challenge
POST /twikoo/redeem
```

Twikoo 服务端会调用：

```http
POST /twikoo/siteverify
Content-Type: application/json

{"secret":"<site secret>","response":"<verification token>"}
```

公开 API 的基础响应必须兼容官方协议：

- challenge：`{challenge, token, expires}` 或 format-2 的 `{format, token, expires, challenges}`；
- redeem 成功：`{success:true, token, expires}`；
- redeem 失败：`{success:false, error/message/...}`；
- siteverify：`{success:true}` 或 `{success:false, error}`。

`?wasm=0` 等 widget 查询参数必须被接受并正确忽略/处理。

### 3.2 路径与站点规则

- slug 只允许小写字母、数字、`-`、`_`，长度限制在 1–32；
- site key、公开 endpoint 和内部签名密钥分离；
- 每个站点独立配置协议、难度、TTL、限流、CORS 和 instrumentation 策略；
- 站点删除默认采用软删除，避免旧 token 和事件失去审计上下文；
- siteverify 必须验证 slug 与 secret 的对应关系，不能只验证全局 secret。

## 4. 总体架构

```text
cmd/capgo/
  └── 进程启动、配置、信号处理、HTTP server

internal/protocol/
  ├── format1/       legacy @cap.js/server 兼容
  ├── format2/       capjs-core envelope / token / scope
  ├── sha256pow/     SHA-256 PoW
  ├── hashwx/        HashWX challenge / verify
  ├── rsw/           RSW keypair / mint / verify
  └── instrumentation/ challenge script / result verify

internal/api/
  ├── public/        challenge、redeem、siteverify
  ├── admin/         登录、站点、配置、统计、事件
  └── middleware/    CORS、限流、body limit、proxy IP、request ID

internal/store/
  ├── memory/        challenge / token / short-lived limiter
  ├── sqlite/        site、secret、session、event、migration
  └── model/

internal/security/
  ├── secretbox/     AES-GCM 加密站点 secret 和私钥
  ├── session/       hashed session token、过期、撤销
  └── csrf/

web/
  ├── templates/     html/template 页面
  ├── static/        CSS、原生 JS、图表和 Cap widget/WASM
  └── embed.go       go:embed

tools/
  ├── oracle/        Node 官方包互操作脚本
  └── capsolve/      测试、fixture 和压测工具

testdata/
  ├── prng/
  ├── format1/
  └── format2/
```

### 4.1 运行时依赖原则

- 运行时只需要 capgo 二进制和 SQLite 文件；
- SQLite 使用纯 Go 驱动（`modernc.org/sqlite`），保持 `CGO_ENABLED=0` 可构建；
- Node/Bun 只允许出现在开发、oracle、fixture 生成和可选构建工具中；
- 不把官方 JS 服务端包动态下载或执行在生产请求路径；
- 不把站点 secret、admin key、master key 写入日志或前端 bundle。

## 5. 协议实现计划

### 阶段 P0：规范锁定与可行性验证

先不写完整服务，建立兼容性基线：

1. 固定 `@cap.js/server@4.0.5`、`capjs-core@0.1.18`、widget 0.1.63、WASM 0.0.8；
2. 从官方包生成 PRNG、challenge、redeem、token、format-2 fixture；
3. 读取并记录 capd 4.0.15 的协议分支、默认参数、错误码和站点配置语义；
4. 确认 Go 对以下 JS 语义的实现方式：无符号溢出、FNV-1a、xorshift32、hex、BigInt、随机数和时间戳；
5. 对 HashWX、RSW、instrumentation 分别建立“官方生成 → Go 验证”和“Go 生成 → 官方验证”的最小实验；
6. 如果某个高级协议无法在真实 widget 中互操作，先记录为阻塞项，不在 UI 宣称已支持。

**出口条件：** 有版本锁定文件、fixture 生成脚本、兼容性矩阵和每个协议的可行性结论。

### 阶段 P1：format-1 与 Twikoo 纵向切片

先让最小可用产品跑通：

- FNV-1a + xorshift32 PRNG；
- challenge 生成与 10 分钟过期；
- `sha256(salt + decimal nonce)` 前缀校验；
- challenge 一次性消费；
- verification token 生成、20 分钟过期、`sha256(token)` 存储、siteverify 一次性消费；
- public API、CORS、错误响应；
- Twikoo 2.0.17 外接模式验收。

**出口条件：** 未修改的 widget 0.1.63 能通过 capgo 完成验证；无 token 的直接评论请求被 Twikoo 拒绝；重放 token 失败。

### 阶段 P2：format-2 基础协议

- format-2 envelope 与 protocol list；
- signed challenge/token 和 scope；
- format-2 SHA-256 PoW；
- 统一的 challenge、redeem、token 消费接口；
- 按 protocol 记录事件和失败 reason；
- 与 `capjs-core@0.1.18` 双向 fixture 和浏览器测试。

### 阶段 P3：HashWX 与 RSW

#### HashWX

- 按 capjs-core 的算法和参数实现 challenge 派生、目标计算和服务端验证；
- 固定边界、溢出、endianness 和难度换算测试；
- 对高并发验证做 benchmark，避免一次请求占满 CPU；
- 通过真实 widget 的 HashWX solve/redeem 后，才允许在站点配置中启用。

#### RSW

- 生成并持久化每站点或实例级 RSW keypair；
- 私钥使用 `CAPGO_MASTER_KEY` 加密，公钥随 challenge 返回；
- 实现 BigInt/modpow、mint、solution verify 和过期/重放保护；
- 用官方 capjs-core fixture 和真实 widget 测试；
- keypair 生成、轮换和备份必须有明确的管理操作。

### 阶段 P4：instrumentation / 行为校验

这是完整 Cap v4 中风险最高的一段，单独实现，不与基础 PoW 混在一起：

- 研究官方 instrumentation blob、metadata、绑定字段和失败 reason；
- Go 生成与压缩 challenge script，或实现一个有明确版本边界的兼容 generator；
- 验证缺失、篡改、超时、自动化浏览器标记和错误结果；
- 区分“报告风险”和“阻断请求”两种策略；
- 使用 Playwright/Chromium 覆盖真实浏览器、无头浏览器、过期、篡改和脚本错误；
- 在没有通过完整矩阵前，默认关闭阻断，只允许观测模式或隐藏实验开关。

**阶段性发布策略：** P1/P2 可以作为内部 beta 使用；P3/P4 通过完整互操作矩阵后，才将版本标记为“完整 Cap v4”。不能因为 P1 可用就对外宣称已经兼容所有 v4 能力。

## 6. 持久化与安全设计

### 6.1 SQLite 数据

至少包含以下表：

- `schema_migrations`：迁移版本；
- `sites`：slug、名称、启用状态、协议配置、CORS、限流和时间戳；
- `site_secrets`：加密后的公开 secret、内部签名密钥、RSW 私钥等；
- `admin_sessions`：只保存随机 session token 的哈希、创建时间、过期时间、撤销状态；
- `events`：challenge、redeem、verify、blocked、error 等审计事件；
- `settings`：可公开的实例级设置和非敏感配置。

challenge 和 verification token 不写 SQLite，原因是它们的生命周期短且单实例内存锁足以保证原子消费。进程重启后未完成的挑战需要重新计算，已发 token 失效，这属于明确接受的单实例行为。

### 6.2 密钥体系

- `CAPGO_ADMIN_KEY`：仅用于登录管理面板，不写数据库；要求使用高熵随机值；
- `CAPGO_MASTER_KEY`：独立的 32 字节密钥，使用 AES-256-GCM 加密站点 secret、内部签名密钥和 RSW 私钥；
- 每条密文使用随机 nonce，并将站点 slug、字段名和 schema 版本作为 AEAD additional data；
- WebUI 只在已认证会话中显示 secret；高风险的 reveal/rotate 操作需要再次输入 admin key 或二次确认；
- 支持 secret rotate 和 master key re-encrypt；master key 丢失时无法恢复密文，部署文档必须要求独立备份；
- 所有 secret 比较使用常数时间比较；日志、事件和错误页面不得输出 secret。

### 6.3 管理面板安全

- admin session 使用 `HttpOnly`、`Secure`、`SameSite=Lax` cookie；
- 所有修改操作使用 CSRF token；
- 登录、reveal、rotate、站点创建和公共 API 均有限流；
- public API 设置请求体上限、超时和并发上限；
- CORS 使用每站点 allowlist，`*` 只能由管理员显式开启；
- `X-Forwarded-For` / `Forwarded` 只有在配置的可信反代来源上才读取；
- IP 限流必须有“直连模式”和“可信反代模式”的测试；
- 默认不保存明文 IP，事件中保存 keyed digest 或按配置脱敏后的地址；事件默认保留 30 天并定期清理；
- 事件 metadata 采用白名单字段，禁止写入请求 body、secret、cookie 和完整邮箱等敏感内容。

## 7. WebUI 计划

采用 Go `html/template` + 原生 JS/CSS + `go:embed`，保持单二进制和无前端构建运行时。

### 页面

1. **登录**：admin key 登录、会话过期、登出；
2. **概览**：站点数、今日 challenge/redeem/verify、成功率、失败原因、协议分布；
3. **站点列表/详情**：创建、启停、名称、slug、secret reveal/rotate、删除；
4. **集成**：endpoint、site secret、widget HTML/JS 示例、Twikoo 配置示例、同源资产地址；
5. **协议配置**：format、SHA-256/HashWX/RSW、instrumentation、难度、TTL、限流、CORS、阻断策略；
6. **事件**：最近事件、过滤、错误原因、协议、耗时、匿名客户端摘要；
7. **统计**：最近 7/30 天的 challenge、成功率、失败原因和按站点汇总；
8. **实例设置**：默认协议、事件保留周期、公开 URL、可信反代、默认限流。

### 交互原则

- 默认提供“Twikoo 兼容”安全预设，避免新建站点时误启用高级协议；
- 高级功能显示协议版本、兼容性状态、CPU/浏览器成本和风险提示；
- SSE 用于事件实时推送，断线自动回退到分页轮询；
- 统计从 SQLite 聚合，避免引入 DuckDB/ClickHouse；
- 图表优先使用原生 SVG/CSS，不引入大型前端框架；
- UI 只借鉴 capd 的信息架构和交互，不复制整个 Svelte dashboard。

### 官方代码与许可证

官方 cap 仓库使用 Apache-2.0。若引用代码、样式或图标：

- 保留上游版权和许可证声明；
- 在 `NOTICE` 或 `third_party/` 中记录来源、版本和修改；
- 自有代码继续使用仓库声明的 Apache-2.0；
- 不把“参考设计”误写成官方项目或官方支持。

## 8. 静态资源与大陆访问

- vendor 固定版本的 `@cap.js/widget@0.1.63` 和 `@cap.js/wasm@0.0.8`；
- 通过 `go:embed` 从 capgo 同源提供 widget/WASM；
- 在集成页面生成 `CAP_CUSTOM_WASM_URL` 示例，避免浏览器访问 jsDelivr；
- 检查正确的 MIME type、缓存头、`Cache-Control` 和跨域头；
- 生产构建不得从网络下载 `latest` 资源；
- 更新 widget/WASM 必须同时运行官方 oracle、浏览器 e2e 和 Twikoo 回归。

## 9. 测试与质量门槛

### 协议测试

- PRNG golden vectors：官方 Node 包、独立实现和 cap-php/其他独立实现交叉验证；
- format-1：官方 server → capgo、capgo → 官方 server；
- format-2：capjs-core → capgo、capgo → capjs-core；
- 每种 protocol 覆盖成功、错误 solution、缺字段、过期、错误 scope、错误站点和重放；
- JSON 字段、数值范围、错误 status/body 和查询参数兼容测试。

### 浏览器测试

固定 widget/WASM，从 capgo 本地静态资源加载：

- Chromium 正常浏览器完成全部已启用协议；
- widget 加载失败、WASM 加载失败、网络超时和重试；
- 无头浏览器、自动化标记和 instrumentation 策略；
- 多站点 endpoint、CORS、HTTPS 反代；
- Twikoo 2.0.17 在无痕窗口完成真实评论提交。

### 安全与并发测试

- `go test -race ./...`；
- challenge/redeem/siteverify 并发重复提交，必须最多成功一次；
- session、CSRF、登录限流、站点隔离和 secret 加密测试；
- fuzz JSON parser、protocol payload 和路由 slug；
- 请求体、超时、并发和事件写入压力测试；
- SQLite 备份、恢复、迁移和 master key re-encrypt 演练。

### 发布门槛

任何协议或 widget 版本更新没有通过互操作和浏览器矩阵时，不得发布为稳定版。协议实现、WebUI 和部署文档必须在同一提交中保持一致。

## 10. 部署计划

目标机器：Aliyun Shenzhen，Rocky Linux 10，单实例。

1. 编译 `CGO_ENABLED=0 GOOS=linux GOARCH=amd64` 静态二进制；
2. 创建专用低权限用户和 `/var/lib/capgo` 数据目录；
3. 使用 systemd 管理服务，监听 `127.0.0.1`，不直接暴露管理端口；
4. 使用现有 Caddy 反向代理到 HTTPS 域名，例如 `cap.mvr.cc`；
5. Caddy 只转发公开 API 和 WebUI，正确传递真实 IP 和 SSE；
6. Aliyun 安全组只开放 80/443，应用端口不对公网开放；
7. 独立备份 SQLite 数据库和 `CAPGO_MASTER_KEY`，两者不能只备份其中一个；
8. 升级采用“构建新二进制 → 停止旧服务 → 数据库迁移 → 启动 → 健康检查 → 回滚”的流程；
9. 部署文档提供 Homepage/Twikoo 配置示例，但不把真实 secret 写入仓库。

### 运行配置（计划）

```text
CAPGO_ADDR=127.0.0.1:3000
CAPGO_PUBLIC_URL=https://cap.example.com
CAPGO_DB_PATH=/var/lib/capgo/capgo.sqlite3
CAPGO_ADMIN_KEY=<high-entropy-admin-key>
CAPGO_MASTER_KEY=<32-byte-base64-or-hex-key>
CAPGO_TRUST_PROXY=<trusted-caddy-network>
CAPGO_LOG_LEVEL=info
```

## 11. 里程碑与交付物

### M0：规范和 fixture

交付：版本锁定、协议笔记、oracle、golden vectors、兼容性矩阵、风险清单。

### M1：format-1 / Twikoo beta

交付：核心库、public HTTP API、siteverify、内存原子存储、Twikoo 外接模式测试。

### M2：SQLite 与安全基础

交付：迁移、站点管理模型、secret 加密、session、CORS、限流、事件记录、健康检查。

### M3：format-2 SHA-256

交付：format-2 envelope、scope、签名 token、官方 capjs-core 双向互操作。

### M4：HashWX / RSW

交付：协议实现、keypair 管理、benchmark、真实 widget 兼容测试；未通过者保持 feature flag 关闭。

### M5：instrumentation

交付：challenge script、结果验证、风险策略、真实浏览器/自动化测试矩阵。

### M6：WebUI 与静态资源

交付：轻量 dashboard、站点配置、集成页、事件 SSE、统计、widget/WASM 同源嵌入。

### M7：生产部署

交付：systemd、Caddy、备份恢复、升级回滚、深圳服务器部署和 Homepage/Twikoo 验收记录。

## 12. 非目标与风险控制

- **不把 PoW 描述为绝对的人类证明**：它主要提高脚本批量请求的成本；有能力运行浏览器和计算资源的攻击者仍可能通过。
- **不在 v1 做多副本**：若未来需要 HA，必须新增共享 challenge/token/limit store，并重新审计一次性消费。
- **不直接复制 capd dashboard**：完整 capd dashboard 的体量和运行时依赖会破坏单二进制目标。
- **高级协议不得阻塞基础服务**：P3/P4 若延期，format-1/P2 仍保持独立可用；UI 通过 feature flag 隐藏未验证功能。
- **不依赖“最新版”**：Cap 生态协议和 widget 可能演进；所有升级必须以 fixture 和真实浏览器互操作为准。
- **原计划“3–5 个工作日完成全部功能”不再适用**：在自行实现完整 Cap v4、WebUI、加密存储和 e2e 的前提下，应按多个里程碑推进，先交付 M1/M2，再评估 M4/M5 的协议复杂度。

## 13. 完成定义

项目可以称为“可用 beta”，需要同时满足：

- Homepage/Twikoo 使用外接 capgo 成功发表评论；
- 官方 widget 通过本地 widget/WASM 资源完成验证；
- siteverify 正确拒绝错误 secret、错误站点、过期 token 和重放 token；
- admin key、master key、session、CSRF 和 CORS 通过测试；
- SQLite 备份/恢复和服务重启行为有文档；
- systemd + Caddy 在深圳服务器完成部署；
- 未通过完整互操作的高级协议不会显示为稳定能力。

项目可以称为“完整 Cap v4 兼容”，还必须额外满足：

- format-1、format-2、SHA-256、HashWX、RSW、instrumentation 全部通过官方 oracle 双向互操作；
- widget 0.1.63 在真实 Chromium 中完成各协议验证；
- 每个协议的失败、过期、重放和跨站点隔离测试通过；
- WebUI 配置与实际 challenge 行为一致，不能出现“面板显示已启用但服务端未生效”。
