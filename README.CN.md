<h1 align="center">powguard</h1>

<p align="center">单二进制、SQLite、无外部服务依赖的 Cap 工作量证明人机验证服务。</p>

<p align="center">
  <a href="https://go.dev/"><img alt="Go" src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go&logoColor=white"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square"></a>
  <a href="docs/m5-acceptance.md"><img alt="Status" src="https://img.shields.io/badge/status-beta-orange?style=flat-square"></a>
  <a href="docs/compat-matrix.md"><img alt="Protocol" src="https://img.shields.io/badge/protocol-Cap%20format--1%20%7C%20format--2-2ea44f?style=flat-square"></a>
  <a href="deploy/README.md"><img alt="Deploy" src="https://img.shields.io/badge/deploy-single%20binary-6f42c1?style=flat-square"></a>
</p>

<p align="center"><a href="README.md">English</a> | <strong>简体中文</strong></p>

powguard 是 [Cap](https://github.com/tiagozip/cap) 工作量证明（PoW）验证服务端的 Go 实现。它与官方 `@cap.js/widget` 的线协议兼容，提供多站点、按站点策略、密钥管理、事件审计和轻量 WebUI；运行时只需要一个静态二进制和一个 SQLite 文件。

**主要场景**：Twikoo 评论区外接验证；同样适用于登录、注册、表单和其他需要防刷的公开接口。

## 特性

- **官方 widget 直连**：未修改的 `@cap.js/widget` 0.1.63 可直接完成 challenge → solve → redeem。
- **双协议**：format-1（`@cap.js/server` 4.0.5 兼容）与 format-2 SHA-256（`capjs-core` 0.1.18 envelope/scope）。
- **Twikoo 2.0.17 外接模式**：`CAPTCHA_PROVIDER=Cap` + `CAP_API_ENDPOINT` + `CAP_SECRET_KEY`。
- **多站点隔离**：路径分站点（`/{site}/`），每个站点独立 secret、协议、难度、TTL、CORS 和限流。
- **一次性消费**：challenge 与通行 token 在内存中原子消费；重放、过期和跨站 token 默认拒绝。
- **安全默认值**：站点密钥 AES-256-GCM 加密存储；管理会话 `HttpOnly`/`Secure`/`SameSite=Lax`；写操作 CSRF；高危操作二次认证；常数时间比较。
- **轻量 WebUI**：概览、站点管理、集成片段、密钥 reveal/rotate、事件 SSE、统计、实例设置。
- **单机零依赖**：纯 Go SQLite 驱动，`CGO_ENABLED=0` 可构建；无 Docker、Node、Redis/Valkey。
- **同源静态资产**：内置钉版本的 widget 与 WASM，并为跨站使用提供 CORS 头，避免依赖 jsDelivr。
- **可运维**：`keyrotate` / `backup` / `verify-keys` 子命令，systemd 加固示例，Caddy 反代与备份恢复文档。

> 当前为**单实例 beta**。challenge 与通行 token 保存在进程内存，重启会让未完成的挑战失效（访客重解一次即可）；不支持多副本 HA。

## 快速开始

要求 Go 1.26+、Make、OpenSSL。

```bash
git clone https://github.com/sseaan/powguard.git
cd powguard
make build

export POWGUARD_MASTER_KEY="$(openssl rand -hex 32)"
export POWGUARD_ADMIN_KEY="$(openssl rand -base64 24)"
export POWGUARD_SITE_SECRET="$(openssl rand -hex 24)"

./powguard
```

启动后：

- 管理面板：<http://127.0.0.1:3000/admin>（使用 `POWGUARD_ADMIN_KEY` 登录）
- 演示页：<http://127.0.0.1:3000/>
- 默认站点：`twikoo` → `http://127.0.0.1:3000/twikoo/`
- SQLite：`./powguard.sqlite3`

首次启动若库中无站点，会用 `POWGUARD_SITE_SLUG` / `POWGUARD_SITE_SECRET` 创建首个站点；未提供 secret 时会生成临时值并打印 WARN，仅用于本机演示。

用 `capsolve` 自检完整链路：

```bash
./capsolve -endpoint http://127.0.0.1:3000/twikoo/ -secret "$POWGUARD_SITE_SECRET"
# 期望：challenge → solve → redeem → siteverify → replay-rejected
```

## 部署

生产构建为静态 Linux 二进制：

```bash
make linux
# 产物：dist/powguard-linux-amd64（+ .sha256）
```

推荐部署形态：

```text
Caddy / Nginx（HTTPS）
        ↓
powguard  127.0.0.1:3000
        ├── SQLite
        └── 内存 challenge / token
```

完整的 systemd 加固、Caddy 配置、可信反代、备份恢复、升级回滚和排障步骤见 **[deploy/README.md](deploy/README.md)**。

已在以下环境完成实机验收：Aliyun 深圳、Rocky Linux 10.2、Caddy 2.11.4、`cap.mvr.cc`。验收记录见 **[docs/m5-acceptance.md](docs/m5-acceptance.md)**。

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `POWGUARD_ADDR` | `127.0.0.1:3000` | 监听地址；生产建议只监听回环，由反代暴露 |
| `POWGUARD_DB_PATH` | `./powguard.sqlite3` | SQLite 文件路径 |
| `POWGUARD_PUBLIC_URL` | 空 | 公开 URL；`https://` 会让管理 cookie 自动加 `Secure` |
| `POWGUARD_MASTER_KEY` | 空 | 32 字节（hex/base64），加密站点密钥；已有密文的库缺此 key 会拒绝启动 |
| `POWGUARD_ADMIN_KEY` | 空 | 管理面板登录密钥；留空则管理面板整体禁用 |
| `POWGUARD_TRUST_PROXY` | 空 | 可信反代 CIDR，逗号分隔；配置后才读取 `X-Forwarded-For` |
| `POWGUARD_SITE_SLUG` | `twikoo` | 仅首次启动 bootstrap 使用 |
| `POWGUARD_SITE_SECRET` | 空 | 仅首次启动 bootstrap 使用；生产必须显式设置 |

> `POWGUARD_MASTER_KEY` 与数据库必须**成对备份、分开存放**。丢失 master key 后，库中的站点密钥无法恢复。

### 运维子命令

```bash
powguard version
powguard backup      --db <path> --out <file>                       # 在线一致性快照
powguard verify-keys --db <path> --master-key <hex|b64>            # 密文可解性校验
powguard keyrotate   --db <path> --old-key <k> --new-key <k>       # master key 轮换
```

`keyrotate` 会重加密全部站点密钥，单事务执行；完成后需同步更新 `POWGUARD_MASTER_KEY` 并重启服务。

## Twikoo 集成

1. 在 powguard 管理面板创建站点（slug 例如 `twikoo`，协议选 **format-1（Twikoo 兼容）**）。
2. 在站点「密钥」页 reveal `CAP_SECRET_KEY`。
3. 在 Twikoo 管理面板配置：

```text
CAPTCHA_PROVIDER  = Cap
CAP_API_ENDPOINT  = https://cap.example.com/twikoo/
CAP_SECRET_KEY    = <powguard 站点 secret>
```

`CAP_BUILTIN` 由 Twikoo 根据 `CAP_API_ENDPOINT` 是否为空自动推导，不需要手动设置。

Twikoo 前端默认会从 `cdn.jsdmirror.com` 加载 Cap widget。若希望完全使用 powguard 的同源资产，可在 Twikoo 脚本加载前预置：

```html
<script>window.CAP_CUSTOM_WASM_URL = "https://cap.example.com/static/vendor/cap_wasm_bg.wasm";</script>
<script src="https://cap.example.com/static/vendor/cap.min.js"></script>
```

验收时检查：

- 正常完成验证 → 评论发布成功；
- 不完成验证直接提交 → 被拒绝；
- 重放同一 token → `404 Token not found`；
- 错误 secret → `403 Invalid site key or secret`；
- 站点 A 的 token 提交到站点 B → 拒绝。

## HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| `POST` | `/{site}/challenge` | 获取挑战（format-1 或 format-2 envelope） |
| `POST` | `/{site}/redeem` | 提交 solution，换取一次性通行 token |
| `POST` | `/{site}/siteverify` | 服务端校验通行 token：`{secret, response}` |
| `POST` | `/siteverify` | capd 风格无路径版本；站点从三段式 token 第一段恢复 |
| `OPTIONS` | `/{site}/challenge` 等 | CORS 预检 |
| `GET` | `/healthz` | 健康检查：`{"status":"ok"}` |
| `GET` | `/` | 内置 widget 演示页 |
| `GET` | `/admin` | 管理面板 |
| `GET` | `/static/vendor/*` | 钉版本的 widget / WASM / CSS |

响应示例：

```jsonc
// POST /twikoo/challenge（format-1）
{ "challenge": { "c": 50, "s": 32, "d": 4 }, "token": "...", "expires": 1795067399614 }

// POST /twikoo/redeem
{ "success": true, "token": "twikoo:...:...", "expires": 1795068000000 }

// POST /twikoo/siteverify
{ "success": true }
// 失败：{ "success": false, "error": "Token not found" }
```

公开端点支持按站点配置的 CORS allowlist、每 IP 限流、请求体上限和 `?wasm=0` 等 widget 查询参数。

## 安全模型

- 站点 secret 与 format-2 签名密钥使用 **AES-256-GCM** 加密，AAD 绑定站点 slug、字段名和 schema 版本。
- 站点 secret 比较使用常数时间比较；日志、事件和错误页面不输出 secret。
- 管理会话只保存 token 哈希；cookie 为 `HttpOnly`、`Secure`（HTTPS）、`SameSite=Lax`。
- 所有修改操作校验 CSRF；reveal/rotate 需要再次提交 admin key。
- 事件默认保存 **keyed IP digest**，不落明文 IP；默认保留 30 天。
- `X-Forwarded-For` 仅在 `POWGUARD_TRUST_PROXY` 命中的可信反代来源上读取；伪造头会被忽略。
- 站点删除为软删除，保留事件审计上下文。

## 项目结构

```text
cmd/powguard/          进程启动、配置、信号处理、HTTP server、运维子命令
internal/protocol/     format-1 / format-2 / PRNG / SHA-256 PoW
internal/api/          public / admin / middleware（CORS、限流、body limit、真实 IP）
internal/policy/       站点解析、协议与策略校验
internal/store/        memory（challenge/token/limiter）与 sqlite（站点/密钥/会话/事件）
internal/security/     secretbox、session、csrf
internal/events/       异步审计事件 sink
web/                   html/template + 原生 JS/CSS + go:embed 静态资产
deploy/                systemd、Caddy、env 示例、备份/恢复脚本
docs/                  协议笔记、兼容性矩阵、M5 验收记录
tools/oracle/          官方 Node 包 fixture / 双向互操作
tools/capsolve/        测试与压测 CLI
```

## 测试与兼容性

```bash
make test     # 单元测试
make race     # go test -race
make check    # gofmt + vet + race（oracle 依赖缺失时互操作测试自动跳过）
make oracle   # 官方包 fixture 双向互操作（首次需 cd tools/oracle && npm ci）
```

兼容性基线（钉版本，见 [versions.lock](versions.lock)）：

| 对象 | 版本 | 验收 |
|---|---:|---|
| `@cap.js/widget` | 0.1.63 | 未修改 widget 完成 challenge → solve → redeem |
| `@cap.js/wasm` | 0.0.8 | 同源加载，无 jsDelivr 依赖 |
| `@cap.js/server` | 4.0.5 | format-1 双向互操作 |
| `capjs-core` | 0.1.18 | format-2 SHA-256 / scope 互操作 |
| Twikoo | 2.0.17 | 外接模式真实评论提交与负向用例 |

更细的协议字段、错误语义和交叉验证结果见 [docs/protocol-notes.md](docs/protocol-notes.md) 与 [docs/compat-matrix.md](docs/compat-matrix.md)。

## 状态与范围

**已实现**

- format-1 与 format-2 SHA-256；
- 多站点、按站点协议/难度/TTL/CORS/限流；
- 管理面板、事件审计、SSE、统计；
- SQLite 持久化、密钥加密、master key 轮换；
- systemd + Caddy 单机部署、备份恢复；
- 真实浏览器与 Twikoo 实机验收。

**当前不实现**

- HashWX、RSW time-lock puzzle、instrumentation / 行为识别；
- 多副本 HA、共享 challenge/token store；
- capd 的 GeoIP/ASN、ClickHouse、Webhook、share links、完整规则 DSL；
- 官方 capd dashboard 的全量功能对标。

这些能力保留为后续 protocol/provider 扩展方向，不会以“已支持”的形式出现在当前稳定接口中。

## 文档

- [AGENT.md](AGENT.md) — 给贡献者/Agent 的项目约定、架构与发布门槛
- [docs/protocol-notes.md](docs/protocol-notes.md) — format-1 / format-2 / Twikoo 协议笔记
- [docs/compat-matrix.md](docs/compat-matrix.md) — 官方包与 Go 实现的兼容性矩阵
- [docs/m5-acceptance.md](docs/m5-acceptance.md) — 深圳实机验收记录
- [deploy/README.md](deploy/README.md) — systemd + Caddy 生产部署与运维
- [versions.lock](versions.lock) — 固定版本与已验证能力

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。

协议设计与线格式参考上游 [tiagozip/cap](https://github.com/tiagozip/cap)（Copyright 2025 Tiago）及 npm 包 `@cap.js/server`、`capjs-core`；`web/static/vendor/` 下的官方 widget/WASM 资产按其上游许可证随二进制再分发，来源与版本见 [web/static/vendor/NOTICE.md](web/static/vendor/NOTICE.md)。
