# AGENT.md

面向在本仓库工作的 AI Agent 与贡献者。开始修改前，先读：

1. [README.md](README.md) —— 功能、快速开始、API 与配置
2. 本文件 —— 不变量、架构、修改流程与发布门槛
3. 相关专题文档：[docs/protocol-notes.md](docs/protocol-notes.md)、[docs/compat-matrix.md](docs/compat-matrix.md)、[deploy/README.md](deploy/README.md)

> 若文档、代码与线上行为不一致，以代码和测试为准，并在同一提交中修正文档。

## 1. 项目现状

- `powguard` 是 Cap 工作量证明验证服务端的 Go 实现，单静态二进制 + SQLite。
- 里程碑 M0–M5 已完成：协议、SQLite/安全、format-2、WebUI、systemd/Caddy 部署与深圳实机验收。
- 当前定位：**单实例可用 beta**，首要场景是 Twikoo 2.0.17 外接验证。
- 生产验收记录：[docs/m5-acceptance.md](docs/m5-acceptance.md)。
- 固定版本与已验证能力：[versions.lock](versions.lock)。

## 2. 不可协商的约束

### 运行时

- 运行时只需要 `powguard` 二进制和 SQLite 文件；不引入 Docker、Node、Redis/Valkey、消息队列。
- SQLite 使用纯 Go 驱动 `modernc.org/sqlite`，必须保持 `CGO_ENABLED=0` 可构建。
- WebUI 使用 Go `html/template` + 原生 JavaScript/CSS + `go:embed`；不引入 SPA、Vite、React/Vue 或前端构建步骤。
- 单实例语义：challenge、通行 token、短期限流状态保存在进程内存。**不要**在没有共享存储和一次性消费重新审计的情况下增加多副本。

### 协议范围

当前稳定协议只有：

- **format-1**：`@cap.js/server@4.0.5` 兼容，Twikoo 外接模式的最低目标。
- **format-2 SHA-256**：`capjs-core@0.1.18` envelope / scope / `sha256-pow`。

明确不实现、也不得在 UI/API 中暗示已支持：

- HashWX；
- RSW time-lock puzzle；
- instrumentation / 行为识别；
- capd 的 GeoIP/ASN、ClickHouse、Webhook、share links、完整规则 DSL。

新增协议必须走独立 provider、fixture、双向互操作、浏览器回归，再进入稳定 API/WebUI。

### 版本

- 所有官方包、widget、WASM、Twikoo、协议 oracle 必须固定版本；禁止 `latest`。
- 官方 `@cap.js/server`、`capjs-core`、`capd` 只作为规范、fixture 和测试 oracle，不作为运行时依赖。
- 升级任何固定版本前，必须重跑 `make oracle`、浏览器矩阵与 Twikoo 回归，并同步更新 `versions.lock`。
- 当前基线：

| 对象 | 版本 |
|---|---:|
| `@cap.js/server` | 4.0.5 |
| `@cap.js/widget` | 0.1.63 |
| `@cap.js/wasm` | 0.0.8 |
| `capjs-core` | 0.1.18 |
| Twikoo | 2.0.17 |

### 安全

- `POWGUARD_MASTER_KEY` 只通过环境变量提供；不得写入仓库、日志、事件、前端 bundle 或错误页面。
- 站点 secret / format-2 签名密钥使用 AES-256-GCM 加密；AAD 必须绑定站点 slug、字段名、schema 版本。
- secret 比较必须常数时间；不得在日志、事件、错误响应中输出 secret。
- 管理会话只存 token 哈希；cookie 使用 `HttpOnly`、`Secure`（HTTPS）、`SameSite=Lax`。
- 所有修改操作必须校验 CSRF；reveal/rotate 必须再次验证 admin key。
- `X-Forwarded-For` 只在 `POWGUARD_TRUST_PROXY` 命中的可信反代来源上读取；直连模式必须忽略伪造头。
- 事件只保存白名单字段和 keyed IP digest，不保存请求体、secret、cookie 或明文 IP。
- 站点删除默认软删除，保留事件审计上下文。
- 数据库迁移只增不减；不要修改已发布的迁移文件。

### 静态资产

- `web/static/vendor/` 下的 widget/WASM/CSS 必须固定版本，来源与修改记录写入 `NOTICE.md`。
- 同源加载优先；跨站使用（Twikoo）依赖 `/static/vendor/` 的 CORS 头，不要移除。
- 生产构建不得从网络下载 `latest` 资源。

## 3. 架构与目录

```text
cmd/powguard/          启动、配置、信号处理、HTTP server、运维子命令
internal/protocol/     format-1、format-2、PRNG、SHA-256 PoW、provider 边界
internal/api/public/   challenge / redeem / siteverify、CORS、公开限流
internal/api/admin/    登录、站点 CRUD、reveal/rotate、事件、统计、SSE
internal/api/middleware/ 请求 ID、访问日志、body limit、Recover、真实 IP
internal/policy/       站点解析、slug/协议校验、策略
internal/store/memory/ challenge/token/limiter（一次性消费在锁内完成）
internal/store/sqlite/ 迁移、站点、密钥、会话、事件、设置
internal/security/     secretbox、session、csrf
internal/events/       异步审计 sink
web/                   templates、static、embed
deploy/                systemd、Caddy、env 示例、backup/restore
docs/                  协议笔记、兼容矩阵、M5 验收
tools/oracle/          官方 Node 包 fixture 与双向互操作
tools/capsolve/        全链路测试/压测 CLI
```

数据边界：

- SQLite：`schema_migrations`、`sites`、`site_secrets`、`admin_sessions`、`events`、`settings`。
- 内存：challenge、verification token、短期限流状态。重启后未完成的 challenge 失效、已发 token 失效，这是明确接受的单实例行为。

## 4. 协议要点

### format-1

```text
challenge  → { challenge: {c, s, d}, token, expires }
redeem     ← { token, solutions: number[] }
             salt_i   = prng(token || i,    s)
             target_i = prng(token || i"d", d)
             sha256(salt_i + solutions[i]) 的 hex 前缀 == target_i
redeem     → { success: true, token, expires }   // 通行 token 一次性
siteverify ← { secret, response } → { success }
```

- PRNG 是 `fnv1a + xorshift32`，seed 按 UTF-16 code unit 处理；这是与官方实现 bit-exact 的关键点。
- 通行 token 形如 `{site}:{id}:{random}`，存储 `sha256(token)`，消费必须原子。
- `POST /siteverify` 是 capd 风格无路径变体，站点从 token 第一段恢复；`POST /{site}/siteverify` 是 Twikoo 使用的路径变体。

### format-2

- envelope：`{ format: 2, token, expires, challenges }`。
- challenge 元素：`{ protocol, payload }`；当前只支持 `sha256-pow`。
- format-2 使用签名 token 与 scope；nonce 一次性消费；不实现 HashWX/RSW/instrumentation。

### Twikoo 外接

```text
CAPTCHA_PROVIDER = Cap
CAP_API_ENDPOINT = https://<powguard>/<site>/
CAP_SECRET_KEY   = <站点 secret>
```

- `CAP_BUILTIN` 由 Twikoo 根据 endpoint 是否为空推导，不要手动设置。
- 负向行为必须保持：无 token 拒绝、错误 secret 403、重放 404、跨站 token 拒绝。

## 5. 开发命令

要求 Go 1.26+；`make oracle` 额外需要 Node 与 `tools/oracle` 依赖。

```bash
make build     # 本机 powguard + capsolve
make test      # go test ./...
make race      # go test -race ./...
make check     # gofmt + vet + race（提交前必跑）
make oracle    # 重新生成 fixture 并跑协议互操作
make linux     # CGO_ENABLED=0 GOOS=linux GOARCH=amd64 静态产物
```

`make oracle` 首次使用：

```bash
cd tools/oracle
npm ci
cd ../..
make oracle
```

## 6. 修改流程

### 协议 / 兼容性

1. 先查 `docs/protocol-notes.md` 与官方包源码，记录字段、错误语义和边界。
2. 在 `tools/oracle` 生成或更新 fixture；同时验证“官方 → Go”和“Go → 官方”。
3. 更新 `internal/protocol/...` 与测试；确保 PRNG、一次性消费、跨站隔离、过期/重放用例。
4. 更新 `versions.lock`、兼容矩阵和相关文档。
5. 跑 `make check`、`make oracle`、浏览器矩阵与 Twikoo 回归。
6. 未通过完整互操作的协议不得出现在稳定 API/WebUI 中。

### 数据库

- 新增迁移文件 `internal/store/sqlite/migrations/000N_*.sql`，保持只增不减。
- 同步更新 `model`、repo、启动迁移测试和 `docs`。
- 不要在迁移中写入 secret 明文；不要修改已发布迁移。

### API / 安全

- 公开端点必须保持官方协议字段与状态码语义；错误响应保持 `{success:false,error}` 或 `{error}` 的既有形态。
- 新增管理操作必须走 session + CSRF；高危操作需要 re-auth。
- 任何新日志/事件字段都要过白名单审查，禁止 secret、body、cookie、明文 IP。

### WebUI

- 页面在 `web/templates/`，逻辑在 `web/static/app.js`，样式在 `web/static/app.css`。
- 不引入前端框架或构建链；图表用原生 SVG/CSS。
- SSE `/admin/api/events/stream` 必须保留断线回退到分页轮询。
- 面板展示的配置必须与服务端实际行为一致；不能出现“面板已启用但服务端未生效”。

### 静态资产

- 升级 widget/WASM：替换 `web/static/vendor/` 文件，更新 `NOTICE.md`、`versions.lock`、`web/embed_test.go`，跑浏览器回归。
- 保持 `/static/vendor/` 的 `Access-Control-Allow-Origin: *` 与 `Cross-Origin-Resource-Policy: cross-origin`，否则 Twikoo 跨站加载 WASM 会失败。

### 文档

- README、`AGENT.md`、`docs/`、`deploy/README.md` 必须与代码同提交更新。
- 不把真实 secret、admin key、master key、生产 IP 或未脱敏日志写入仓库。
- 验收记录只写可复现的命令、状态码和结论。

## 7. 测试与发布门槛

提交前最低要求：

```bash
make check
```

发布/升级前必须全部通过：

1. `make check`；
2. `make oracle`；
3. 真实 Chromium：widget 0.1.63 + 同源 WASM 0.0.8，format-1 与 format-2 各完成一次；
4. Twikoo 2.0.17 外接模式真实评论 + 负向用例（无 token、重放、错误 secret、跨站 token）；
5. 部署检查：`/healthz`、管理登录、SSE、CORS、限流；
6. 备份/恢复演练：`powguard backup` + `verify-keys` + `restore`；
7. 升级前备份数据库与 master key 的独立副本。

协议或 widget 版本更新没有通过互操作与浏览器矩阵时，不得发布为稳定版。

## 8. 部署与运维

完整步骤见 [deploy/README.md](deploy/README.md)。必须保持的要点：

- `POWGUARD_ADDR=127.0.0.1:3000`，由 Caddy/Nginx 暴露 HTTPS。
- 反代后设置 `POWGUARD_TRUST_PROXY=127.0.0.1/8,::1/128`；直连部署留空。
- Caddy 的 `/admin/api/events/stream` 必须关闭缓冲（`flush_interval -1`）。
- Caddy 日志目录 `/var/log/caddy` 必须由 caddy 用户可写。
- 单实例：不要同时运行两个进程共用同一个 SQLite。
- `POWGUARD_MASTER_KEY` 与数据库分开备份；恢复时先 `verify-keys`。
- `restore.sh` 保留 `.pre-restore` + `-wal` + `-shm` 三件套；回滚时成组放回。
- `keyrotate` 在停服后执行，完成后同步更新 env 并重启。
- 升级流程：备份 → 替换二进制 → 重启 → `/healthz` → 回滚保留 `powguard.prev`。

## 9. 代码风格

- Go：`gofmt`；优先标准库；错误信息简洁；包内注释说明不变量和边界。
- 中文注释与中文文档保持一致；协议字段、错误码沿用官方英文。
- 测试优先表驱动；涉及并发、一次性消费、限流、IP 提取的改动必须补测试。
- 前端只用原生 API；不引入 npm 运行时依赖。
- 不提交 `dist/`、编译产物、`node_modules/`、SQLite 文件、`.env` 或任何密钥。

## 10. 常见坑

| 现象 | 原因 | 处理 |
|---|---|---|
| Caddy 启动失败 `permission denied` | `/var/log/caddy` 不属于 caddy | `install -d -o caddy -g caddy -m 0750 /var/log/caddy` |
| 管理端日志全是 `127.0.0.1` | 未接入可信反代 IP 或未配置 `POWGUARD_TRUST_PROXY` | 配置 CIDR；确认 admin/middleware 使用 `IPExtractor` |
| 所有访客共用一个限流桶 | 反代未传真实 IP，或直连模式读了伪造 XFF | 配置可信反代网段；直连留空 |
| 恢复后回滚丢数据 | 只移动主库、删除 WAL | 使用修复后的 `restore.sh`，三件套成组保留 |
| `master key 不匹配` | key 与库不是一对 | 用正确 key 重启或恢复对应备份 |
| 大陆访问 widget 卡住 | Twikoo 从 jsdmirror/jsDelivr 加载 | 预置同源 widget + `CAP_CUSTOM_WASM_URL` |
| 新域名短时间不解析 | 递归解析器 NXDOMAIN 负缓存 | 以权威 NS 查询和 Let's Encrypt HTTP-01 成功为准 |
| SSE 不实时 | 反代缓冲 | Caddy `flush_interval -1` |
| cookie 无法保存 | HTTPS 但 `POWGUARD_PUBLIC_URL` 为 http | 改成 `https://…` |

## 11. 禁止事项

- 不实现 HashWX、RSW、instrumentation，或把它们以“已支持”暴露。
- 不在没有共享 challenge/token store 的情况下做多副本 HA。
- 不复制 capd 的完整 Svelte dashboard；保持轻量 WebUI。
- 不使用 `latest` 或运行时下载官方 JS 服务端包。
- 不把站点 secret、admin key、master key 写入日志、事件、前端 bundle 或仓库。
- 不修改已发布迁移；不直接编辑生产 SQLite 结构。
- 不跳过 `make check`、oracle、浏览器与 Twikoo 回归直接发布。
