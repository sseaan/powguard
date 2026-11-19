# M5 深圳实机验收记录

- 日期：2026-11-19
- 目标机：Aliyun 深圳，Rocky Linux 10.2（x86_64），单实例
- 公网入口：`https://cap.mvr.cc`
- 部署形态：`powguard` 静态二进制 + SQLite + systemd + Caddy（Let's Encrypt）
- 部署产物：`powguard c3f14cb-m5 (go1.27.4 linux/amd64)`
  - sha256：`7887d9cd5ab039390a7e26942e0c9d60b5f11d21274c51f9807e4c912d58e7fc`
- 依赖版本：见 `versions.lock`（widget 0.1.63 / WASM 0.0.8 / Twikoo 2.0.17 / @cap.js/server 4.0.5 / capjs-core 0.1.18）

## 1. 部署状态

| 项 | 结果 |
|---|---|
| systemd 服务 | `active (running)`，仅监听 `127.0.0.1:3000` |
| `/healthz` | `{"status":"ok"}` |
| Caddy | 2.11.4，`cap.mvr.cc` 自动签发 Let's Encrypt 证书成功 |
| DNS | EdgeOne NS 接入；`cap.mvr.cc A 120.77.249.139`，TTL 60 |
| 旧域名清理 | Caddy 仅保留 `cap.mvr.cc`；`pi.mvr.cc`、`bot.mvr.cc` 配置与旧证书缓存已移除并备份 |
| 静态资产 | `/static/vendor/` 返回正确 MIME、`Cache-Control: public, max-age=86400`、`Access-Control-Allow-Origin: *`、`Cross-Origin-Resource-Policy: cross-origin` |
| 数据/密钥 | SQLite 与 `POWGUARD_MASTER_KEY` 分开备份；本地运维副本权限 0600，不进入仓库 |

## 2. 公开 API 与协议

`capsolve` 经 HTTPS 全链路：

```text
challenge → solve → redeem → siteverify → replay-rejected
```

| 用例 | 结果 |
|---|---|
| format-1（twikoo）challenge/redeem/siteverify | 通过；50 个挑战，约 1s 求解 |
| format-2 SHA-256（demo2）50 个 `sha256-pow` 挑战 | 通过；envelope `format:2`，约 1.5s 求解 |
| 重复 siteverify 同一 token | `404 {"error":"Token not found"}` |
| 错误 site secret | `403 {"error":"Invalid site key or secret"}` |
| 跨站点 token（demo2 token → twikoo siteverify） | 拒绝；事件记录 `site_mismatch` |
| CORS allowlist（demo2 临时限制） | 允许 Origin 返回 `Access-Control-Allow-Origin`；非允许 Origin 不返回；预检 204 |
| 限流（demo2 临时 3 次/60s） | 超出后 `429` |
| 引导首个站点 | 通过管理 API 创建/轮换 secret；`twikoo` 站点为 format-1 安全预设 |

## 3. 浏览器验收

### 3.1 widget 0.1.63 + 同源 WASM 0.0.8

- Chromium 156（headless）加载 `https://cap.mvr.cc/`：
  - format-1：504ms 完成，token `twikoo:...`，siteverify 通过，重放 404；
  - format-2（`?site=demo2`）：251ms 完成，token `demo2:...`，siteverify 通过，重放 404；
  - 资源列表仅出现 `cap.mvr.cc`，无 jsDelivr 请求。
- 跨源页面（`http://127.0.0.1:8898`）从 `https://cap.mvr.cc/static/vendor/` 加载未修改 widget 与 WASM，
  完成 challenge/redeem 并 siteverify 通过；验证了本轮新增的静态资产 CORS 头。

### 3.2 真实浏览器与 Twikoo

- 在真实浏览器中打开 Homepage 文章页，评论区的 Cap 控件正常显示并快速完成验证，评论提交成功。
- Twikoo 2.0.17 外接模式配置（管理面板）：

```text
CAPTCHA_PROVIDER = Cap
CAP_API_ENDPOINT = https://cap.mvr.cc/twikoo/
CAP_SECRET_KEY   = <powguard 站点密钥，不记录>
CAP_BUILTIN      = false（由空/非空 endpoint 推导）
```

- Twikoo 客户端网络请求观察到：`cap.mvr.cc/twikoo/challenge` → `redeem` → `tk.mvr.cc`；
  powguard 事件依次记录 challenge/redeem/siteverify 且均为 `pass`。
- 评论成功写入并在 Homepage 文章页显示；验收用测试评论已在管理面板删除。
- 负向用例：
  - 直接 `COMMENT_SUBMIT` 不带 `capToken` → `{"code":1000,"message":"验证码 token 缺失，请刷新页面重试"}`；
  - 提交 demo2 站点的 token → `{"code":1000,"message":"Cap验证码检测失败: Request failed with status code 404"}`；
  - siteverify 重放 → 404。

## 4. 管理面板与安全

| 项 | 结果 |
|---|---|
| 登录 | admin key 登录成功；cookie `HttpOnly; Secure; SameSite=Lax` |
| CSRF | 写操作缺少/错误 `X-CSRF-Token` 被拒绝 |
| 高危操作 | reveal/rotate 需再次提交 admin key；rotate 后旧 secret 立即失效 |
| 站点/事件/统计 API | 正常返回；事件含 outcome、reason、protocol、耗时 |
| SSE | `200 text/event-stream`，`X-Accel-Buffering: no`，首帧 `event: hello` |
| 可信反代 | `POWGUARD_TRUST_PROXY=127.0.0.1/8,::1/128`；伪造 `X-Forwarded-For` 被忽略，管理登录失败日志与访问日志均记录真实客户端 IP |
| 限流桶 | 管理员登录与公开 API 均按真实 IP 计数（修复后） |

## 5. 备份、恢复、升级

| 演练 | 结果 |
|---|---|
| `powguard backup` 在线快照 | 成功，生成 `.sha256`；`verify-keys` 全部密文可解 |
| 全量恢复 | `restore.sh`：停服 → 校验 → 保留 `.pre-restore*` → 放置备份 → verify-keys → 启动 → `/healthz`，通过 |
| 回滚完整性 | 发现旧脚本只移动主库、删除 WAL 会丢数据；已修复为 `.pre-restore` + `-wal` + `-shm` 成组保留 |
| master key 轮换 | 在备份副本上演练：新 key 校验通过，旧 key 被拒绝；未改动线上 key |
| 服务重启 | 未完成 challenge 在重启后失效（`Challenge invalid or expired`）；重启后新链路正常 |
| 升级 | 保留 `powguard.prev`，备份数据库后替换二进制、重启、健康检查通过 |

## 6. 本轮发现并修复

1. **Caddy 日志目录权限**：`/var/log/caddy` 需由 `caddy` 用户可写，否则 Caddy 启动失败；已写入部署文档。
2. **静态资产跨源**：`/static/vendor/` 缺少 CORS 头，跨站 Twikoo 无法加载同源 WASM；
   已增加 `Access-Control-Allow-Origin: *` 与 `Cross-Origin-Resource-Policy: cross-origin`，并补测试。
3. **管理端未使用可信反代 IP**：admin 登录限流/日志此前固定取 `RemoteAddr`（127.0.0.1）；
   已接入 `IPExtractor`，并让访问日志同样记录真实 IP。
4. **restore.sh 回滚丢 WAL**：已改为 `.pre-restore*` 三件套成组保留，回滚文档同步更新。

## 7. 遗留项与建议

- Twikoo 客户端默认从 `cdn.jsdmirror.com` 加载 Cap widget（上游行为，未钉版本）。
  若要彻底避免第三方 CDN，可在 Homepage 的 Twikoo 组件加载前预置：

  ```html
  <script>window.CAP_CUSTOM_WASM_URL = "https://cap.mvr.cc/static/vendor/cap_wasm_bg.wasm";</script>
  <script src="https://cap.mvr.cc/static/vendor/cap.min.js"></script>
  ```

  powguard 的静态资产已具备跨源头；预置后 Twikoo 会跳过 jsdmirror 加载。
- `demo2` 为 format-2 测试站点，保留用于演示/复测；不需要时可在管理面板删除（软删除）。
- Twikoo 数据库中可能残留一条路径为 `/` 的验收测试评论（首页不渲染 Twikoo，不可见）；
  需要时在 Twikoo 管理面板「评论管理」中删除。
- EdgeOne 新增记录后，部分递归解析器对 NXDOMAIN 的负缓存约 5–20 分钟；实际生效以
  `dig @ns1.qeodns.com cap.mvr.cc` 与 Let's Encrypt HTTP-01 成功为准。
