# capgo

Cap 工作量证明（PoW）人机验证服务端的 Go 实现：与官方 `@cap.js/widget` 线协议兼容，自带轻量 WebUI，单二进制直接部署。

> 🚧 规划 / WIP —— 协议规格已从 `@cap.js/server@4.0.5` 与上游 [tiagozip/cap](https://github.com/tiagozip/cap)（Apache-2.0）逐行核对，核心协议极小（官方服务端为 569 行零依赖单文件）。

## 目标

- **线协议兼容**：`POST /{site}/challenge`、`POST /{site}/redeem`、`POST /{site}/siteverify`（reCAPTCHA 风格 `{secret, response}` → `{success}`），未修改的官方 widget 可直接对接；`siteverify` 为 Twikoo 2.0.x 外接模式（`CAPTCHA_PROVIDER=Cap` + `CAP_API_ENDPOINT` + `CAP_SECRET_KEY`）唯一依赖的后端接口。
- **多站点复用**：路径分站点（`/{site}/`），每站点独立 secret、难度参数与限流桶；密钥可 reveal / reset。
- **WebUI**：参照官方 capd 的信息架构做轻量实现——登录（admin key 会话）、站点密钥管理、集成片段展示、SSE 实时事件流、按天统计。砍掉规则引擎 / GeoIP / share links / webhooks。
- **零依赖部署**：单静态二进制 + systemd + 任意反代（Caddy/Nginx）；无 Docker、无 Node、无 Redis/Valkey。SQLite（纯 Go 驱动）持久化密钥与事件，挑战 / token 留内存（生命周期 10 / 20 分钟，重启至多让读者重解一次）。
- **同源静态资产**：自托管 widget（钉版本）与 `@cap.js/wasm` solver（`CAP_CUSTOM_WASM_URL`），大陆访客零 jsdelivr 依赖。

## 协议要点（format-1，已从官方源码提取）

```text
challenge  → { challenge: {c: 50, s: 32, d: 4}, token, expires }
redeem     ← { token, solutions: number[] }
             salt_i   = prng(token || i,    s)   // fnv1a + xorshift32
             target_i = prng(token || i"d", d)
             校验 sha256(salt_i + solutions[i]) hex 前缀 == target_i
redeem  →  → { success, token, expires }          // 20 分钟一次性，库存 sha256(token)
siteverify ← { secret, response } → { success }   // 常数时间比较 secret
```

唯一 bit-exact 硬兼容点是 `fnv1a + xorshift32` PRNG（seed 为 ASCII，按 UTF-16 code unit）。验证策略：用官方 `@cap.js/server@4.0.5` 作 oracle 生成 PRNG 对拍向量，外加双向互操作测试与真实浏览器 e2e（钉死 widget 版本）。

## 路线图

- [x] PRNG 对拍向量（oracle：官方包双实现交叉断言，`tools/oracle`）
- [x] 协议核心（challenge / redeem / validate，内存存储 + 原子一次性消费）
- [x] HTTP 面（CORS、`?wasm=0` 容忍、每 IP 限流、站点路由）
- [x] SQLite 层（sites / site_secrets / admin_sessions / events / settings；secret 以 `CAPGO_MASTER_KEY` AES-256-GCM 加密 + AAD 绑定）
- [x] 管理 API（admin key 登录、会话 cookie、CSRF、站点 CRUD、reveal/rotate 再认证、事件/统计查询）
- [x] capsolve CLI（测试与压测工具）
- [x] 真实浏览器 e2e（未修改 widget 0.1.63 + 同源 WASM，format-1 与 format-2 双格式）
- [x] format-2 SHA-256 接入公开端点与按站点协议开关（scope 隔离、nonce 一次性、capd 错误语义）
- [ ] WebUI v1（登录、密钥管理、集成片段、SSE 事件流、基础统计）
- [ ] 部署（systemd + Caddy）与 Twikoo 对接验收

## 许可证

Apache-2.0。协议参照上游 [tiagozip/cap](https://github.com/tiagozip/cap)（Copyright 2025 Tiago）与 npm 包 `@cap.js/server`，在此致谢。
