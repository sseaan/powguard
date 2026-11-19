# capgo 兼容性矩阵（P0 出口条件）

> 生成时间：2026-11-18 · oracle 版本锁定见 [versions.lock](../versions.lock)
> 对拍脚本：`tools/oracle/gen-fixtures.mjs`（官方 → Go）、`tools/oracle/verify-go.mjs`（Go → 官方）

## 可行性结论

**format-1 与 format-2 SHA-256 在 Go 中完全可行，且已达 bit-exact 双向互操作。**

| 项 | 官方 → Go | Go → 官方 | 证据 |
|---|---|---|---|
| fnv1a + xorshift32 PRNG | ✅ bit-exact | ✅ | `testdata/prng/vectors.json`（12 种子 × 15 长度，含代理对/非 ASCII/边界长度；@cap.js/server 与 capjs-core 双实现交叉断言） |
| format-1 解校验（官方签发） | ✅ | — | `testdata/format1/cases.json` `default_lifecycle`/`small_params` |
| format-1 挑战（Go 签发 → 官方 redeem + validateToken） | — | ✅ | `internal/protocol/format1/interop_test.go` → `verify-go.mjs mode=format1` |
| format-1 通行 token 存储键推导 | ✅ | ✅ | Go 推导键 == 官方 tokensList 实际键 |
| format-1 失败语义（烧挑战/过期/非法 body/畸形 token） | ✅ | — | `wrong_solution_burns_challenge` 等 6 case |
| format-2 sha256-pow（官方 capjs-core 签发 → Go 校验） | ✅ | — | `testdata/format2/cases.json` `sha256_lifecycle` |
| format-2 sha256-pow（Go 签发 → capjs-core validateChallenge） | — | ✅ | `internal/protocol/format2/format2_test.go` → `verify-go.mjs mode=format2` |
| format-2 失败 reason（expired/invalid_solution/invalid_solutions/invalid_token/scope_mismatch/already_redeemed） | ✅ 与官方逐条一致 | — | `TestFailureReasons` |
| JWT HS256 逐字节 | ✅ header/body/签名与官方 jwtSign 完全一致 | ✅ 官方验签 Go token | `testdata/format2/crypto.json` |
| AES-GCM（cap:fmt2-v1） | ✅ Go 解密官方 ev blob | ✅ 官方解密 Go blob（verify-go.mjs 路径） | `TestGCMInterop` / `TestGoToOfficialDirection` |
| consumeNonce 一次性 | ✅ | ✅ | `consume_nonce` case：首过、重放 already_redeemed |

## 已发现并修复的实现陷阱（记录防止回归）

1. **官方 GCM blob 布局是 `iv ‖ tag ‖ ciphertext`**（tag 在密文前），不是 Go `Seal` 的
   `ciphertext ‖ tag` 顺序 —— 首版实现踩坑，已有 fixture 回归覆盖。
2. **format-2 solution 的 nonce 是对象内字段**：校验入口必须先解出
   `Sha256Solution{Nonce}` 再字符串化，不能把整个 solution 对象当 nonce。
3. **JS 常量 `2166136261` 不能直接转 Go int32 常量**（编译期溢出），用位型 `-2128831035`。
4. **官方失败 reason 的判定顺序**：scope → exp → ev 解密 → solutions 形状 → 逐条解 →
   consumeNonce。任何重排都会与官方 fixture 产生 reason 分歧。
5. **先删后验**：官方 redeem 在验证前删除挑战（失败也烧）；capgo 必须在读取状态时原子删除。

## 待补互操作（后续里程碑）

| 项 | 状态 | 计划 |
|---|---|---|
| 未修改 widget 0.1.63 真实浏览器 e2e | ✅ Chromium 实测通过（同源 WASM） | M1 已验：挑战→求解→redeem→siteverify→重放拒绝全链路 |
| Twikoo 2.0.17 外接模式端到端 | ✅ 调用形状已验 | 实例化真实 Twikoo 部署留待 M5（服务端调用形状已在 `TestTwikooExactCallShape` 逐字段复刻） |
| format-2 双向 + scope + 浏览器 | Go 侧已双向 | M3 收口（含 hashwx 拒绝语义） |
| HashWX / RSW / instrumentation | 明确不实现 | 以后经 provider 接口另立项 |

## 风险清单（P0 视角）

1. **浮点 nonce 偏差**：官方接受任意 JS number；capgo 拒绝非整数。真实 widget
   不受影响；oracle 对拍不覆盖该输入（docs/protocol-notes.md §9.1）。
2. **widget 版本漂移**：Twikoo 从 jsdmirror 拉未钉版本的 widget（当前 latest=0.1.63）。
   capgo 升级流程必须重验当时 latest 的请求形状。
3. **capd 的 format-1 是 JWT 无状态变体**，capgo 采用 @cap.js/server 有状态模型 ——
   两者对 widget 等价（token 是不透明种子），但与 capd 逐字节 token 互操作不在目标内。
4. **大陆访问**：官方默认 WASM/jsDelivr 不可达；capgo 必须同源托管全部静态资产（M4）。

## 复跑方式

```bash
cd tools/oracle && node gen-fixtures.mjs   # 重新生成官方 fixtures
go test ./internal/protocol/... -count=1   # 官方 → Go
go test ./internal/protocol/... -run Direction -count=1 -v  # Go → 官方（需 node）
```
