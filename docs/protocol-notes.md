# capgo 协议笔记（P0 规范锁定）

> 来源与版本锁定见 [versions.lock](../versions.lock)。
> 本文档是从官方源码逐行核对后的实现规范，Go 实现以此为准。
> 所有引用均标注来源：`[S]` = @cap.js/server 4.0.5、`[C]` = capjs-core 0.1.18、
> `[D]` = capd 4.0.15、`[W]` = @cap.js/widget 0.1.63、`[T]` = Twikoo 2.0.17。

## 1. PRNG（fnv1a + xorshift32）

两个包中的实现 bit-exact 等价 `[S][C]`：

```js
// fnv1a：种子哈希。注意：按 UTF-16 code unit（charCodeAt），不是 UTF-8 字节。
function fnv1a(str) {
  let hash = 2166136261;               // 0x811C9DC5
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return hash >>> 0;                    // 截断为 uint32
}

// xorshift32 输出流
function prngFromHash(initialHash, length) {
  let state = initialHash;
  let result = "";
  while (result.length < length) {
    state ^= state << 13;
    state ^= state >>> 17;             // 无符号右移
    state ^= state << 5;
    state >>>= 0;
    result += state.toString(16).padStart(8, "0");  // 每次恰好 8 个 hex 字符
  }
  return result.substring(0, length);
}
```

Go 实现要点（已论证与 JS bit-exact）：

1. **32 位语义**：JS 的 `<<`/`>>>/^` 都在 int32 上进行；`+=` 在 double 上进行但每一步
   XOR 都会截断回 int32。由于加法对模 2³² 分配，Go 用 `int32` 环绕运算即可等价
   （加法溢出环绕 = double 求和后 XOR 截断，两者模 2³² 相同）。
2. **`>>> 17`**：Go 写作 `state ^= int32(uint32(state) >> 17)`。
3. **UTF-16 code unit**：`charCodeAt(i)` 取 UTF-16 单元（0–65535）。协议 seed 全部是
   ASCII（hex token + 十进制索引 + `"d"`），字节遍历等价；但 Go 实现必须按
   UTF-16 code unit 语义编码（`utf16.Encode`），否则一旦未来出现非 ASCII scope 就会分叉。
4. **输出格式**：`state.toString(16).padStart(8, "0")` = 小写 hex、8 位零填充；长度按需
   截断到 `length`（最后一轮可能多生成最多 7 个字符再截掉）。

`[C]` 额外导出 `fnv1aResume(state, str)`：从已有 uint32 状态继续哈希。
format-1 JWT 校验用它避免重复哈希长 token（`saltSeed = fnv1aResume(tokenFnv, idxStr)`、
`targetSeed = fnv1aResume(saltSeed, "d")`），与 legacy `prng(token+i)` / `prng(token+i+"d")`
数值等价。

## 2. PoW 校验（两种 format 共用）

- 目标：`target` 是长度为 `d` 的 hex 前缀（legacy 由 PRNG 生成；format-2 sha256-pow
  直接是 `"0".repeat(d)`）`[C generateChallengeV2]`。
- 解：`sha256(salt + solution)` 的 **hex 字符串** 以 `target` 开头
  （`hash.startsWith(target)` `[S]`；`[C]` 用字节级前缀比较 `powMatchesPrefix`，
  支持 odd-length target —— 结果等价，hex 前缀比较是超集语义）。
- **solution 的字符串化**：JS 侧是 `salt + solutions[i]`（number → string 隐式转换）。
  官方不校验整数性，只查 `typeof === "number"` `[S]`。真实 widget/WASM 解出的
  nonce 是 `[0, 2^32)` 的非负整数。JS `String(n)` 对整数是十进制、无小数点；
  `-0` → `"0"`；`1e21` 以上走指数记法。capgo 策略：接受 JSON number，
  整数（含超出 int64 的安全整数范围内）按十进制字符串化，浮点/NaN/Infinity 拒绝
  （记 `invalid_solutions`）。与官方的差异只影响恶意构造的非整数输入，fixture
  对拍不覆盖浮点 nonce（明确记录为已知偏差）。

## 3. format-1（legacy，@cap.js/server 4.0.5 有状态模型）

### 3.1 challenge 生成 `[S createChallenge]`

```
challenge = { c: 50, s: 32, d: 4 }          // 数量/盐长/难度，均可配置
token   = randomHex(25)                      // 50 个 hex 字符（25 字节随机）
expires = Date.now() + expiresMs             // 默认 600000 = 10 分钟
存 challengesList[token] = { challenge, expires }
响应 { challenge: {c,s,d}, token, expires }
```

- 参数上界 `[C]`（capjs-core 校验，capgo 沿用）：`c ≤ 1000`、`s ≤ 256`、`d ≤ 16`，
  均为正整数。
- 过期挑战惰性清理（官方 5 分钟一轮）。

### 3.2 redeem `[S redeemChallenge]`

```
body: { token: string, solutions: number[] }
1. 形状校验：token 非空、solutions 是全 number 数组，否则 {success:false, message:"Invalid body"}
2. 读出并【立即删除】challenge（先删后验 —— 失败的 redeem 也烧掉挑战）
3. 不存在/过期 → {success:false, message:"Challenge invalid or expired"}
4. 对 i = 1..c（注意从 1 开始）：
     salt_i   = prng(`${token}${i}`,   s)
     target_i = prng(`${token}${i}d`,  d)
     要求 sha256hex(salt_i + solutions[i-1]) 前缀 == target_i
5. 全部通过 →
     vertoken = randomHex(15)                  // 30 hex
     id       = randomHex(8)                   // 16 hex
     内存 tokensList[`${id}:${sha256(vertoken)}`] = now + 20 分钟
     → {success:true, token:`${id}:${vertoken}`, expires}
   否则 → {success:false, message:"Invalid solution"}
```

**一次性语义**：challenge 在读取时即删除 → 同一挑战最多一次 redeem 尝试（无论成败）。

### 3.3 validateToken `[S validateToken]`（即 siteverify 的核心）

```
token 形如 "id:vertoken"，split(":") 必须恰好 2 个非空段
key = `${id}:${sha256(vertoken)}`
存在且未过期 → {success:true}；默认即删（一次性）；keepToken 可保留
```

注意官方存储 key 的是 vertoken 的 **sha256 hex**，id 原文存储。

### 3.4 capd 4.0.15 的 JWT 变体 `[D cap.js]`

capd 用 capjs-core 的无状态 format-1：challenge token 是 HS256 JWT
（payload `{n,c,s,d,exp,iat,sk?}`），盐/目标由 token 字符串经同一个 PRNG 推导；
一次性靠 Redis `SET NX` 记录 token 签名。redeem 签发的通行 token 是三段式
`${siteKey}:${redeemId}:${redeemSecret}`。**capgo 的 format-1 采用 `[S]` 的有状态模型**
（token 不透明、状态在内存），与 widget 兼容性完全一致（widget 把 token 当不透明种子）。

## 4. format-2（capjs-core 0.1.18 envelope）

### 4.1 envelope `[C generateChallengeV2]`

```
protocols = ["sha256-pow"]（capgo 当前只开放这一种；hashwx/rsw/instrumentation 不实现）
challenges = [ {protocol:"sha256-pow", payload:{ salt: randomHex(s), target: "0".repeat(d) }} × c ]
tokenPayload = { f: 2, n: randomHex(16), exp, iat,
                 ev: encryptGcm({expected:[{protocol,salt,target}...]}, secret, "cap:fmt2-v1"),
                 sk?: scope, x?: extra }
token = jwtSign(tokenPayload, secret)
响应 { token, format: 2, challenges, expires }
```

### 4.2 校验 `[C validateChallengeV2]`

```
1. jwtVerify(token, secret) → payload；失败 reason "invalid_token"
2. scope（payload.sk 与配置不符 → "scope_mismatch"）；exp（→ "expired"）
3. decryptGcm(payload.ev) → expected[]（失败 "invalid_token"）
4. solutions 必须是对象数组，长度 == expected.length（"invalid_solutions"）
5. sha256-pow 条目：solution {nonce: number|string}
     sha256(salt + String(nonce)) 前缀 == target，否则 "invalid_solution"
6. consumeNonce(jwtSigHex(token)) 一次性 → "already_redeemed"
7. 签发通行 token（同 format-1 流程，或 signToken 回调）
```

### 4.3 JWT 与 AES-GCM 语义 `[C crypto.js]`

- JWT：`b64url({"alg":"HS256","typ":"JWT"}) + "." + b64url(JSON(payload))`，
  HMAC-SHA256 签名，base64url 无填充；verify 用 timingSafeEqual。
- `encryptGcm(data, secret, info)`：key = HMAC-SHA256(secret, info)
  （info 默认 `"cap:enc-v1"`，format-2 expected 用 `"cap:fmt2-v1"`）；
  12 字节随机 IV；blob = base64url(iv ‖ tag ‖ ciphertext)。
- `jwtSigHex(token)`：取最后一段 base64url 解码为 bytes → hex，作为一次性消费 key。

## 5. HTTP 面（capd 4.0.15 语义，capgo 的对外约定）

| 端点 | 语义 | 错误（状态码 + body） |
|---|---|---|
| `POST /{site}/challenge` | 签发挑战；query `?wasm=0` 必须被容忍 | 404 `{error:"Invalid site key or secret"}` |
| `POST /{site}/redeem` | body `{token, solutions}` | 400 `{error:"Missing required fields"}` / `{error:"Invalid solutions"}`；403 `{error:"Challenge expired"}` / `Invalid challenge token` / `Challenge already redeemed` / `Invalid solution` / `Challenge token does not match site key`；413 body 过大 |
| redeem 成功 | format-1：`{success:true, token, expires}` | |
| `POST /{site}/siteverify` | body `{secret, response}`，一次性消费 | 400 `{success:false, error:"Missing required parameters"}`；404 `Invalid site key or secret` / `Token not found`；403 `{success:false, error:"Token expired"}` |
| siteverify 成功 | `{success:true}`（可附 riskFlags 等） | |

- `?wasm=0`：widget 在 WebAssembly 不可用时追加 `[W cap.js #fetchChallenge]`；
  对 capgo（sha256-pow only）语义上忽略即可。
- 限流：capd 默认 30 次 / 5 秒 / IP（可按站点覆盖），超限 429 `[D ratelimit.js]`。
- body 上限：capd redeem 256 KiB → 413 `[D cap.js]`。
- CORS `[D app.js onRequest]`：`Vary: Origin`；allowlist 命中回显 Origin（`*` 需显式）；
  `OPTIONS` → 204，`Access-Control-Allow-Methods: GET, POST`，
  `Access-Control-Allow-Headers` 回显请求头，`Access-Control-Max-Age: 600`。

### 5.1 通行 token 格式决策

capgo redeem 签发 capd 风格三段式 `${siteKey}:${id}:${vertoken}`：

- capd 的 siteverify 从 `response` 第一段恢复 siteKey，并要求与路径一致 `[D siteverify.js]`；
- 同时接受 legacy 两段式 `${id}:${vertoken}`（site 取路径 slug），保证官方 `[S]`
  生成的 token 也能被 capgo siteverify 验证（共享内存状态不可行，纯 fixture 层互操作）。

## 6. Widget 0.1.63 客户端行为（兼容性约束）

- 元素 `<cap-widget data-cap-api-endpoint="https://cap.example.com/twikoo/">`；
  endpoint 以 `/` 结尾会归一 `[W #endpoint]`。
- 请求：`{endpoint}challenge`（WASM 不可用时 `{endpoint}challenge?wasm=0`）→
  `{endpoint}redeem`，body `{token, solutions}`，`Content-Type: application/json`。
- format-1：widget 用同一 PRNG 本地重推导盐/目标（token 为种子）——
  **capgo 与官方的 PRNG 必须 bit-exact，否则用户永远解不出来**。
- format-2：widget 只解 `challenges[].protocol == "sha256-pow"` 的 payload
  （盐和目标直接来自服务端，PRNG 不参与求解）→ solution `{nonce}`。
- 解题器 WASM：`window.CAP_CUSTOM_WASM_URL` 覆盖，默认 jsDelivr
  `@cap.js/wasm@0.0.8/browser/cap_wasm_bg.wasm`；capgo 同源自托管。
- token 刷新：widget 解析 `resp.token.split(".")[1]` 的 JWT claims 取 TTL，
  非 JWT（legacy hex token）回退 `resp.expires - now` `[W #scheduleRefresh]`。

## 7. Twikoo 2.0.17 外接模式（唯一验收路径）

- 配置：`CAPTCHA_PROVIDER=Cap`、`CAP_API_ENDPOINT=https://cap.example.com/twikoo/`、
  `CAP_SECRET_KEY=<site secret>`。
- 客户端 `[T TkSubmit.vue]`：把 endpoint 原样写入 `data-cap-api-endpoint`；
  widget 从 `cdn.jsdmirror.com/npm/@cap.js/widget` 加载（**未钉版本** —— 大陆镜像，
  当前 latest 即 0.1.63；因此 capgo 必须持续兼容最新 widget 的请求形状）。
- 服务端 `[T services/cap.ts / spam.ts checkCapCaptcha]`：
  `POST {endpoint 去尾斜杠}/siteverify`，body `{secret, response: token}`，
  判定只看 `data.success`，失败时把 `data.error` 抛给用户。
- 内嵌模式（`CAP_API_ENDPOINT` 为空）走 Twikoo 自带 @cap.js/server，与 capgo 无关。

## 8. 明确不实现（记录边界，防误接）

HashWX、RSW time-lock、instrumentation/behavior、capd 规则引擎/GeoIP/webhook/share
均不实现。遇到 format-2 请求未知 protocol 时返回 invalid 语义（`invalid_token`
或 400/403 系列，见 fixture），不静默降级。

## 9. 已知偏差与风险

1. **浮点 nonce**：官方接受 `typeof number` 的任意值（如 `1.5`、`1e30`）并按 JS
   `String(n)` 语义哈希；capgo 只接受 `[0, 2^53)` 整数。恶意/畸形输入行为不同，
   正常 widget 不受影响。
2. **challenge 参数上界**：`[S]` 不设上界（信任部署方配置）；capgo 按 `[C]` 的
   1000/256/16 钳制，防 DoS。
3. **widget 版本漂移**：Twikoo 加载的 widget 是 jsdmirror 的 latest，capgo 的
   兼容矩阵必须覆盖发布时的最新 widget（0.1.63）。
4. **大陆网络**：官方默认 WASM/CDN 不可达是常态，capgo 必须同源托管全部静态资产。
