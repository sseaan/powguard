# NOTICE — 第三方静态资产

`web/static/vendor/` 下的文件来自 Cap 生态官方 npm 包，按上游 Apache-2.0 许可随二进制再分发。
上游版权所有：Copyright 2025 Tiago (https://github.com/tiagozip/cap)。

| 文件 | 来源包 | 锁定版本 | 校验说明 |
|---|---|---|---|
| `cap.min.js` | `@cap.js/widget` | 0.1.63 | 未修改；主入口即为该压缩产物 |
| `cap.css` | `@cap.js/widget` src/cap.css | 0.1.63 | 未修改 |
| `cap_wasm_bg.wasm` | `@cap.js/wasm` browser/ | 0.0.8 | 未修改；求解器 WASM（单 wbg import） |

版本以根目录 `versions.lock` 与 `tools/oracle/package-lock.json` 为准。
升级流程必须重跑 `tools/oracle` 互操作矩阵与浏览器回归。
