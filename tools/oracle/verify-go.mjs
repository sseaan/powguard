/**
 * verify-go.mjs —— 「Go 生成 → 官方验证」方向的互操作 oracle。
 *
 * 输入（stdin 或 argv[1] 的 JSON 文件）：
 *   mode: "format1" | "format2"
 *   format1: { token, c, s, d, expires, solutions: number[] }
 *   format2: { secret, scope?, challenge: {token, format, challenges, expires},
 *              solutions: [{nonce}|...] }
 *
 * 输出（stdout JSON）：{ ok, redeem?: {success,message?}|Result, validate? }
 * 退出码 0 = 官方接受；1 = 拒绝；2 = 脚本错误。
 */
import { readFileSync } from "node:fs";
import Cap from "@cap.js/server";
import { validateChallenge } from "capjs-core";

const input = JSON.parse(
  process.argv[2]
    ? readFileSync(process.argv[2], "utf8")
    : readFileSync(0, "utf8"),
);

function out(obj) {
  process.stdout.write(JSON.stringify(obj));
}

try {
  if (input.mode === "format1") {
    const { token, c, s, d, expires, solutions } = input;
    const cap = new Cap({ noFSState: true });
    // 用官方实例自身的存储路径播种 Go 生成的挑战状态
    cap.config.state.challengesList[token] = {
      expires,
      challenge: { c, s, d },
    };
    const redeem = await cap.redeemChallenge({ token, solutions });
    let validate = null;
    if (redeem.success) {
      validate = await cap.validateToken(redeem.token);
    }
    const ok = !!redeem.success;
    out({ ok, redeem, validate });
    process.exit(ok ? 0 : 1);
  }

  if (input.mode === "format2") {
    const { secret, scope, challenge, solutions } = input;
    const opts = {};
    if (scope) opts.scope = scope;
    const result = await validateChallenge(
      secret,
      { token: challenge.token, solutions },
      opts,
    );
    const ok = !!result.success;
    out({ ok, result });
    process.exit(ok ? 0 : 1);
  }

  out({ ok: false, error: "unknown mode" });
  process.exit(2);
} catch (e) {
  out({ ok: false, error: String(e?.message || e) });
  process.exit(2);
}
