/**
 * gen-fixtures.mjs —— 从官方包生成 capgo 的兼容性 fixtures。
 *
 * 产物（写入 testdata/）：
 *   prng/vectors.json      PRNG golden vectors（@cap.js/server 与 capjs-core 双实现交叉断言）
 *   format1/cases.json     官方 server 生成的挑战/兑换/通行 token 全生命周期向量
 *   format2/cases.json     capjs-core format-2 sha256-pow 向量（JWT + AES-GCM expected）
 *   format2/crypto.json    jwtSign 精确输出向量 + encryptGcm 解密向量
 *
 * 用法：node tools/oracle/gen-fixtures.mjs
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import Cap from "@cap.js/server";
import {
  generateChallenge,
  validateChallenge,
} from "capjs-core";
import {
  jwtSign,
  jwtVerify,
  encryptGcm,
  decryptGcm,
} from "./node_modules/capjs-core/src/crypto.js";
import {
  fnv1a,
  fnv1aResume,
  prng as corePrng,
} from "./node_modules/capjs-core/src/prng.js";
import {
  assertPrngConsistency,
  solveFormat1,
  solveFormat2,
  sha256Hex,
} from "./lib/prng.mjs";

const ROOT = new URL("../../testdata/", import.meta.url);
const write = (rel, data) => {
  const path = new URL(rel, ROOT);
  mkdirSync(new URL(".", path), { recursive: true });
  writeFileSync(path, JSON.stringify(data, null, 2) + "\n");
  console.error(`wrote ${rel}`);
};

const now = Date.now();

// ---------------------------------------------------------------- prng 向量
{
  const seeds = [
    "",
    "a",
    "d",
    "1",
    "twikoo",
    "1d",
    "abcdef0123456789",
    "a".repeat(50),
    "deadbeefcafebabe" + "1",
    "😀",
    "héllo",
    "\u0000\u007f\u00ff",
  ];
  const lengths = [0, 1, 2, 3, 5, 7, 8, 9, 16, 17, 31, 32, 33, 64, 100];
  assertPrngConsistency(seeds, lengths);

  const vectors = seeds.map((seed) => ({
    seed,
    fnv1a: fnv1a(seed),
    outputs: Object.fromEntries(lengths.map((len) => [len, corePrng(seed, len)])),
  }));
  write("prng/vectors.json", {
    source: {
      "cap.js/server": "4.0.5",
      "capjs-core": "0.1.18",
      seedEncoding: "UTF-16 code units (charCodeAt)",
    },
    vectors,
    resume: [
      { state: 0, str: "", expect: fnv1aResume(0, "") },
      { state: 0, str: "1", expect: fnv1aResume(0, "1") },
      { state: 0x811c9dc5, str: "d", expect: fnv1aResume(0x811c9dc5, "d") },
      { state: 4294967295, str: "12", expect: fnv1aResume(4294967295, "12") },
      { state: 2166136261, str: "😀", expect: fnv1aResume(2166136261, "😀") },
    ],
  });
}

// ------------------------------------------------------------- format-1 向量
async function format1() {
  const cap = new Cap({ noFSState: true });
  const state = cap.config.state;

  const cases = [];

  const record = (name, obj) => cases.push({ name, ...obj });

  // 默认参数挑战：完整生命周期（官方签发 → oracle 求解 → 官方兑换 → 官方消费）
  {
    const conf = { challengeCount: 50, challengeSize: 32, challengeDifficulty: 4, expiresMs: 600000 };
    const keysBefore = new Set(Object.keys(state.tokensList));
    const ch = await cap.createChallenge(conf);
    const challengeState = state.challengesList[ch.token];
    const solutions = solveFormat1(ch.token, ch.challenge);
    const redeem = await cap.redeemChallenge({ token: ch.token, solutions });
    const newKeys = Object.keys(state.tokensList).filter((k) => !keysBefore.has(k));
    const tokenStateKey = newKeys[newKeys.length - 1];
    const firstValidate = await cap.validateToken(redeem.token);
    const replayValidate = await cap.validateToken(redeem.token);
    record("default_lifecycle", {
      config: conf,
      challenge: ch,
      challengeState,
      solutions,
      redeem,
      tokenStateKey,
      tokenStateExpires: redeem.expires,
      firstValidate,
      replayValidate,
    });
  }

  // 小参数挑战（快速）：c=2, s=16, d=3
  {
    const conf = { challengeCount: 2, challengeSize: 16, challengeDifficulty: 3, expiresMs: 600000 };
    const keysBefore = new Set(Object.keys(state.tokensList));
    const ch = await cap.createChallenge(conf);
    const challengeState = state.challengesList[ch.token];
    const solutions = solveFormat1(ch.token, ch.challenge);
    const redeem = await cap.redeemChallenge({ token: ch.token, solutions });
    const newKeys = Object.keys(state.tokensList).filter((k) => !keysBefore.has(k));
    const tokenStateKey = newKeys[newKeys.length - 1];
    const firstValidate = await cap.validateToken(redeem.token);
    const replayValidate = await cap.validateToken(redeem.token);
    record("small_params", {
      config: conf,
      challenge: ch,
      challengeState,
      solutions,
      redeem,
      tokenStateKey,
      firstValidate,
      replayValidate,
    });
  }

  // 错误解：第一轮兑换错误 solution（挑战被烧掉），第二轮再兑换正确解 → 已失效
  {
    const conf = { challengeCount: 1, challengeSize: 16, challengeDifficulty: 3, expiresMs: 600000 };
    const ch = await cap.createChallenge(conf);
    const challengeState = state.challengesList[ch.token];
    const good = solveFormat1(ch.token, ch.challenge);
    const wrong = [good[0] + 1];
    const redeemWrong = await cap.redeemChallenge({ token: ch.token, solutions: wrong });
    const redeemAgain = await cap.redeemChallenge({ token: ch.token, solutions: good });
    record("wrong_solution_burns_challenge", {
      config: conf,
      challenge: ch,
      challengeState,
      goodSolutions: good,
      wrongSolutions: wrong,
      redeemWrong,
      redeemAgain,
    });
  }

  // 过期挑战（生成即过期）
  {
    const conf = { challengeCount: 1, challengeSize: 16, challengeDifficulty: 3, expiresMs: -60000 };
    const ch = await cap.createChallenge(conf);
    const challengeState = state.challengesList[ch.token];
    const solutions = solveFormat1(ch.token, ch.challenge);
    const redeem = await cap.redeemChallenge({ token: ch.token, solutions });
    record("expired_challenge", {
      config: conf,
      challenge: ch,
      challengeState,
      solutions,
      redeem,
    });
  }

  // 非法请求体
  {
    record("invalid_bodies", {
      missingToken: await cap.redeemChallenge({ solutions: [1] }),
      missingSolutions: await cap.redeemChallenge({ token: "x" }),
      solutionsNotArray: await cap.redeemChallenge({ token: "x", solutions: "1" }),
      solutionsNotNumbers: await cap.redeemChallenge({ token: "x", solutions: ["1"] }),
      unknownToken: await cap.redeemChallenge({
        token: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        solutions: [1],
      }),
    });
  }

  // 通行 token 结构（官方格式 "id:vertoken" + 存储 key "id:sha256(vertoken)"）
  {
    const conf = { challengeCount: 1, challengeSize: 16, challengeDifficulty: 3, expiresMs: 600000 };
    const ch = await cap.createChallenge(conf);
    const solutions = solveFormat1(ch.token, ch.challenge);
    const redeem = await cap.redeemChallenge({ token: ch.token, solutions });
    const parts = redeem.token.split(":");
    record("verification_token_structure", {
      challenge: ch,
      solutions,
      redeemToken: redeem.token,
      idPart: parts[0],
      verPart: parts[1],
      verPartIsHex30: /^[0-9a-f]{30}$/.test(parts[1]),
      storedKeyDerived: `${parts[0]}:${sha256Hex(parts[1])}`,
      validateFresh: await (async () => {
        // 官方一次性消费后再验证同一 token 应失败；这里重新生成一个挑战验证 keepToken 语义
        const ch2 = await cap.createChallenge(conf);
        const sol2 = solveFormat1(ch2.token, ch2.challenge);
        const redeem2 = await cap.redeemChallenge({ token: ch2.token, solutions: sol2 });
        const keep1 = await cap.validateToken(redeem2.token, { keepToken: true });
        const keep2 = await cap.validateToken(redeem2.token, { keepToken: true });
        const consumeAfterKeep = await cap.validateToken(redeem2.token);
        return { keep1, keep2, consumeAfterKeep };
      })(),
      validateOneShot: await (async () => {
        const ch3 = await cap.createChallenge(conf);
        const sol3 = solveFormat1(ch3.token, ch3.challenge);
        const redeem3 = await cap.redeemChallenge({ token: ch3.token, solutions: sol3 });
        return {
          first: await cap.validateToken(redeem3.token),
          second: await cap.validateToken(redeem3.token),
        };
      })(),
      malformedTokens: {
        empty: await cap.validateToken(""),
        onePart: await cap.validateToken("abc"),
        threeParts: await cap.validateToken("a:b:c"),
        emptyPart: await cap.validateToken(":abc"),
      },
    });
  }

  write("format1/cases.json", {
    source: "@cap.js/server@4.0.5",
    generatedAt: now,
    cases,
  });
}
await format1();

// ------------------------------------------------------------- format-2 向量
async function format2() {
  const secret = "capgo-fixture-secret-32-bytes-min!!"; // ≥16 bytes
  const cases = [];

  // sha256-pow 基本生命周期
  {
    const opts = {
      format: 2,
      protocols: ["sha256-pow"],
      challengeCount: 3,
      challengeSize: 32,
      challengeDifficulty: 3,
      expiresMs: 365 * 24 * 60 * 60 * 1000,
      scope: "twikoo",
    };
    const ch = await generateChallenge(secret, opts);
    const solutions = solveFormat2(ch.challenges);
    const nonces = [];
    const validate = await validateChallenge(secret, {
      token: ch.token,
      solutions,
    });
    const claims = jwtVerify(ch.token, secret);
    cases.push({
      name: "sha256_lifecycle",
      opts,
      challenge: ch,
      solutions,
      validate,
      claims,
      expectedDecrypted: decryptGcm(claims.ev, secret, "cap:fmt2-v1"),
    });
  }

  // 立即过期
  {
    const opts = {
      format: 2,
      protocols: ["sha256-pow"],
      challengeCount: 1,
      challengeSize: 16,
      challengeDifficulty: 3,
      expiresMs: -60000,
      scope: "twikoo",
    };
    const ch = await generateChallenge(secret, opts);
    const solutions = solveFormat2(ch.challenges);
    const validate = await validateChallenge(secret, { token: ch.token, solutions });
    cases.push({ name: "expired", opts, challenge: ch, solutions, validate });
  }

  // 错误解
  {
    const opts = {
      format: 2,
      protocols: ["sha256-pow"],
      challengeCount: 1,
      challengeSize: 16,
      challengeDifficulty: 3,
      expiresMs: 365 * 24 * 60 * 60 * 1000,
    };
    const ch = await generateChallenge(secret, opts);
    const good = solveFormat2(ch.challenges);
    const wrong = [{ nonce: good[0].nonce + 1 }];
    const validate = await validateChallenge(secret, { token: ch.token, solutions: wrong });
    cases.push({ name: "wrong_solution", opts, challenge: ch, goodSolutions: good, wrongSolutions: wrong, validate });
  }

  // solutions 数量不符 / 非对象 / 非法 nonce
  {
    const opts = {
      format: 2,
      protocols: ["sha256-pow"],
      challengeCount: 2,
      challengeSize: 16,
      challengeDifficulty: 3,
      expiresMs: 365 * 24 * 60 * 60 * 1000,
    };
    const ch = await generateChallenge(secret, opts);
    const r1 = await validateChallenge(secret, { token: ch.token, solutions: [{ nonce: 1 }] });
    const r2 = await validateChallenge(secret, { token: ch.token, solutions: [1, 2] });
    const r3 = await validateChallenge(secret, { token: ch.token, solutions: [{ nonce: "x" }, { nonce: 1 }] });
    const r4 = await validateChallenge(secret, { token: ch.token, solutions: [] });
    cases.push({
      name: "malformed_solutions",
      opts,
      challenge: ch,
      shortSolutions: r1,
      nonObjectSolutions: r2,
      stringNonceFirst: r3,
      emptySolutions: r4,
    });
  }

  // 错误 secret / 篡改 token
  {
    const opts = {
      format: 2,
      protocols: ["sha256-pow"],
      challengeCount: 1,
      challengeSize: 16,
      challengeDifficulty: 3,
      expiresMs: 365 * 24 * 60 * 60 * 1000,
    };
    const ch = await generateChallenge(secret, opts);
    const solutions = solveFormat2(ch.challenges);
    const wrongSecret = await validateChallenge(
      "another-secret-value-16bytes!!",
      { token: ch.token, solutions },
    );
    const claims = jwtVerify(ch.token, secret);
    const forgedBody = JSON.parse(
      Buffer.from(ch.token.split(".")[1], "base64url").toString(),
    );
    forgedBody.sk = "othersite";
    const forgedToken = jwtSign(forgedBody, secret);
    const scopeMismatch = await validateChallenge(secret, {
      token: forgedToken,
      solutions,
    }, { scope: "twikoo" });
    cases.push({
      name: "secret_and_scope",
      opts,
      challenge: ch,
      solutions,
      wrongSecret,
      scopeMismatch,
    });
  }

  // consumeNonce 一次性
  {
    const opts = {
      format: 2,
      protocols: ["sha256-pow"],
      challengeCount: 1,
      challengeSize: 16,
      challengeDifficulty: 3,
      expiresMs: 365 * 24 * 60 * 60 * 1000,
    };
    const ch = await generateChallenge(secret, opts);
    const solutions = solveFormat2(ch.challenges);
    const seen = new Set();
    const consume = (sig) => {
      if (seen.has(sig)) return false;
      seen.add(sig);
      return true;
    };
    const first = await validateChallenge(secret, { token: ch.token, solutions }, { consumeNonce: consume });
    const replay = await validateChallenge(secret, { token: ch.token, solutions }, { consumeNonce: consume });
    cases.push({ name: "consume_nonce", opts, challenge: ch, solutions, first, replay });
  }

  write("format2/cases.json", {
    source: "capjs-core@0.1.18",
    secret,
    generatedAt: now,
    cases,
  });

  // 精确 crypto 向量
  const jwtSecret = "jwt-fixture-secret-0123456789abcdef";
  const payload = { n: "0123456789abcdef", c: 2, s: 16, d: 3, exp: 1737000000000, iat: 1736999400000, sk: "twikoo" };
  write("format2/crypto.json", {
    source: "capjs-core@0.1.18 src/crypto.js",
    jwt: {
      secret: jwtSecret,
      payload,
      token: jwtSign(payload, jwtSecret),
      header: jwtSign(payload, jwtSecret).split(".")[0],
      tamperedLastChar:
        jwtSign(payload, jwtSecret).slice(0, -1) +
        (jwtSign(payload, jwtSecret).slice(-1) === "A" ? "B" : "A"),
      verifyGood: jwtVerify(jwtSign(payload, jwtSecret), jwtSecret),
      verifyBad: jwtVerify(jwtSign(payload, jwtSecret), "wrong-secret-wrong-secret"),
      notJwt: jwtVerify("no-dots-here", jwtSecret),
      twoDots: jwtVerify("a.b", jwtSecret),
      fourDots: jwtVerify("a.b.c.d", jwtSecret),
    },
    gcm: {
      info: "cap:fmt2-v1",
      secret,
      data: { expected: [{ protocol: "sha256-pow", salt: "cafebabe", target: "000" }] },
      blobFromCore: encryptGcm(
        { expected: [{ protocol: "sha256-pow", salt: "cafebabe", target: "000" }] },
        secret,
        "cap:fmt2-v1",
      ),
      roundtrip: decryptGcm(
        encryptGcm({ a: 1, list: [1, 2, 3] }, secret, "cap:fmt2-v1"),
        secret,
        "cap:fmt2-v1",
      ),
    },
  });
}
await format2();

console.error("fixtures done");
process.exit(0);
