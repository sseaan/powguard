/**
 * prng：从 @cap.js/server@4.0.5 index.js（第 133–163 行）逐字复制的实现。
 * 官方包未导出该函数，故在此复制以便 fixture 脚本本地求解（与 widget 行为一致）。
 * capjs-core@0.1.18 的等价实现（src/prng.js）从包内直接导入并交叉断言。
 */
import {
  fnv1a,
  fnv1aResume,
  prng as corePrng,
} from "../node_modules/capjs-core/src/prng.js";

function fnv1aServer(str) {
  let hash = 2166136261;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash +=
      (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return hash >>> 0;
}

export function prngServer(seed, length) {
  let state = fnv1aServer(seed);
  let result = "";

  function next() {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  }

  while (result.length < length) {
    const rnd = next();
    result += rnd.toString(16).padStart(8, "0");
  }

  return result.substring(0, length);
}

/** 断言两份官方实现 bit-exact（fixture 生成前置条件）。 */
export function assertPrngConsistency(seeds, lengths) {
  for (const seed of seeds) {
    if (fnv1aServer(seed) !== fnv1a(seed)) {
      throw new Error(`fnv1a mismatch on seed ${JSON.stringify(seed)}`);
    }
    for (const len of lengths) {
      if (prngServer(seed, len) !== corePrng(seed, len)) {
        throw new Error(
          `prng mismatch seed=${JSON.stringify(seed)} len=${len}`,
        );
      }
    }
  }
}

/** 求解 legacy format-1 挑战：返回与官方服务端校验一致的 solutions 数组。 */
export function solveFormat1(token, { c, s, d }) {
  const solutions = [];
  for (let i = 1; i <= c; i++) {
    const salt = prngServer(`${token}${i}`, s);
    const target = prngServer(`${token}${i}d`, d);
    let nonce = 0;
    for (;;) {
      if (sha256Hex(salt + nonce).startsWith(target)) break;
      nonce++;
    }
    solutions.push(nonce);
  }
  return solutions;
}

/** 求解 format-2 sha256-pow 条目：返回 {nonce} 对象数组。 */
export function solveFormat2(challenges) {
  return challenges.map((ch) => {
    if (ch.protocol !== "sha256-pow") {
      throw new Error(`oracle 不支持求解 protocol=${ch.protocol}`);
    }
    const { salt, target } = ch.payload;
    let nonce = 0;
    for (;;) {
      if (sha256Hex(salt + nonce).startsWith(target)) break;
      nonce++;
    }
    return { nonce };
  });
}

import { createHash } from "node:crypto";
export function sha256Hex(str) {
  return createHash("sha256").update(str).digest("hex");
}
