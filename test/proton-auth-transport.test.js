import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function source(path) {
  return readFile(new URL(`../${path}`, import.meta.url), "utf8");
}

test("Proton login records exact auth stages", async () => {
  const text = await source("src/proton/client-v2.js");
  for (const stage of ["auth_info_request", "srp_compute", "auth_submit", "server_proof_verify"]) {
    assert.match(text, new RegExp(`noteAuthStage\\(\\"${stage}\\"\\)`));
  }
});

test("Proton 2028 local cooldown is not exposed as server Retry-After", async () => {
  const text = await source("src/proton/session.js");
  assert.match(text, /error\.localCooldownSeconds = delay/);
  assert.doesNotMatch(text, /error\.retryAfterSeconds = delay/);
  assert.match(text, /serverRetryAfterSeconds/);
  assert.match(text, /policy: \"local\"/);
});

test("Proton transport persists encrypted cookie state without returning cookie values", async () => {
  const text = await source("src/proton/session.js");
  assert.match(text, /const COOKIE_KEY = \"proton:cookies:v1\"/);
  assert.match(text, /writeEncrypted\(COOKIE_KEY/);
  assert.match(text, /transport: \{ cookieCount: client\.getCookieState\(\)\.length \}/);
});
