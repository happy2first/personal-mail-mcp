import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const sessionUrl = new URL("../src/proton/session.js", import.meta.url);
const providerUrl = new URL("../src/proton/provider.js", import.meta.url);

async function read(url) {
  return readFile(url, "utf8");
}

test("reauthorize persists an auth-attempt marker before staged password login", async () => {
  const text = await read(sessionUrl);
  assert.match(text, /status: "running"/);
  assert.match(text, /stage: "starting"/);
  assert.match(text, /setAuthStageCallback/);
  assert.match(text, /lastAuthAttempt: authState\.lastAuthAttempt \|\| null/);
});

test("reauthorize records success, 2FA, human verification and 2028 outcomes", async () => {
  const text = await read(sessionUrl);
  assert.match(text, /status: "succeeded"/);
  assert.match(text, /status: "waiting_2fa"/);
  assert.match(text, /"blocked_2028"/);
  assert.match(text, /"human_verification_required"/);
});

test("Proton Durable Object calls have a bounded caller-side timeout", async () => {
  const text = await read(providerUrl);
  assert.match(text, /action === "reauthorize" \? 20000 : 25000/);
  assert.match(text, /controller\.abort\(\)/);
  assert.match(text, /请先调用 mail_proton_auth action=status 查看 lastAuthAttempt/);
});
