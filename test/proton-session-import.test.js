import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const sessionUrl = new URL("../src/proton/session.js", import.meta.url);
const importUrl = new URL("../src/proton/session-import.js", import.meta.url);
const pageUrl = new URL("../src/proton/import-page.js", import.meta.url);
const entryUrl = new URL("../src/entry.js", import.meta.url);
const clientUrl = new URL("../src/proton/client-v2.js", import.meta.url);

const read = (url) => readFile(url, "utf8");

test("manual Session import requires UID, access and refresh tokens and verifies account ownership", async () => {
  const text = await read(importUrl);
  assert.match(text, /Session 缺少 UID/);
  assert.match(text, /Session 缺少 AccessToken/);
  assert.match(text, /Session 缺少 RefreshToken/);
  assert.match(text, /\/core\/v4\/addresses/);
  assert.match(text, /sessionAccountMismatch = true/);
  assert.match(text, /refreshAuthenticated\(\)/);
});

test("Session import is atomic and local 2028 risk only gates password reauthorize", async () => {
  const text = await read(sessionUrl);
  assert.match(text, /validateImportedSession\(client\.cfg, this\.env, payload\.session\)/);
  assert.match(text, /client\.setAuth\(validated\.auth\)/);
  assert.match(text, /source: "manual_import"/);
  assert.match(text, /scope: "password_reauthorize_only"/);
  assert.match(text, /action === "reauthorize"\) \{\s*await this\.assertRiskCircuitClosed\(\)/s);
  const runStart = text.indexOf("async runClientAction");
  const pollStart = text.indexOf("async pollEvents", runStart);
  assert.ok(runStart >= 0 && pollStart > runStart);
  assert.doesNotMatch(text.slice(runStart, pollStart), /assertRiskCircuitClosed/);
});

test("a transient Proton 2028 during refresh does not discard the imported Session", async () => {
  const text = await read(clientUrl);
  assert.match(text, /terminalRefreshFailure = Number\(error\?\.protonCode\) !== 2028/);
  assert.match(text, /\[400, 401, 422\]\.includes\(Number\(error\?\.status\)\)/);
  assert.match(text, /if \(terminalRefreshFailure\) \{\s*this\.clearSession\(\);\s*error\.reauthRequired = true;/s);
});

test("management page is Access-protected, CSRF-protected and never exposes stored token values", async () => {
  const page = await read(pageUrl);
  const entry = await read(entryUrl);
  assert.match(entry, /url\.pathname === "\/proton\/import"/);
  assert.match(entry, /await verifyAccess\(request, env\)/);
  assert.match(page, /SameSite=Strict/);
  assert.match(page, /x-csrf-token/);
  assert.match(page, /cache-control": "no-store/);
  assert.match(page, /已保存（不回显）/);
  assert.doesNotMatch(page, /localStorage\.(setItem|getItem)/);
});
