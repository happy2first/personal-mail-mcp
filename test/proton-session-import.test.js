import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { normalizeImportedSession } from "../src/proton/session-import.js";

const sessionUrl = new URL("../src/proton/session.js", import.meta.url);
const importUrl = new URL("../src/proton/session-import.js", import.meta.url);
const pageUrl = new URL("../src/proton/import-page.js", import.meta.url);
const entryUrl = new URL("../src/entry.js", import.meta.url);
const clientUrl = new URL("../src/proton/client-v2.js", import.meta.url);

const read = (url) => readFile(url, "utf8");

test("manual Session import requires UID and verifies account ownership", async () => {
  const text = await read(importUrl);
  assert.match(text, /Session 缺少 UID/);
  assert.match(text, /Session 缺少 RefreshToken/);
  assert.match(text, /\/core\/v4\/addresses/);
  assert.match(text, /sessionAccountMismatch = true/);
  assert.match(text, /refreshAuthenticated\(\)/);
});

test("browser REFRESH cookie can bootstrap a Session without an AccessToken", () => {
  const cookieValue = encodeURIComponent(JSON.stringify({
    ResponseType: "token",
    GrantType: "refresh_token",
    UID: "uid-demo",
    RefreshToken: "refresh-demo",
  }));
  const session = normalizeImportedSession(`REFRESH-uid-demo=${cookieValue}`);
  assert.equal(session.UID, "uid-demo");
  assert.equal(session.RefreshToken, "refresh-demo");
  assert.equal(session.AccessToken, undefined);
});

test("browser Cookie request header bootstraps cookie-auth from AUTH-UID", () => {
  const session = normalizeImportedSession("Cookie: AUTH-uid-demo=secret-auth; Session-Id=session-id; st=token");
  assert.equal(session.UID, "uid-demo");
  assert.equal(session.cookies, true);
  assert.equal(session.AccessToken, undefined);
  assert.ok(Array.isArray(session.CookieState));
  assert.equal(session.CookieState.find((x) => x.name === "AUTH-uid-demo")?.value, "secret-auth");
});

test("REFRESH cookie name UID must match its encoded UID", () => {
  const cookieValue = encodeURIComponent(JSON.stringify({ UID: "uid-a", RefreshToken: "refresh-demo" }));
  assert.throws(
    () => normalizeImportedSession(`REFRESH-uid-b=${cookieValue}`),
    /UID 与 Cookie 内容不一致/,
  );
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

test("token refresh matches the current Proton WebClients request shape", async () => {
  const text = await read(clientUrl);
  const start = text.indexOf("async refreshAuthenticated()");
  const end = text.indexOf("async ensureKeys()", start);
  assert.ok(start >= 0 && end > start);
  const refresh = text.slice(start, end);
  assert.match(refresh, /this\.raw\("\/auth\/refresh"/);
  assert.match(refresh, /auth: true/);
  assert.match(refresh, /ResponseType: "token"/);
  assert.match(refresh, /GrantType: "refresh_token"/);
  assert.match(refresh, /RefreshToken: previous\.RefreshToken/);
  assert.match(refresh, /RedirectURI: PROTON_REFRESH_REDIRECT_URI/);
  assert.doesNotMatch(refresh, /\/auth\/v4\/refresh/);
  assert.doesNotMatch(refresh, /UID: previous\.UID/);
  assert.doesNotMatch(refresh, /State:/);
  assert.doesNotMatch(refresh, /AccessToken: previous\.AccessToken/);
  assert.match(text, /PROTON_REFRESH_REDIRECT_URI = "https:\/\/protonmail\.com"/);
});

test("cookie auth uses x-pm-uid without Bearer and refreshes with an empty POST body", async () => {
  const text = await read(clientUrl);
  assert.match(text, /if \(!this\.auth\.cookies && this\.auth\.AccessToken\) headers\.authorization/);
  assert.match(text, /if \(this\.auth\?\.UID && this\.auth\?\.cookies\) return this\.auth/);
  const start = text.indexOf("async refreshAuthenticated()");
  const end = text.indexOf("async ensureKeys()", start);
  const refresh = text.slice(start, end);
  assert.match(refresh, /if \(previous\.cookies\)/);
  assert.match(refresh, /this\.raw\("\/auth\/refresh", \{\s*method: "POST",\s*auth: true,\s*\}\)/s);
});

test("a transient Proton 2028 during refresh does not discard the imported Session", async () => {
  const text = await read(clientUrl);
  assert.match(text, /terminalRefreshFailure = Number\(error\?\.protonCode\) !== 2028/);
  assert.match(text, /\[400, 401, 422\]\.includes\(Number\(error\?\.status\)\)/);
  assert.match(text, /if \(terminalRefreshFailure\) \{\s*this\.clearSession\(\);\s*error\.reauthRequired = true;/s);
});

test("management page is Access-protected, CSRF-protected and separates normal and refresh cookies", async () => {
  const page = await read(pageUrl);
  const entry = await read(entryUrl);
  assert.match(entry, /url\.pathname === "\/proton\/import"/);
  assert.match(entry, /await verifyAccess\(request, env\)/);
  assert.match(page, /SameSite=Strict/);
  assert.match(page, /x-csrf-token/);
  assert.match(page, /cache-control": "no-store/);
  assert.match(page, /id="sessionCookie"/);
  assert.match(page, /id="refreshCookie"/);
  assert.match(page, /\/api\/auth\/refresh/);
  assert.match(page, /\/test-refresh/);
  assert.match(page, /id="keySalts"/);
  assert.doesNotMatch(page, /localStorage\.(setItem|getItem)/);
});
