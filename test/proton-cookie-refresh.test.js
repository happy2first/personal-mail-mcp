import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { normalizeRefreshCookieInput, PROTON_REFRESH_COOKIE_PATH } from "../src/proton/cookie-bundle.js";

const refreshUrl = new URL("../src/proton/cookie-refresh.js", import.meta.url);
const sessionUrl = new URL("../src/proton/cookie-refresh-session.js", import.meta.url);
const keySessionUrl = new URL("../src/proton/key-material-session.js", import.meta.url);
const pageUrl = new URL("../src/proton/import-page.js", import.meta.url);

const read = (url) => readFile(url, "utf8");

test("refresh cookie shorthand is stored on Proton refresh path", () => {
  const rows = normalizeRefreshCookieInput("AUTH-uid-demo=refresh-secret", "https://mail.proton.me/api");
  assert.equal(rows.length, 1);
  assert.equal(rows[0].name, "AUTH-uid-demo");
  assert.equal(rows[0].value, "refresh-secret");
  assert.equal(rows[0].path, PROTON_REFRESH_COOKIE_PATH);
  assert.equal(rows[0].domain, "mail.proton.me");
  assert.equal(rows[0].hostOnly, true);
});

test("refresh cookie Set-Cookie input preserves domain and enforces path", () => {
  const rows = normalizeRefreshCookieInput(
    "Set-Cookie: AUTH-uid-demo=refresh-secret; Domain=.proton.me; Path=/api/auth/refresh; Secure; HttpOnly",
    "https://mail.proton.me/api",
  );
  assert.equal(rows[0].domain, "proton.me");
  assert.equal(rows[0].hostOnly, false);
  assert.equal(rows[0].path, "/api/auth/refresh");
  assert.throws(
    () => normalizeRefreshCookieInput("Set-Cookie: X=1; Path=/", "https://mail.proton.me/api"),
    /Path 必须是 \/api\/auth\/refresh/,
  );
});

test("cookie refresh failure preserves imported cookie session and diagnostics", async () => {
  const refresh = await read(refreshUrl);
  const session = await read(sessionUrl);
  assert.match(refresh, /previousAuth/);
  assert.match(refresh, /this\.setAuth\(previousAuth\)/);
  assert.match(refresh, /this\.setCookieState\(previousCookies\)/);
  assert.match(refresh, /error\.preserveSession = true/);
  assert.match(refresh, /error\.refreshFailed = true/);
  assert.match(session, /if \(error\?\.preserveSession\)/);
  assert.match(session, /patchAuthState\(\{ reauthRequired: true/);
  assert.match(session, /lastRefreshResult/);
});

test("cookie bundle exposes import and explicit refresh test actions", async () => {
  const session = await read(sessionUrl);
  const keySession = await read(keySessionUrl);
  const page = await read(pageUrl);
  assert.match(keySession, /import "\.\/cookie-refresh-session\.js"/);
  assert.match(session, /action === "importCookieBundle"/);
  assert.match(session, /action === "testRefresh"/);
  assert.match(session, /refreshSucceeded: true/);
  assert.match(session, /refreshCookieCount/);
  assert.match(page, /import-cookies/);
  assert.match(page, /test-refresh/);
  assert.match(page, /自动续期已验证/);
});
