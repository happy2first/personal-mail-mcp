import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  countRefreshCookies,
  isRefreshCapableCookie,
  normalizeRefreshCookieInput,
  PROTON_AUTH_COOKIE_PATH,
  PROTON_REFRESH_REQUEST_PATH,
} from "../src/proton/cookie-bundle.js";

const refreshUrl = new URL("../src/proton/cookie-refresh.js", import.meta.url);
const sessionUrl = new URL("../src/proton/cookie-refresh-session.js", import.meta.url);
const keySessionUrl = new URL("../src/proton/key-material-session.js", import.meta.url);
const pageUrl = new URL("../src/proton/import-page.js", import.meta.url);

const read = (url) => readFile(url, "utf8");

test("AUTH cookie on /api/ is refresh-capable for /api/auth/refresh", () => {
  const cookie = {
    name: "AUTH-uid-demo",
    value: "secret",
    domain: "mail.proton.me",
    path: PROTON_AUTH_COOKIE_PATH,
  };
  assert.equal(PROTON_AUTH_COOKIE_PATH, "/api/");
  assert.equal(PROTON_REFRESH_REQUEST_PATH, "/api/auth/refresh");
  assert.equal(isRefreshCapableCookie(cookie), true);
  assert.equal(countRefreshCookies([cookie]), 1);
});

test("legacy imported AUTH cookie on / still covers refresh endpoint", () => {
  assert.equal(isRefreshCapableCookie({ name: "AUTH-uid-demo", path: "/" }), true);
  assert.equal(isRefreshCapableCookie({ name: "Session-Id", path: "/" }), false);
});

test("optional extra cookie accepts any path that covers refresh request", () => {
  const rows = normalizeRefreshCookieInput(
    "Set-Cookie: AUTH-uid-demo=refresh-secret; Domain=.proton.me; Path=/api/; Secure; HttpOnly",
    "https://mail.proton.me/api",
  );
  assert.equal(rows[0].domain, "proton.me");
  assert.equal(rows[0].hostOnly, false);
  assert.equal(rows[0].path, "/api/");
  assert.throws(
    () => normalizeRefreshCookieInput("Set-Cookie: X=1; Path=/other/", "https://mail.proton.me/api"),
    /不会发送到 \/api\/auth\/refresh/,
  );
  assert.deepEqual(normalizeRefreshCookieInput("", "https://mail.proton.me/api"), []);
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

test("management page makes extra refresh cookie optional and keeps explicit refresh test", async () => {
  const session = await read(sessionUrl);
  const keySession = await read(keySessionUrl);
  const page = await read(pageUrl);
  assert.match(keySession, /import "\.\/cookie-refresh-session\.js"/);
  assert.match(session, /action === "importCookieBundle"/);
  assert.match(session, /action === "testRefresh"/);
  assert.match(session, /refreshSucceeded: true/);
  assert.match(session, /可发送到 \/api\/auth\/refresh 的 AUTH-\* Cookie/);
  assert.match(page, /id="sessionCookie"/);
  assert.match(page, /可选：额外的专用刷新 Cookie/);
  assert.match(page, /refreshCookie:refreshCookie\|\|null/);
  assert.match(page, /test-refresh/);
  assert.match(page, /自动续期已验证/);
});
