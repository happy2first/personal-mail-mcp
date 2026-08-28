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
import { dedupeSessionIdCookies } from "../src/proton/cookie-refresh.js";

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

test("refresh keeps one Session-Id and prefers the Proton domain cookie", () => {
  const rows = dedupeSessionIdCookies([
    { name: "AUTH-demo", value: "auth", domain: "mail.proton.me", hostOnly: true, path: "/api/" },
    { name: "Session-Id", value: "imported-old", domain: "mail.proton.me", hostOnly: true, path: "/" },
    { name: "Tag", value: "default", domain: "mail.proton.me", hostOnly: true, path: "/" },
    { name: "Session-Id", value: "server-new", domain: "proton.me", hostOnly: false, path: "/" },
  ]);
  assert.equal(rows.filter((x) => x.name === "Session-Id").length, 1);
  assert.equal(rows.find((x) => x.name === "Session-Id")?.value, "server-new");
  assert.equal(rows.find((x) => x.name === "Session-Id")?.domain, "proton.me");
});

test("cookie refresh omits JSON content-type for the bodyless WebClients request", async () => {
  const refresh = await read(refreshUrl);
  assert.match(refresh, /originalBaseHeaders/);
  assert.match(refresh, /__protonCookieRefreshNoContentType/);
  assert.match(refresh, /delete headers\["content-type"\]/);
  assert.match(refresh, /contentTypeOmitted: cookieAuth/);
  assert.match(refresh, /cookieHeaderForUrl/);
  assert.match(refresh, /sentCookieNames/);
  assert.match(refresh, /dedupeSessionIdCookies/);
});

test("cookie refresh failure preserves canonicalized cookie session and diagnostics", async () => {
  const refresh = await read(refreshUrl);
  const session = await read(sessionUrl);
  assert.match(refresh, /previousAuth/);
  assert.match(refresh, /this\.setAuth\(previousAuth\)/);
  assert.match(refresh, /this\.setCookieState\(refreshCookies\)/);
  assert.match(refresh, /sessionIdCookiesRemoved/);
  assert.match(refresh, /error\.preserveSession = true/);
  assert.match(refresh, /error\.refreshFailed = true/);
  assert.match(session, /if \(error\?\.preserveSession\)/);
  assert.match(session, /patchAuthState\(\{ reauthRequired: true/);
  assert.match(session, /lastRefreshResult/);
  assert.match(session, /lastRefreshSentCookieNames/);
  assert.match(session, /lastRefreshSessionIdCookiesRemoved/);
  assert.match(session, /contentTypeOmitted/);
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
  assert.match(session, /diagnostics: refreshDiagnostics/);
  assert.match(page, /id="sessionCookie"/);
  assert.match(page, /可选：额外的专用刷新 Cookie/);
  assert.match(page, /refreshCookie:refreshCookie\|\|null/);
  assert.match(page, /test-refresh/);
  assert.match(page, /自动续期已验证/);
});
