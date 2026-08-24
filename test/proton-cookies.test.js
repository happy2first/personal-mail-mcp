import assert from "node:assert/strict";
import test from "node:test";

import { cookieHeaderForUrl, mergeSetCookieHeaders, normalizeCookieState } from "../src/proton/cookies.js";

test("Proton cookies survive across auth requests without exposing expired values", () => {
  const now = Date.UTC(2026, 7, 24, 8, 0, 0);
  const first = mergeSetCookieHeaders([], [
    "Session-A=alpha; Path=/api/auth; Secure; HttpOnly; Max-Age=3600",
    "Global-B=beta; Path=/; Secure; Max-Age=3600",
  ], "https://mail.proton.me/api/auth/v4/info", now);

  assert.equal(first.length, 2);
  assert.equal(
    cookieHeaderForUrl(first, "https://mail.proton.me/api/auth/v4", now + 1000),
    "Session-A=alpha; Global-B=beta",
  );
  assert.equal(
    cookieHeaderForUrl(first, "https://mail.proton.me/api/core/v4/users", now + 1000),
    "Global-B=beta",
  );

  const cleared = mergeSetCookieHeaders(first, [
    "Session-A=; Path=/api/auth; Secure; Max-Age=0",
  ], "https://mail.proton.me/api/auth/v4", now + 2000);
  assert.equal(cookieHeaderForUrl(cleared, "https://mail.proton.me/api/auth/v4", now + 3000), "Global-B=beta");
});

test("Proton cookie state rejects unrelated domains and expired persisted values", () => {
  const now = Date.UTC(2026, 7, 24, 8, 0, 0);
  const state = mergeSetCookieHeaders([], [
    "Bad=x; Domain=example.com; Path=/",
    "Good=y; Domain=.proton.me; Path=/; Secure; Max-Age=60",
  ], "https://mail.proton.me/api/auth/v4/info", now);
  assert.deepEqual(state.map((cookie) => cookie.name), ["Good"]);
  assert.equal(cookieHeaderForUrl(state, "https://mail.proton.me/api/auth/v4", now + 1000), "Good=y");
  assert.equal(normalizeCookieState(state, now + 61000).length, 0);
});
