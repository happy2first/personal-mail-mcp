import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { normalizeExtensionBundle } from "../src/proton/extension-policy.js";

const cookie = (name, value, domain, path, hostOnly = true) => ({
  name, value, domain, path, hostOnly, secure: true, httpOnly: true, sameSite: "strict", session: false,
  expiresAt: Date.now() + 60 * 60 * 1000,
});

function bundle(overrides = {}) {
  const uid = "uid-demo";
  const refreshValue = encodeURIComponent(JSON.stringify({
    ResponseType: "token", ClientID: "WebMail", GrantType: "refresh_token",
    RefreshToken: "refresh-demo", UID: uid,
  }));
  return {
    version: 2,
    source: "proton-browser-session",
    capturedAt: Date.now(),
    uid,
    email: "demo@proton.me",
    session: {
      cookies: [
        cookie(`AUTH-${uid}`, "auth-demo", "mail.proton.me", "/api/"),
        cookie(`REFRESH-${uid}`, refreshValue, "mail.proton.me", "/api/auth/refresh"),
        cookie("Session-Id", "session-demo", ".proton.me", "/", false),
        cookie("Tag", "default", "mail.proton.me", "/"),
      ],
    },
    user: { ID: "user-demo", keyIds: ["key-demo"] },
    addresses: [{ ID: "address-demo", Email: "demo@proton.me" }],
    keySalts: [{ ID: "key-demo", KeySalt: "salt-demo" }],
    client: { mailAppVersion: "web-mail@test", accountAppVersion: "web-account@test", locale: "en_US" },
    ...overrides,
  };
}

test("browser bundle v2 keeps structured cookie paths and validates core components", () => {
  const normalized = normalizeExtensionBundle(bundle(), "demo@proton.me");
  assert.equal(normalized.uid, "uid-demo");
  assert.equal(normalized.cookies.find((c) => c.name.startsWith("AUTH-")).path, "/api/");
  assert.equal(normalized.cookies.find((c) => c.name.startsWith("REFRESH-")).path, "/api/auth/refresh");
  assert.equal(normalized.cookies.find((c) => c.name === "Session-Id").domain, "proton.me");
  assert.equal(normalized.keySalts.length, 1);
});

test("browser bundle v2 rejects missing refresh/session-id and cross-account data", () => {
  const noRefresh = bundle();
  noRefresh.session.cookies = noRefresh.session.cookies.filter((c) => !c.name.startsWith("REFRESH-"));
  assert.throws(() => normalizeExtensionBundle(noRefresh, "demo@proton.me"), /REFRESH/);

  const noSession = bundle();
  noSession.session.cookies = noSession.session.cookies.filter((c) => c.name !== "Session-Id");
  assert.throws(() => normalizeExtensionBundle(noSession, "demo@proton.me"), /Session-Id/);

  assert.throws(() => normalizeExtensionBundle(bundle(), "other@proton.me"), /不匹配/);
});

test("browser bundle v2 rejects REFRESH cookie whose embedded UID does not match", () => {
  const value = encodeURIComponent(JSON.stringify({ UID: "other-uid", RefreshToken: "refresh-demo" }));
  const bad = bundle();
  bad.session.cookies = bad.session.cookies.map((c) => c.name.startsWith("REFRESH-") ? { ...c, value } : c);
  assert.throws(() => normalizeExtensionBundle(bad, "demo@proton.me"), /UID/);
});

test("management page exposes Access-bound extension pair/import routes and CSRF meta", async () => {
  const page = await readFile(new URL("../src/proton/import-page.js", import.meta.url), "utf8");
  const session = await readFile(new URL("../src/proton/extension-session.js", import.meta.url), "utf8");
  assert.match(page, /proton-extension-csrf/);
  assert.match(page, /extension-pair/);
  assert.match(page, /extension-import/);
  assert.match(page, /actorKey/);
  assert.match(session, /proton:extensionPair:v2/);
  assert.match(session, /state\.storage\.transaction/);
  assert.match(session, /candidate\.raw\("\/core\/v4\/addresses"/);
  assert.match(session, /candidate\.raw\("\/core\/v4\/users"/);
  assert.doesNotMatch(session, /refreshAuthenticated\(\)/);
});
