import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  EXTENSION_BUNDLE_SOURCE,
  EXTENSION_BUNDLE_VERSION,
  normalizeExtensionBundle,
} from "../src/proton/extension-policy.js";

const entryUrl = new URL("../src/entry.js", import.meta.url);
const pageUrl = new URL("../src/proton/import-page.js", import.meta.url);
const extensionSessionUrl = new URL("../src/proton/extension-session.js", import.meta.url);

const read = (url) => readFile(url, "utf8");

function refreshValue(uid, token = "refresh-test") {
  return encodeURIComponent(JSON.stringify({
    ResponseType: "token",
    ClientID: "WebMail",
    GrantType: "refresh_token",
    RefreshToken: token,
    UID: uid,
  }));
}

function cookie(name, value, domain, path, hostOnly = true) {
  return { name, value, domain, path, hostOnly, secure: true, httpOnly: true, sameSite: "strict", session: false };
}

test("extension bundle v2 preserves structured AUTH/REFRESH/Session-Id cookies", () => {
  const uid = "uid_demo";
  const bundle = normalizeExtensionBundle({
    version: EXTENSION_BUNDLE_VERSION,
    source: EXTENSION_BUNDLE_SOURCE,
    capturedAt: Date.now(),
    uid,
    email: "demo@proton.me",
    user: { id: "user-id", keyIds: ["key-1"], passwordMode: 1 },
    addresses: [{ id: "address-id", email: "demo@proton.me" }],
    keySalts: [{ id: "key-1", keySalt: "salt-value" }, { id: "key-2", keySalt: null }],
    session: {
      cookies: [
        cookie(`AUTH-${uid}`, "auth-value", "mail.proton.me", "/api/"),
        cookie(`REFRESH-${uid}`, refreshValue(uid), "mail.proton.me", "/api/auth/refresh"),
        cookie("Session-Id", "session-value", ".proton.me", "/", false),
        cookie("Tag", "default", "mail.proton.me", "/", true),
      ],
    },
    client: { mailAppVersion: "web-mail@test", accountAppVersion: "web-account@test", locale: "en_US" },
  });

  assert.equal(bundle.version, 2);
  assert.equal(bundle.uid, uid);
  assert.equal(bundle.keySalts.length, 1);
  assert.equal(bundle.cookies.find((x) => x.name === `AUTH-${uid}`)?.path, "/api/");
  assert.equal(bundle.cookies.find((x) => x.name === `REFRESH-${uid}`)?.path, "/api/auth/refresh");
  assert.equal(bundle.cookies.find((x) => x.name === "Session-Id")?.domain, "proton.me");
  assert.equal(bundle.cookies.find((x) => x.name === "Session-Id")?.hostOnly, false);
});

test("extension bundle v2 rejects missing refresh, missing Session-Id and UID mismatch", () => {
  const uid = "uid_demo";
  const base = {
    version: 2,
    source: EXTENSION_BUNDLE_SOURCE,
    capturedAt: Date.now(),
    uid,
    email: "demo@proton.me",
    user: { id: "user-id", keyIds: ["key-1"] },
    addresses: [{ id: "address-id", email: "demo@proton.me" }],
    keySalts: [{ id: "key-1", keySalt: "salt-value" }],
  };
  const auth = cookie(`AUTH-${uid}`, "auth-value", "mail.proton.me", "/api/");
  const session = cookie("Session-Id", "session-value", ".proton.me", "/", false);
  assert.throws(() => normalizeExtensionBundle({ ...base, session: { cookies: [auth, session] } }), /缺少 REFRESH/);
  const refresh = cookie(`REFRESH-${uid}`, refreshValue(uid), "mail.proton.me", "/api/auth/refresh");
  assert.throws(() => normalizeExtensionBundle({ ...base, session: { cookies: [auth, refresh] } }), /缺少 Session-Id/);
  const wrong = cookie(`REFRESH-${uid}`, refreshValue("other_uid"), "mail.proton.me", "/api/auth/refresh");
  assert.throws(() => normalizeExtensionBundle({ ...base, session: { cookies: [auth, wrong, session] } }), /UID 与 Bundle UID 不一致/);
});

test("extension routes are Access/CSRF protected and loaded into the Durable Object class", async () => {
  const entry = await read(entryUrl);
  const page = await read(pageUrl);
  const session = await read(extensionSessionUrl);
  assert.match(entry, /import "\.\/proton\/extension-session\.js"/);
  assert.match(page, /meta name="proton-extension-csrf"/);
  assert.match(page, /extension-pair/);
  assert.match(page, /extension-import/);
  assert.match(page, /import-key-salts/);
  assert.doesNotMatch(page, /legacySession|importLegacy|\/api\/import["']/);
  assert.match(page, /actorIdentity\(actor\)/);
  assert.match(session, /action === "extensionPair"/);
  assert.match(session, /action === "extensionImport"/);
  assert.match(session, /source: "extension_bundle_v2"/);
  assert.match(session, /refreshTestRequired: true/);
  assert.doesNotMatch(session, /refreshAuthenticated\(\)/);
});
