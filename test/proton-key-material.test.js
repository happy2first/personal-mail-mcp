import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { normalizeKeySalts } from "../src/proton/key-material.js";

const providerUrl = new URL("../src/proton/provider.js", import.meta.url);
const keyMaterialUrl = new URL("../src/proton/key-material.js", import.meta.url);

const read = (url) => readFile(url, "utf8");

test("normalizes Proton keys/salts API response", () => {
  const salts = normalizeKeySalts(JSON.stringify({
    Code: 1000,
    KeySalts: [
      { ID: "key-1", KeySalt: "salt-1" },
      { ID: "key-2", KeySalt: "salt-2" },
    ],
  }));
  assert.deepEqual(salts, [
    { ID: "key-1", KeySalt: "salt-1" },
    { ID: "key-2", KeySalt: "salt-2" },
  ]);
});

test("rejects arbitrary JSON as key material", () => {
  assert.equal(normalizeKeySalts('{"Code":1000,"AccessToken":"secret"}'), null);
});

test("cookie-session key material path caches imported salts and explains 9101", async () => {
  const provider = await read(providerUrl);
  const source = await read(keyMaterialUrl);
  assert.match(provider, /import "\.\/key-material\.js"/);
  assert.match(source, /this\.auth\?\.KeySalts/);
  assert.match(source, /\/core\/v4\/keys\/salts/);
  assert.match(source, /protonCode\) === 9101/);
  assert.match(source, /keySaltsRequired = true/);
  assert.match(source, /importMode: "key_salts_json"/);
  assert.match(source, /client\.setAuth\(\{ \.\.\.client\.auth, KeySalts: salts \}\)/);
});

test("cookie session status does not pretend to expose a RefreshToken", async () => {
  const source = await read(keyMaterialUrl);
  assert.match(source, /status\.session\.cookieAuth = cookieAuth/);
  assert.match(source, /status\.session\.hasRefreshToken = !cookieAuth/);
  assert.match(source, /status\.session\.keySaltCount = keySaltCount/);
});

test("provider includes Proton request path in user-visible error message", async () => {
  const provider = await read(providerUrl);
  assert.match(provider, /pathSuffix/);
  assert.match(provider, /body\?\.requestPath/);
});
