import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { normalizeKeySalts } from "../src/proton/key-material.js";

const providerUrl = new URL("../src/proton/provider.js", import.meta.url);
const keyMaterialUrl = new URL("../src/proton/key-material.js", import.meta.url);
const keyMaterialSessionUrl = new URL("../src/proton/key-material-session.js", import.meta.url);
const verifyUrl = new URL("../src/proton/verify.js", import.meta.url);

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
  const clientSource = await read(keyMaterialUrl);
  const sessionSource = await read(keyMaterialSessionUrl);
  const verifySource = await read(verifyUrl);
  assert.match(provider, /import "\.\/key-material\.js"/);
  assert.match(verifySource, /import "\.\/key-material-session\.js"/);
  assert.match(clientSource, /this\.auth\?\.KeySalts/);
  assert.match(clientSource, /\/core\/v4\/keys\/salts/);
  assert.match(clientSource, /protonCode\) === 9101/);
  assert.match(clientSource, /keySaltsRequired = true/);
  assert.match(sessionSource, /importMode: "key_salts_json"/);
  assert.match(sessionSource, /client\.setAuth\(\{ \.\.\.client\.auth, KeySalts: salts \}\)/);
});

test("cookie session status does not pretend to expose a RefreshToken", async () => {
  const source = await read(keyMaterialSessionUrl);
  assert.match(source, /status\.session\.cookieAuth = cookieAuth/);
  assert.match(source, /status\.session\.hasRefreshToken = !cookieAuth/);
  assert.match(source, /status\.session\.keySaltCount = keySaltCount/);
});

test("provider includes Proton request path in user-visible error message", async () => {
  const provider = await read(providerUrl);
  assert.match(provider, /pathSuffix/);
  assert.match(provider, /body\?\.requestPath/);
});
