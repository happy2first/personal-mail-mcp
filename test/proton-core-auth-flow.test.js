import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const clientUrl = new URL("../src/proton/client-v2.js", import.meta.url);

async function source() {
  return readFile(clientUrl, "utf8");
}

test("Proton core auth flow is the default and legacy remains opt-in", async () => {
  const text = await source();
  assert.match(text, /env\.PROTON_AUTH_FLOW \|\| "core"/);
  assert.match(text, /configuredFlow === "legacy" \? "legacy" : "core"/);
  assert.match(text, /info: "\/core\/v4\/auth\/info"/);
  assert.match(text, /submit: "\/core\/v4\/auth"/);
  assert.match(text, /twoFactor: "\/core\/v4\/auth\/2fa"/);
  assert.match(text, /info: "\/auth\/v4\/info"/);
  assert.match(text, /submit: "\/auth\/v4"/);
});

test("core auth sends the current WebClients SRP fields without auto fallback", async () => {
  const text = await source();
  assert.match(text, /Intent: "Proton"/);
  assert.match(text, /PersistentCookies: 0/);
  assert.match(text, /ClientProof: proof\.clientProof/);
  assert.match(text, /ClientEphemeral: proof\.clientEphemeral/);
  assert.match(text, /SRPSession: info\.SRPSession/);
  assert.doesNotMatch(text, /catch[\s\S]{0,500}authFlow\s*=\s*"legacy"/);
});
