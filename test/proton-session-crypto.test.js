import assert from "node:assert/strict";
import test from "node:test";
import { decryptJson, encryptJson, hasSessionEncryption } from "../src/proton/session-crypto.js";

test("session encryption round-trips with account-bound AAD", async () => {
  const secret = "a-long-test-secret";
  const value = { UID: "uid", AccessToken: "access", RefreshToken: "refresh", ExpiresAt: 123 };
  const envelope = await encryptJson(value, secret, "proton1:session");
  assert.equal(envelope.v, 1);
  assert.notEqual(envelope.data.includes("refresh"), true);
  assert.deepEqual(await decryptJson(envelope, secret, "proton1:session"), value);
});

test("session ciphertext cannot be replayed under another account AAD", async () => {
  const envelope = await encryptJson({ RefreshToken: "secret" }, "key", "proton1:session");
  await assert.rejects(() => decryptJson(envelope, "key", "proton2:session"));
});

test("session encryption is reported only when PROTON_SESSION_KEY exists", () => {
  assert.equal(hasSessionEncryption({ PROTON_SESSION_KEY: "x" }), true);
  assert.equal(hasSessionEncryption({}), false);
});
