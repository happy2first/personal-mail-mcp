import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const sourceUrl = new URL("../src/proton/session.js", import.meta.url);

async function source() {
  return readFile(sourceUrl, "utf8");
}

test("Proton 2028 persistence is idempotent for the same error object", async () => {
  const text = await source();
  assert.match(text, /if \(error\?\.riskRemembered\) return this\.readRisk\(\);/);
  assert.match(text, /error\.riskRemembered = true;/);
});

test("persistent 2028 risk recorder is scoped to explicit password reauthorize", async () => {
  const text = await source();
  assert.match(text, /if \(action === "reauthorize"\) await this\.rememberRiskBlock\(error\)\.catch\(\(\) => \{\}\);/);
  assert.match(text, /scope: "password_reauthorize_only"/);
});
