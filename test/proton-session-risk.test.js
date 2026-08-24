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

test("outer Proton action errors are passed through the persistent risk recorder", async () => {
  const text = await source();
  assert.match(text, /await this\.rememberRiskBlock\(error\)\.catch\(\(\) => \{\}\);/);
});
