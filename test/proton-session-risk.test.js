import assert from "node:assert/strict";
import test from "node:test";
import { ProtonSession } from "../src/proton/session.js";

class MemoryStorage {
  constructor() { this.map = new Map(); }
  async get(key) { return this.map.get(key); }
  async put(key, value) { this.map.set(key, value); }
  async delete(key) { this.map.delete(key); }
}

function makeSession() {
  return new ProtonSession({ storage: new MemoryStorage() }, {});
}

function riskError() {
  const error = new Error("unusual activity");
  error.protonCode = 2028;
  return error;
}

test("the same Proton 2028 error is persisted exactly once", async () => {
  const session = makeSession();
  const error = riskError();

  const first = await session.rememberRiskBlock(error);
  const second = await session.rememberRiskBlock(error);

  assert.equal(first.attempt, 1);
  assert.equal(second.attempt, 1);
  assert.equal(error.riskRemembered, true);
  assert.equal((await session.readRisk()).attempt, 1);
});

test("distinct Proton 2028 failures still escalate backoff", async () => {
  const session = makeSession();

  await session.rememberRiskBlock(riskError());
  const second = await session.rememberRiskBlock(riskError());
  const third = await session.rememberRiskBlock(riskError());

  assert.equal(second.attempt, 2);
  assert.ok(second.blockedUntil > Date.now());
  assert.equal(third.attempt, 3);
  assert.equal(third.manualResetRequired, true);
  assert.equal(third.blockedUntil, 0);
});
