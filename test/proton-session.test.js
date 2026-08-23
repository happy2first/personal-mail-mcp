import assert from "node:assert/strict";
import test from "node:test";
import { ProtonSession } from "../src/proton/session.js";

class MemoryStorage {
  constructor() {
    this.values = new Map();
  }

  async get(key) {
    return this.values.get(key);
  }

  async put(key, value) {
    this.values.set(key, value);
  }

  async delete(key) {
    this.values.delete(key);
  }
}

const request = () => new Request("https://example.test/proton", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ account: "proton1", action: "test", payload: {} }),
});

test("a real 2028 response is persisted and blocks later DO calls without touching Proton", async () => {
  const storage = new MemoryStorage();
  const session = new ProtonSession({ storage }, {});
  let clientCalls = 0;
  session.getClient = () => ({
    async testConnection() {
      clientCalls += 1;
      const error = new Error("Proton API 2028: unusual activity");
      error.protonCode = 2028;
      error.blockedUntil = Date.now() + (30 * 60 * 1000);
      throw error;
    },
  });

  const first = await session.fetch(request());
  assert.equal(first.status, 429);
  assert.equal(clientCalls, 1);
  const firstPayload = await first.json();
  assert.equal(firstPayload.protonCode, 2028);
  assert.ok([...storage.values.values()].some((value) => Number(value) > Date.now()));

  const restarted = new ProtonSession({ storage }, {});
  restarted.getClient = () => {
    throw new Error("getClient must not run while the persisted circuit is open");
  };
  const second = await restarted.fetch(request());
  assert.equal(second.status, 429);
  const secondPayload = await second.json();
  assert.equal(secondPayload.protonCode, 2028);
  assert.ok(secondPayload.retryAfterSeconds > 0);
});
