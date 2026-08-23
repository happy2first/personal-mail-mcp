import assert from "node:assert/strict";
import test from "node:test";
import { ProtonClient } from "../src/proton/client.js";

const cfg = {
  id: "proton-test",
  label: "Proton Test",
  provider: "proton",
  email: "user@example.test",
  credential: "secret",
};

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

class LoginSingleFlightClient extends ProtonClient {
  constructor() {
    super(cfg, {});
    this.loginCalls = 0;
  }

  async login() {
    this.loginCalls += 1;
    await wait(10);
    this.auth = { UID: "uid", AccessToken: "access", RefreshToken: "refresh" };
    return this.auth;
  }
}

test("ensureAuthenticated coalesces concurrent password logins", async () => {
  const client = new LoginSingleFlightClient();
  await Promise.all(Array.from({ length: 6 }, () => client.ensureAuthenticated()));
  assert.equal(client.loginCalls, 1);
});

class RefreshSingleFlightClient extends ProtonClient {
  constructor() {
    super(cfg, {});
    this.auth = { UID: "uid", AccessToken: "old-access", RefreshToken: "old-refresh" };
    this.refreshCalls = 0;
    this.loginCalls = 0;
    this.refreshBody = null;
  }

  async login() {
    this.loginCalls += 1;
    throw new Error("password login must not be used during a 401 refresh");
  }

  async raw(path, options = {}) {
    if (path === "/auth/v4/refresh") {
      this.refreshCalls += 1;
      this.refreshBody = options.body;
      await wait(10);
      return { UID: "uid", AccessToken: "new-access", RefreshToken: "new-refresh" };
    }
    if (path === "/resource") {
      if (this.auth?.AccessToken === "old-access") {
        await wait(5);
        const error = new Error("unauthorized");
        error.status = 401;
        throw error;
      }
      return { Code: 1000, value: "ok" };
    }
    throw new Error(`unexpected path ${path}`);
  }
}

test("concurrent 401 responses share one refresh and do not password-login", async () => {
  const client = new RefreshSingleFlightClient();
  const rows = await Promise.all(Array.from({ length: 4 }, () => client.request("/resource")));
  assert.equal(client.refreshCalls, 1);
  assert.equal(client.loginCalls, 0);
  assert.equal(client.auth.AccessToken, "new-access");
  assert.equal(client.auth.RefreshToken, "new-refresh");
  assert.equal(client.refreshBody.UID, "uid");
  assert.equal(client.refreshBody.RefreshToken, "old-refresh");
  assert.equal(client.refreshBody.GrantType, "refresh_token");
  assert.equal(client.refreshBody.ResponseType, "token");
  assert.equal(client.refreshBody.RedirectURI, "https://protonmail.ch");
  assert.ok(client.refreshBody.State);
  assert.deepEqual(rows.map((x) => x.value), ["ok", "ok", "ok", "ok"]);
});

class InvalidRefreshClient extends ProtonClient {
  constructor() {
    super(cfg, {});
    this.auth = { UID: "uid", AccessToken: "old-access", RefreshToken: "bad-refresh" };
    this.loginCalls = 0;
  }

  async login() {
    this.loginCalls += 1;
    this.auth = { UID: "uid2", AccessToken: "fresh-access", RefreshToken: "fresh-refresh" };
    return this.auth;
  }

  async raw(path) {
    if (path === "/resource") {
      const error = new Error("unauthorized");
      error.status = 401;
      throw error;
    }
    if (path === "/auth/v4/refresh") {
      const error = new Error("invalid refresh token");
      error.status = 422;
      throw error;
    }
    throw new Error(`unexpected path ${path}`);
  }
}

test("an invalid refresh never falls back to password login inside the failed request", async () => {
  const client = new InvalidRefreshClient();
  await assert.rejects(() => client.request("/resource"), /invalid refresh token/);
  assert.equal(client.loginCalls, 0);
  assert.equal(client.auth, null);

  await client.ensureAuthenticated();
  assert.equal(client.loginCalls, 1);
  assert.equal(client.auth.AccessToken, "fresh-access");
});

test("Proton code 2028 opens an in-memory circuit before a second network request", async () => {
  const client = new ProtonClient(cfg, {});
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    return new Response(JSON.stringify({ Code: 2028, Error: "unusual activity" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  try {
    await assert.rejects(
      () => client.raw("/auth/v4/info", { method: "POST", body: { Username: "user" } }),
      (error) => Number(error?.protonCode) === 2028 && Number(error?.retryAfterSeconds) > 0,
    );
    assert.equal(fetchCalls, 1);

    await assert.rejects(
      () => client.raw("/auth/v4/info", { method: "POST", body: { Username: "user" } }),
      (error) => error?.circuitOpen === true && Number(error?.protonCode) === 2028,
    );
    assert.equal(fetchCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
