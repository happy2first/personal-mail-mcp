import assert from "node:assert/strict";
import test from "node:test";
import { ProtonClient } from "../src/proton/client-v2.js";

const cfg = {
  id: "proton-test",
  label: "Proton Test",
  provider: "proton",
  email: "user@example.test",
  credential: "secret",
  mailboxPassword: null,
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
    this.auth = { UID: "uid", AccessToken: "access", RefreshToken: "refresh", ExpiresAt: Date.now() + 3600000 };
    return this.auth;
  }
}

test("ensureAuthenticated coalesces concurrent password logins", async () => {
  const client = new LoginSingleFlightClient();
  await Promise.all(Array.from({ length: 6 }, () => client.ensureAuthenticated()));
  assert.equal(client.loginCalls, 1);
});

test("ensureAuthenticated can forbid password fallback", async () => {
  const client = new LoginSingleFlightClient();
  await assert.rejects(
    () => client.ensureAuthenticated({ allowPasswordLogin: false }),
    (error) => error?.reauthRequired === true,
  );
  assert.equal(client.loginCalls, 0);
});

class RefreshSingleFlightClient extends ProtonClient {
  constructor() {
    super(cfg, {});
    this.auth = { UID: "uid", AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: Date.now() + 3600000 };
    this.refreshCalls = 0;
    this.loginCalls = 0;
    this.refreshBody = null;
    this.refreshAuth = null;
  }
  async login() {
    this.loginCalls += 1;
    throw new Error("password login must not be used during a 401 refresh");
  }
  async raw(path, options = {}) {
    if (path === "/auth/refresh") {
      this.refreshCalls += 1;
      this.refreshBody = options.body;
      this.refreshAuth = options.auth;
      await wait(10);
      return { UID: "uid", AccessToken: "new-access", RefreshToken: "new-refresh", ExpiresIn: 3600 };
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
  assert.equal(client.refreshAuth, true);
  assert.equal(client.refreshBody.RefreshToken, "old-refresh");
  assert.equal(client.refreshBody.GrantType, "refresh_token");
  assert.equal(client.refreshBody.ResponseType, "token");
  assert.equal(client.refreshBody.RedirectURI, "https://protonmail.com");
  assert.equal(client.refreshBody.UID, undefined);
  assert.equal(client.refreshBody.State, undefined);
  assert.equal(client.refreshBody.AccessToken, undefined);
  assert.deepEqual(rows.map((x) => x.value), ["ok", "ok", "ok", "ok"]);
});

class ProactiveRefreshClient extends RefreshSingleFlightClient {
  constructor() {
    super();
    this.auth.ExpiresAt = Date.now() + 30000;
  }
}

test("near-expiry access token refreshes proactively", async () => {
  const client = new ProactiveRefreshClient();
  await client.ensureAuthenticated();
  assert.equal(client.refreshCalls, 1);
  assert.equal(client.auth.AccessToken, "new-access");
});

class InvalidRefreshClient extends ProtonClient {
  constructor() {
    super(cfg, {});
    this.auth = { UID: "uid", AccessToken: "old-access", RefreshToken: "bad-refresh", ExpiresAt: Date.now() + 3600000 };
    this.loginCalls = 0;
  }
  async login() {
    this.loginCalls += 1;
    this.auth = { UID: "uid2", AccessToken: "fresh-access", RefreshToken: "fresh-refresh", ExpiresAt: Date.now() + 3600000 };
    return this.auth;
  }
  async raw(path) {
    if (path === "/resource") {
      const error = new Error("unauthorized");
      error.status = 401;
      throw error;
    }
    if (path === "/auth/refresh") {
      const error = new Error("invalid refresh token");
      error.status = 422;
      throw error;
    }
    throw new Error(`unexpected path ${path}`);
  }
}

test("invalid refresh never falls back to password login inside failed request", async () => {
  const client = new InvalidRefreshClient();
  await assert.rejects(() => client.request("/resource"), /invalid refresh token/);
  assert.equal(client.loginCalls, 0);
  assert.equal(client.auth, null);
  await client.ensureAuthenticated();
  assert.equal(client.loginCalls, 1);
});

class RiskBlockedRefreshClient extends ProtonClient {
  constructor() {
    super(cfg, {});
    this.auth = { UID: "uid", AccessToken: "old-access", RefreshToken: "valuable-refresh", ExpiresAt: Date.now() + 30000 };
  }
  async raw(path) {
    if (path !== "/auth/refresh") throw new Error(`unexpected path ${path}`);
    const error = new Error("temporarily limited");
    error.status = 422;
    error.protonCode = 2028;
    throw error;
  }
}

test("Proton 2028 during refresh preserves the existing Session for a later retry", async () => {
  const client = new RiskBlockedRefreshClient();
  await assert.rejects(
    () => client.ensureAuthenticated({ allowPasswordLogin: false }),
    (error) => error?.protonCode === 2028 && error?.reauthRequired !== true,
  );
  assert.equal(client.auth.UID, "uid");
  assert.equal(client.auth.AccessToken, "old-access");
  assert.equal(client.auth.RefreshToken, "valuable-refresh");
});

test("API error preserves Proton human-verification details", async () => {
  const client = new ProtonClient(cfg, {});
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    Code: 9001,
    Error: "Human verification required",
    Details: {
      HumanVerificationMethods: ["captcha"],
      HumanVerificationToken: "challenge-token",
    },
  }), { status: 200, headers: { "content-type": "application/json" } });
  try {
    await assert.rejects(
      () => client.raw("/auth/v4/info", { method: "POST", body: { Username: "user" } }),
      (error) => error?.protonCode === 9001
        && error?.humanVerification?.token === "challenge-token"
        && error?.humanVerification?.methods?.[0] === "captcha",
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
