import "./cookie-refresh.js";
import { ProtonSession } from "./session.js";
import { countRefreshCookies, validateCookieBundle } from "./cookie-bundle.js";

const text = (value) => value === undefined || value === null ? "" : String(value).trim();

function normalCookieCount(client) {
  const state = client.getCookieState();
  return Math.max(0, state.length - countRefreshCookies(state));
}

async function persistRefreshMeta(session, client) {
  const info = client.lastRefreshInfo;
  if (!info?.completedAt) return;
  const previous = await session.readSessionMeta();
  if (Number(previous?.lastRefreshAt || 0) >= Number(info.completedAt)) return;
  await session.writeSessionMeta(client, {
    lastRefreshAt: Number(info.completedAt),
    lastRefreshResult: info.success ? "success" : "failed",
    lastRefreshCookiesUpdated: Boolean(info.cookiesUpdated),
    lastRefreshProtonCode: info.protonCode || null,
    lastRefreshRequestPath: info.requestPath || "/auth/refresh",
    lastRefreshRequestMethod: info.requestMethod || "POST",
  });
}

const originalRunClientAction = ProtonSession.prototype.runClientAction;
ProtonSession.prototype.runClientAction = async function runClientActionPreservingCookieSession(client, fn, { allowPasswordLogin = false } = {}) {
  await this.hydrate(client);
  try {
    await this.initializeOrRestore(client, { allowPasswordLogin });
    const data = await fn(client);
    await this.persistClient(client);
    await persistRefreshMeta(this, client);
    return data;
  } catch (error) {
    await this.persistClient(client).catch(() => {});
    await persistRefreshMeta(this, client).catch(() => {});
    if (error?.reauthRequired) {
      if (error?.preserveSession) {
        await this.patchAuthState({ reauthRequired: true, twoFactorPending: false });
      } else {
        await this.clearPersistedSession(client);
        await this.patchAuthState({ reauthRequired: true, twoFactorPending: false });
      }
    }
    throw error;
  }
};

const originalAuthStatus = ProtonSession.prototype.authStatus;
ProtonSession.prototype.authStatus = async function authStatusWithCookieRefresh(client) {
  const status = await originalAuthStatus.call(this, client);
  const meta = await this.readSessionMeta();
  const cookieAuth = Boolean(client.auth?.cookies);
  const refreshCookieCount = countRefreshCookies(client.getCookieState());
  const normalCount = normalCookieCount(client);
  const refreshCapable = cookieAuth && refreshCookieCount > 0;
  const refreshVerified = refreshCapable && meta?.lastRefreshResult === "success";
  status.transport = {
    ...(status.transport || {}),
    normalCookieCount: normalCount,
    refreshCookieCount,
  };
  if (status.session) {
    status.session.refreshCapable = refreshCapable;
    status.session.refreshVerified = refreshVerified;
    status.session.refreshCookieCount = refreshCookieCount;
    status.session.normalCookieCount = normalCount;
  }
  status.refresh = {
    capable: refreshCapable,
    verified: refreshVerified,
    cookieCount: refreshCookieCount,
    lastAttemptAt: meta?.lastRefreshAt || null,
    lastResult: meta?.lastRefreshResult || null,
    cookiesUpdated: Boolean(meta?.lastRefreshCookiesUpdated),
    protonCode: meta?.lastRefreshProtonCode || null,
    requestPath: meta?.lastRefreshRequestPath || null,
  };
  return status;
};

function addressEmails(payload) {
  return (Array.isArray(payload?.Addresses) ? payload.Addresses : [])
    .map((item) => text(item?.Email ?? item?.email).toLowerCase())
    .filter(Boolean);
}

async function validateCurrentAddress(client) {
  const payload = await client.raw("/core/v4/addresses", { auth: true });
  const addresses = addressEmails(payload);
  if (!addresses.includes(String(client.cfg.email || "").trim().toLowerCase())) {
    const error = new Error("刷新后的 Proton Session 与当前账号不匹配");
    error.sessionAccountMismatch = true;
    throw error;
  }
  return addresses.length;
}

const originalFetch = ProtonSession.prototype.fetch;
ProtonSession.prototype.fetch = async function fetchWithCookieRefreshActions(request) {
  if (request.method === "POST") {
    const parsed = await request.clone().json().catch(() => null);
    const account = String(parsed?.account || "").trim();
    const action = String(parsed?.action || "").trim();
    const payload = parsed?.payload || {};

    if (account && action === "importCookieBundle") {
      try {
        const client = this.getClient(account);
        await this.hydrate(client);
        const preservedKeySalts = client.auth?.KeySalts;
        const preservedPasswordMode = client.auth?.PasswordMode;
        const validated = await validateCookieBundle(client.cfg, this.env, {
          sessionCookie: payload.sessionCookie,
          refreshCookie: payload.refreshCookie,
        });
        client.setAuth({
          ...validated.auth,
          ...(preservedKeySalts?.length ? { KeySalts: preservedKeySalts } : {}),
          ...(preservedPasswordMode !== undefined ? { PasswordMode: preservedPasswordMode } : {}),
        });
        client.setCookieState(validated.cookies);
        await this.persistClient(client);
        await this.patchAuthState({ reauthRequired: false, twoFactorPending: false });
        const refreshAt = validated.safe.refreshedDuringValidation ? Date.now() : null;
        await this.writeSessionMeta(client, {
          source: "manual_cookie_bundle",
          importedAt: Date.now(),
          lastValidatedAt: Date.now(),
          refreshedDuringValidation: Boolean(validated.safe.refreshedDuringValidation),
          refreshCookieCount: validated.safe.refreshCookieCount,
          refreshCapable: true,
          ...(refreshAt ? {
            lastRefreshAt: refreshAt,
            lastRefreshResult: "success",
            lastRefreshCookiesUpdated: true,
            lastRefreshRequestPath: "/auth/refresh",
            lastRefreshRequestMethod: "POST",
          } : {}),
        });
        return Response.json({ ok: true, data: { success: true, imported: true, ...validated.safe } });
      } catch (error) {
        return Response.json({
          ok: false,
          error: error instanceof Error ? error.message : String(error),
          protonCode: Number(error?.protonCode) || undefined,
          requestPath: error?.requestPath || undefined,
          requestMethod: error?.requestMethod || undefined,
          sessionAccountMismatch: Boolean(error?.sessionAccountMismatch),
          reauthRequired: Boolean(error?.reauthRequired),
        }, { status: error?.sessionAccountMismatch ? 409 : 400 });
      }
    }

    if (account && action === "testRefresh") {
      const client = this.getClient(account);
      await this.hydrate(client);
      try {
        if (!client.auth?.UID || !client.auth?.cookies) throw new Error("当前账号没有 Cookie Session，请先导入浏览器 Session Cookie");
        const refreshCookieCount = countRefreshCookies(client.getCookieState());
        if (!refreshCookieCount) throw new Error("当前 Cookie Session 没有可发送到 /api/auth/refresh 的 AUTH-* Cookie，无法测试自动续期");
        const before = JSON.stringify(client.getCookieState());
        await client.refreshAuthenticated();
        const addressCount = await validateCurrentAddress(client);
        const after = JSON.stringify(client.getCookieState());
        await this.persistClient(client);
        await this.patchAuthState({ reauthRequired: false, twoFactorPending: false });
        await persistRefreshMeta(this, client);
        return Response.json({
          ok: true,
          data: {
            success: true,
            account,
            refreshSucceeded: true,
            sessionStillValid: true,
            addressCount,
            cookiesUpdated: before !== after,
            refreshCookieCount: countRefreshCookies(client.getCookieState()),
          },
        });
      } catch (error) {
        await this.persistClient(client).catch(() => {});
        await persistRefreshMeta(this, client).catch(() => {});
        if (error?.reauthRequired) await this.patchAuthState({ reauthRequired: true, twoFactorPending: false }).catch(() => {});
        return Response.json({
          ok: false,
          error: error instanceof Error ? error.message : String(error),
          protonCode: Number(error?.protonCode) || undefined,
          requestPath: error?.requestPath || undefined,
          requestMethod: error?.requestMethod || undefined,
          refreshFailed: true,
          reauthRequired: Boolean(error?.reauthRequired),
          sessionPreserved: Boolean(error?.preserveSession),
        }, { status: 400 });
      }
    }
  }
  return originalFetch.call(this, request);
};

export { originalRunClientAction };
