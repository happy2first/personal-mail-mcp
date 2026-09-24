import "./key-material-session.js";
import { ProtonClient } from "./client-v2.js";
import { bundleCookieComponents, normalizeExtensionBundle } from "./extension-policy.js";
import { hasSessionEncryption } from "./session-crypto.js";
import { ProtonSession } from "./session.js";
import { suffix } from "./session-import.js";

const PAIR_KEY = "proton:extensionPair:v2";
const EVENT_CURSOR_KEY = "proton:eventCursor:v1";
const COOKIE_SESSION_MARKER = "__BROWSER_COOKIE_SESSION__";
const PAIR_TTL_MS = 5 * 60 * 1000;

const text = (value) => value === undefined || value === null ? "" : String(value).trim();
const lower = (value) => text(value).toLowerCase();

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64url");
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(String(value || ""));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Buffer.from(digest).toString("base64url");
}

function addressEmails(payload) {
  return (Array.isArray(payload?.Addresses) ? payload.Addresses : [])
    .map((item) => lower(item?.Email ?? item?.email))
    .filter(Boolean);
}

function activeKeyIds(userPayload) {
  return (Array.isArray(userPayload?.User?.Keys) ? userPayload.User.Keys : [])
    .filter((item) => item?.Active === true || item?.Active === 1)
    .map((item) => text(item?.ID))
    .filter(Boolean);
}

async function issuePair(session, account, payload) {
  const uid = text(payload.uid);
  const email = lower(payload.email);
  const actorKey = lower(payload.actorKey);
  if (!uid || !email || !actorKey) throw new Error("扩展配对缺少 UID、邮箱或 Access 身份");
  if (email !== lower(session.getClient(account).cfg.email)) {
    const error = new Error("扩展检测到的邮箱与所选 MCP 账号不匹配");
    error.sessionAccountMismatch = true;
    throw error;
  }
  const token = randomToken();
  const expiresAt = Date.now() + PAIR_TTL_MS;
  await session.state.storage.put(PAIR_KEY, {
    tokenHash: await sha256(token),
    account: lower(account),
    uid,
    email,
    actorKey,
    expiresAt,
    createdAt: Date.now(),
  });
  return { token, expiresAt };
}

async function consumePair(session, account, payload, bundle) {
  const tokenHash = await sha256(payload.token);
  const actorKey = lower(payload.actorKey);
  let record = null;
  await session.state.storage.transaction(async (txn) => {
    record = await txn.get(PAIR_KEY);
    if (!record) throw new Error("扩展配对不存在或已使用，请重新配对");
    if (Number(record.expiresAt || 0) <= Date.now()) {
      await txn.delete(PAIR_KEY);
      throw new Error("扩展配对已过期，请重新配对");
    }
    if (record.tokenHash !== tokenHash
      || record.account !== lower(account)
      || record.actorKey !== actorKey
      || record.uid !== bundle.uid
      || record.email !== bundle.email) {
      throw new Error("扩展配对与当前 Access 身份、账号或 Proton Session 不匹配");
    }
    await txn.delete(PAIR_KEY);
  });
  return record;
}

async function validateUpstream(cfg, env, bundle) {
  const candidate = new ProtonClient(cfg, env);
  candidate.setAuth({
    UID: bundle.uid,
    UserID: bundle.user.ID,
    RefreshToken: COOKIE_SESSION_MARKER,
    cookies: true,
    KeySalts: bundle.keySalts,
  });
  candidate.setCookieState(bundle.cookies);
  const [addressesPayload, userPayload] = await Promise.all([
    candidate.raw("/core/v4/addresses", { auth: true }),
    candidate.raw("/core/v4/users", { auth: true }),
  ]);
  const emails = addressEmails(addressesPayload);
  if (!emails.includes(lower(cfg.email))) {
    const error = new Error("Proton 服务端返回的邮箱地址与所选 MCP 账号不匹配");
    error.sessionAccountMismatch = true;
    throw error;
  }
  const ids = activeKeyIds(userPayload);
  const matchedKeySaltCount = bundle.keySalts.filter((item) => ids.includes(String(item.ID))).length;
  if (!matchedKeySaltCount) {
    const error = new Error("KeySalt 与 Proton 服务端当前有效用户密钥不匹配");
    error.sessionAccountMismatch = true;
    throw error;
  }
  const passwordMode = Number(userPayload?.User?.PasswordMode);
  return {
    auth: {
      UID: bundle.uid,
      UserID: text(userPayload?.User?.ID) || bundle.user.ID,
      RefreshToken: COOKIE_SESSION_MARKER,
      cookies: true,
      KeySalts: bundle.keySalts,
      ...(Number.isFinite(passwordMode) ? { PasswordMode: passwordMode } : {}),
    },
    cookies: candidate.getCookieState(),
    addressCount: emails.length,
    matchedKeySaltCount,
  };
}

const originalFetch = ProtonSession.prototype.fetch;
ProtonSession.prototype.fetch = async function fetchWithExtensionImport(request) {
  if (request.method === "POST") {
    const parsed = await request.clone().json().catch(() => null);
    const account = text(parsed?.account);
    const action = text(parsed?.action);
    const payload = parsed?.payload || {};

    if (account && action === "extensionPair") {
      try {
        const data = await issuePair(this, account, payload);
        return Response.json({ ok: true, data });
      } catch (error) {
        return Response.json({
          ok: false,
          error: error instanceof Error ? error.message : String(error),
          sessionAccountMismatch: Boolean(error?.sessionAccountMismatch),
        }, { status: error?.sessionAccountMismatch ? 409 : 400 });
      }
    }

    if (account && action === "extensionImport") {
      try {
        if (!hasSessionEncryption(this.env)) throw new Error("未配置 PROTON_SESSION_KEY，禁止导入浏览器 Session");
        const client = this.getClient(account);
        await this.hydrate(client);
        const bundle = normalizeExtensionBundle(payload.bundle, client.cfg.email);
        await consumePair(this, account, payload, bundle);
        const validated = await validateUpstream(client.cfg, this.env, bundle);
        client.setAuth(validated.auth);
        client.setCookieState(validated.cookies);
        await this.persistClient(client);
        await this.state.storage.delete(EVENT_CURSOR_KEY);
        await this.patchAuthState({ reauthRequired: false, twoFactorPending: false });
        await this.writeSessionMeta(client, {
          source: "extension_browser_bundle_v2",
          importedAt: Date.now(),
          lastValidatedAt: Date.now(),
          refreshedDuringValidation: false,
          refreshCapable: true,
          refreshCookieCount: 1,
          lastRefreshAt: null,
          lastRefreshResult: null,
          lastRefreshCookiesUpdated: false,
        });
        const components = bundleCookieComponents(bundle);
        return Response.json({
          ok: true,
          data: {
            success: true,
            imported: true,
            account,
            bundleVersion: 2,
            uidSuffix: suffix(bundle.uid),
            cookieCount: validated.cookies.length,
            keySaltCount: bundle.keySalts.length,
            matchedKeySaltCount: validated.matchedKeySaltCount,
            addressCount: validated.addressCount,
            components,
            refreshVerified: false,
          },
        });
      } catch (error) {
        return Response.json({
          ok: false,
          error: error instanceof Error ? error.message : String(error),
          protonCode: Number(error?.protonCode) || undefined,
          requestPath: error?.requestPath || undefined,
          requestMethod: error?.requestMethod || undefined,
          sessionAccountMismatch: Boolean(error?.sessionAccountMismatch),
        }, { status: error?.sessionAccountMismatch ? 409 : 400 });
      }
    }
  }
  return originalFetch.call(this, request);
};
