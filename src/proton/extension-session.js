import "./key-material-session.js";
import { ProtonClient } from "./client-v2.js";
import { ProtonSession } from "./session.js";
import { normalizeExtensionBundle } from "./extension-policy.js";

const PAIR_KEY = "proton:extensionPair:v2";
const EVENT_CURSOR_KEY = "proton:eventCursor:v1";
const HUMAN_VERIFY_KEY = "proton:humanVerification:v1";
const COOKIE_SESSION_MARKER = "__BROWSER_COOKIE_SESSION__";
const PAIR_TTL_MS = 5 * 60 * 1000;

const text = (value) => value === undefined || value === null ? "" : String(value).trim();

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64url");
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(String(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Buffer.from(new Uint8Array(digest)).toString("hex");
}

function addressEmails(payload) {
  return (Array.isArray(payload?.Addresses) ? payload.Addresses : [])
    .map((item) => text(item?.Email ?? item?.email).toLowerCase())
    .filter(Boolean);
}

function activeUserKeyIds(payload) {
  return (Array.isArray(payload?.User?.Keys) ? payload.User.Keys : [])
    .filter((item) => item?.Active === true || item?.Active === 1)
    .map((item) => text(item?.ID))
    .filter(Boolean);
}

async function validateExtensionCandidate(cfg, env, bundle) {
  const candidate = new ProtonClient(cfg, env);
  candidate.setAuth({
    UID: bundle.uid,
    RefreshToken: COOKIE_SESSION_MARKER,
    cookies: true,
    KeySalts: bundle.keySalts,
    ...(bundle.user.passwordMode ? { PasswordMode: bundle.user.passwordMode } : {}),
  });
  candidate.setCookieState(bundle.cookies);

  const [addressesPayload, userPayload] = await Promise.all([
    candidate.raw("/core/v4/addresses", { auth: true }),
    candidate.raw("/core/v4/users", { auth: true }),
  ]);
  const emails = addressEmails(addressesPayload);
  const expected = text(cfg.email).toLowerCase();
  if (!emails.includes(expected) || !emails.includes(bundle.email)) {
    const error = new Error("扩展 Bundle 与所选 Proton 账号不匹配");
    error.sessionAccountMismatch = true;
    throw error;
  }
  const userId = text(userPayload?.User?.ID);
  if (!userId || userId !== bundle.user.id) {
    const error = new Error("扩展 Bundle 用户 ID 与当前 Session 不匹配");
    error.sessionAccountMismatch = true;
    throw error;
  }
  const activeIds = new Set(activeUserKeyIds(userPayload));
  if (!bundle.keySalts.some((item) => activeIds.has(item.ID))) {
    const error = new Error("扩展 Bundle KeySalt 与当前 Proton 用户主密钥不匹配");
    error.sessionAccountMismatch = true;
    throw error;
  }
  return {
    auth: candidate.auth,
    cookies: candidate.getCookieState(),
    addressCount: emails.length,
    activeKeyCount: activeIds.size,
  };
}

const originalFetch = ProtonSession.prototype.fetch;
ProtonSession.prototype.fetch = async function fetchWithExtensionBundle(request) {
  if (request.method === "POST") {
    const parsed = await request.clone().json().catch(() => null);
    const account = text(parsed?.account);
    const action = text(parsed?.action);
    const payload = parsed?.payload || {};

    if (account && action === "extensionPair") {
      try {
        const client = this.getClient(account);
        await this.hydrate(client);
        const uid = text(payload.uid);
        const email = text(payload.email).toLowerCase();
        const actorId = text(payload.actorId);
        if (!uid || !email || !actorId) throw new Error("扩展配对参数不完整");
        if (email !== text(client.cfg.email).toLowerCase()) {
          const error = new Error("扩展检测邮箱与所选 MCP 账号不匹配");
          error.sessionAccountMismatch = true;
          throw error;
        }
        const token = randomToken();
        const expiresAt = Date.now() + PAIR_TTL_MS;
        await this.writeEncrypted(PAIR_KEY, account, {
          tokenHash: await sha256(token),
          uid,
          email,
          actorId,
          createdAt: Date.now(),
          expiresAt,
        });
        return Response.json({ ok: true, data: { token, expiresAt } });
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
        const client = this.getClient(account);
        await this.hydrate(client);
        const pair = await this.readEncrypted(PAIR_KEY, account);
        if (!pair) throw new Error("扩展配对不存在或已使用，请重新配对");
        const token = text(payload.token);
        const actorId = text(payload.actorId);
        if (!token || !actorId || actorId !== text(pair.actorId)) throw new Error("扩展配对身份不匹配");
        if (Date.now() > Number(pair.expiresAt || 0)) {
          await this.state.storage.delete(PAIR_KEY);
          throw new Error("扩展配对已过期，请重新配对");
        }
        if (await sha256(token) !== text(pair.tokenHash)) throw new Error("扩展配对令牌无效");

        // Consume before validation: any failed import requires a fresh pair.
        await this.state.storage.delete(PAIR_KEY);

        const bundle = normalizeExtensionBundle(payload.bundle);
        if (bundle.uid !== text(pair.uid) || bundle.email !== text(pair.email).toLowerCase()) {
          const error = new Error("扩展 Bundle 与配对摘要不一致");
          error.sessionAccountMismatch = true;
          throw error;
        }

        const validated = await validateExtensionCandidate(client.cfg, this.env, bundle);
        client.setAuth({
          ...validated.auth,
          KeySalts: bundle.keySalts,
          ...(bundle.user.passwordMode ? { PasswordMode: bundle.user.passwordMode } : {}),
        });
        client.setCookieState(validated.cookies);
        await this.persistClient(client);
        await this.state.storage.delete(EVENT_CURSOR_KEY);
        await this.state.storage.delete(HUMAN_VERIFY_KEY);
        await this.patchAuthState({ reauthRequired: false, twoFactorPending: false });
        await this.writeSessionMeta(client, {
          source: "extension_bundle_v2",
          importedAt: Date.now(),
          lastValidatedAt: Date.now(),
          refreshedDuringValidation: false,
          keySaltsImportedAt: Date.now(),
          keySaltCount: bundle.keySalts.length,
          extensionBundleVersion: bundle.version,
          extensionClient: bundle.client || null,
        });

        return Response.json({
          ok: true,
          data: {
            success: true,
            imported: true,
            account,
            importMode: "extension_bundle_v2",
            bundleVersion: bundle.version,
            cookieAuth: true,
            addressCount: validated.addressCount,
            keySaltCount: bundle.keySalts.length,
            activeKeyCount: validated.activeKeyCount,
            refreshTestRequired: true,
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
