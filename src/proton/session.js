import { getAccount } from "../mail-config.js";
import { ProtonClient } from "./client-v2.js";
import { decryptJson, encryptJson, hasSessionEncryption } from "./session-crypto.js";
import { suffix, validateImportedSession } from "./session-import.js";

const SESSION_KEY = "proton:session:v2";
const SESSION_META_KEY = "proton:sessionMeta:v1";
const COOKIE_KEY = "proton:cookies:v1";
const EVENT_CURSOR_KEY = "proton:eventCursor:v1";
const RISK_KEY = "proton:risk:v2";
const AUTH_STATE_KEY = "proton:authState:v1";
const HUMAN_VERIFY_KEY = "proton:humanVerification:v1";

const SIX_HOURS = 6 * 60 * 60 * 1000;
const ONE_DAY = 24 * 60 * 60 * 1000;

function now() { return Date.now(); }

function riskDelayMs(attempt) {
  if (attempt <= 1) return SIX_HOURS;
  if (attempt === 2) return ONE_DAY;
  return 0;
}

function riskBlockError(risk) {
  const blockedUntil = Number(risk?.blockedUntil || 0);
  const manual = Boolean(risk?.manualResetRequired);
  const localCooldownSeconds = manual || !blockedUntil
    ? undefined
    : Math.max(1, Math.ceil((blockedUntil - now()) / 1000));
  const error = new Error(manual
    ? "Proton 2028 后本地密码登录保护已进入人工恢复状态；不会继续密码 reauthorize。该状态不影响已导入 Session 的正常使用，也不代表 Proton 服务器给出的等待时间"
    : `Proton 2028 后本地密码登录保护中：不会自动重试密码 reauthorize；本地剩余保护时间约 ${localCooldownSeconds} 秒（不是 Proton 服务器 Retry-After）`);
  error.protonCode = 2028;
  error.localCooldownSeconds = localCooldownSeconds;
  error.localPolicy = true;
  error.circuitOpen = true;
  error.manualResetRequired = manual;
  return error;
}

function twoFactorError() {
  const error = new Error("Proton 登录需要 2FA TOTP，请调用 mail_proton_auth action=submit_2fa 并提供当前验证码");
  error.twoFactorRequired = true;
  return error;
}

function verificationUrl(env, account, state) {
  const base = String(env.PROTON_VERIFY_BASE_URL || "").replace(/\/$/, "");
  if (!base || !state) return null;
  return `${base}/proton/verify/${encodeURIComponent(account)}/${encodeURIComponent(state)}`;
}

function publicError(error, env, account, verifyState) {
  return {
    error: error instanceof Error ? error.message : String(error),
    ...(Number(error?.protonCode) ? { protonCode: Number(error.protonCode) } : {}),
    ...(Number.isFinite(error?.serverRetryAfterSeconds) ? { serverRetryAfterSeconds: Number(error.serverRetryAfterSeconds) } : {}),
    ...(Number.isFinite(error?.localCooldownSeconds) ? { localCooldownSeconds: Number(error.localCooldownSeconds) } : {}),
    ...(error?.localPolicy ? { localPolicy: true } : {}),
    ...(error?.requestPath ? { requestPath: String(error.requestPath) } : {}),
    ...(error?.requestMethod ? { requestMethod: String(error.requestMethod) } : {}),
    ...(error?.circuitOpen ? { circuitOpen: true } : {}),
    ...(error?.manualResetRequired ? { manualResetRequired: true } : {}),
    ...(error?.twoFactorRequired ? { twoFactorRequired: true } : {}),
    ...(error?.reauthRequired ? { reauthRequired: true } : {}),
    ...(error?.mailboxPasswordRequired ? { mailboxPasswordRequired: true } : {}),
    ...(error?.sessionAccountMismatch ? { sessionAccountMismatch: true } : {}),
    ...(error?.humanVerification ? {
      humanVerificationRequired: true,
      humanVerificationMethods: error.humanVerification.methods || [],
      verificationUrl: verificationUrl(env, account, verifyState),
      verificationState: verifyState || null,
    } : {}),
  };
}

function compactAuthError(error) {
  return {
    message: error instanceof Error ? error.message : String(error),
    ...(Number(error?.protonCode) ? { protonCode: Number(error.protonCode) } : {}),
    ...(Number(error?.status) ? { httpStatus: Number(error.status) } : {}),
    ...(Number.isFinite(error?.serverRetryAfterSeconds) ? { serverRetryAfterSeconds: Number(error.serverRetryAfterSeconds) } : {}),
    ...(Number.isFinite(error?.localCooldownSeconds) ? { localCooldownSeconds: Number(error.localCooldownSeconds) } : {}),
    ...(error?.localPolicy ? { localPolicy: true } : {}),
    ...(error?.requestPath ? { requestPath: String(error.requestPath) } : {}),
    ...(error?.requestMethod ? { requestMethod: String(error.requestMethod) } : {}),
    ...(error?.twoFactorRequired ? { twoFactorRequired: true } : {}),
    ...(error?.humanVerification ? { humanVerificationRequired: true, methods: error.humanVerification.methods || [] } : {}),
  };
}

export class ProtonSession {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.client = null;
    this.accountId = null;
    this.hydrated = false;
  }

  getClient(accountId) {
    const cfg = getAccount(this.env, accountId);
    if (cfg.provider !== "proton") throw new Error(`账号 ${cfg.id} 不是 Proton Provider`);
    if (!this.client || this.accountId?.toLowerCase() !== cfg.id.toLowerCase()) {
      this.client = new ProtonClient(cfg, this.env);
      this.accountId = cfg.id;
      this.hydrated = false;
    }
    return this.client;
  }

  async readEncrypted(key, account) {
    const envelope = await this.state.storage.get(key);
    if (!envelope) return null;
    return decryptJson(envelope, this.env.PROTON_SESSION_KEY, `${account}:${key}`);
  }

  async writeEncrypted(key, account, value) {
    if (!hasSessionEncryption(this.env)) return false;
    const envelope = await encryptJson(value, this.env.PROTON_SESSION_KEY, `${account}:${key}`);
    await this.state.storage.put(key, envelope);
    return true;
  }

  async hydrate(client) {
    if (this.hydrated) return;
    this.hydrated = true;
    const account = client.cfg.id;
    client.setCookiePersistence(async (cookieState) => {
      await this.writeEncrypted(COOKIE_KEY, account, cookieState);
    });
    const cookies = await this.readEncrypted(COOKIE_KEY, account).catch((error) => {
      console.error("ProtonSession cookie decrypt:", error?.message || String(error));
      return null;
    });
    client.setCookieState(cookies || []);
    const auth = await this.readEncrypted(SESSION_KEY, account).catch((error) => {
      console.error("ProtonSession session decrypt:", error?.message || String(error));
      return null;
    });
    if (auth?.UID && auth?.RefreshToken) client.setAuth(auth);
    const hv = await this.readEncrypted(HUMAN_VERIFY_KEY, account).catch(() => null);
    if (hv?.completedToken && hv?.type) client.setHumanVerification({ token: hv.completedToken, type: hv.type });
  }

  async persistClient(client) {
    const account = client.cfg.id;
    if (client.auth?.UID && client.auth?.RefreshToken) await this.writeEncrypted(SESSION_KEY, account, client.auth);
    await this.writeEncrypted(COOKIE_KEY, account, client.getCookieState());
  }

  async readSessionMeta() {
    return (await this.state.storage.get(SESSION_META_KEY)) || null;
  }

  async writeSessionMeta(client, patch = {}) {
    const previous = (await this.readSessionMeta()) || {};
    const next = {
      ...previous,
      ...patch,
      uidSuffix: suffix(client.auth?.UID),
      userIdSuffix: suffix(client.auth?.UserID),
      expiresAt: client.auth?.ExpiresAt || null,
      hasAccessToken: Boolean(client.auth?.AccessToken),
      hasRefreshToken: Boolean(client.auth?.RefreshToken),
      updatedAt: now(),
    };
    await this.state.storage.put(SESSION_META_KEY, next);
    return next;
  }

  async clearPersistedSession(client, { clearCookies = true } = {}) {
    await this.state.storage.delete(SESSION_KEY);
    await this.state.storage.delete(SESSION_META_KEY);
    if (clearCookies) {
      await this.state.storage.delete(COOKIE_KEY);
      client.setCookieState([]);
    }
    client.clearSession();
  }

  async readRisk() {
    return (await this.state.storage.get(RISK_KEY)) || null;
  }

  async readAuthState() {
    return (await this.state.storage.get(AUTH_STATE_KEY)) || {};
  }

  async patchAuthState(patch) {
    const previous = await this.readAuthState();
    const next = { ...previous, ...patch };
    await this.state.storage.put(AUTH_STATE_KEY, next);
    return next;
  }

  async updateAuthAttempt(attemptId, patch) {
    const authState = await this.readAuthState();
    const current = authState.lastAuthAttempt || {};
    if (attemptId && current.attemptId && current.attemptId !== attemptId) return authState;
    const lastAuthAttempt = {
      ...current,
      ...(attemptId ? { attemptId } : {}),
      ...patch,
      lastUpdatedAt: now(),
    };
    return this.patchAuthState({ lastAuthAttempt });
  }

  async assertRiskCircuitClosed({ allowManual = false } = {}) {
    if (allowManual) return;
    const risk = await this.readRisk();
    if (!risk) return;
    if (risk.manualResetRequired) throw riskBlockError(risk);
    if (Number(risk.blockedUntil || 0) > now()) throw riskBlockError(risk);
    if (Number(risk.blockedUntil || 0) > 0) await this.state.storage.put(RISK_KEY, { ...risk, blockedUntil: 0, policy: "local" });
  }

  async rememberRiskBlock(error) {
    if (error?.riskRemembered) return this.readRisk();
    if (Number(error?.protonCode) !== 2028 || error?.circuitOpen) return null;
    const previous = await this.readRisk();
    const attempt = Number(previous?.attempt || 0) + 1;
    const delay = riskDelayMs(attempt);
    const risk = {
      attempt,
      lastAt: now(),
      blockedUntil: delay ? now() + delay : 0,
      manualResetRequired: delay === 0,
      policy: "local",
    };
    await this.state.storage.put(RISK_KEY, risk);
    error.localCooldownSeconds = delay ? Math.ceil(delay / 1000) : undefined;
    error.localPolicy = true;
    error.manualResetRequired = risk.manualResetRequired;
    error.riskRemembered = true;
    return risk;
  }

  async rememberHumanVerification(error, client) {
    if (!error?.humanVerification?.token) return null;
    const state = crypto.randomUUID();
    const record = {
      state,
      challengeToken: error.humanVerification.token,
      methods: error.humanVerification.methods || [],
      createdAt: now(),
      type: "captcha",
    };
    await this.writeEncrypted(HUMAN_VERIFY_KEY, client.cfg.id, record);
    return state;
  }

  async authStatus(client) {
    const risk = await this.readRisk();
    const authState = await this.readAuthState();
    const meta = await this.readSessionMeta();
    const hv = await this.readEncrypted(HUMAN_VERIFY_KEY, client.cfg.id).catch(() => null);
    const hasSession = Boolean(client.auth?.UID && client.auth?.RefreshToken);
    return {
      account: client.cfg.id,
      provider: "proton",
      sessionPersistenceConfigured: hasSessionEncryption(this.env),
      hasSession,
      expiresAt: client.auth?.ExpiresAt || null,
      session: hasSession ? {
        source: meta?.source || "existing",
        importedAt: meta?.importedAt || null,
        authenticatedAt: meta?.authenticatedAt || null,
        lastValidatedAt: meta?.lastValidatedAt || null,
        refreshedDuringValidation: Boolean(meta?.refreshedDuringValidation),
        uidSuffix: suffix(client.auth?.UID),
        userIdSuffix: suffix(client.auth?.UserID),
        hasAccessToken: Boolean(client.auth?.AccessToken),
        hasRefreshToken: Boolean(client.auth?.RefreshToken),
      } : null,
      twoFactorPending: Boolean(authState.twoFactorPending),
      reauthRequired: Boolean(authState.reauthRequired),
      lastAuthAttempt: authState.lastAuthAttempt || null,
      transport: { cookieCount: client.getCookieState().length },
      risk: risk ? { ...risk, policy: "local", scope: "password_reauthorize_only" } : null,
      humanVerification: hv ? {
        pending: Boolean(hv.challengeToken && !hv.completedToken),
        methods: hv.methods || [],
        verificationUrl: verificationUrl(this.env, client.cfg.id, hv.state),
        createdAt: hv.createdAt || null,
      } : null,
    };
  }

  async initializeOrRestore(client, { allowPasswordLogin = true } = {}) {
    await this.hydrate(client);
    if (client.auth?.UID && client.auth?.RefreshToken) {
      await client.ensureAuthenticated({ allowPasswordLogin: false });
      await this.persistClient(client);
      return client.auth;
    }
    if (!allowPasswordLogin) {
      const error = new Error("Proton 没有可恢复的持久 session，需要人工重新授权或从 /proton/import 导入 Session");
      error.reauthRequired = true;
      throw error;
    }
    try {
      await client.ensureAuthenticated({ allowPasswordLogin: true });
      await this.persistClient(client);
      await this.patchAuthState({ reauthRequired: false, twoFactorPending: false });
      return client.auth;
    } catch (error) {
      if (error?.twoFactorRequired && client.auth?.UID) {
        await this.persistClient(client);
        await this.patchAuthState({ reauthRequired: false, twoFactorPending: true });
      }
      throw error;
    }
  }

  async runClientAction(client, fn, { allowPasswordLogin = false } = {}) {
    await this.hydrate(client);
    try {
      await this.initializeOrRestore(client, { allowPasswordLogin });
      const data = await fn(client);
      await this.persistClient(client);
      return data;
    } catch (error) {
      await this.persistClient(client).catch(() => {});
      if (error?.reauthRequired) {
        await this.clearPersistedSession(client);
        await this.patchAuthState({ reauthRequired: true, twoFactorPending: false });
      }
      throw error;
    }
  }

  async pollEvents(client) {
    return this.runClientAction(client, async (c) => {
      let cursor = String((await this.state.storage.get(EVENT_CURSOR_KEY)) || "");
      if (!cursor) {
        cursor = await c.getLatestEventId();
        await this.state.storage.put(EVENT_CURSOR_KEY, cursor);
        return { initialized: true, eventId: cursor, events: [], more: false };
      }
      const { events, more } = await c.getEventsSince(cursor);
      if (events.length) {
        const last = events[events.length - 1]?.EventID || events[events.length - 1]?.ID;
        if (last) {
          cursor = String(last);
          await this.state.storage.put(EVENT_CURSOR_KEY, cursor);
        }
      }
      return { initialized: false, eventId: cursor, events, more };
    });
  }

  async fetch(request) {
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
    let client;
    let account = "";
    let action = "";
    let verifyState = null;
    try {
      const body = await request.json();
      account = String(body?.account || "").trim();
      action = String(body?.action || "").trim();
      const payload = body?.payload || {};
      if (!account) throw new Error("缺少 Proton account");
      client = this.getClient(account);
      await this.hydrate(client);

      let data;
      if (action === "authStatus") {
        data = await this.authStatus(client);
      } else if (action === "resetRisk") {
        await this.state.storage.delete(RISK_KEY);
        data = { success: true, account, riskReset: true };
      } else if (action === "importSession") {
        if (!hasSessionEncryption(this.env)) throw new Error("未配置 PROTON_SESSION_KEY，禁止导入 Session");
        const validated = await validateImportedSession(client.cfg, this.env, payload.session);
        client.setAuth(validated.auth);
        if (validated.cookies?.length) client.setCookieState(validated.cookies);
        await this.persistClient(client);
        await this.state.storage.delete(HUMAN_VERIFY_KEY);
        await this.patchAuthState({ reauthRequired: false, twoFactorPending: false });
        await this.writeSessionMeta(client, {
          source: "manual_import",
          importedAt: now(),
          lastValidatedAt: now(),
          refreshedDuringValidation: Boolean(validated.safe.refreshedDuringValidation),
        });
        data = { success: true, imported: true, ...validated.safe };
      } else if (action === "validateSession") {
        if (!client.auth?.UID || !client.auth?.RefreshToken) throw new Error("当前账号没有可校验的持久 Session");
        const validated = await validateImportedSession(client.cfg, this.env, client.auth);
        client.setAuth(validated.auth);
        if (validated.cookies?.length) client.setCookieState(validated.cookies);
        await this.persistClient(client);
        await this.writeSessionMeta(client, {
          lastValidatedAt: now(),
          refreshedDuringValidation: Boolean(validated.safe.refreshedDuringValidation),
        });
        data = { success: true, validated: true, ...validated.safe };
      } else if (action === "clearSession") {
        await this.clearPersistedSession(client);
        await this.state.storage.delete(HUMAN_VERIFY_KEY);
        await this.patchAuthState({ reauthRequired: false, twoFactorPending: false });
        data = { success: true, account, sessionCleared: true };
      } else if (action === "reauthorize") {
        await this.assertRiskCircuitClosed();
        const attemptId = crypto.randomUUID();
        const startedAt = now();
        await this.state.storage.delete(SESSION_KEY);
        await this.state.storage.delete(SESSION_META_KEY);
        client.clearSession();
        await this.patchAuthState({
          reauthRequired: false,
          twoFactorPending: false,
          lastAuthAttempt: {
            attemptId,
            status: "running",
            stage: "starting",
            startedAt,
            lastUpdatedAt: startedAt,
          },
        });
        client.setAuthStageCallback(async (stage) => {
          await this.updateAuthAttempt(attemptId, { status: "running", stage });
        });
        try {
          await this.initializeOrRestore(client, { allowPasswordLogin: true });
          await this.state.storage.delete(RISK_KEY);
          await this.writeSessionMeta(client, { source: "password", authenticatedAt: now() });
          await this.updateAuthAttempt(attemptId, {
            status: "succeeded",
            stage: "authenticated",
            completedAt: now(),
            error: null,
          });
          data = { success: true, account, authenticated: true, twoFactorRequired: false, attemptId };
        } catch (error) {
          if (error?.twoFactorRequired) {
            await this.updateAuthAttempt(attemptId, {
              status: "waiting_2fa",
              stage: "two_factor",
              error: compactAuthError(error),
            });
            data = { success: false, account, authenticated: false, twoFactorRequired: true, attemptId };
          } else {
            await this.rememberRiskBlock(error).catch(() => {});
            const attemptStatus = Number(error?.protonCode) === 2028
              ? "blocked_2028"
              : error?.humanVerification
                ? "human_verification_required"
                : "failed";
            const current = await this.readAuthState();
            const currentStage = current.lastAuthAttempt?.attemptId === attemptId
              ? current.lastAuthAttempt?.stage || "unknown"
              : "unknown";
            await this.updateAuthAttempt(attemptId, {
              status: attemptStatus,
              stage: currentStage,
              completedAt: now(),
              error: compactAuthError(error),
            }).catch(() => {});
            throw error;
          }
        } finally {
          client.setAuthStageCallback(null);
        }
      } else if (action === "submit2fa") {
        const code = String(payload.code || "").trim();
        if (!code) throw new Error("缺少 2FA TOTP code");
        await this.assertRiskCircuitClosed({ allowManual: true });
        await this.hydrate(client);
        if (!client.auth?.UID) throw twoFactorError();
        data = await client.submitTwoFactor(code);
        await this.persistClient(client);
        await this.writeSessionMeta(client, { source: "password", authenticatedAt: now() });
        const authState = await this.patchAuthState({ reauthRequired: false, twoFactorPending: false });
        await this.updateAuthAttempt(authState.lastAuthAttempt?.attemptId, {
          status: "succeeded",
          stage: "authenticated",
          completedAt: now(),
          error: null,
        });
      } else if (action === "getHumanVerificationChallenge") {
        const state = String(payload.state || "");
        const hv = await this.readEncrypted(HUMAN_VERIFY_KEY, account);
        if (!hv || !state || hv.state !== state || !hv.challengeToken) throw new Error("Proton 验证会话不存在或已失效");
        if (now() - Number(hv.createdAt || 0) > 30 * 60 * 1000) throw new Error("Proton 验证会话已超过 30 分钟，请重新发起授权");
        data = { methods: hv.methods || [], challengeToken: hv.challengeToken, state: hv.state, type: hv.type || "captcha" };
      } else if (action === "completeHumanVerification") {
        const state = String(payload.state || "");
        const token = String(payload.token || "").trim();
        const hv = await this.readEncrypted(HUMAN_VERIFY_KEY, account);
        if (!hv || !state || hv.state !== state) throw new Error("Proton 验证会话不存在或已失效");
        if (!token) throw new Error("Human Verification token 为空");
        const completed = { ...hv, completedToken: token, completedAt: now(), type: hv.type || "captcha" };
        await this.writeEncrypted(HUMAN_VERIFY_KEY, account, completed);
        client.setHumanVerification({ token, type: completed.type });
        const authState = await this.readAuthState();
        await this.updateAuthAttempt(authState.lastAuthAttempt?.attemptId, {
          status: "verification_completed",
          stage: "awaiting_reauthorize",
          error: null,
        });
        data = { success: true, account, completed: true };
      } else if (action === "pollEvents") {
        data = await this.pollEvents(client);
      } else {
        data = await this.runClientAction(client, async (c) => {
          if (action === "test") return c.testConnection();
          if (action === "listMessages") return c.listMessages(payload);
          if (action === "searchMessages") return c.searchMessages(payload);
          if (action === "getMessage") return c.getMessage(payload.messageId, payload.folder);
          if (action === "getAttachment") return c.getAttachment(payload.messageId, payload.attachmentIndex);
          if (action === "listFolders") return c.listFolders();
          if (action === "folderStatus") return c.folderStatus(payload.folder);
          if (action === "setState") return c.setMessageState(payload.messageId, payload.action);
          if (action === "transfer") return c.transferMessage(payload.messageId, payload.sourceFolder, payload.targetFolder, payload.action);
          if (action === "send") return c.sendMail(payload);
          if (action === "reply") return c.reply(payload.messageId, payload);
          if (action === "forward") return c.forward(payload.messageId, payload);
          if (action === "saveDraft") return c.saveDraft(payload);
          throw new Error(`未知 Proton action：${action}`);
        });
      }

      return Response.json({ ok: true, data });
    } catch (error) {
      if (client) {
        if (action === "reauthorize") await this.rememberRiskBlock(error).catch(() => {});
        verifyState = await this.rememberHumanVerification(error, client).catch(() => null);
      }
      console.error("ProtonSession:", error?.message || String(error));
      const details = publicError(error, this.env, account, verifyState);
      const status = Number(error?.protonCode) === 2028 ? 429 : 400;
      return Response.json({ ok: false, ...details }, { status });
    }
  }
}
