import { getAccount } from "../mail-config.js";
import { ProtonClient } from "./client-v2.js";
import { decryptJson, encryptJson, hasSessionEncryption } from "./session-crypto.js";

const SESSION_KEY = "proton:session:v2";
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
  const retryAfterSeconds = manual || !blockedUntil
    ? undefined
    : Math.max(1, Math.ceil((blockedUntil - now()) / 1000));
  const error = new Error(manual
    ? "Proton 2028 风控已进入人工恢复状态；后台任务不会继续密码登录，请先处理 Proton 账号后再执行 proton_auth reset_risk/reauthorize"
    : `Proton 2028 风控熔断中：后台任务不会重试密码登录，请约 ${retryAfterSeconds} 秒后再试`);
  error.protonCode = 2028;
  error.retryAfterSeconds = retryAfterSeconds;
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
    ...(Number(error?.retryAfterSeconds) ? { retryAfterSeconds: Number(error.retryAfterSeconds) } : {}),
    ...(error?.circuitOpen ? { circuitOpen: true } : {}),
    ...(error?.manualResetRequired ? { manualResetRequired: true } : {}),
    ...(error?.twoFactorRequired ? { twoFactorRequired: true } : {}),
    ...(error?.reauthRequired ? { reauthRequired: true } : {}),
    ...(error?.mailboxPasswordRequired ? { mailboxPasswordRequired: true } : {}),
    ...(error?.humanVerification ? {
      humanVerificationRequired: true,
      humanVerificationMethods: error.humanVerification.methods || [],
      verificationUrl: verificationUrl(env, account, verifyState),
      verificationState: verifyState || null,
    } : {}),
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
  }

  async clearPersistedSession(client) {
    await this.state.storage.delete(SESSION_KEY);
    client.clearSession();
  }

  async readRisk() {
    return (await this.state.storage.get(RISK_KEY)) || null;
  }

  async assertRiskCircuitClosed({ allowManual = false } = {}) {
    if (allowManual) return;
    const risk = await this.readRisk();
    if (!risk) return;
    if (risk.manualResetRequired) throw riskBlockError(risk);
    if (Number(risk.blockedUntil || 0) > now()) throw riskBlockError(risk);
    if (Number(risk.blockedUntil || 0) > 0) await this.state.storage.put(RISK_KEY, { ...risk, blockedUntil: 0 });
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
    };
    await this.state.storage.put(RISK_KEY, risk);
    error.retryAfterSeconds = delay ? Math.ceil(delay / 1000) : undefined;
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
    const authState = (await this.state.storage.get(AUTH_STATE_KEY)) || {};
    const hv = await this.readEncrypted(HUMAN_VERIFY_KEY, client.cfg.id).catch(() => null);
    return {
      account: client.cfg.id,
      provider: "proton",
      sessionPersistenceConfigured: hasSessionEncryption(this.env),
      hasSession: Boolean(client.auth?.UID && client.auth?.RefreshToken),
      expiresAt: client.auth?.ExpiresAt || null,
      twoFactorPending: Boolean(authState.twoFactorPending),
      reauthRequired: Boolean(authState.reauthRequired),
      risk: risk || null,
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
      const error = new Error("Proton 没有可恢复的持久 session，需要人工重新授权");
      error.reauthRequired = true;
      throw error;
    }
    try {
      await client.ensureAuthenticated({ allowPasswordLogin: true });
      await this.persistClient(client);
      await this.state.storage.put(AUTH_STATE_KEY, { reauthRequired: false, twoFactorPending: false });
      return client.auth;
    } catch (error) {
      if (error?.twoFactorRequired && client.auth?.UID) {
        await this.persistClient(client);
        await this.state.storage.put(AUTH_STATE_KEY, { reauthRequired: false, twoFactorPending: true });
      }
      throw error;
    }
  }

  async runClientAction(client, fn, { allowPasswordLogin = false, allowRiskBypass = false } = {}) {
    await this.assertRiskCircuitClosed({ allowManual: allowRiskBypass });
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
        await this.state.storage.put(AUTH_STATE_KEY, { reauthRequired: true, twoFactorPending: false });
      }
      await this.rememberRiskBlock(error);
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
    let verifyState = null;
    try {
      const body = await request.json();
      account = String(body?.account || "").trim();
      const action = String(body?.action || "").trim();
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
      } else if (action === "reauthorize") {
        await this.state.storage.delete(SESSION_KEY);
        await this.state.storage.delete(AUTH_STATE_KEY);
        client.clearSession();
        try {
          await this.initializeOrRestore(client, { allowPasswordLogin: true });
          await this.state.storage.delete(RISK_KEY);
          data = { success: true, account, authenticated: true, twoFactorRequired: false };
        } catch (error) {
          if (error?.twoFactorRequired) data = { success: false, account, authenticated: false, twoFactorRequired: true };
          else throw error;
        }
      } else if (action === "submit2fa") {
        const code = String(payload.code || "").trim();
        if (!code) throw new Error("缺少 2FA TOTP code");
        await this.assertRiskCircuitClosed({ allowManual: true });
        await this.hydrate(client);
        if (!client.auth?.UID) throw twoFactorError();
        data = await client.submitTwoFactor(code);
        await this.persistClient(client);
        await this.state.storage.put(AUTH_STATE_KEY, { reauthRequired: false, twoFactorPending: false });
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
        await this.rememberRiskBlock(error).catch(() => {});
        verifyState = await this.rememberHumanVerification(error, client).catch(() => null);
      }
      console.error("ProtonSession:", error?.message || String(error));
      const details = publicError(error, this.env, account, verifyState);
      const status = Number(error?.protonCode) === 2028 ? 429 : 400;
      return Response.json({ ok: false, ...details }, { status });
    }
  }
}
