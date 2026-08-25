import {
  createMessage, decrypt, decryptKey, readMessage, readPrivateKey, readSignature, verify,
} from "@protontech/openpgp";
import { ProtonClient as LegacyProtonClient } from "./client.js";
import { computeKeyPassword, getSrp } from "./srp.js";
import { cookieHeaderForUrl, getSetCookieHeaders, mergeSetCookieHeaders, normalizeCookieState } from "./cookies.js";
import { forward, reply, saveDraft, sendMail } from "./write.js";

const PROTON_REFRESH_REDIRECT_URI = "https://protonmail.ch";
const PROACTIVE_REFRESH_MS = 2 * 60 * 1000;
const decoder = new TextDecoder();
const list = (v) => Array.isArray(v) ? v : [];
const bool = (v) => v === true || v === 1;
const b64Equal = (a, b) => {
  const aa = Buffer.from(String(a || ""), "base64");
  const bb = Buffer.from(String(b || ""), "base64");
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i += 1) diff |= aa[i] ^ bb[i];
  return diff === 0;
};
const unb64 = (v) => Uint8Array.from(Buffer.from(String(v || ""), "base64"));

function concatBytes(...parts) {
  const arrays = parts.filter(Boolean).map((x) => x instanceof Uint8Array ? x : new Uint8Array(x));
  const out = new Uint8Array(arrays.reduce((n, x) => n + x.length, 0));
  let offset = 0;
  for (const x of arrays) { out.set(x, offset); offset += x.length; }
  return out;
}
function randomState() {
  const bytes = new Uint8Array(32); crypto.getRandomValues(bytes); return Buffer.from(bytes).toString("base64url");
}
function normalizedAuth(input, previous = {}) {
  const auth = { ...previous, ...input };
  const expiresIn = Number(input?.ExpiresIn ?? input?.expiresIn ?? 0);
  if (expiresIn > 0) auth.ExpiresAt = Date.now() + expiresIn * 1000;
  else if (!auth.ExpiresAt && auth.AccessToken) auth.ExpiresAt = Date.now() + 25 * 60 * 1000;
  return auth;
}
function parseHumanVerification(payload) {
  let details = payload?.Details ?? payload?.details ?? null;
  if (typeof details === "string") { try { details = JSON.parse(details); } catch { details = null; } }
  const methods = details?.HumanVerificationMethods ?? payload?.HumanVerificationMethods;
  const token = details?.HumanVerificationToken ?? payload?.HumanVerificationToken;
  return token && Array.isArray(methods) ? { token: String(token), methods: methods.map(String) } : null;
}
function parseRetryAfterSeconds(value) {
  const raw = String(value || "").trim();
  if (!raw) return null;
  if (/^\d+$/.test(raw)) return Number(raw);
  const at = Date.parse(raw);
  if (!Number.isFinite(at)) return null;
  return Math.max(0, Math.ceil((at - Date.now()) / 1000));
}
function apiError(payload, status, meta = {}) {
  const code = Number(payload?.Code ?? payload?.code ?? status);
  const message = payload?.Error ?? payload?.error ?? payload?.Message ?? payload?.message ?? `HTTP ${status}`;
  const error = new Error(`Proton API ${code}: ${message}`);
  error.status = status;
  error.protonCode = code;
  error.details = payload?.Details ?? payload?.details ?? null;
  error.humanVerification = parseHumanVerification(payload);
  error.fromApi = true;
  if (meta.requestPath) error.requestPath = meta.requestPath;
  if (meta.requestMethod) error.requestMethod = meta.requestMethod;
  if (Number.isFinite(meta.serverRetryAfterSeconds)) error.serverRetryAfterSeconds = meta.serverRetryAfterSeconds;
  return error;
}
function isApiSuccess(payload, status) {
  return status >= 200 && status < 300 && !(payload && typeof payload.Code === "number" && payload.Code !== 1000);
}
async function unlockPrivateKey(armoredKey, passphrase) {
  const key = await readPrivateKey({ armoredKey });
  return key.isDecrypted() ? key : decryptKey({ privateKey: key, passphrase });
}
async function decryptToken(key, userKeys) {
  const message = await readMessage({ armoredMessage: key.Token });
  const decrypted = await decrypt({ message, decryptionKeys: userKeys, format: "binary" });
  const token = decrypted.data instanceof Uint8Array ? decrypted.data : new Uint8Array(decrypted.data);
  if (key.Signature) {
    const signature = await readSignature({ armoredSignature: key.Signature });
    const checked = await verify({
      message: await createMessage({ binary: token }), signature,
      verificationKeys: userKeys.map((k) => k.toPublic()),
    });
    if (!checked.signatures?.length) throw new Error("Proton address key token 缺少签名");
    await checked.signatures[0].verified;
  }
  return decoder.decode(token);
}

export class ProtonClient extends LegacyProtonClient {
  constructor(cfg, env) {
    super(cfg, env);
    this.humanVerification = null;
    this.cookieState = [];
    this.cookiePersistence = null;
    this.authStageCallback = null;
    const configuredFlow = String(env.PROTON_AUTH_FLOW || "core").trim().toLowerCase();
    this.authFlow = configuredFlow === "legacy" ? "legacy" : "core";
  }

  authPaths() {
    if (this.authFlow === "legacy") {
      return {
        info: "/auth/v4/info",
        submit: "/auth/v4",
        twoFactor: "/auth/v4/2fa",
      };
    }
    return {
      info: "/core/v4/auth/info",
      submit: "/core/v4/auth",
      twoFactor: "/core/v4/auth/2fa",
    };
  }

  setAuth(auth) { this.auth = auth ? normalizedAuth(auth) : null; }
  setHumanVerification(v) {
    this.humanVerification = v?.token ? { token: String(v.token), type: String(v.type || "captcha") } : null;
  }
  setCookieState(state) { this.cookieState = normalizeCookieState(state); }
  getCookieState() {
    this.cookieState = normalizeCookieState(this.cookieState);
    return this.cookieState.map((cookie) => ({ ...cookie }));
  }
  setCookiePersistence(fn) { this.cookiePersistence = typeof fn === "function" ? fn : null; }
  setAuthStageCallback(fn) { this.authStageCallback = typeof fn === "function" ? fn : null; }
  async noteAuthStage(stage) {
    if (this.authStageCallback) await this.authStageCallback(stage);
  }
  baseHeaders() {
    const headers = super.baseHeaders();
    if (this.humanVerification?.token) {
      headers["x-pm-human-verification-token"] = this.humanVerification.token;
      headers["x-pm-human-verification-token-type"] = this.humanVerification.type;
    }
    return headers;
  }

  async captureResponseCookies(response, requestUrl) {
    const setCookies = getSetCookieHeaders(response?.headers);
    if (!setCookies.length) return;
    const next = mergeSetCookieHeaders(this.cookieState, setCookies, requestUrl);
    if (JSON.stringify(next) === JSON.stringify(this.cookieState)) return;
    this.cookieState = next;
    if (this.cookiePersistence) await this.cookiePersistence(this.getCookieState());
  }

  async raw(path, { method = "GET", body, auth = false, headers = {}, responseType = "json" } = {}) {
    const isForm = typeof FormData !== "undefined" && body instanceof FormData;
    const requestUrl = `${this.baseUrl}${path}`;
    const requestHeaders = { ...(auth ? this.authHeaders() : this.baseHeaders()), ...headers };
    if (isForm) { delete requestHeaders["content-type"]; delete requestHeaders["Content-Type"]; }
    const cookie = cookieHeaderForUrl(this.cookieState, requestUrl);
    if (cookie && requestHeaders.cookie === undefined && requestHeaders.Cookie === undefined) requestHeaders.cookie = cookie;
    const response = await fetch(requestUrl, {
      method, headers: requestHeaders,
      body: body === undefined ? undefined : (isForm || typeof body === "string" || body instanceof Uint8Array ? body : JSON.stringify(body)),
    });
    await this.captureResponseCookies(response, requestUrl);
    const contentType = String(response.headers.get("content-type") || "").toLowerCase();
    if (responseType === "binary" && response.ok && !contentType.includes("json")) return new Uint8Array(await response.arrayBuffer());
    let payload;
    try { payload = contentType.includes("json") ? await response.json() : JSON.parse(await response.text()); }
    catch {
      const error = new Error(`Proton API 返回不可解析响应（HTTP ${response.status}）`);
      error.status = response.status;
      error.requestPath = path;
      error.requestMethod = method;
      throw error;
    }
    if (!isApiSuccess(payload, response.status)) {
      throw apiError(payload, response.status, {
        requestPath: path,
        requestMethod: method,
        serverRetryAfterSeconds: parseRetryAfterSeconds(response.headers.get("retry-after")),
      });
    }
    return payload;
  }

  reset() { this.clearSession(); this.humanVerification = null; }

  async login({ twoFactorCode } = {}) {
    const username = this.cfg.email;
    const paths = this.authPaths();
    await this.noteAuthStage("auth_info_request");
    const info = await this.raw(paths.info, {
      method: "POST",
      body: this.authFlow === "core" ? { Username: username, Intent: "Proton" } : { Username: username },
    });
    await this.noteAuthStage("srp_compute");
    const proof = await getSrp(info, { username, password: this.cfg.credential });
    await this.noteAuthStage("auth_submit");
    const auth = await this.raw(paths.submit, {
      method: "POST",
      body: {
        Username: username,
        ClientProof: proof.clientProof,
        ClientEphemeral: proof.clientEphemeral,
        SRPSession: info.SRPSession,
        ...(this.authFlow === "core" ? { PersistentCookies: 0 } : {}),
      },
    });
    await this.noteAuthStage("server_proof_verify");
    if (!b64Equal(auth.ServerProof, proof.expectedServerProof)) throw new Error("Proton SRP server proof校验失败");
    if (!auth.UID || !auth.AccessToken || !auth.RefreshToken) throw new Error("Proton 登录成功但缺少 UID/AccessToken/RefreshToken");
    this.auth = normalizedAuth(auth);
    const twoFA = Number(auth?.["2FA"]?.Enabled ?? auth?.TwoFA?.Enabled ?? 0);
    if (twoFA !== 0 && !twoFactorCode) {
      const error = new Error("Proton 需要 2FA；请通过 mail_proton_auth 提交一次性 TOTP 验证码");
      error.twoFactorRequired = true;
      throw error;
    }
    if (twoFA !== 0) await this.submitTwoFactor(twoFactorCode);
    return this.auth;
  }

  async submitTwoFactor(code) {
    if (!this.auth?.AccessToken) throw new Error("没有待完成 2FA 的 Proton 登录会话");
    if (!/^\d{6,8}$/.test(String(code || "").trim())) throw new Error("TOTP 验证码格式无效");
    const payload = await this.raw(this.authPaths().twoFactor, {
      method: "POST",
      auth: true,
      body: { TwoFactorCode: String(code).trim() },
    });
    if (payload?.Scope) this.auth.Scope = payload.Scope;
    this.auth.TwoFactorComplete = true;
    return this.auth;
  }

  async ensureAuthenticated({ allowPasswordLogin = true } = {}) {
    if (this.auth?.AccessToken) {
      const expiresAt = Number(this.auth.ExpiresAt || 0);
      if (!expiresAt || expiresAt - Date.now() > PROACTIVE_REFRESH_MS) return this.auth;
      if (this.auth.RefreshToken) return this.refreshAuthenticated();
    }
    if (!allowPasswordLogin) {
      const error = new Error("Proton 没有可恢复的有效 session，需要人工重新授权");
      error.reauthRequired = true; throw error;
    }
    if (!this.loginPromise) this.loginPromise = this.login().finally(() => { this.loginPromise = null; });
    return this.loginPromise;
  }

  async refreshAuthenticated() {
    if (!this.auth?.UID || !this.auth?.RefreshToken) {
      const error = new Error("Proton Session 缺少 UID/RefreshToken，需要重新授权"); error.reauthRequired = true; throw error;
    }
    if (!this.refreshPromise) {
      const previous = { ...this.auth };
      this.refreshPromise = (async () => {
        try {
          const refreshed = await this.raw("/auth/v4/refresh", {
            method: "POST",
            body: {
              UID: previous.UID, RefreshToken: previous.RefreshToken,
              ResponseType: "token", GrantType: "refresh_token",
              RedirectURI: PROTON_REFRESH_REDIRECT_URI, State: randomState(), AccessToken: previous.AccessToken || undefined,
            },
          });
          if (!refreshed.AccessToken) throw new Error("Proton refresh 成功响应缺少 AccessToken");
          this.auth = normalizedAuth({ ...previous, ...refreshed, UID: refreshed.UID || previous.UID, RefreshToken: refreshed.RefreshToken || previous.RefreshToken }, previous);
          return this.auth;
        } catch (error) {
          if ([400, 401, 422].includes(Number(error?.status))) { this.clearSession(); error.reauthRequired = true; }
          throw error;
        }
      })().finally(() => { this.refreshPromise = null; });
    }
    return this.refreshPromise;
  }

  async ensureKeys() {
    await this.ensureAuthenticated();
    if (this.userKeys.length && this.addressKeys.size) return;
    const [userPayload, saltsPayload, addressesPayload] = await Promise.all([
      this.request("/core/v4/users"), this.request("/core/v4/keys/salts"), this.request("/core/v4/addresses"),
    ]);
    this.user = userPayload.User;
    this.addresses = list(addressesPayload.Addresses);
    const userApiKeys = list(this.user?.Keys).filter((x) => bool(x.Active));
    const primary = userApiKeys.find((x) => bool(x.Primary)) || userApiKeys[0];
    const salt = list(saltsPayload.KeySalts).find((x) => String(x.ID) === String(primary?.ID));
    if (!primary?.PrivateKey || !salt?.KeySalt) throw new Error("Proton 用户主密钥或 KeySalt 不存在");
    const mailboxPassword = Number(this.auth?.PasswordMode || 1) === 2 ? this.cfg.mailboxPassword : this.cfg.credential;
    if (!mailboxPassword) { const error = new Error("该 Proton 账号使用双密码模式，需要配置 MAIL_<ACCOUNT>_MAILBOX_PASSWORD"); error.mailboxPasswordRequired = true; throw error; }
    const keyPass = await computeKeyPassword(mailboxPassword, salt.KeySalt);
    const userKeys = [];
    for (const key of userApiKeys) {
      try { userKeys.push(await unlockPrivateKey(key.PrivateKey, keyPass)); } catch (error) { console.warn(`Proton user key ${key.ID} unlock failed:`, error?.message || String(error)); }
    }
    if (!userKeys.length) throw new Error("无法解锁 Proton 用户密钥");
    this.userKeys = userKeys;
    const addressKeys = new Map();
    for (const addr of this.addresses) {
      const unlocked = [];
      for (const key of list(addr.Keys).filter((x) => bool(x.Active))) {
        try {
          const passphrase = key.Token && key.Signature ? await decryptToken(key, userKeys) : keyPass;
          unlocked.push(await unlockPrivateKey(key.PrivateKey, passphrase));
        } catch (error) { console.warn(`Proton address key ${key.ID} unlock failed:`, error?.message || String(error)); }
      }
      if (unlocked.length) addressKeys.set(String(addr.ID), unlocked);
    }
    if (!addressKeys.size) throw new Error("无法解锁任何 Proton 地址密钥");
    this.addressKeys = addressKeys;
  }

  async getAttachment(messageId, attachmentIndex, maxBytes = 5 * 1024 * 1024) {
    await this.ensureKeys();
    const payload = await this.request(`/mail/v4/messages/${encodeURIComponent(messageId)}`);
    const message = payload.Message;
    const attachment = list(message?.Attachments)[Number(attachmentIndex)];
    if (!attachment?.ID) throw new Error("Proton 附件不存在");
    if (Number(attachment.Size || 0) > maxBytes) throw new Error("附件超过 5MB");
    const encrypted = await this.request(`/mail/v4/attachments/${encodeURIComponent(attachment.ID)}`, { responseType: "binary" });
    const preferred = this.addressKeys.get(String(message.AddressID)) || [];
    const keys = preferred.length ? preferred : [...this.addressKeys.values()].flat();
    let plain = encrypted;
    if (attachment.KeyPackets) {
      const pgp = await readMessage({ binaryMessage: concatBytes(unb64(attachment.KeyPackets), encrypted) });
      const dec = await decrypt({ message: pgp, decryptionKeys: keys, format: "binary" });
      plain = dec.data instanceof Uint8Array ? dec.data : new Uint8Array(dec.data);
    }
    if (plain.length > maxBytes) throw new Error("解密后的附件超过 5MB");
    return {
      protonAttachmentId: attachment.ID, filename: attachment.Name || null,
      contentType: attachment.MIMEType || null, size: plain.length,
      cid: attachment.Headers?.["Content-ID"] || attachment.Headers?.["Content-Id"] || null,
      disposition: attachment.Disposition || null, base64: Buffer.from(plain).toString("base64"),
    };
  }

  async getLatestEventId() {
    const payload = await this.request("/core/v4/events/latest");
    return String(payload.EventID || payload.Event?.EventID || "");
  }
  async getEventsSince(eventId, maxEvents = 50) {
    let cursor = String(eventId || "") || await this.getLatestEventId();
    const events = []; let more = false;
    for (let i = 0; i < Math.min(Math.max(Number(maxEvents) || 50, 1), 50); i += 1) {
      const payload = await this.request(`/core/v4/events/${encodeURIComponent(cursor)}`);
      const event = payload.Event || payload;
      if (event?.EventID) { events.push(event); cursor = String(event.EventID); }
      more = bool(payload.More); if (!more) break;
    }
    return { events, eventId: cursor, more };
  }

  async setMessageState(messageId, action) {
    const path = { mark_read: "/mail/v4/messages/read", mark_unread: "/mail/v4/messages/unread" }[action];
    if (path) await this.request(path, { method: "PUT", body: { IDs: [messageId] } });
    else if (action === "star") await this.request("/mail/v4/messages/label", { method: "PUT", body: { IDs: [messageId], LabelID: "10" } });
    else if (action === "unstar") await this.request("/mail/v4/messages/unlabel", { method: "PUT", body: { IDs: [messageId], LabelID: "10" } });
    else throw new Error(`不支持的 Proton 状态操作：${action}`);
    return { success: true, messageId, action };
  }
  async transferMessage(messageId, sourceFolder, targetFolder, action) {
    const labels = { INBOX: "0", ARCHIVE: "6", SENT: "7", DRAFTS: "8", STARRED: "10", "ALL MAIL": "5", TRASH: "3", SPAM: "4" };
    const label = (folder) => /^\d+$/.test(String(folder || "")) ? String(folder) : labels[String(folder || "INBOX").toUpperCase()] ?? "0";
    const target = label(targetFolder);
    if (["3", "4"].includes(target)) throw new Error("删除/垃圾邮件目标已禁用");
    await this.request("/mail/v4/messages/label", { method: "PUT", body: { IDs: [messageId], LabelID: target } });
    if (action === "move") {
      const source = label(sourceFolder);
      if (source !== target && !["5", "10"].includes(source)) await this.request("/mail/v4/messages/unlabel", { method: "PUT", body: { IDs: [messageId], LabelID: source } });
    }
    return { success: true, messageId, action, sourceFolder, targetFolder };
  }

  sendMail(params) { return sendMail(this, params); }
  saveDraft(params) { return saveDraft(this, params); }
  reply(messageId, params) { return reply(this, messageId, params); }
  forward(messageId, params) { return forward(this, messageId, params); }
}
