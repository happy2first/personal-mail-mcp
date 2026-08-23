import {
  createMessage,
  decrypt,
  decryptKey,
  readMessage,
  readPrivateKey,
  readSignature,
  verify,
} from "@protontech/openpgp";
import { computeKeyPassword, getSrp } from "./srp.js";

const DEFAULT_API = "https://mail.proton.me/api";
const DEFAULT_APP_VERSION = "macos-bridge@3.24.1";
const PROTON_REFRESH_REDIRECT_URI = "https://protonmail.ch";
const PROTON_2028_COOLDOWN_MS = 30 * 60 * 1000;
const decoder = new TextDecoder();

const SYSTEM_LABELS = {
  INBOX: "0",
  "ALL DRAFTS": "1",
  "ALL SENT": "2",
  TRASH: "3",
  SPAM: "4",
  "ALL MAIL": "5",
  ARCHIVE: "6",
  SENT: "7",
  DRAFTS: "8",
  OUTBOX: "9",
  STARRED: "10",
  SCHEDULED: "12",
};

function b64Equal(a, b) {
  const aa = Buffer.from(String(a || ""), "base64");
  const bb = Buffer.from(String(b || ""), "base64");
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i += 1) diff |= aa[i] ^ bb[i];
  return diff === 0;
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

function bool(value) {
  return value === true || value === 1;
}

function address(value) {
  if (!value) return null;
  if (typeof value === "string") return { name: "", address: value };
  return {
    name: String(value.Name ?? value.name ?? ""),
    address: String(value.Address ?? value.address ?? value.Email ?? value.email ?? ""),
  };
}

function addresses(values) {
  return list(values).map(address).filter((x) => x?.address);
}

function labelForFolder(folder = "INBOX") {
  const raw = String(folder || "INBOX").trim();
  if (/^\d+$/.test(raw)) return raw;
  return SYSTEM_LABELS[raw.toUpperCase()] ?? "0";
}

function messageFlags(meta) {
  const flags = [];
  if (!bool(meta.Unread)) flags.push("\\Seen");
  if (list(meta.LabelIDs).map(String).includes("10")) flags.push("\\Flagged");
  if (bool(meta.IsReplied) || bool(meta.IsRepliedAll)) flags.push("\\Answered");
  return flags;
}

function metaToMail(meta, cfg, folder = "INBOX") {
  const id = String(meta.ID || "");
  const sender = address(meta.Sender);
  return {
    account: cfg.id,
    accountLabel: cfg.label,
    provider: "proton",
    folder,
    protonId: id,
    subject: String(meta.Subject || ""),
    from: sender ? [sender] : [],
    to: addresses(meta.ToList),
    cc: addresses(meta.CCList),
    date: meta.Time ? new Date(Number(meta.Time) * 1000).toISOString() : null,
    size: Number(meta.Size || 0),
    flags: messageFlags(meta),
    unread: bool(meta.Unread),
    addressId: String(meta.AddressID || ""),
    attachmentCount: Number(meta.NumAttachments || 0),
  };
}

function apiError(payload, status) {
  const code = payload?.Code ?? payload?.code ?? status;
  const message = payload?.Error ?? payload?.error ?? payload?.Message ?? payload?.message ?? `HTTP ${status}`;
  const error = new Error(`Proton API ${code}: ${message}`);
  error.status = status;
  error.protonCode = code;
  error.fromApi = true;
  return error;
}

function isApiSuccess(payload, status) {
  if (!status || status < 200 || status >= 300) return false;
  if (payload && typeof payload.Code === "number" && payload.Code !== 1000) return false;
  return true;
}

function randomState() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64url");
}

function circuitError(blockedUntil) {
  const retryAfterSeconds = Math.max(1, Math.ceil((blockedUntil - Date.now()) / 1000));
  const error = new Error(`Proton 2028 风控熔断中：为避免重复登录，请约 ${retryAfterSeconds} 秒后再试`);
  error.status = 429;
  error.protonCode = 2028;
  error.retryAfterSeconds = retryAfterSeconds;
  error.blockedUntil = blockedUntil;
  error.circuitOpen = true;
  return error;
}

async function unlockPrivateKey(armoredKey, passphrase) {
  const privateKey = await readPrivateKey({ armoredKey });
  if (!privateKey.isDecrypted()) return decryptKey({ privateKey, passphrase });
  return privateKey;
}

async function decryptToken(key, userKeys) {
  const message = await readMessage({ armoredMessage: key.Token });
  const decrypted = await decrypt({ message, decryptionKeys: userKeys, format: "binary" });
  const token = decrypted.data instanceof Uint8Array ? decrypted.data : new Uint8Array(decrypted.data);
  if (key.Signature) {
    const signature = await readSignature({ armoredSignature: key.Signature });
    const tokenMessage = await createMessage({ binary: token });
    const checked = await verify({ message: tokenMessage, signature, verificationKeys: userKeys });
    if (!checked.signatures?.length) throw new Error("Proton address key token 缺少签名");
    await checked.signatures[0].verified;
  }
  return decoder.decode(token);
}

export class ProtonClient {
  constructor(cfg, env) {
    this.cfg = cfg;
    this.env = env;
    this.baseUrl = String(env.PROTON_API_BASE || DEFAULT_API).replace(/\/$/, "");
    this.appVersion = String(env.PROTON_APP_VERSION || DEFAULT_APP_VERSION);
    this.auth = null;
    this.user = null;
    this.addresses = [];
    this.userKeys = [];
    this.addressKeys = new Map();
    this.loginPromise = null;
    this.refreshPromise = null;
    this.blockedUntil = 0;
  }

  baseHeaders() {
    return {
      accept: "application/json",
      "content-type": "application/json",
      "x-pm-appversion": this.appVersion,
      "x-pm-apiversion": "3",
    };
  }

  authHeaders() {
    if (!this.auth) return this.baseHeaders();
    return {
      ...this.baseHeaders(),
      "x-pm-uid": this.auth.UID,
      authorization: `Bearer ${this.auth.AccessToken}`,
    };
  }

  assertCircuitClosed() {
    if (!this.blockedUntil) return;
    if (this.blockedUntil <= Date.now()) {
      this.blockedUntil = 0;
      return;
    }
    throw circuitError(this.blockedUntil);
  }

  tripRiskCircuit(error) {
    if (Number(error?.protonCode) !== 2028) return error;
    this.blockedUntil = Math.max(this.blockedUntil, Date.now() + PROTON_2028_COOLDOWN_MS);
    error.blockedUntil = this.blockedUntil;
    error.retryAfterSeconds = Math.max(1, Math.ceil((this.blockedUntil - Date.now()) / 1000));
    return error;
  }

  async raw(path, { method = "GET", body, auth = false } = {}) {
    this.assertCircuitClosed();
    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: auth ? this.authHeaders() : this.baseHeaders(),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new Error(`Proton API 返回非 JSON（HTTP ${response.status}）`);
    }
    if (!isApiSuccess(payload, response.status)) {
      throw this.tripRiskCircuit(apiError(payload, response.status));
    }
    return payload;
  }

  async request(path, options = {}, retry = true) {
    await this.ensureAuthenticated();
    const usedAccessToken = this.auth?.AccessToken;
    try {
      return await this.raw(path, { ...options, auth: true });
    } catch (error) {
      if (retry && error?.status === 401) {
        if (this.auth?.AccessToken && this.auth.AccessToken !== usedAccessToken) {
          return this.raw(path, { ...options, auth: true });
        }
        await this.refreshAuthenticated();
        return this.raw(path, { ...options, auth: true });
      }
      throw error;
    }
  }

  clearSession() {
    this.auth = null;
    this.user = null;
    this.addresses = [];
    this.userKeys = [];
    this.addressKeys = new Map();
  }

  reset() {
    this.clearSession();
  }

  async login() {
    const username = this.cfg.email;
    const password = this.cfg.credential;
    const info = await this.raw("/auth/v4/info", {
      method: "POST",
      body: { Username: username },
    });
    const proof = await getSrp(info, { username, password });
    const auth = await this.raw("/auth/v4", {
      method: "POST",
      body: {
        Username: username,
        ClientProof: proof.clientProof,
        ClientEphemeral: proof.clientEphemeral,
        SRPSession: info.SRPSession,
      },
    });
    if (!b64Equal(auth.ServerProof, proof.expectedServerProof)) {
      throw new Error("Proton SRP server proof 校验失败");
    }
    const twoFA = Number(auth?.["2FA"]?.Enabled ?? auth?.TwoFA?.Enabled ?? 0);
    if (twoFA !== 0) throw new Error("当前 Proton 适配器尚未启用 2FA 登录");
    if (Number(auth.PasswordMode || 1) !== 1) throw new Error("当前 Proton 适配器仅支持单密码模式");
    if (!auth.UID || !auth.AccessToken || !auth.RefreshToken) {
      throw new Error("Proton 登录成功但缺少 UID/AccessToken/RefreshToken");
    }
    this.auth = auth;
    return auth;
  }

  async ensureAuthenticated() {
    this.assertCircuitClosed();
    if (this.auth?.AccessToken) return this.auth;
    if (!this.loginPromise) {
      this.loginPromise = this.login().finally(() => {
        this.loginPromise = null;
      });
    }
    return this.loginPromise;
  }

  async refreshAuthenticated() {
    this.assertCircuitClosed();
    if (!this.auth?.UID || !this.auth?.RefreshToken) {
      throw new Error("Proton Session 缺少 UID/RefreshToken，需要重新登录");
    }
    if (!this.refreshPromise) {
      const previous = { ...this.auth };
      this.refreshPromise = (async () => {
        try {
          const refreshed = await this.raw("/auth/v4/refresh", {
            method: "POST",
            body: {
              UID: previous.UID,
              RefreshToken: previous.RefreshToken,
              ResponseType: "token",
              GrantType: "refresh_token",
              RedirectURI: PROTON_REFRESH_REDIRECT_URI,
              State: randomState(),
              AccessToken: previous.AccessToken || undefined,
            },
          });
          if (!refreshed.AccessToken) throw new Error("Proton refresh 成功响应缺少 AccessToken");
          this.auth = {
            ...previous,
            ...refreshed,
            UID: refreshed.UID || previous.UID,
            AccessToken: refreshed.AccessToken,
            RefreshToken: refreshed.RefreshToken || previous.RefreshToken,
          };
          return this.auth;
        } catch (error) {
          if ([400, 401, 422].includes(Number(error?.status))) {
            this.clearSession();
          }
          throw error;
        }
      })().finally(() => {
        this.refreshPromise = null;
      });
    }
    return this.refreshPromise;
  }

  async ensureKeys() {
    await this.ensureAuthenticated();
    if (this.userKeys.length && this.addressKeys.size) return;

    const [userPayload, saltsPayload, addressesPayload] = await Promise.all([
      this.request("/core/v4/users"),
      this.request("/core/v4/keys/salts"),
      this.request("/core/v4/addresses"),
    ]);
    this.user = userPayload.User;
    this.addresses = list(addressesPayload.Addresses);
    const userApiKeys = list(this.user?.Keys).filter((x) => bool(x.Active));
    const primary = userApiKeys.find((x) => bool(x.Primary)) || userApiKeys[0];
    if (!primary?.ID || !primary?.PrivateKey) throw new Error("Proton 用户主密钥不存在");
    const salt = list(saltsPayload.KeySalts).find((x) => String(x.ID) === String(primary.ID));
    if (!salt?.KeySalt) throw new Error("Proton 用户主密钥 KeySalt 不存在");
    const keyPass = await computeKeyPassword(this.cfg.credential, salt.KeySalt);

    const userKeys = [];
    for (const key of userApiKeys) {
      try {
        userKeys.push(await unlockPrivateKey(key.PrivateKey, keyPass));
      } catch (error) {
        console.warn(`Proton user key ${key.ID} unlock failed:`, error?.message || String(error));
      }
    }
    if (!userKeys.length) throw new Error("无法解锁 Proton 用户密钥");
    this.userKeys = userKeys;

    const addressKeys = new Map();
    for (const addr of this.addresses) {
      const unlocked = [];
      for (const key of list(addr.Keys).filter((x) => bool(x.Active))) {
        try {
          const passphrase = key.Token && key.Signature
            ? await decryptToken(key, this.userKeys)
            : keyPass;
          unlocked.push(await unlockPrivateKey(key.PrivateKey, passphrase));
        } catch (error) {
          console.warn(`Proton address key ${key.ID} unlock failed:`, error?.message || String(error));
        }
      }
      if (unlocked.length) addressKeys.set(String(addr.ID), unlocked);
    }
    if (!addressKeys.size) throw new Error("无法解锁任何 Proton 地址密钥");
    this.addressKeys = addressKeys;
  }

  async testConnection() {
    await this.ensureAuthenticated();
    const userPayload = await this.request("/core/v4/users");
    return {
      success: true,
      account: this.cfg.id,
      accountLabel: this.cfg.label,
      provider: "proton",
      api: { authenticated: true, userId: userPayload.User?.ID || null },
      readOnly: true,
    };
  }

  async listMessages({ folder = "INBOX", limit = 20 } = {}) {
    const payload = await this.request("/mail/v4/messages", {
      method: "POST",
      body: {
        LabelID: labelForFolder(folder),
        Desc: 1,
        Page: 0,
        PageSize: Math.min(Math.max(Number(limit) || 20, 1), 100),
        Sort: "Time",
      },
    });
    return list(payload.Messages).map((m) => metaToMail(m, this.cfg, folder));
  }

  async searchMessages(params = {}) {
    const scanLimit = Math.min(Math.max(Number(params.limit || 20) * 5, 50), 100);
    const rows = await this.listMessages({ folder: params.folder || "INBOX", limit: scanLimit });
    const lower = (x) => String(x || "").toLowerCase();
    const includesAddr = (arr, q) => arr.some((a) => lower(`${a.name} ${a.address}`).includes(lower(q)));
    const since = params.since ? new Date(params.since).getTime() : null;
    const before = params.before ? new Date(params.before).getTime() : null;
    const filtered = rows.filter((m) => {
      if (params.subject && !lower(m.subject).includes(lower(params.subject))) return false;
      if (params.from && !includesAddr(m.from, params.from)) return false;
      if (params.to && !includesAddr(m.to, params.to)) return false;
      if (params.text) {
        const hay = `${m.subject} ${m.from.map((x) => `${x.name} ${x.address}`).join(" ")} ${m.to.map((x) => `${x.name} ${x.address}`).join(" ")}`;
        if (!lower(hay).includes(lower(params.text))) return false;
      }
      if (typeof params.seen === "boolean" && params.seen !== m.flags.includes("\\Seen")) return false;
      if (typeof params.starred === "boolean" && params.starred !== m.flags.includes("\\Flagged")) return false;
      const time = m.date ? new Date(m.date).getTime() : 0;
      if (since !== null && time < since) return false;
      if (before !== null && time >= before) return false;
      return true;
    });
    return filtered.slice(0, Math.min(Math.max(Number(params.limit) || 20, 1), 100));
  }

  async getMessage(messageId, folder = "INBOX") {
    if (!messageId) throw new Error("缺少 Proton messageId");
    await this.ensureKeys();
    const payload = await this.request(`/mail/v4/messages/${encodeURIComponent(messageId)}`);
    const message = payload.Message;
    if (!message?.Body) throw new Error("Proton 邮件正文为空或不可用");
    const pgp = await readMessage({ armoredMessage: message.Body });
    const preferred = this.addressKeys.get(String(message.AddressID)) || [];
    const fallback = [...this.addressKeys.values()].flat();
    const decryptionKeys = preferred.length ? preferred : fallback;
    const decrypted = await decrypt({ message: pgp, decryptionKeys, format: "binary" });
    const bytes = decrypted.data instanceof Uint8Array ? decrypted.data : new Uint8Array(decrypted.data);
    const body = decoder.decode(bytes);
    const mimeType = String(message.MIMEType || "").toLowerCase();
    const isHtml = mimeType.includes("html") || /<html[\s>]|<body[\s>]/i.test(body);
    const meta = metaToMail(message, this.cfg, folder);
    return {
      ...meta,
      messageId: message.ExternalID || null,
      replyTo: addresses(message.ReplyTos),
      text: isHtml ? "" : body.slice(0, 120000),
      html: isHtml ? body.slice(0, 120000) : "",
      attachments: list(message.Attachments).map((a, index) => ({
        index,
        protonAttachmentId: a.ID || null,
        filename: a.Name || null,
        contentType: a.MIMEType || null,
        size: Number(a.Size || 0),
        cid: a.Headers?.["Content-ID"] || null,
        disposition: a.Disposition || null,
      })),
    };
  }

  listFolders() {
    return [
      ["INBOX", "Inbox", "\\Inbox", "0"],
      ["Archive", "Archive", "\\Archive", "6"],
      ["All Mail", "All Mail", "\\All", "5"],
      ["Sent", "Sent", "\\Sent", "7"],
      ["Drafts", "Drafts", "\\Drafts", "8"],
      ["Spam", "Spam", "\\Junk", "4"],
      ["Trash", "Trash", "\\Trash", "3"],
      ["Starred", "Starred", null, "10"],
    ].map(([path, name, specialUse, labelId]) => ({
      path, name, specialUse, subscribed: true, messages: null, unseen: null, protonLabelId: labelId,
    }));
  }

  async folderStatus(folder = "INBOX") {
    const messages = await this.listMessages({ folder, limit: 1 });
    return {
      account: this.cfg.id,
      accountLabel: this.cfg.label,
      folder,
      status: { messages: null, unseen: null, uidNext: null, uidValidity: null, size: null },
      quota: this.user ? { storageUsed: this.user.UsedSpace, storageLimit: this.user.MaxSpace } : null,
      sampleAvailable: messages.length > 0,
      provider: "proton",
    };
  }
}
