import { normalizeKeySalts } from "./key-material.js";

const MAX_COOKIES = 64;
const MAX_COOKIE_BYTES = 8192;
const MAX_BUNDLE_AGE_MS = 10 * 60 * 1000;
const UID_RE = /^[A-Za-z0-9_-]{1,256}$/;

const text = (value) => value === undefined || value === null ? "" : String(value).trim();

function normalizeDomain(value) {
  return text(value).toLowerCase().replace(/^\./, "");
}

function domainMatches(hostname, domain, hostOnly) {
  const host = String(hostname || "").toLowerCase();
  const normalized = normalizeDomain(domain);
  return hostOnly ? host === normalized : host === normalized || host.endsWith(`.${normalized}`);
}

function pathMatches(pathname, cookiePath) {
  const path = String(pathname || "/");
  const target = String(cookiePath || "/");
  if (path === target) return true;
  if (!path.startsWith(target)) return false;
  return target.endsWith("/") || path.charAt(target.length) === "/";
}

function appliesTo(cookie, url) {
  const parsed = new URL(url);
  return domainMatches(parsed.hostname, cookie.domain, cookie.hostOnly)
    && pathMatches(parsed.pathname, cookie.path)
    && (!cookie.secure || parsed.protocol === "https:");
}

function normalizeExpires(raw) {
  if (raw?.expiresAt !== undefined && raw?.expiresAt !== null) {
    const n = Number(raw.expiresAt);
    return Number.isFinite(n) ? n : null;
  }
  if (raw?.expirationDate !== undefined && raw?.expirationDate !== null) {
    const n = Number(raw.expirationDate);
    return Number.isFinite(n) ? n * 1000 : null;
  }
  return null;
}

function normalizeCookie(raw, nowMs) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const name = text(raw.name);
  const value = String(raw.value ?? "");
  if (!name || !value || value.length > MAX_COOKIE_BYTES) return null;
  const domain = normalizeDomain(raw.domain);
  if (domain !== "mail.proton.me" && domain !== "proton.me") return null;
  const hostOnly = raw.hostOnly !== false;
  if (domain === "proton.me" && hostOnly) return null;
  const path = text(raw.path) || "/";
  if (!path.startsWith("/")) return null;
  const expiresAt = normalizeExpires(raw);
  if (expiresAt !== null && expiresAt <= nowMs) return null;
  return {
    name,
    value,
    domain,
    hostOnly,
    path,
    secure: raw.secure !== false,
    expiresAt,
  };
}

function decodeRefreshPayload(cookie) {
  let raw = String(cookie?.value || "");
  for (let i = 0; i < 2 && raw.includes("%"); i += 1) {
    try {
      const decoded = decodeURIComponent(raw);
      if (decoded === raw) break;
      raw = decoded;
    } catch {
      break;
    }
  }
  try {
    const payload = JSON.parse(raw);
    return payload && typeof payload === "object" && !Array.isArray(payload) ? payload : null;
  } catch {
    return null;
  }
}

function normalizeAddresses(value) {
  return (Array.isArray(value) ? value : []).map((row) => ({
    ID: text(row?.ID ?? row?.id),
    Email: text(row?.Email ?? row?.email).toLowerCase(),
  })).filter((row) => row.ID && row.Email).slice(0, 64);
}

function normalizeUser(value) {
  const user = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    ID: text(user.ID ?? user.id),
    keyIds: (Array.isArray(user.keyIds) ? user.keyIds : []).map(text).filter(Boolean).slice(0, 64),
  };
}

export function normalizeExtensionBundle(value, expectedEmail, nowMs = Date.now()) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("扩展 Bundle 必须是 JSON 对象");
  if (Number(value.version) !== 2) throw new Error("只接受 Proton Browser Session Bundle v2");
  if (text(value.source) !== "proton-browser-session") throw new Error("扩展 Bundle source 无效");

  const uid = text(value.uid);
  if (!UID_RE.test(uid)) throw new Error("扩展 Bundle UID 无效");
  const email = text(value.email).toLowerCase();
  if (!email || email !== text(expectedEmail).toLowerCase()) {
    const error = new Error("扩展检测到的 Proton 邮箱与所选 MCP 账号不匹配");
    error.sessionAccountMismatch = true;
    throw error;
  }

  const capturedAt = Number(value.capturedAt || 0);
  if (!Number.isFinite(capturedAt) || capturedAt <= 0 || capturedAt > nowMs + 2 * 60 * 1000 || nowMs - capturedAt > MAX_BUNDLE_AGE_MS) {
    throw new Error("扩展 Bundle 已过期，请在 Proton 页面重新检测后导入");
  }

  const rawCookies = Array.isArray(value?.session?.cookies) ? value.session.cookies : [];
  const byKey = new Map();
  for (const raw of rawCookies.slice(0, MAX_COOKIES)) {
    const cookie = normalizeCookie(raw, nowMs);
    if (!cookie) continue;
    if (/^(AUTH|REFRESH)-/i.test(cookie.name)
      && cookie.name !== `AUTH-${uid}`
      && cookie.name !== `REFRESH-${uid}`) continue;
    byKey.set(`${cookie.name}\n${cookie.domain}\n${cookie.path}`, cookie);
  }
  const cookies = [...byKey.values()];
  const auth = cookies.find((cookie) => cookie.name === `AUTH-${uid}`
    && appliesTo(cookie, "https://mail.proton.me/api/core/v4/addresses"));
  const refresh = cookies.find((cookie) => cookie.name === `REFRESH-${uid}`
    && appliesTo(cookie, "https://mail.proton.me/api/auth/refresh"));
  const sessionId = cookies.find((cookie) => cookie.name.toLowerCase() === "session-id"
    && appliesTo(cookie, "https://mail.proton.me/api/core/v4/addresses"));
  if (!auth) throw new Error("扩展 Bundle 缺少可用于 Proton API 的 AUTH Cookie");
  if (!refresh) throw new Error("扩展 Bundle 缺少 /api/auth/refresh 专用 REFRESH Cookie");
  if (!sessionId) throw new Error("扩展 Bundle 缺少 Session-Id Cookie");

  const refreshPayload = decodeRefreshPayload(refresh);
  const refreshUid = text(refreshPayload?.UID ?? refreshPayload?.uid);
  const refreshToken = text(refreshPayload?.RefreshToken ?? refreshPayload?.refreshToken);
  if (!refreshPayload || refreshUid !== uid || !refreshToken) {
    throw new Error("REFRESH Cookie 内容与 Bundle UID 不一致");
  }

  const keySalts = normalizeKeySalts({ KeySalts: value.keySalts });
  if (!keySalts?.length) throw new Error("扩展 Bundle 缺少有效 KeySalt");

  const addresses = normalizeAddresses(value.addresses);
  if (!addresses.some((row) => row.Email === email)) throw new Error("扩展 Bundle 地址列表不包含所选邮箱");
  const user = normalizeUser(value.user);
  if (!user.ID || !user.keyIds.length) throw new Error("扩展 Bundle 缺少 Proton 用户密钥标识");
  if (!keySalts.some((salt) => user.keyIds.includes(String(salt.ID)))) {
    throw new Error("扩展 Bundle 的 KeySalt 与用户密钥不匹配");
  }

  return {
    version: 2,
    source: "proton-browser-session",
    capturedAt,
    uid,
    email,
    cookies,
    keySalts,
    addresses,
    user,
    client: value.client && typeof value.client === "object" && !Array.isArray(value.client) ? {
      mailAppVersion: text(value.client.mailAppVersion),
      accountAppVersion: text(value.client.accountAppVersion),
      locale: text(value.client.locale),
    } : null,
  };
}

export function bundleCookieComponents(bundle) {
  const uid = bundle?.uid;
  const cookies = Array.isArray(bundle?.cookies) ? bundle.cookies : [];
  return {
    auth: cookies.some((cookie) => cookie.name === `AUTH-${uid}`),
    refresh: cookies.some((cookie) => cookie.name === `REFRESH-${uid}`),
    sessionId: cookies.some((cookie) => String(cookie.name || "").toLowerCase() === "session-id"),
  };
}
