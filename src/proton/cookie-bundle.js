import { ProtonClient } from "./client-v2.js";
import { normalizeImportedSession } from "./session-import.js";

export const PROTON_REFRESH_REQUEST_PATH = "/api/auth/refresh";
export const PROTON_AUTH_COOKIE_PATH = "/api/";

const MAX_COOKIE_BYTES = 8192;
const MAX_COOKIES = 64;

const text = (value) => value === undefined || value === null ? "" : String(value).trim();
const object = (value) => value && typeof value === "object" && !Array.isArray(value) ? value : null;

function normalizeExpires(value) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value === "number" || /^\d+$/.test(String(value))) {
    const n = Number(value);
    if (!Number.isFinite(n)) return null;
    return n > 0 && n < 1e12 ? n * 1000 : n;
  }
  const parsed = Date.parse(String(value));
  return Number.isFinite(parsed) ? parsed : null;
}

function domainAllowed(host, domain) {
  const h = String(host || "").toLowerCase();
  const d = String(domain || "").toLowerCase().replace(/^\./, "");
  return Boolean(d) && (h === d || h.endsWith(`.${d}`));
}

function cookieKey(cookie) {
  return `${cookie.name}\n${cookie.domain}\n${cookie.path}`;
}

function pathCoversRequest(cookiePath, requestPath = PROTON_REFRESH_REQUEST_PATH) {
  const path = String(cookiePath || "/");
  const target = String(requestPath || "/");
  if (path === target) return true;
  if (!target.startsWith(path)) return false;
  return path.endsWith("/") || target.charAt(path.length) === "/";
}

export function isRefreshCapableCookie(cookie) {
  return /^AUTH-/i.test(String(cookie?.name || "")) && pathCoversRequest(cookie?.path, PROTON_REFRESH_REQUEST_PATH);
}

function normalizeExtraCookieObject(raw, baseUrl) {
  const host = new URL(baseUrl).hostname.toLowerCase();
  const name = text(raw?.name ?? raw?.Name);
  const value = text(raw?.value ?? raw?.Value);
  if (!name || !value) throw new Error("Cookie 必须包含 name 和 value");
  if (value.length > MAX_COOKIE_BYTES) throw new Error(`Cookie ${name} 超过大小限制`);

  const rawDomain = text(raw?.domain ?? raw?.Domain);
  const domain = (rawDomain || host).toLowerCase().replace(/^\./, "");
  if (!domainAllowed(host, domain)) throw new Error(`Cookie ${name} 的 Domain 与 Proton API 主机不匹配`);

  const path = text(raw?.path ?? raw?.Path) || PROTON_REFRESH_REQUEST_PATH;
  if (!pathCoversRequest(path, PROTON_REFRESH_REQUEST_PATH)) {
    throw new Error(`Cookie ${name} 的 Path=${path} 不会发送到 ${PROTON_REFRESH_REQUEST_PATH}`);
  }

  const explicitHostOnly = raw?.hostOnly ?? raw?.HostOnly;
  const hostOnly = explicitHostOnly === undefined
    ? domain === host && !rawDomain.startsWith(".")
    : Boolean(explicitHostOnly);
  if (hostOnly && domain !== host) throw new Error(`Cookie ${name} 的 hostOnly 与 Domain 不一致`);

  return {
    name,
    value,
    domain,
    hostOnly,
    path,
    secure: true,
    expiresAt: normalizeExpires(raw?.expiresAt ?? raw?.ExpiresAt ?? raw?.expires ?? raw?.Expires),
  };
}

function parseSetCookieLine(line, baseUrl) {
  const raw = String(line || "").replace(/^set-cookie\s*:\s*/i, "").trim();
  if (!raw) return null;
  const parts = raw.split(";").map((part) => part.trim()).filter(Boolean);
  const pair = parts.shift() || "";
  const eq = pair.indexOf("=");
  if (eq <= 0) return null;
  const candidate = {
    name: pair.slice(0, eq).trim(),
    value: pair.slice(eq + 1).trim(),
  };
  for (const part of parts) {
    const attrEq = part.indexOf("=");
    const key = (attrEq < 0 ? part : part.slice(0, attrEq)).trim().toLowerCase();
    const value = attrEq < 0 ? "" : part.slice(attrEq + 1).trim();
    if (key === "domain") candidate.domain = value;
    else if (key === "path") candidate.path = value;
    else if (key === "expires") candidate.expires = value;
    else if (key === "max-age") {
      const seconds = Number(value);
      if (Number.isFinite(seconds)) candidate.expiresAt = seconds <= 0 ? 0 : Date.now() + seconds * 1000;
    }
  }
  return normalizeExtraCookieObject(candidate, baseUrl);
}

function parseCookiePairs(raw, baseUrl) {
  const ignored = new Set(["path", "domain", "expires", "max-age", "secure", "httponly", "samesite", "priority"]);
  const input = String(raw || "").replace(/^cookie\s*:\s*/i, "").trim();
  const out = [];
  for (const segment of input.split(";")) {
    const part = segment.trim();
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    if (!name || ignored.has(name.toLowerCase())) continue;
    const value = part.slice(eq + 1).trim();
    if (!value) continue;
    out.push(normalizeExtraCookieObject({ name, value }, baseUrl));
    if (out.length >= MAX_COOKIES) break;
  }
  return out;
}

function parseExtraValue(value, baseUrl) {
  if (value === undefined || value === null || value === "") return [];
  if (Array.isArray(value)) return value.flatMap((item) => parseExtraValue(item, baseUrl));
  const obj = object(value);
  if (obj) {
    const nested = obj.refreshCookies ?? obj.cookies ?? obj.CookieState;
    if (Array.isArray(nested)) return nested.flatMap((item) => parseExtraValue(item, baseUrl));
    return [normalizeExtraCookieObject(obj, baseUrl)];
  }
  if (typeof value !== "string") throw new Error("额外 Cookie 输入格式无效");
  const raw = value.trim();
  if (!raw) return [];
  if (raw.startsWith("{") || raw.startsWith("[")) {
    try { return parseExtraValue(JSON.parse(raw), baseUrl); }
    catch (error) {
      if (error instanceof SyntaxError) throw new Error("额外 Cookie JSON 无效");
      throw error;
    }
  }
  const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const out = [];
  for (const line of lines) {
    const looksLikeSetCookie = /^set-cookie\s*:/i.test(line)
      || /;\s*(?:path|domain|expires|max-age|secure|httponly|samesite)(?:=|;|$)/i.test(line);
    if (looksLikeSetCookie) {
      const cookie = parseSetCookieLine(line, baseUrl);
      if (cookie) out.push(cookie);
    } else {
      out.push(...parseCookiePairs(line, baseUrl));
    }
  }
  return out;
}

export function normalizeRefreshCookieInput(value, baseUrl = "https://mail.proton.me/api") {
  const parsed = parseExtraValue(value, baseUrl);
  const byKey = new Map();
  for (const cookie of parsed) {
    if (cookie.expiresAt !== null && cookie.expiresAt <= Date.now()) continue;
    byKey.set(cookieKey(cookie), cookie);
  }
  return [...byKey.values()].slice(-MAX_COOKIES);
}

function normalizeSessionCookieInput(value, candidate) {
  const auth = normalizeImportedSession(value);
  if (!auth?.UID || !auth.cookies) throw new Error("普通 Session Cookie 必须包含 AUTH-<UID> Cookie");
  const host = new URL(candidate.baseUrl).hostname.toLowerCase();
  const raw = Array.isArray(auth.CookieState) ? auth.CookieState : [];
  const cookies = raw.slice(0, MAX_COOKIES).map((item) => {
    const name = text(item?.name);
    return {
      name,
      value: text(item?.value),
      domain: host,
      hostOnly: true,
      path: /^AUTH-/i.test(name) ? PROTON_AUTH_COOKIE_PATH : "/",
      secure: true,
      expiresAt: null,
    };
  }).filter((item) => item.name && item.value && item.value.length <= MAX_COOKIE_BYTES);
  if (!cookies.length) throw new Error("普通 Session Cookie 中没有可导入的 Cookie");
  return { auth, cookies };
}

function mergeCookieState(...states) {
  const byKey = new Map();
  for (const state of states) {
    for (const cookie of Array.isArray(state) ? state : []) byKey.set(cookieKey(cookie), cookie);
  }
  return [...byKey.values()].slice(-MAX_COOKIES);
}

export function countRefreshCookies(state) {
  return (Array.isArray(state) ? state : []).filter(isRefreshCapableCookie).length;
}

function addressesFromPayload(payload) {
  return (Array.isArray(payload?.Addresses) ? payload.Addresses : [])
    .map((item) => text(item?.Email ?? item?.email).toLowerCase())
    .filter(Boolean);
}

async function validateAddressOwnership(candidate, expectedEmail) {
  const payload = await candidate.raw("/core/v4/addresses", { auth: true });
  const addresses = addressesFromPayload(payload);
  if (!addresses.length) throw new Error("Proton Cookie Session 校验成功，但未返回可核对的邮箱地址");
  if (!addresses.includes(text(expectedEmail).toLowerCase())) {
    const error = new Error("导入的 Proton Cookie Session 与所选账号不匹配");
    error.sessionAccountMismatch = true;
    throw error;
  }
  return addresses.length;
}

export async function validateCookieBundle(cfg, env, { sessionCookie, refreshCookie } = {}) {
  const candidate = new ProtonClient(cfg, env);
  const session = normalizeSessionCookieInput(sessionCookie, candidate);
  const extraCookies = normalizeRefreshCookieInput(refreshCookie, candidate.baseUrl);
  candidate.setAuth(session.auth);
  candidate.setCookieState(mergeCookieState(session.cookies, extraCookies));

  let refreshedDuringValidation = false;
  let addressCount;
  try {
    addressCount = await validateAddressOwnership(candidate, cfg.email);
  } catch (error) {
    if (Number(error?.status) !== 401) throw error;
    await candidate.refreshAuthenticated();
    refreshedDuringValidation = true;
    addressCount = await validateAddressOwnership(candidate, cfg.email);
  }

  const cookieState = candidate.getCookieState();
  const refreshCookieCount = countRefreshCookies(cookieState);
  if (!refreshCookieCount) {
    throw new Error(`Cookie Session 已校验，但没有 AUTH-* Cookie 可发送到 ${PROTON_REFRESH_REQUEST_PATH}`);
  }
  const auth = {
    ...candidate.auth,
    cookies: true,
    CookieState: cookieState,
  };
  return {
    auth,
    cookies: cookieState,
    safe: {
      account: cfg.id,
      importMode: extraCookies.length ? "browser_cookie_bundle_with_extra" : "browser_cookie_header",
      cookieAuth: true,
      emailMatched: true,
      addressCount,
      refreshedDuringValidation,
      cookieCount: cookieState.length,
      normalCookieCount: Math.max(0, cookieState.length - refreshCookieCount),
      refreshCookieCount,
      refreshCapable: true,
      extraCookieCount: extraCookies.length,
    },
  };
}
