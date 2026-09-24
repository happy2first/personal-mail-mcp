import { normalizeCookieState } from "./cookies.js";

export const EXTENSION_BUNDLE_VERSION = 2;
export const EXTENSION_BUNDLE_SOURCE = "proton-browser-session";
export const PROTON_REFRESH_PATH = "/api/auth/refresh";
export const PROTON_API_PATH = "/api/";

const MAX_COOKIES = 64;
const MAX_COOKIE_BYTES = 8192;
const MAX_BUNDLE_AGE_MS = 15 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 2 * 60 * 1000;

const text = (value) => value === undefined || value === null ? "" : String(value).trim();

function pathCovers(cookiePath, requestPath) {
  const path = text(cookiePath) || "/";
  if (path === requestPath) return true;
  if (!requestPath.startsWith(path)) return false;
  return path.endsWith("/") || requestPath.charAt(path.length) === "/";
}

function decodeRefreshPayload(value) {
  let raw = text(value);
  if (!raw) return null;
  for (let i = 0; i < 2; i += 1) {
    try {
      const decoded = decodeURIComponent(raw);
      if (decoded === raw) break;
      raw = decoded;
    } catch {
      break;
    }
  }
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function normalizeKeySalts(rows) {
  const out = [];
  const seen = new Set();
  for (const row of Array.isArray(rows) ? rows : []) {
    const ID = text(row?.ID ?? row?.id);
    const KeySalt = text(row?.KeySalt ?? row?.keySalt);
    if (!ID || !KeySalt || KeySalt.length > 4096 || seen.has(ID)) continue;
    seen.add(ID);
    out.push({ ID, KeySalt });
  }
  return out.slice(0, 32);
}

function normalizeAddresses(rows) {
  const out = [];
  const seen = new Set();
  for (const row of Array.isArray(rows) ? rows : []) {
    const ID = text(row?.ID ?? row?.id);
    const Email = text(row?.Email ?? row?.email).toLowerCase();
    if (!ID || !Email || seen.has(ID)) continue;
    seen.add(ID);
    out.push({ ID, Email });
  }
  return out.slice(0, 64);
}

function normalizeClient(client) {
  if (!client || typeof client !== "object" || Array.isArray(client)) return null;
  const mailAppVersion = text(client.mailAppVersion);
  const accountAppVersion = text(client.accountAppVersion);
  const locale = text(client.locale);
  return {
    ...(mailAppVersion ? { mailAppVersion } : {}),
    ...(accountAppVersion ? { accountAppVersion } : {}),
    ...(locale ? { locale } : {}),
  };
}

export function normalizeExtensionCookies(rows, uid, nowMs = Date.now()) {
  if (!Array.isArray(rows) || !rows.length) throw new Error("扩展 Bundle 缺少 Cookie");
  if (rows.length > MAX_COOKIES) throw new Error("扩展 Bundle Cookie 数量超过限制");
  const selected = [];
  for (const raw of rows) {
    const name = text(raw?.name);
    const value = raw?.value === undefined || raw?.value === null ? "" : String(raw.value);
    if (!name || !value || value.length > MAX_COOKIE_BYTES) continue;
    const domain = text(raw?.domain).toLowerCase().replace(/^\./, "");
    if (domain !== "mail.proton.me" && domain !== "proton.me") continue;
    if (/^(AUTH|REFRESH)-/i.test(name) && ![
      `AUTH-${uid}`,
      `REFRESH-${uid}`,
    ].includes(name)) continue;
    selected.push({
      name,
      value,
      domain,
      hostOnly: raw?.hostOnly !== false,
      path: text(raw?.path) || "/",
      secure: raw?.secure !== false,
      expiresAt: raw?.expiresAt == null
        ? (raw?.expirationDate == null ? null : Number(raw.expirationDate) * 1000)
        : Number(raw.expiresAt),
    });
  }
  const cookies = normalizeCookieState(selected, nowMs);
  const auth = cookies.find((cookie) => cookie.name === `AUTH-${uid}`);
  const refresh = cookies.find((cookie) => cookie.name === `REFRESH-${uid}`);
  const sessionId = cookies.find((cookie) => cookie.name === "Session-Id");
  if (!auth) throw new Error("扩展 Bundle 缺少 AUTH Cookie");
  if (!pathCovers(auth.path, "/api/core/v4/addresses")) throw new Error("AUTH Cookie Path 不能覆盖 Proton API");
  if (!refresh) throw new Error("扩展 Bundle 缺少 REFRESH Cookie");
  if (!pathCovers(refresh.path, PROTON_REFRESH_PATH)) throw new Error("REFRESH Cookie Path 不能覆盖 /api/auth/refresh");
  if (!sessionId) throw new Error("扩展 Bundle 缺少 Session-Id Cookie");
  const refreshPayload = decodeRefreshPayload(refresh.value);
  const refreshUid = text(refreshPayload?.UID ?? refreshPayload?.uid);
  const refreshToken = text(refreshPayload?.RefreshToken ?? refreshPayload?.refreshToken);
  if (!refreshPayload || !refreshUid || !refreshToken) throw new Error("REFRESH Cookie 内容无法识别");
  if (refreshUid !== uid) throw new Error("REFRESH Cookie UID 与 Bundle UID 不一致");
  return cookies;
}

export function normalizeExtensionBundle(bundle, nowMs = Date.now()) {
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) throw new Error("扩展 Bundle 格式无效");
  if (Number(bundle.version) !== EXTENSION_BUNDLE_VERSION) throw new Error(`只接受 Proton Browser Session Bundle v${EXTENSION_BUNDLE_VERSION}`);
  if (text(bundle.source) !== EXTENSION_BUNDLE_SOURCE) throw new Error("扩展 Bundle source 无效");
  const capturedAt = Number(bundle.capturedAt);
  if (!Number.isFinite(capturedAt)) throw new Error("扩展 Bundle 缺少 capturedAt");
  if (capturedAt > nowMs + MAX_FUTURE_SKEW_MS || nowMs - capturedAt > MAX_BUNDLE_AGE_MS) {
    throw new Error("扩展 Bundle 已过期，请重新检测 Proton 会话");
  }

  const uid = text(bundle.uid);
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(uid)) throw new Error("扩展 Bundle UID 无效");
  const email = text(bundle.email).toLowerCase();
  if (!email || !email.includes("@")) throw new Error("扩展 Bundle 邮箱地址无效");

  const userId = text(bundle.user?.id ?? bundle.user?.ID);
  const keyIds = [...new Set((Array.isArray(bundle.user?.keyIds) ? bundle.user.keyIds : []).map(text).filter(Boolean))].slice(0, 64);
  if (!userId || !keyIds.length) throw new Error("扩展 Bundle 缺少用户密钥信息");
  const passwordModeValue = Number(bundle.user?.passwordMode ?? bundle.user?.PasswordMode);
  const passwordMode = [1, 2].includes(passwordModeValue) ? passwordModeValue : undefined;

  const addresses = normalizeAddresses(bundle.addresses);
  if (!addresses.some((item) => item.Email === email)) throw new Error("扩展 Bundle 邮箱与地址列表不一致");

  const keySalts = normalizeKeySalts(bundle.keySalts);
  if (!keySalts.length) throw new Error("扩展 Bundle 缺少有效 KeySalt");
  const keyIdSet = new Set(keyIds);
  if (!keySalts.some((item) => keyIdSet.has(item.ID))) throw new Error("扩展 Bundle KeySalt 与用户密钥不匹配");

  const cookieRows = Array.isArray(bundle.session?.cookies) ? bundle.session.cookies : bundle.cookies;
  const cookies = normalizeExtensionCookies(cookieRows, uid, nowMs);

  return {
    version: EXTENSION_BUNDLE_VERSION,
    source: EXTENSION_BUNDLE_SOURCE,
    capturedAt,
    uid,
    email,
    user: { id: userId, keyIds, ...(passwordMode ? { passwordMode } : {}) },
    addresses,
    keySalts,
    cookies,
    client: normalizeClient(bundle.client),
  };
}
