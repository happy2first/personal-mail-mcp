import { ProtonClient } from "./client-v2.js";

function object(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function text(value) {
  return value === undefined || value === null ? "" : String(value).trim();
}

function number(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

function decodeCookieValue(value) {
  let raw = text(value);
  if (!raw) return "";
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) raw = raw.slice(1, -1);
  for (let i = 0; i < 2; i += 1) {
    if (!raw.includes("%")) break;
    try {
      const decoded = decodeURIComponent(raw);
      if (decoded === raw) break;
      raw = decoded;
    } catch {
      break;
    }
  }
  return raw;
}

function parseRefreshCookie(value) {
  let cookieName = "";
  let cookieValue = "";

  if (object(value) && /^REFRESH-/i.test(text(value.name)) && value.value !== undefined) {
    cookieName = text(value.name);
    cookieValue = text(value.value);
  } else if (typeof value === "string") {
    let raw = value.trim();
    raw = raw.replace(/^cookie\s*:\s*/i, "");
    const full = raw.match(/(?:^|;\s*)(REFRESH-[^=;\s]+)=([^;]+)/i);
    if (full) {
      cookieName = full[1];
      cookieValue = full[2];
    } else {
      cookieValue = raw;
    }
  } else {
    return null;
  }

  const decoded = decodeCookieValue(cookieValue);
  if (!decoded) return null;
  let payload;
  try { payload = JSON.parse(decoded); }
  catch { return null; }
  if (!object(payload) || !text(payload.UID ?? payload.uid) || !text(payload.RefreshToken ?? payload.refreshToken)) return null;

  const UID = text(payload.UID ?? payload.uid);
  if (cookieName) {
    const suffixUid = cookieName.replace(/^REFRESH-/i, "");
    if (suffixUid && suffixUid !== UID) throw new Error("REFRESH Cookie 名称中的 UID 与 Cookie 内容不一致");
  }
  return { input: payload, importMode: "browser_refresh_cookie" };
}

function parseImportedInput(value) {
  const cookie = parseRefreshCookie(value);
  if (cookie) return cookie;

  let current = value;
  if (typeof current === "string") {
    const raw = current.trim();
    if (!raw) throw new Error("Session / REFRESH Cookie 输入为空");
    try { current = JSON.parse(raw); }
    catch { throw new Error("输入既不是有效 Session JSON，也不是可识别的 REFRESH-* Cookie"); }
  }
  current = object(current);
  if (!current) throw new Error("Session 数据必须是 JSON 对象，或浏览器 REFRESH-* Cookie");

  if (/^REFRESH-/i.test(text(current.name)) && current.value !== undefined) {
    const parsed = parseRefreshCookie(current);
    if (parsed) return parsed;
  }

  for (const key of ["AuthResponse", "auth", "session", "data", "result", "response"]) {
    if (object(current[key]) && (current[key].UID || current[key].AccessToken || current[key].RefreshToken)) {
      current = current[key];
      break;
    }
  }
  const hasAccess = Boolean(text(current.AccessToken ?? current.accessToken));
  return { input: current, importMode: hasAccess ? "token_json" : "refresh_token_json" };
}

function normalizeParsedSession(parsed) {
  const input = parsed.input;
  const UID = text(input.UID ?? input.uid);
  const AccessToken = text(input.AccessToken ?? input.accessToken);
  const RefreshToken = text(input.RefreshToken ?? input.refreshToken);
  if (!UID) throw new Error("Session 缺少 UID");
  if (!RefreshToken) throw new Error("Session 缺少 RefreshToken");

  const session = { UID, RefreshToken };
  if (AccessToken) session.AccessToken = AccessToken;
  const stringFields = ["TokenType", "Scope", "UserID", "EventID"];
  for (const key of stringFields) {
    const value = text(input[key] ?? input[key.charAt(0).toLowerCase() + key.slice(1)]);
    if (value) session[key] = value;
  }
  const numericFields = ["ExpiresIn", "ExpiresAt", "PasswordMode", "LocalID", "TwoFactor"];
  for (const key of numericFields) {
    const value = number(input[key] ?? input[key.charAt(0).toLowerCase() + key.slice(1)]);
    if (value !== undefined) session[key] = value;
  }
  if (object(input["2FA"])) session["2FA"] = input["2FA"];
  return session;
}

export function normalizeImportedSession(value) {
  return normalizeParsedSession(parseImportedInput(value));
}

export function suffix(value, length = 6) {
  const raw = text(value);
  if (!raw) return null;
  return raw.length <= length ? raw : raw.slice(-length);
}

function addressesFromPayload(payload) {
  const rows = Array.isArray(payload?.Addresses) ? payload.Addresses : [];
  return rows.map((item) => text(item?.Email ?? item?.email).toLowerCase()).filter(Boolean);
}

async function validateCandidate(candidate, expectedEmail) {
  const payload = await candidate.raw("/core/v4/addresses", { auth: true });
  const addresses = addressesFromPayload(payload);
  if (!addresses.length) throw new Error("Proton Session 校验成功，但未返回可核对的邮箱地址");
  if (!addresses.includes(text(expectedEmail).toLowerCase())) {
    const error = new Error("导入的 Proton Session 与所选账号不匹配");
    error.sessionAccountMismatch = true;
    throw error;
  }
  return addresses.length;
}

export async function validateImportedSession(cfg, env, value) {
  const parsed = parseImportedInput(value);
  const imported = normalizeParsedSession(parsed);
  const candidate = new ProtonClient(cfg, env);
  candidate.setAuth(imported);
  let refreshedDuringValidation = false;
  let addressCount;

  if (!candidate.auth?.AccessToken) {
    await candidate.refreshAuthenticated();
    refreshedDuringValidation = true;
    addressCount = await validateCandidate(candidate, cfg.email);
  } else {
    try {
      addressCount = await validateCandidate(candidate, cfg.email);
    } catch (error) {
      if (Number(error?.status) !== 401 || !candidate.auth?.RefreshToken) throw error;
      await candidate.refreshAuthenticated();
      refreshedDuringValidation = true;
      addressCount = await validateCandidate(candidate, cfg.email);
    }
  }

  if (!candidate.auth?.UID || !candidate.auth?.AccessToken || !candidate.auth?.RefreshToken) {
    throw new Error("Proton Session 校验后缺少必要 Token");
  }
  return {
    auth: { ...candidate.auth },
    cookies: candidate.getCookieState(),
    safe: {
      account: cfg.id,
      importMode: parsed.importMode,
      emailMatched: true,
      addressCount,
      refreshedDuringValidation,
      uidSuffix: suffix(candidate.auth.UID),
      userIdSuffix: suffix(candidate.auth.UserID),
      expiresAt: candidate.auth.ExpiresAt || null,
      hasAccessToken: true,
      hasRefreshToken: true,
    },
  };
}
