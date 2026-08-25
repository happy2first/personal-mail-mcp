import { ProtonClient } from "./client-v2.js";

function object(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function unwrapSession(value) {
  let current = value;
  if (typeof current === "string") {
    const text = current.trim();
    if (!text) throw new Error("Session JSON 为空");
    try { current = JSON.parse(text); }
    catch { throw new Error("Session JSON 不是有效 JSON"); }
  }
  current = object(current);
  if (!current) throw new Error("Session 数据必须是 JSON 对象");
  for (const key of ["AuthResponse", "auth", "session", "data", "result", "response"]) {
    if (object(current[key]) && (current[key].UID || current[key].AccessToken || current[key].RefreshToken)) {
      current = current[key];
      break;
    }
  }
  return current;
}

function text(value) {
  return value === undefined || value === null ? "" : String(value).trim();
}

function number(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

export function normalizeImportedSession(value) {
  const input = unwrapSession(value);
  const UID = text(input.UID ?? input.uid);
  const AccessToken = text(input.AccessToken ?? input.accessToken);
  const RefreshToken = text(input.RefreshToken ?? input.refreshToken);
  if (!UID) throw new Error("Session 缺少 UID");
  if (!AccessToken) throw new Error("Session 缺少 AccessToken");
  if (!RefreshToken) throw new Error("Session 缺少 RefreshToken");

  const session = {
    UID,
    AccessToken,
    RefreshToken,
  };
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

export async function validateImportedSession(cfg, env, input) {
  const imported = normalizeImportedSession(input);
  const candidate = new ProtonClient(cfg, env);
  candidate.setAuth(imported);
  let refreshedDuringValidation = false;
  let addressCount;
  try {
    addressCount = await validateCandidate(candidate, cfg.email);
  } catch (error) {
    if (Number(error?.status) !== 401 || !candidate.auth?.RefreshToken) throw error;
    await candidate.refreshAuthenticated();
    refreshedDuringValidation = true;
    addressCount = await validateCandidate(candidate, cfg.email);
  }
  if (!candidate.auth?.UID || !candidate.auth?.AccessToken || !candidate.auth?.RefreshToken) {
    throw new Error("Proton Session 校验后缺少必要 Token");
  }
  return {
    auth: { ...candidate.auth },
    cookies: candidate.getCookieState(),
    safe: {
      account: cfg.id,
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
