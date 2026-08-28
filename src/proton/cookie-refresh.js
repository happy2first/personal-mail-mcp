import { ProtonClient } from "./client-v2.js";
import { cookieHeaderForUrl } from "./cookies.js";

const REFRESH_COOKIE_PATH = "/api/auth/refresh";

function fingerprintCookies(state) {
  return JSON.stringify((Array.isArray(state) ? state : []).map((cookie) => ({
    name: cookie?.name,
    value: cookie?.value,
    domain: cookie?.domain,
    path: cookie?.path,
    expiresAt: cookie?.expiresAt ?? null,
  })));
}

function dedupeRefreshCookies(state) {
  const rows = Array.isArray(state) ? state : [];
  const seen = new Set();
  const reversed = [];
  for (let i = rows.length - 1; i >= 0; i -= 1) {
    const cookie = rows[i];
    if (cookie?.path === REFRESH_COOKIE_PATH) {
      const name = String(cookie?.name || "");
      if (seen.has(name)) continue;
      seen.add(name);
    }
    reversed.push(cookie);
  }
  return reversed.reverse();
}

function cookieNames(header) {
  return String(header || "")
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => part.slice(0, Math.max(0, part.indexOf("="))).trim())
    .filter(Boolean);
}

const originalBaseHeaders = ProtonClient.prototype.baseHeaders;
ProtonClient.prototype.baseHeaders = function baseHeadersWithoutEmptyJsonContentType() {
  const headers = originalBaseHeaders.call(this);
  if (this.__protonCookieRefreshNoContentType) {
    delete headers["content-type"];
    delete headers["Content-Type"];
  }
  return headers;
};

const originalRefreshAuthenticated = ProtonClient.prototype.refreshAuthenticated;

ProtonClient.prototype.refreshAuthenticated = async function refreshAuthenticatedWithCookiePreservation() {
  const cookieAuth = Boolean(this.auth?.cookies);
  const previousAuth = this.auth ? { ...this.auth } : null;
  const previousCookies = this.getCookieState();
  const refreshUrl = `${this.baseUrl}/auth/refresh`;
  const refreshCookieHeader = cookieAuth ? cookieHeaderForUrl(previousCookies, refreshUrl) : "";
  const sentCookieNames = cookieNames(refreshCookieHeader);
  const startedAt = Date.now();
  const previousNoContentTypeFlag = this.__protonCookieRefreshNoContentType;
  try {
    if (cookieAuth) this.__protonCookieRefreshNoContentType = true;
    const result = await originalRefreshAuthenticated.call(this);
    const rawNextCookies = this.getCookieState();
    const nextCookies = cookieAuth ? dedupeRefreshCookies(rawNextCookies) : rawNextCookies;
    if (fingerprintCookies(rawNextCookies) !== fingerprintCookies(nextCookies)) {
      this.setCookieState(nextCookies);
      if (this.cookiePersistence) await this.cookiePersistence(this.getCookieState());
    }
    this.lastRefreshInfo = {
      attemptedAt: startedAt,
      completedAt: Date.now(),
      success: true,
      cookieAuth,
      cookiesUpdated: fingerprintCookies(previousCookies) !== fingerprintCookies(nextCookies),
      sentCookieNames,
      sentCookieCount: sentCookieNames.length,
      contentTypeOmitted: cookieAuth,
    };
    return result;
  } catch (error) {
    if (cookieAuth && previousAuth?.UID && error?.reauthRequired) {
      this.setAuth(previousAuth);
      this.setCookieState(previousCookies);
      if (this.cookiePersistence) await this.cookiePersistence(this.getCookieState()).catch(() => {});
      error.preserveSession = true;
      error.refreshFailed = true;
    }
    this.lastRefreshInfo = {
      attemptedAt: startedAt,
      completedAt: Date.now(),
      success: false,
      cookieAuth,
      protonCode: Number(error?.protonCode) || null,
      requestPath: error?.requestPath || "/auth/refresh",
      requestMethod: error?.requestMethod || "POST",
      sentCookieNames,
      sentCookieCount: sentCookieNames.length,
      contentTypeOmitted: cookieAuth,
    };
    throw error;
  } finally {
    this.__protonCookieRefreshNoContentType = previousNoContentTypeFlag;
  }
};

export { dedupeRefreshCookies };
