import { ProtonClient } from "./client-v2.js";

function fingerprintCookies(state) {
  return JSON.stringify((Array.isArray(state) ? state : []).map((cookie) => ({
    name: cookie?.name,
    value: cookie?.value,
    domain: cookie?.domain,
    path: cookie?.path,
    expiresAt: cookie?.expiresAt ?? null,
  })));
}

const originalRefreshAuthenticated = ProtonClient.prototype.refreshAuthenticated;

ProtonClient.prototype.refreshAuthenticated = async function refreshAuthenticatedWithCookiePreservation() {
  const cookieAuth = Boolean(this.auth?.cookies);
  const previousAuth = this.auth ? { ...this.auth } : null;
  const previousCookies = this.getCookieState();
  const startedAt = Date.now();
  try {
    const result = await originalRefreshAuthenticated.call(this);
    const nextCookies = this.getCookieState();
    this.lastRefreshInfo = {
      attemptedAt: startedAt,
      completedAt: Date.now(),
      success: true,
      cookieAuth,
      cookiesUpdated: fingerprintCookies(previousCookies) !== fingerprintCookies(nextCookies),
    };
    return result;
  } catch (error) {
    if (cookieAuth && previousAuth?.UID && error?.reauthRequired) {
      this.setAuth(previousAuth);
      this.setCookieState(previousCookies);
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
    };
    throw error;
  }
};
