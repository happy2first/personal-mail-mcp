const MAX_COOKIES = 64;
const MAX_COOKIE_BYTES = 8192;

function defaultPath(pathname) {
  const path = String(pathname || "/");
  if (!path.startsWith("/") || path === "/") return "/";
  const lastSlash = path.lastIndexOf("/");
  return lastSlash <= 0 ? "/" : path.slice(0, lastSlash);
}

function domainMatches(hostname, domain, hostOnly) {
  const host = String(hostname || "").toLowerCase();
  const normalized = String(domain || "").toLowerCase().replace(/^\./, "");
  if (!normalized) return false;
  return hostOnly ? host === normalized : host === normalized || host.endsWith(`.${normalized}`);
}

function pathMatches(pathname, cookiePath) {
  const path = String(pathname || "/");
  const target = String(cookiePath || "/");
  if (path === target) return true;
  if (!path.startsWith(target)) return false;
  return target.endsWith("/") || path.charAt(target.length) === "/";
}

function keyOf(cookie) {
  return `${cookie.name}\n${cookie.domain}\n${cookie.path}`;
}

function parseSetCookie(header, requestUrl, nowMs) {
  const text = String(header || "").trim();
  if (!text || text.length > MAX_COOKIE_BYTES) return null;
  const segments = text.split(";");
  const pair = segments.shift() || "";
  const eq = pair.indexOf("=");
  if (eq <= 0) return null;
  const name = pair.slice(0, eq).trim();
  const value = pair.slice(eq + 1).trim();
  if (!name) return null;

  const url = new URL(requestUrl);
  let domain = url.hostname.toLowerCase();
  let hostOnly = true;
  let path = defaultPath(url.pathname);
  let secure = false;
  let expiresAt = null;
  let maxAge = null;

  for (const raw of segments) {
    const part = raw.trim();
    if (!part) continue;
    const attrEq = part.indexOf("=");
    const attrName = (attrEq < 0 ? part : part.slice(0, attrEq)).trim().toLowerCase();
    const attrValue = attrEq < 0 ? "" : part.slice(attrEq + 1).trim();
    if (attrName === "domain" && attrValue) {
      const candidate = attrValue.toLowerCase().replace(/^\./, "");
      if (!domainMatches(url.hostname, candidate, false)) return null;
      domain = candidate;
      hostOnly = false;
    } else if (attrName === "path" && attrValue.startsWith("/")) {
      path = attrValue;
    } else if (attrName === "secure") {
      secure = true;
    } else if (attrName === "max-age") {
      const parsed = Number.parseInt(attrValue, 10);
      if (Number.isFinite(parsed)) maxAge = parsed;
    } else if (attrName === "expires") {
      const parsed = Date.parse(attrValue);
      if (Number.isFinite(parsed)) expiresAt = parsed;
    }
  }

  if (maxAge !== null) expiresAt = maxAge <= 0 ? 0 : nowMs + maxAge * 1000;
  return { name, value, domain, hostOnly, path, secure, expiresAt };
}

export function normalizeCookieState(state, nowMs = Date.now()) {
  const input = Array.isArray(state) ? state : [];
  const byKey = new Map();
  for (const raw of input) {
    const name = String(raw?.name || "").trim();
    const domain = String(raw?.domain || "").trim().toLowerCase().replace(/^\./, "");
    const path = String(raw?.path || "/");
    const value = String(raw?.value ?? "");
    const expiresAt = raw?.expiresAt == null ? null : Number(raw.expiresAt);
    if (!name || !domain || value.length > MAX_COOKIE_BYTES) continue;
    if (expiresAt !== null && Number.isFinite(expiresAt) && expiresAt <= nowMs) continue;
    const cookie = {
      name,
      value,
      domain,
      hostOnly: raw?.hostOnly !== false,
      path: path.startsWith("/") ? path : "/",
      secure: Boolean(raw?.secure),
      expiresAt: Number.isFinite(expiresAt) ? expiresAt : null,
    };
    byKey.set(keyOf(cookie), cookie);
  }
  return [...byKey.values()].slice(-MAX_COOKIES);
}

export function mergeSetCookieHeaders(state, headers, requestUrl, nowMs = Date.now()) {
  const byKey = new Map(normalizeCookieState(state, nowMs).map((cookie) => [keyOf(cookie), cookie]));
  for (const header of Array.isArray(headers) ? headers : []) {
    const parsed = parseSetCookie(header, requestUrl, nowMs);
    if (!parsed) continue;
    const key = keyOf(parsed);
    if (parsed.expiresAt === 0 || (parsed.expiresAt !== null && parsed.expiresAt <= nowMs)) byKey.delete(key);
    else byKey.set(key, parsed);
  }
  return normalizeCookieState([...byKey.values()], nowMs);
}

export function cookieHeaderForUrl(state, requestUrl, nowMs = Date.now()) {
  const url = new URL(requestUrl);
  return normalizeCookieState(state, nowMs)
    .filter((cookie) => domainMatches(url.hostname, cookie.domain, cookie.hostOnly))
    .filter((cookie) => pathMatches(url.pathname, cookie.path))
    .filter((cookie) => !cookie.secure || url.protocol === "https:")
    .sort((a, b) => b.path.length - a.path.length)
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join("; ");
}

export function getSetCookieHeaders(headers) {
  if (!headers) return [];
  if (typeof headers.getSetCookie === "function") {
    const values = headers.getSetCookie();
    if (Array.isArray(values)) return values.filter(Boolean).map(String);
  }
  if (typeof headers.getAll === "function") {
    try {
      const values = headers.getAll("Set-Cookie");
      if (Array.isArray(values)) return values.filter(Boolean).map(String);
    } catch {}
  }
  const single = headers.get?.("set-cookie");
  return single ? [String(single)] : [];
}
