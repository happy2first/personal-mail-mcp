import { ProtonSession } from "./session.js";
import { normalizeKeySalts } from "./key-material.js";

const list = (value) => Array.isArray(value) ? value : [];
const bool = (value) => value === true || value === 1;

const originalAuthStatus = ProtonSession.prototype.authStatus;
ProtonSession.prototype.authStatus = async function authStatusWithKeyMaterial(client) {
  const status = await originalAuthStatus.call(this, client);
  const cookieAuth = Boolean(client.auth?.cookies);
  const keySaltCount = normalizeKeySalts({ KeySalts: client.auth?.KeySalts })?.length || 0;
  status.hasSession = Boolean(client.auth?.UID && (cookieAuth || client.auth?.RefreshToken));
  if (status.session) {
    status.session.cookieAuth = cookieAuth;
    status.session.hasRefreshToken = !cookieAuth && Boolean(client.auth?.RefreshToken);
    status.session.keySaltCount = keySaltCount;
  }
  status.keyMaterial = { keySaltCount, imported: keySaltCount > 0 };
  return status;
};

const originalFetch = ProtonSession.prototype.fetch;
ProtonSession.prototype.fetch = async function fetchWithKeySaltImport(request) {
  if (request.method === "POST") {
    const parsed = await request.clone().json().catch(() => null);
    const account = String(parsed?.account || "").trim();
    const action = String(parsed?.action || "").trim();
    const salts = action === "importSession" ? normalizeKeySalts(parsed?.payload?.session) : null;
    if (account && salts?.length) {
      try {
        const client = this.getClient(account);
        await this.hydrate(client);
        if (!client.auth?.UID || !client.auth?.cookies) {
          throw new Error("请先导入并验证浏览器 Cookie Session，再导入 KeySalt");
        }
        const userPayload = await client.request("/core/v4/users");
        const activeIds = new Set(list(userPayload?.User?.Keys).filter((item) => bool(item.Active)).map((item) => String(item.ID)));
        const matched = salts.filter((item) => activeIds.has(String(item.ID)));
        if (!matched.length) {
          const error = new Error("KeySalt 与所选 Proton 账号的用户主密钥不匹配");
          error.sessionAccountMismatch = true;
          throw error;
        }
        client.setAuth({ ...client.auth, KeySalts: salts });
        await this.persistClient(client);
        await this.writeSessionMeta(client, { keySaltsImportedAt: Date.now(), keySaltCount: salts.length });
        return Response.json({
          ok: true,
          data: {
            success: true,
            imported: true,
            account,
            importMode: "key_salts_json",
            keySaltCount: salts.length,
            matchedKeySaltCount: matched.length,
            cookieAuth: true,
          },
        });
      } catch (error) {
        return Response.json({
          ok: false,
          error: error instanceof Error ? error.message : String(error),
          sessionAccountMismatch: Boolean(error?.sessionAccountMismatch),
        }, { status: 400 });
      }
    }
  }
  return originalFetch.call(this, request);
};
