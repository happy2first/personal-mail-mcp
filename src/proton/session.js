import { getAccount } from "../mail-config.js";
import { ProtonClient } from "./client.js";

const RISK_BLOCK_KEY = "proton:2028:blockedUntil";
const RISK_COOLDOWN_MS = 30 * 60 * 1000;

function riskBlockError(blockedUntil) {
  const retryAfterSeconds = Math.max(1, Math.ceil((blockedUntil - Date.now()) / 1000));
  const error = new Error(`Proton 2028 风控熔断中：为避免重复登录，请约 ${retryAfterSeconds} 秒后再试`);
  error.protonCode = 2028;
  error.retryAfterSeconds = retryAfterSeconds;
  error.circuitOpen = true;
  return error;
}

export class ProtonSession {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.client = null;
    this.accountId = null;
  }

  getClient(accountId) {
    const cfg = getAccount(this.env, accountId);
    if (cfg.provider !== "proton") throw new Error(`账号 ${cfg.id} 不是 Proton Provider`);
    if (!this.client || this.accountId?.toLowerCase() !== cfg.id.toLowerCase()) {
      this.client = new ProtonClient(cfg, this.env);
      this.accountId = cfg.id;
    }
    return this.client;
  }

  async assertRiskCircuitClosed() {
    const blockedUntil = Number((await this.state.storage.get(RISK_BLOCK_KEY)) || 0);
    if (!blockedUntil) return;
    if (blockedUntil <= Date.now()) {
      await this.state.storage.delete(RISK_BLOCK_KEY);
      return;
    }
    throw riskBlockError(blockedUntil);
  }

  async rememberRiskBlock(error) {
    if (Number(error?.protonCode) !== 2028 || error?.circuitOpen) return;
    const blockedUntil = Number(error?.blockedUntil) || (Date.now() + RISK_COOLDOWN_MS);
    await this.state.storage.put(RISK_BLOCK_KEY, blockedUntil);
  }

  async fetch(request) {
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
    try {
      await this.assertRiskCircuitClosed();
      const body = await request.json();
      const account = String(body?.account || "").trim();
      const action = String(body?.action || "").trim();
      const payload = body?.payload || {};
      if (!account) throw new Error("缺少 Proton account");
      const client = this.getClient(account);

      let data;
      if (action === "test") data = await client.testConnection();
      else if (action === "listMessages") data = await client.listMessages(payload);
      else if (action === "searchMessages") data = await client.searchMessages(payload);
      else if (action === "getMessage") data = await client.getMessage(payload.messageId, payload.folder);
      else if (action === "listFolders") data = client.listFolders();
      else if (action === "folderStatus") data = await client.folderStatus(payload.folder);
      else throw new Error(`未知 Proton action：${action}`);

      return Response.json({ ok: true, data });
    } catch (error) {
      await this.rememberRiskBlock(error);
      console.error("ProtonSession:", error?.message || String(error));
      const protonCode = Number(error?.protonCode) || undefined;
      const retryAfterSeconds = Number(error?.retryAfterSeconds) || undefined;
      return Response.json({
        ok: false,
        error: error instanceof Error ? error.message : String(error),
        ...(protonCode ? { protonCode } : {}),
        ...(retryAfterSeconds ? { retryAfterSeconds } : {}),
      }, { status: protonCode === 2028 ? 429 : 400 });
    }
  }
}
