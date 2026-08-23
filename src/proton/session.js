import { getAccount } from "../mail-config.js";
import { ProtonClient } from "./client.js";

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

  async fetch(request) {
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
    try {
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
      console.error("ProtonSession:", error?.message || String(error));
      return Response.json({
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }, { status: 400 });
    }
  }
}
