import { WorkerImapClient } from "./mail-sockets.js";

const PATCH_FLAG = Symbol.for("personal-mail-mcp.netease-imap-id-patched");
const originalConnect = WorkerImapClient.prototype.connect;

if (!WorkerImapClient.prototype[PATCH_FLAG]) {
  Object.defineProperty(WorkerImapClient.prototype, PATCH_FLAG, {
    value: true,
    enumerable: false,
    configurable: false,
    writable: false,
  });

  WorkerImapClient.prototype.connect = async function connectWithNeteaseId() {
    await originalConnect.call(this);

    const host = String(this.options?.host || "").toLowerCase();
    if (host !== "imap.163.com") return;

    const idCommand = 'ID ("name" "personal-mail-mcp" "version" "1.1.0" "vendor" "happy2first")';
    await this.command(idCommand, { operation: "ID" });

    console.info(JSON.stringify({
      component: "imap",
      stage: "client_identified",
      provider: "163",
      host,
    }));
  };
}
