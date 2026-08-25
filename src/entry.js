import { createRemoteJWKSet, jwtVerify } from "jose";
import legacyWorker from "./index.js";
import { getAccount, listAccountIds } from "./mail-config.js";
import {
  isProtonAccount,
  protonAuthStatus,
  protonForward,
  protonGetAttachment,
  protonPollEvents,
  protonReauthorize,
  protonReply,
  protonResetRisk,
  protonSaveDraft,
  protonSend,
  protonSetState,
  protonSubmit2FA,
  protonTransfer,
} from "./proton/provider.js";
import { handleProtonImport } from "./proton/import-page.js";
import { handleProtonVerification } from "./proton/verify.js";
export { ProtonSession } from "./proton/session.js";

const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;
const MAX_OUTGOING_ATTACHMENTS = 10 * 1024 * 1024;

function must(v, n) {
  if (v === undefined || v === null || String(v).trim() === "") throw new Error(`缺少配置：${n}`);
  return v;
}

async function verifyAccess(request, env) {
  const team = String(must(env.TEAM_DOMAIN, "TEAM_DOMAIN")).replace(/\/$/, "");
  const aud = must(env.POLICY_AUD, "POLICY_AUD");
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) throw new Error("缺少 Cloudflare Access JWT");
  const JWKS = createRemoteJWKSet(new URL(`${team}/cdn-cgi/access/certs`));
  return (await jwtVerify(token, JWKS, { issuer: team, audience: aud })).payload;
}

function decodeMessageRef(ref) {
  try {
    const parsed = JSON.parse(Buffer.from(String(ref), "base64url").toString("utf8"));
    if (!parsed || typeof parsed.a !== "string" || typeof parsed.f !== "string") throw new Error("invalid");
    if (typeof parsed.i === "string" && parsed.i.length > 0) return { account: parsed.a, folder: parsed.f, messageId: parsed.i };
    if (Number.isInteger(parsed.u) && parsed.u > 0) return { account: parsed.a, folder: parsed.f, uid: parsed.u };
    throw new Error("invalid");
  } catch {
    throw new Error("messageRef 无效");
  }
}

function encodeMessageRef(account, folder, messageId) {
  return Buffer.from(JSON.stringify({ a: account, f: folder, i: String(messageId) }), "utf8").toString("base64url");
}

function targetFromArgs(args, defaultFolder = "INBOX") {
  if (args?.messageRef) return decodeMessageRef(args.messageRef);
  if (!args?.account) throw new Error("必须提供 messageRef 或 account");
  return { account: args.account, folder: args.folder || args.sourceFolder || defaultFolder, uid: args.uid };
}

function buildAttachments(items = []) {
  let total = 0;
  const out = (items || []).map((a) => {
    const content = Uint8Array.from(Buffer.from(String(a.base64 || ""), "base64"));
    if (content.length > MAX_ATTACHMENT_BYTES) throw new Error(`附件 ${a.filename || "未命名"} 超过 5MB`);
    total += content.length;
    return { filename: a.filename || "attachment", contentType: a.contentType || undefined, content };
  });
  if (total > MAX_OUTGOING_ATTACHMENTS) throw new Error("附件总大小超过 10MB");
  return out;
}

function textContent(data, isError = false) {
  return {
    content: [{ type: "text", text: typeof data === "string" ? data : JSON.stringify(data, null, 2) }],
    ...(isError ? { isError: true } : {}),
  };
}

function errorData(error) {
  const out = { error: error instanceof Error ? error.message : String(error) };
  for (const key of [
    "protonCode", "retryAfterSeconds", "circuitOpen", "manualResetRequired",
    "twoFactorRequired", "reauthRequired", "mailboxPasswordRequired",
    "humanVerificationRequired", "humanVerificationMethods", "verificationUrl", "verificationState",
  ]) if (error?.[key] !== undefined) out[key] = error[key];
  return out;
}

function rpc(id, result) {
  return Response.json({ jsonrpc: "2.0", id, result });
}

function protonAuthTool() {
  return {
    name: "mail_proton_auth",
    description: "[Proton] 查看认证状态、人工重新授权、提交 TOTP 2FA 或重置 2028 风控。定时任务不会自动执行密码重新登录；Session 也可通过受 Access 保护的 /proton/import 管理。",
    inputSchema: {
      type: "object",
      properties: {
        account: { type: "string", minLength: 1, description: "Proton 邮箱账号 ID" },
        action: { type: "string", enum: ["status", "reauthorize", "submit_2fa", "reset_risk"] },
        twoFactorCode: { type: "string", description: "action=submit_2fa 时填写当前 TOTP 验证码" },
      },
      required: ["account", "action"],
      additionalProperties: false,
    },
  };
}

function protonPollTool() {
  return {
    name: "mail_proton_poll_changes",
    description: "[只读] 使用 Proton EventID 增量游标读取变化；首次调用只初始化游标，不回扫历史邮件。account 不填默认扫描全部 Proton 账号。",
    inputSchema: {
      type: "object",
      properties: { account: { type: "string", description: "Proton 邮箱账号 ID；不填或 all 表示全部 Proton 账号" } },
      additionalProperties: false,
    },
  };
}

function reviseToolDescriptions(tools) {
  const replacements = {
    mail_get_attachment: "[只读] 获取邮件附件并以 Base64 返回，单附件最多 5MB；支持 IMAP 与 Proton。",
    mail_set_state: "[写] 修改具体邮件状态：已读、未读、加星、取消星标；支持 IMAP 与 Proton。",
    mail_transfer: "[写] 复制或移动具体邮件，可用于归档；禁止目标为已删除/Trash；支持 IMAP 与 Proton。",
    mail_send: "[高风险写] 从明确指定的邮箱账号发送新邮件；支持 IMAP/SMTP 与 Proton API。",
    mail_reply: "[高风险写] 回复或回复全部；支持 IMAP/SMTP 与 Proton API。",
    mail_forward: "[高风险写] 转发具体邮件；支持 IMAP/SMTP 与 Proton API。",
    mail_save_draft: "[写] 保存草稿但不发送；支持 IMAP 与 Proton API。",
  };
  return tools.map((tool) => replacements[tool.name] ? { ...tool, description: replacements[tool.name] } : tool);
}

async function protonAccount(env, account) {
  const cfg = getAccount(env, account);
  if (!isProtonAccount(cfg)) return null;
  return cfg;
}

async function pollAll(env, requested) {
  const ids = String(requested || "all").toLowerCase() === "all" ? listAccountIds(env) : [requested];
  const changes = [];
  const errors = [];
  for (const id of ids) {
    try {
      const cfg = getAccount(env, id);
      if (!isProtonAccount(cfg)) continue;
      changes.push({ account: cfg.id, accountLabel: cfg.label, ...(await protonPollEvents(env, cfg)) });
    } catch (error) {
      errors.push({ account: id, ...errorData(error) });
    }
  }
  return { changes, errors };
}

async function handleProtonTool(name, args, env) {
  if (name === "mail_proton_auth") {
    const cfg = await protonAccount(env, args.account);
    if (!cfg) throw new Error("mail_proton_auth 仅适用于 Proton 账号");
    if (args.action === "status") return protonAuthStatus(env, cfg);
    if (args.action === "reauthorize") return protonReauthorize(env, cfg);
    if (args.action === "reset_risk") return protonResetRisk(env, cfg);
    if (args.action === "submit_2fa") {
      if (!args.twoFactorCode) throw new Error("submit_2fa 必须提供 twoFactorCode");
      return protonSubmit2FA(env, cfg, args.twoFactorCode);
    }
    throw new Error(`未知 Proton auth action：${args.action}`);
  }
  if (name === "mail_proton_poll_changes") return pollAll(env, args.account);

  if (name === "mail_send") {
    const cfg = await protonAccount(env, args.account);
    if (!cfg) return null;
    return protonSend(env, cfg, { ...args, attachments: buildAttachments(args.attachments) });
  }
  if (name === "mail_save_draft") {
    const cfg = await protonAccount(env, args.account);
    if (!cfg) return null;
    return protonSaveDraft(env, cfg, { ...args, attachments: buildAttachments(args.attachments) });
  }

  const target = targetFromArgs(args);
  const cfg = await protonAccount(env, target.account);
  if (!cfg) return null;
  if (!target.messageId) throw new Error("Proton 具体邮件操作必须使用 mail_list_messages 返回的 messageRef");

  if (name === "mail_get_attachment") {
    const data = await protonGetAttachment(env, cfg, target.messageId, args.attachmentIndex);
    return { ...data, messageRef: encodeMessageRef(cfg.id, target.folder, target.messageId) };
  }
  if (name === "mail_set_state") return protonSetState(env, cfg, target.messageId, args.action);
  if (name === "mail_transfer") return protonTransfer(env, cfg, target.messageId, target.folder, args.targetFolder, args.action);
  if (name === "mail_reply") {
    return protonReply(env, cfg, target.messageId, {
      folder: target.folder,
      replyAll: Boolean(args.replyAll),
      text: args.text,
      html: args.html,
      cc: args.cc || [],
      attachments: buildAttachments(args.attachments),
    });
  }
  if (name === "mail_forward") {
    return protonForward(env, cfg, target.messageId, {
      folder: target.folder,
      to: args.to || [], cc: args.cc || [], bcc: args.bcc || [],
      note: args.note || "",
      includeOriginalAttachments: Boolean(args.includeOriginalAttachments),
    });
  }
  return null;
}

const INTERCEPTED = new Set([
  "mail_get_attachment", "mail_set_state", "mail_transfer", "mail_send", "mail_reply",
  "mail_forward", "mail_save_draft", "mail_proton_auth", "mail_proton_poll_changes",
]);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/proton/import" || url.pathname.startsWith("/proton/import/api/")) {
      try {
        const actor = await verifyAccess(request, env);
        const response = await handleProtonImport(request, env, actor);
        if (response) return response;
      } catch (error) {
        return Response.json({ error: "access_denied", message: error instanceof Error ? error.message : String(error) }, {
          status: 401,
          headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
        });
      }
    }

    const verify = await handleProtonVerification(request, env);
    if (verify) return verify;

    if (url.pathname === "/") {
      return Response.json({ ok: true, service: "personal-mail-mcp", version: "1.4.0", protonLifecycle: "v3-session-import" });
    }
    if (url.pathname !== "/mcp" || request.method !== "POST") return legacyWorker.fetch(request, env, ctx);

    let message;
    try { message = await request.clone().json(); }
    catch { return legacyWorker.fetch(request, env, ctx); }

    if (message?.method === "tools/list") {
      const response = await legacyWorker.fetch(request, env, ctx);
      try {
        const payload = await response.clone().json();
        if (payload?.result?.tools) {
          const names = new Set(payload.result.tools.map((x) => x.name));
          payload.result.tools = reviseToolDescriptions(payload.result.tools);
          if (!names.has("mail_proton_auth")) payload.result.tools.push(protonAuthTool());
          if (!names.has("mail_proton_poll_changes")) payload.result.tools.push(protonPollTool());
          return Response.json(payload, { status: response.status, headers: { "cache-control": "no-store" } });
        }
      } catch { /* delegate unchanged */ }
      return response;
    }

    const name = message?.params?.name;
    if (message?.method !== "tools/call" || !INTERCEPTED.has(name)) return legacyWorker.fetch(request, env, ctx);

    try {
      await verifyAccess(request, env);
      const args = message?.params?.arguments || {};
      const data = await handleProtonTool(name, args, env);
      if (data === null) return legacyWorker.fetch(request, env, ctx);
      return rpc(message.id, textContent(data));
    } catch (error) {
      return rpc(message.id, textContent(errorData(error), true));
    }
  },
};
