import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { simpleParser } from "mailparser";
import nodemailer from "nodemailer";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { z } from "zod";
import { WorkerImapClient, WorkerSmtpTransport } from "./mail-sockets.js";
import { getAccount, listAccountIds, listAccounts } from "./mail-config.js";
import {
  isProtonAccount,
  protonFolderStatus,
  protonGetMessage,
  protonListFolders,
  protonListMessages,
  protonSearchMessages,
  protonTestConnection,
} from "./proton/provider.js";
export { ProtonSession } from "./proton/session.js";

const MAX_MAIL_BYTES = 8 * 1024 * 1024;
const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;
const MAX_OUTGOING_ATTACHMENTS = 10 * 1024 * 1024;

const must = (v, n) => {
  if (v === undefined || v === null || String(v).trim() === "") throw new Error(`缺少配置：${n}`);
  return v;
};

const result = (data) => ({
  content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
});

function accountSchema({ all = false, required = false } = {}) {
  let schema = z.string().min(1).describe(
    all
      ? "邮箱账号 ID；查询全部已配置邮箱时使用 all。"
      : "邮箱账号 ID，可先调用 mail_list_accounts 获取。",
  );
  if (!required) schema = schema.optional();
  if (all && !required) schema = schema.default("all");
  return schema;
}

const queryAccount = accountSchema({ all: true });
const specificAccount = accountSchema({ required: true });
const optionalSpecificAccount = accountSchema();
const folder = z.string().min(1).optional().default("INBOX");
const uid = z.number().int().positive();
const optionalUid = uid.optional();
const messageRef = z.string().min(1).optional().describe("Worker 返回的邮件唯一引用，优先于 account/folder/uid。\n");
const emails = z.array(z.string().email()).min(1);
const optionalEmails = z.array(z.string().email()).optional();
const attachment = z.object({
  filename: z.string().min(1),
  contentType: z.string().optional(),
  base64: z.string().min(1),
});

function encodeMessageRef(account, folderName, messageId) {
  const payload = Number.isInteger(messageId)
    ? { a: account, f: folderName, u: messageId }
    : { a: account, f: folderName, i: String(messageId) };
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

function decodeMessageRef(ref) {
  try {
    const parsed = JSON.parse(Buffer.from(String(ref), "base64url").toString("utf8"));
    if (!parsed || typeof parsed.a !== "string" || typeof parsed.f !== "string") throw new Error("invalid");
    if (Number.isInteger(parsed.u) && parsed.u > 0) {
      return { account: parsed.a, folder: parsed.f, uid: parsed.u };
    }
    if (typeof parsed.i === "string" && parsed.i.length > 0) {
      return { account: parsed.a, folder: parsed.f, messageId: parsed.i };
    }
    throw new Error("invalid");
  } catch {
    throw new Error("messageRef 无效");
  }
}

function resolveMessageTarget(p, defaultFolder = "INBOX") {
  if (p.messageRef) return decodeMessageRef(p.messageRef);
  if (!p.account) throw new Error("必须提供 messageRef 或 account");
  if (!p.uid) throw new Error("必须提供 messageRef 或 uid");
  if (String(p.account).toLowerCase() === "all") throw new Error("具体邮件操作不能使用 account=all");
  return { account: p.account, folder: p.folder || p.sourceFolder || defaultFolder, uid: p.uid };
}

function addresses(list) {
  return (list || []).map((x) => ({ name: x.name || "", address: x.address || "" }));
}

function normalize(message, cfg, folderName) {
  const messageUid = message.uid;
  return {
    account: cfg.id,
    accountLabel: cfg.label,
    provider: cfg.provider,
    folder: folderName,
    uid: messageUid,
    messageRef: encodeMessageRef(cfg.id, folderName, messageUid),
    subject: message.envelope?.subject || "",
    from: addresses(message.envelope?.from),
    to: addresses(message.envelope?.to),
    cc: addresses(message.envelope?.cc),
    date: message.envelope?.date?.toISOString?.() || message.internalDate?.toISOString?.() || null,
    size: message.size || 0,
    flags: message.flags ? Array.from(message.flags) : [],
  };
}

function normalizeProtonMessages(messages, cfg, folderName) {
  return (messages || []).map((message) => ({
    ...message,
    messageRef: encodeMessageRef(cfg.id, folderName, message.protonId),
  }));
}

function sortMessages(messages) {
  return messages.sort((a, b) => {
    const at = a.date ? new Date(a.date).getTime() : 0;
    const bt = b.date ? new Date(b.date).getTime() : 0;
    return bt - at;
  });
}

async function withImapConfig(cfg, fn) {
  if (isProtonAccount(cfg)) throw new Error("Proton 当前仅支持只读收件能力，不提供 IMAP 写操作");
  const client = new WorkerImapClient({
    host: cfg.imap.host,
    port: cfg.imap.port,
    security: cfg.imap.security,
    auth: { user: cfg.email, pass: cfg.credential },
    logger: false,
    disableAutoIdle: true,
    connectionTimeout: 15000,
    greetingTimeout: 10000,
    socketTimeout: 30000,
  });
  client.on("error", (e) => console.error("IMAP:", e?.message || String(e)));
  await client.connect();
  try {
    return await fn(client, cfg);
  } finally {
    try { await client.logout(); }
    catch { await client.close(); }
  }
}

async function withImap(env, accountId, fn) {
  return withImapConfig(getAccount(env, accountId), fn);
}

function smtpConfig(cfg) {
  if (isProtonAccount(cfg)) throw new Error("Proton 当前仅支持只读收件能力，不提供 SMTP 发信");
  return new WorkerSmtpTransport({
    host: cfg.smtp.host,
    port: cfg.smtp.port,
    security: cfg.smtp.security,
    email: cfg.email,
    credential: cfg.credential,
  });
}

function smtp(env, accountId) {
  const cfg = getAccount(env, accountId);
  return { cfg, transporter: smtpConfig(cfg) };
}

async function mapLimit(items, limit, fn) {
  const output = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      output[index] = await fn(items[index], index);
    }
  });
  await Promise.all(workers);
  return output;
}

async function forAccounts(env, accountId, fn) {
  const requested = String(accountId || "all");
  if (requested.toLowerCase() !== "all") {
    const cfg = getAccount(env, requested);
    return { all: false, value: await fn(cfg) };
  }

  const ids = listAccountIds(env);
  if (!ids.length) throw new Error("未配置任何邮箱账号");
  const settled = await mapLimit(ids, 4, async (id) => {
    try {
      const cfg = getAccount(env, id);
      return { ok: true, id: cfg.id, label: cfg.label, value: await fn(cfg) };
    } catch (error) {
      return { ok: false, id, error: error instanceof Error ? error.message : String(error) };
    }
  });
  return {
    all: true,
    values: settled.filter((x) => x.ok),
    errors: settled.filter((x) => !x.ok).map((x) => ({ account: x.id, error: x.error })),
  };
}

function parseDate(v, n) {
  if (!v) return undefined;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) throw new Error(`${n} 日期无效`);
  return d;
}

function buildAttachments(items = []) {
  let total = 0;
  const out = items.map((a) => {
    const content = Buffer.from(a.base64, "base64");
    if (content.length > MAX_ATTACHMENT_BYTES) throw new Error(`附件 ${a.filename} 超过 5MB`);
    total += content.length;
    return { filename: a.filename, contentType: a.contentType || undefined, content };
  });
  if (total > MAX_OUTGOING_ATTACHMENTS) throw new Error("附件总大小超过 10MB");
  return out;
}

const addrValues = (x) => (x?.value || []).map((v) => v.address).filter(Boolean);

function dedupe(list, own) {
  const seen = new Set();
  const out = [];
  const me = own.toLowerCase();
  for (const x of list || []) {
    const v = String(x || "").trim();
    const k = v.toLowerCase();
    if (v && k !== me && !seen.has(k)) {
      seen.add(k);
      out.push(v);
    }
  }
  return out;
}

async function readParsed(client, folderName, messageUid) {
  const lock = await client.getMailboxLock(folderName, { readOnly: true });
  try {
    const meta = await client.fetchOne(messageUid, {
      uid: true, envelope: true, flags: true, size: true, internalDate: true,
    }, { uid: true });
    if (!meta) throw new Error(`找不到 UID=${messageUid}`);
    if ((meta.size || 0) > MAX_MAIL_BYTES) throw new Error("邮件原文超过 8MB；本版不读取完整原文");
    const full = await client.fetchOne(messageUid, {
      uid: true, envelope: true, flags: true, size: true, internalDate: true, source: true,
    }, { uid: true });
    if (!full || !full.source) throw new Error("无法读取邮件原文");
    return { message: full, parsed: await simpleParser(full.source) };
  } finally {
    lock.release();
  }
}

function isDeleteFolder(f) {
  return f?.specialUse === "\\Trash" || /trash|deleted|已删除|废纸篓|垃圾桶/i.test(String(f?.path || ""));
}

async function blockDeleteDestination(client, path) {
  const folders = await client.list();
  const f = folders.find((x) => x.path === path);
  if (isDeleteFolder(f) || /trash|deleted|已删除|废纸篓|垃圾桶/i.test(path)) {
    throw new Error("删除能力已禁用：禁止移动或复制到删除类文件夹");
  }
}

async function verifyAccess(request, env) {
  const team = String(must(env.TEAM_DOMAIN, "TEAM_DOMAIN")).replace(/\/$/, "");
  const aud = must(env.POLICY_AUD, "POLICY_AUD");
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) throw new Error("缺少 Cloudflare Access JWT");
  const JWKS = createRemoteJWKSet(new URL(`${team}/cdn-cgi/access/certs`));
  return (await jwtVerify(token, JWKS, { issuer: team, audience: aud })).payload;
}

async function listMessagesForAccount(env, cfg, folderName, limit) {
  if (isProtonAccount(cfg)) {
    return normalizeProtonMessages(await protonListMessages(env, cfg, folderName, limit), cfg, folderName);
  }
  return withImapConfig(cfg, async (c) => {
    const lock = await c.getMailboxLock(folderName, { readOnly: true });
    try {
      if (!c.mailbox?.exists) return [];
      const rows = await c.fetchAll(`:-${limit}`, {
        uid: true, envelope: true, flags: true, size: true, internalDate: true,
      });
      return rows.map((m) => normalize(m, cfg, folderName)).reverse();
    } finally {
      lock.release();
    }
  });
}

async function searchMessagesForAccount(env, cfg, p) {
  if (isProtonAccount(cfg)) {
    return normalizeProtonMessages(await protonSearchMessages(env, cfg, p), cfg, p.folder);
  }
  return withImapConfig(cfg, async (c) => {
    const lock = await c.getMailboxLock(p.folder, { readOnly: true });
    try {
      const q = {};
      if (p.text) q.or = [{ subject: p.text }, { from: p.text }, { to: p.text }, { body: p.text }];
      if (p.from) q.from = p.from;
      if (p.to) q.to = p.to;
      if (p.subject) q.subject = p.subject;
      if (p.since) q.since = parseDate(p.since, "since");
      if (p.before) q.before = parseDate(p.before, "before");
      if (typeof p.seen === "boolean") q.seen = p.seen;
      if (typeof p.starred === "boolean") q.flagged = p.starred;
      if (!Object.keys(q).length) q.all = true;
      const uids = await c.search(q, { uid: true });
      if (!Array.isArray(uids) || !uids.length) return [];
      const rows = await c.fetchAll(uids.slice(-p.limit), {
        uid: true, envelope: true, flags: true, size: true, internalDate: true,
      }, { uid: true });
      return rows.map((m) => normalize(m, cfg, p.folder)).reverse();
    } finally {
      lock.release();
    }
  });
}

function createServer(env) {
  const s = new McpServer({ name: "personal-mail-mcp", version: "1.2.0" });

  s.registerTool("mail_list_accounts", {
    description: "[只读] 列出当前 Worker 已配置的邮箱账号及 Provider，不返回邮箱地址、密码或授权码。",
    inputSchema: {},
  }, async () => result(listAccounts(env)));

  s.registerTool("mail_test_connection", {
    description: "[只读] 测试一个或全部邮箱账号连接；IMAP/SMTP 账号验证登录，Proton 验证 Proton API 登录。account 不填时默认 all。",
    inputSchema: { account: queryAccount },
  }, async ({ account }) => {
    const run = await forAccounts(env, account, async (cfg) => {
      if (isProtonAccount(cfg)) return protonTestConnection(env, cfg);
      const imap = await withImapConfig(cfg, async (c) => ({
        authenticated: !!c.authenticated,
        secure: c.secureConnection,
        capabilities: Array.from(c.capabilities.keys()),
      }));
      const transporter = smtpConfig(cfg);
      await transporter.verify();
      return {
        success: true,
        account: cfg.id,
        accountLabel: cfg.label,
        provider: cfg.provider,
        imap,
        smtp: { verified: true },
      };
    });
    if (!run.all) return result(run.value);
    return result({ accounts: run.values.map((x) => x.value), errors: run.errors });
  });

  s.registerTool("mail_list_folders", {
    description: "[只读] 列出一个或全部邮箱账号的文件夹及邮件数、未读数。account 不填时默认 all。",
    inputSchema: { account: queryAccount },
  }, async ({ account }) => {
    const run = await forAccounts(env, account, async (cfg) => {
      if (isProtonAccount(cfg)) return protonListFolders(env, cfg);
      return withImapConfig(cfg, async (c) => (
        await c.list({ statusQuery: { messages: true, unseen: true } })
      ).map((f) => ({
        path: f.path,
        name: f.name,
        specialUse: f.specialUse || null,
        subscribed: !!f.subscribed,
        messages: f.status?.messages ?? null,
        unseen: f.status?.unseen ?? null,
      })));
    });
    if (!run.all) return result(run.value);
    return result({
      accounts: run.values.map((x) => ({ account: x.id, accountLabel: x.label, folders: x.value })),
      errors: run.errors,
    });
  });

  s.registerTool("mail_folder_status", {
    description: "[只读] 查看一个或全部邮箱账号的指定文件夹状态与邮箱配额。account 不填时默认 all。",
    inputSchema: { account: queryAccount, folder },
  }, async ({ account, folder: folderName }) => {
    const run = await forAccounts(env, account, async (cfg) => {
      if (isProtonAccount(cfg)) return protonFolderStatus(env, cfg, folderName);
      return withImapConfig(cfg, async (c) => ({
        account: cfg.id,
        accountLabel: cfg.label,
        folder: folderName,
        status: await c.status(folderName, { messages: true, unseen: true, uidNext: true, uidValidity: true, size: true }),
        quota: (await c.getQuota(folderName)) || null,
      }));
    });
    if (!run.all) return result(run.value);
    return result({ accounts: run.values.map((x) => x.value), errors: run.errors });
  });

  s.registerTool("mail_list_messages", {
    description: "[只读] 列出一个或全部邮箱账号的最近邮件摘要；跨账号结果按时间合并排序。account 不填时默认 all。",
    inputSchema: {
      account: queryAccount,
      folder,
      limit: z.number().int().min(1).max(100).optional().default(20),
    },
  }, async ({ account, folder: folderName, limit }) => {
    const run = await forAccounts(env, account, (cfg) => listMessagesForAccount(env, cfg, folderName, limit));
    if (!run.all) return result(run.value);
    const messages = sortMessages(run.values.flatMap((x) => x.value)).slice(0, limit);
    return result({ messages, errors: run.errors });
  });

  s.registerTool("mail_search_messages", {
    description: "[只读] 在一个或全部邮箱账号中按关键词、发件人、收件人、主题、日期、已读和星标状态搜索；跨账号结果按时间合并排序。Proton 第一版的 text 搜索仅覆盖标题和地址元数据，不扫描正文。",
    inputSchema: {
      account: queryAccount,
      folder,
      text: z.string().optional(),
      from: z.string().optional(),
      to: z.string().optional(),
      subject: z.string().optional(),
      since: z.string().optional(),
      before: z.string().optional(),
      seen: z.boolean().optional(),
      starred: z.boolean().optional(),
      limit: z.number().int().min(1).max(100).optional().default(20),
    },
  }, async (p) => {
    const run = await forAccounts(env, p.account, (cfg) => searchMessagesForAccount(env, cfg, p));
    if (!run.all) return result(run.value);
    const messages = sortMessages(run.values.flatMap((x) => x.value)).slice(0, p.limit);
    return result({ messages, errors: run.errors });
  });

  s.registerTool("mail_get_message", {
    description: "[只读] 读取邮件正文、HTML 与附件元数据。优先传 messageRef；IMAP 兼容 account + folder + uid。",
    inputSchema: {
      messageRef,
      account: optionalSpecificAccount,
      folder: z.string().min(1).optional(),
      uid: optionalUid,
    },
  }, async (p) => {
    const target = resolveMessageTarget(p);
    const cfg = getAccount(env, target.account);
    if (isProtonAccount(cfg)) {
      if (!target.messageId) throw new Error("Proton 邮件请使用 mail_list_messages 返回的 messageRef");
      const message = await protonGetMessage(env, cfg, target.messageId, target.folder);
      return result({
        ...message,
        messageRef: encodeMessageRef(cfg.id, target.folder, target.messageId),
      });
    }
    return result(await withImapConfig(cfg, async (c) => {
      const { message, parsed } = await readParsed(c, target.folder, target.uid);
      return {
        ...normalize(message, cfg, target.folder),
        messageId: parsed.messageId || null,
        replyTo: parsed.replyTo?.text || null,
        text: String(parsed.text || "").slice(0, 120000),
        html: typeof parsed.html === "string" ? parsed.html.slice(0, 120000) : "",
        attachments: parsed.attachments.map((a, index) => ({
          index,
          filename: a.filename || null,
          contentType: a.contentType || null,
          size: a.size || 0,
          cid: a.cid || null,
        })),
      };
    }));
  });

  s.registerTool("mail_get_attachment", {
    description: "[只读] 获取邮件附件并以 Base64 返回，单附件最多 5MB。Proton 第一版暂不支持附件内容下载。",
    inputSchema: {
      messageRef,
      account: optionalSpecificAccount,
      folder: z.string().min(1).optional(),
      uid: optionalUid,
      attachmentIndex: z.number().int().min(0),
    },
  }, async (p) => {
    const target = resolveMessageTarget(p);
    const cfg = getAccount(env, target.account);
    if (isProtonAccount(cfg)) throw new Error("Proton 第一版暂不支持附件内容下载，仅返回附件元数据");
    return result(await withImapConfig(cfg, async (c) => {
      const { parsed } = await readParsed(c, target.folder, target.uid);
      const a = parsed.attachments[p.attachmentIndex];
      if (!a) throw new Error("附件不存在");
      if (a.content.length > MAX_ATTACHMENT_BYTES) throw new Error("附件超过 5MB");
      return {
        messageRef: encodeMessageRef(target.account, target.folder, target.uid),
        filename: a.filename || null,
        contentType: a.contentType || null,
        size: a.content.length,
        base64: a.content.toString("base64"),
      };
    }));
  });

  s.registerTool("mail_set_state", {
    description: "[写] 修改具体邮件状态：已读、未读、加星、取消星标。优先传 messageRef；不支持 account=all；Proton 第一版只读。",
    inputSchema: {
      messageRef,
      account: optionalSpecificAccount,
      folder: z.string().min(1).optional(),
      uid: optionalUid,
      action: z.enum(["mark_read", "mark_unread", "star", "unstar"]),
    },
  }, async (p) => {
    const target = resolveMessageTarget(p);
    return result(await withImap(env, target.account, async (c) => {
      const map = {
        mark_read: ["\\Seen", true],
        mark_unread: ["\\Seen", false],
        star: ["\\Flagged", true],
        unstar: ["\\Flagged", false],
      };
      const [flag, add] = map[p.action];
      const lock = await c.getMailboxLock(target.folder, { readOnly: false });
      try {
        if (add) await c.messageFlagsAdd(target.uid, [flag]);
        else await c.messageFlagsRemove(target.uid, [flag]);
        return {
          success: true,
          action: p.action,
          account: target.account,
          folder: target.folder,
          uid: target.uid,
          messageRef: encodeMessageRef(target.account, target.folder, target.uid),
        };
      } finally { lock.release(); }
    }));
  });

  s.registerTool("mail_transfer", {
    description: "[写] 复制或移动具体邮件，可用于归档；禁止目标为已删除/Trash；Proton 第一版只读。优先传 messageRef。",
    inputSchema: {
      messageRef,
      account: optionalSpecificAccount,
      action: z.enum(["copy", "move"]),
      sourceFolder: z.string().min(1).optional(),
      uid: optionalUid,
      targetFolder: z.string().min(1),
    },
  }, async (p) => {
    const target = resolveMessageTarget({ ...p, folder: p.sourceFolder });
    return result(await withImap(env, target.account, async (c) => {
      await blockDeleteDestination(c, p.targetFolder);
      const lock = await c.getMailboxLock(target.folder, { readOnly: false });
      try {
        const r = p.action === "copy"
          ? await c.messageCopy(target.uid, p.targetFolder)
          : await c.messageMove(target.uid, p.targetFolder);
        return {
          success: true,
          action: p.action,
          account: target.account,
          sourceFolder: target.folder,
          targetFolder: p.targetFolder,
          uid: target.uid,
          result: r,
        };
      } finally { lock.release(); }
    }));
  });

  s.registerTool("mail_manage_folder", {
    description: "[写] 在指定邮箱账号中创建、重命名、订阅或取消订阅文件夹；不提供删除文件夹；Proton 第一版只读。",
    inputSchema: {
      account: specificAccount,
      action: z.enum(["create", "rename", "subscribe", "unsubscribe"]),
      folder: z.string().min(1),
      newFolder: z.string().optional(),
    },
  }, async ({ account, action, folder: folderName, newFolder }) => result(await withImap(env, account, async (c) => {
    const folders = await c.list();
    const current = folders.find((f) => f.path === folderName);
    if (isDeleteFolder(current)) throw new Error("不允许操作删除类文件夹");
    if (action === "create") return { success: true, result: await c.mailboxCreate(folderName) };
    if (action === "rename") {
      if (!newFolder) throw new Error("rename 必须提供 newFolder");
      if (current?.specialUse) throw new Error("系统特殊文件夹不能重命名");
      return { success: true, result: await c.mailboxRename(folderName, newFolder) };
    }
    if (action === "subscribe") return { success: await c.mailboxSubscribe(folderName) };
    return { success: await c.mailboxUnsubscribe(folderName) };
  })));

  s.registerTool("mail_send", {
    description: "[高风险写] 从明确指定的邮箱账号发送新邮件，支持 To/Cc/Bcc、文本/HTML 和 Base64 附件；Proton 第一版不支持发送。",
    inputSchema: {
      account: specificAccount,
      to: emails,
      cc: optionalEmails,
      bcc: optionalEmails,
      subject: z.string().max(500).optional().default(""),
      text: z.string().optional(),
      html: z.string().optional(),
      attachments: z.array(attachment).max(10).optional().default([]),
    },
  }, async (p) => {
    const { cfg, transporter } = smtp(env, p.account);
    const info = await transporter.sendMail({
      from: cfg.email,
      to: p.to,
      cc: p.cc,
      bcc: p.bcc,
      subject: p.subject,
      text: p.text,
      html: p.html,
      attachments: buildAttachments(p.attachments),
      disableFileAccess: true,
      disableUrlAccess: true,
    });
    return result({
      success: true,
      account: cfg.id,
      accountLabel: cfg.label,
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected,
      response: info.response,
    });
  });

  s.registerTool("mail_reply", {
    description: "[高风险写] 回复或回复全部；优先传 messageRef；成功后给原邮件添加 Answered 标记；Proton 第一版不支持。",
    inputSchema: {
      messageRef,
      account: optionalSpecificAccount,
      folder: z.string().min(1).optional(),
      uid: optionalUid,
      replyAll: z.boolean().optional().default(false),
      text: z.string().optional(),
      html: z.string().optional(),
      cc: optionalEmails,
      attachments: z.array(attachment).max(10).optional().default([]),
    },
  }, async (p) => {
    const target = resolveMessageTarget(p);
    const original = await withImap(env, target.account, (c) => readParsed(c, target.folder, target.uid));
    const { cfg, transporter } = smtp(env, target.account);
    const m = original.parsed;
    const base = addrValues(m.replyTo).length ? addrValues(m.replyTo) : addrValues(m.from);
    const to = p.replyAll
      ? dedupe([...base, ...addrValues(m.to), ...addrValues(m.cc)], cfg.email)
      : dedupe(base, cfg.email);
    if (!to.length) throw new Error("找不到回复地址");
    const info = await transporter.sendMail({
      from: cfg.email,
      to,
      cc: dedupe(p.cc || [], cfg.email),
      subject: /^re:/i.test(m.subject || "") ? m.subject : `Re: ${m.subject || ""}`,
      text: p.text,
      html: p.html,
      inReplyTo: m.messageId || undefined,
      references: m.references || m.messageId || undefined,
      attachments: buildAttachments(p.attachments),
      disableFileAccess: true,
      disableUrlAccess: true,
    });
    await withImap(env, target.account, async (c) => {
      const lock = await c.getMailboxLock(target.folder, { readOnly: false });
      try { await c.messageFlagsAdd(target.uid, ["\\Answered"]); }
      finally { lock.release(); }
    });
    return result({ success: true, account: cfg.id, messageId: info.messageId, to, accepted: info.accepted, rejected: info.rejected });
  });

  s.registerTool("mail_forward", {
    description: "[高风险写] 转发具体邮件，可选择带上原附件。优先传 messageRef；Proton 第一版不支持。",
    inputSchema: {
      messageRef,
      account: optionalSpecificAccount,
      folder: z.string().min(1).optional(),
      uid: optionalUid,
      to: emails,
      cc: optionalEmails,
      bcc: optionalEmails,
      note: z.string().optional().default(""),
      includeOriginalAttachments: z.boolean().optional().default(false),
    },
  }, async (p) => {
    const target = resolveMessageTarget(p);
    const original = await withImap(env, target.account, (c) => readParsed(c, target.folder, target.uid));
    const { cfg, transporter } = smtp(env, target.account);
    const m = original.parsed;
    const attachments = p.includeOriginalAttachments
      ? m.attachments.map((a) => {
          if (a.content.length > MAX_ATTACHMENT_BYTES) throw new Error(`附件 ${a.filename || "未命名"} 超过 5MB`);
          return { filename: a.filename || "attachment", contentType: a.contentType || undefined, content: a.content };
        })
      : [];
    if (attachments.reduce((n, a) => n + a.content.length, 0) > MAX_OUTGOING_ATTACHMENTS) {
      throw new Error("原附件总大小超过 10MB");
    }
    const text = [
      p.note,
      "",
      "---------- Forwarded message ----------",
      `From: ${m.from?.text || ""}`,
      `Date: ${m.date?.toISOString?.() || ""}`,
      `Subject: ${m.subject || ""}`,
      `To: ${m.to?.text || ""}`,
      "",
      m.text || "",
    ].join("\n");
    const info = await transporter.sendMail({
      from: cfg.email,
      to: p.to,
      cc: p.cc,
      bcc: p.bcc,
      subject: /^fwd:/i.test(m.subject || "") ? m.subject : `Fwd: ${m.subject || ""}`,
      text,
      attachments,
      disableFileAccess: true,
      disableUrlAccess: true,
    });
    return result({ success: true, account: cfg.id, messageId: info.messageId, accepted: info.accepted, rejected: info.rejected });
  });

  s.registerTool("mail_save_draft", {
    description: "[写] 在明确指定的邮箱账号中保存草稿，不发送；支持正文和附件；Proton 第一版不支持。",
    inputSchema: {
      account: specificAccount,
      to: z.array(z.string().email()).optional().default([]),
      cc: optionalEmails,
      bcc: optionalEmails,
      subject: z.string().max(500).optional().default(""),
      text: z.string().optional(),
      html: z.string().optional(),
      attachments: z.array(attachment).max(10).optional().default([]),
    },
  }, async (p) => result(await withImap(env, p.account, async (c, cfg) => {
    const folders = await c.list();
    const drafts = folders.find((f) => f.specialUse === "\\Drafts")
      || folders.find((f) => /draft|草稿/i.test(f.path));
    if (!drafts) throw new Error("未找到草稿箱");
    const t = nodemailer.createTransport({
      streamTransport: true,
      buffer: true,
      newline: "windows",
      disableFileAccess: true,
      disableUrlAccess: true,
    });
    const info = await t.sendMail({
      from: cfg.email,
      to: p.to,
      cc: p.cc,
      bcc: p.bcc,
      subject: p.subject,
      text: p.text,
      html: p.html,
      attachments: buildAttachments(p.attachments),
      disableFileAccess: true,
      disableUrlAccess: true,
    });
    return {
      success: true,
      account: cfg.id,
      draftFolder: drafts.path,
      result: await c.append(drafts.path, info.message, ["\\Draft"], new Date()),
    };
  })));

  return s;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/") {
      return Response.json({ ok: true, service: "personal-mail-mcp", version: "1.2.0" });
    }
    if (url.pathname !== "/mcp" && url.pathname !== "/health") {
      return new Response("Not Found", { status: 404 });
    }

    let identity;
    try {
      identity = await verifyAccess(request, env);
    } catch (e) {
      return Response.json({
        error: "access_denied",
        message: e instanceof Error ? e.message : String(e),
      }, { status: 403 });
    }

    if (url.pathname === "/health") {
      return Response.json({
        ok: true,
        service: "personal-mail-mcp",
        version: "1.2.0",
        user: identity.email || identity.sub || "authenticated",
      });
    }

    return createMcpHandler(() => createServer(env), {
      route: "/mcp",
      responseMode: "json",
    })(request, env, ctx);
  },
};
