import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createLegacyMcpHandler } from "agents/mcp";
import { ImapFlow } from "imapflow";
import { simpleParser } from "mailparser";
import nodemailer from "nodemailer";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { z } from "zod";

const MAX_MAIL_BYTES = 8 * 1024 * 1024;
const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;
const MAX_OUTGOING_ATTACHMENTS = 10 * 1024 * 1024;

const must = (v, n) => {
  if (!v) throw new Error(`缺少配置：${n}`);
  return v;
};

function normalizeTeamDomain(value) {
  const raw = must(
    value,
    "TEAM_DOMAIN",
  )
    .trim()
    .replace(/\/+$/, "");

  const candidate =
    /^https?:\/\//i.test(raw)
      ? raw
      : `https://${raw}`;

  const url = new URL(candidate);

  if (url.protocol !== "https:") {
    throw new Error(
      "TEAM_DOMAIN 必须使用 https",
    );
  }

  return url.origin;
}

const result = (data) => ({
  content: [
    {
      type: "text",
      text: JSON.stringify(data, null, 2),
    },
  ],
});

/*
 * 邮箱供应商配置。
 * 以后增加 163，只需要在这里增加 provider，
 * 不需要再写一套 MCP Tool。
 */
function accountConfig(env, account = "qq") {
  if (account !== "qq") {
    throw new Error(`当前只启用 qq，收到：${account}`);
  }

  return {
    id: "qq",
    email: must(env.MAIL_QQ_EMAIL, "MAIL_QQ_EMAIL"),
    authCode: must(env.MAIL_QQ_AUTH_CODE, "MAIL_QQ_AUTH_CODE"),

    imap: {
      host: "imap.qq.com",
      port: 993,
      secure: true,
    },

    smtp: {
      host: "smtp.qq.com",
      port: 465,
      secure: true,
    },
  };
}

/*
 * 每次操作建立短 IMAP 连接，
 * 完成后主动断开。
 */
async function withImap(env, account, fn) {
  const cfg = accountConfig(env, account);

  const client = new ImapFlow({
    host: cfg.imap.host,
    port: cfg.imap.port,
    secure: cfg.imap.secure,

    auth: {
      user: cfg.email,
      pass: cfg.authCode,
    },

    logger: false,
    disableAutoIdle: true,

    connectionTimeout: 15000,
    greetingTimeout: 10000,
    socketTimeout: 30000,
  });

  client.on("error", (e) => {
    console.error("IMAP:", e?.message || String(e));
  });

  await client.connect();

  try {
    return await fn(client, cfg);
  } finally {
    try {
      await client.logout();
    } catch {
      client.close();
    }
  }
}

/*
 * SMTP
 */
function smtp(env, account = "qq") {
  const cfg = accountConfig(env, account);

  const transporter = nodemailer.createTransport({
    host: cfg.smtp.host,
    port: cfg.smtp.port,
    secure: cfg.smtp.secure,

    auth: {
      user: cfg.email,
      pass: cfg.authCode,
    },

    logger: false,
    debug: false,

    connectionTimeout: 15000,
    greetingTimeout: 10000,
    socketTimeout: 30000,

    /*
     * 禁止邮件参数让 Worker 自己去读取文件或 URL。
     */
    disableFileAccess: true,
    disableUrlAccess: true,
  });

  return {
    cfg,
    transporter,
  };
}

const addresses = (list) =>
  (list || []).map((x) => ({
    name: x.name || "",
    address: x.address || "",
  }));

const normalize = (m) => ({
  uid: m.uid,

  subject: m.envelope?.subject || "",

  from: addresses(m.envelope?.from),
  to: addresses(m.envelope?.to),
  cc: addresses(m.envelope?.cc),

  date:
    m.envelope?.date?.toISOString?.() ||
    m.internalDate?.toISOString?.() ||
    null,

  size: m.size || 0,

  flags: m.flags
    ? Array.from(m.flags)
    : [],
});

const addrValues = (x) =>
  (x?.value || [])
    .map((v) => v.address)
    .filter(Boolean);

function dedupe(list, own) {
  const seen = new Set();
  const out = [];
  const me = own.toLowerCase();

  for (const x of list || []) {
    const v = String(x || "").trim();
    const k = v.toLowerCase();

    if (
      v &&
      k !== me &&
      !seen.has(k)
    ) {
      seen.add(k);
      out.push(v);
    }
  }

  return out;
}

function parseDate(v, n) {
  if (!v) return undefined;

  const d = new Date(v);

  if (Number.isNaN(d.getTime())) {
    throw new Error(`${n} 日期无效`);
  }

  return d;
}

function buildAttachments(items = []) {
  let total = 0;

  const out = items.map((a) => {
    const content = Buffer.from(
      a.base64,
      "base64",
    );

    if (
      content.length >
      MAX_ATTACHMENT_BYTES
    ) {
      throw new Error(
        `附件 ${a.filename} 超过 5MB`,
      );
    }

    total += content.length;

    return {
      filename: a.filename,
      contentType:
        a.contentType || undefined,
      content,
    };
  });

  if (
    total >
    MAX_OUTGOING_ATTACHMENTS
  ) {
    throw new Error(
      "附件总大小超过 10MB",
    );
  }

  return out;
}

/*
 * 读取并解析完整邮件。
 */
async function readParsed(
  client,
  folder,
  uid,
) {
  const lock =
    await client.getMailboxLock(
      folder,
      {
        readOnly: true,
      },
    );

  try {
    const meta =
      await client.fetchOne(
        uid,
        {
          uid: true,
          envelope: true,
          flags: true,
          size: true,
          internalDate: true,
        },
        {
          uid: true,
        },
      );

    if (!meta) {
      throw new Error(
        `找不到 UID=${uid}`,
      );
    }

    if (
      (meta.size || 0) >
      MAX_MAIL_BYTES
    ) {
      throw new Error(
        "邮件原文超过 8MB；本版不读取完整原文",
      );
    }

    const full =
      await client.fetchOne(
        uid,
        {
          uid: true,
          envelope: true,
          flags: true,
          size: true,
          internalDate: true,
          source: true,
        },
        {
          uid: true,
        },
      );

    if (
      !full ||
      !full.source
    ) {
      throw new Error(
        "无法读取邮件原文",
      );
    }

    return {
      message: full,
      parsed:
        await simpleParser(
          full.source,
        ),
    };
  } finally {
    lock.release();
  }
}

/*
 * 判断是否为删除类目录。
 */
function isDeleteFolder(f) {
  return (
    f?.specialUse === "\\Trash" ||
    /trash|deleted|已删除|废纸篓|垃圾桶/i.test(
      String(f?.path || ""),
    )
  );
}

/*
 * 防止通过“移动邮件”绕过删除限制。
 */
async function blockDeleteDestination(
  client,
  path,
) {
  const folders =
    await client.list();

  const f =
    folders.find(
      (x) => x.path === path,
    );

  if (
    isDeleteFolder(f) ||
    /trash|deleted|已删除|废纸篓|垃圾桶/i.test(
      path,
    )
  ) {
    throw new Error(
      "删除能力已禁用：禁止移动或复制到删除类文件夹",
    );
  }
}

/*
 * 校验 Cloudflare Access JWT。
 */
async function verifyAccess(
  request,
  env,
) {
  const team =
    normalizeTeamDomain(
      env.TEAM_DOMAIN,
    );

  const aud =
    must(
      env.POLICY_AUD,
      "POLICY_AUD",
    );

  const token =
    request.headers.get(
      "cf-access-jwt-assertion",
    );

  if (!token) {
    throw new Error(
      "缺少 Cloudflare Access JWT",
    );
  }

  const JWKS =
    createRemoteJWKSet(
      new URL(
        "/cdn-cgi/access/certs",
        team,
      ),
    );

  return (
    await jwtVerify(
      token,
      JWKS,
      {
        issuer: team,
        audience: aud,
      },
    )
  ).payload;
}

/*
 * 公共 Schema
 */
const account =
  z.enum(["qq"])
    .optional()
    .default("qq");

const folder =
  z.string()
    .min(1)
    .optional()
    .default("INBOX");

const uid =
  z.number()
    .int()
    .positive();

const emails =
  z.array(
    z.string().email(),
  ).min(1);

const optionalEmails =
  z.array(
    z.string().email(),
  ).optional();

const attachment =
  z.object({
    filename:
      z.string().min(1),

    contentType:
      z.string().optional(),

    base64:
      z.string().min(1),
  });

function createServer(env) {
  const s =
    new McpServer({
      name:
        "personal-mail-mcp",
      version:
        "1.0.0",
    });

  /*
   * 1. 测试 IMAP + SMTP
   */
  s.registerTool(
    "mail_test_connection",
    {
      description:
        "[只读] 测试 QQ 邮箱 IMAP 与 SMTP 登录，不发送邮件。",

      inputSchema: {
        account,
      },
    },

    async ({ account }) => {
      const imap =
        await withImap(
          env,
          account,
          async (c) => ({
            authenticated:
              !!c.authenticated,

            secure:
              c.secureConnection,

            capabilities:
              Array.from(
                c.capabilities.keys(),
              ),
          }),
        );

      const {
        transporter,
      } =
        smtp(env, account);

      await transporter.verify();

      return result({
        success: true,
        account,

        imap,

        smtp: {
          verified: true,
        },
      });
    },
  );

  /*
   * 2. 文件夹列表
   */
  s.registerTool(
    "mail_list_folders",
    {
      description:
        "[只读] 列出文件夹及邮件数、未读数。",

      inputSchema: {
        account,
      },
    },

    async ({ account }) =>
      result(
        await withImap(
          env,
          account,
          async (c) =>
            (
              await c.list({
                statusQuery: {
                  messages: true,
                  unseen: true,
                },
              })
            ).map((f) => ({
              path: f.path,
              name: f.name,

              specialUse:
                f.specialUse ||
                null,

              subscribed:
                !!f.subscribed,

              messages:
                f.status
                  ?.messages ??
                null,

              unseen:
                f.status
                  ?.unseen ??
                null,
            })),
        ),
      ),
  );

  /*
   * 3. 文件夹状态
   */
  s.registerTool(
    "mail_folder_status",
    {
      description:
        "[只读] 查看文件夹状态与邮箱配额。",

      inputSchema: {
        account,
        folder,
      },
    },

    async ({
      account,
      folder,
    }) =>
      result(
        await withImap(
          env,
          account,
          async (c) => ({
            folder,

            status:
              await c.status(
                folder,
                {
                  messages: true,
                  unseen: true,
                  uidNext: true,
                  uidValidity: true,
                  size: true,
                },
              ),

            quota:
              (
                await c.getQuota(
                  folder,
                )
              ) || null,
          }),
        ),
      ),
  );

  /*
   * 4. 最近邮件
   */
  s.registerTool(
    "mail_list_messages",
    {
      description:
        "[只读] 列出指定文件夹最近邮件摘要。",

      inputSchema: {
        account,
        folder,

        limit:
          z.number()
            .int()
            .min(1)
            .max(100)
            .optional()
            .default(20),
      },
    },

    async ({
      account,
      folder,
      limit,
    }) =>
      result(
        await withImap(
          env,
          account,
          async (c) => {
            const lock =
              await c.getMailboxLock(
                folder,
                {
                  readOnly: true,
                },
              );

            try {
              if (
                !c.mailbox?.exists
              ) {
                return [];
              }

              return (
                await c.fetchAll(
                  `:-${limit}`,
                  {
                    uid: true,
                    envelope: true,
                    flags: true,
                    size: true,
                    internalDate: true,
                  },
                )
              )
                .map(normalize)
                .reverse();
            } finally {
              lock.release();
            }
          },
        ),
      ),
  );

  /*
   * 5. 搜索邮件
   */
  s.registerTool(
    "mail_search_messages",
    {
      description:
        "[只读] 按关键词、发件人、收件人、主题、日期、已读和星标状态搜索邮件。",

      inputSchema: {
        account,
        folder,

        text:
          z.string()
            .optional(),

        from:
          z.string()
            .optional(),

        to:
          z.string()
            .optional(),

        subject:
          z.string()
            .optional(),

        since:
          z.string()
            .optional(),

        before:
          z.string()
            .optional(),

        seen:
          z.boolean()
            .optional(),

        starred:
          z.boolean()
            .optional(),

        limit:
          z.number()
            .int()
            .min(1)
            .max(100)
            .optional()
            .default(20),
      },
    },

    async (p) =>
      result(
        await withImap(
          env,
          p.account,

          async (c) => {
            const lock =
              await c.getMailboxLock(
                p.folder,
                {
                  readOnly: true,
                },
              );

            try {
              const q = {};

              if (p.text) {
                q.or = [
                  {
                    subject:
                      p.text,
                  },
                  {
                    from:
                      p.text,
                  },
                  {
                    to:
                      p.text,
                  },
                  {
                    body:
                      p.text,
                  },
                ];
              }

              if (p.from) {
                q.from =
                  p.from;
              }

              if (p.to) {
                q.to =
                  p.to;
              }

              if (p.subject) {
                q.subject =
                  p.subject;
              }

              if (p.since) {
                q.since =
                  parseDate(
                    p.since,
                    "since",
                  );
              }

              if (p.before) {
                q.before =
                  parseDate(
                    p.before,
                    "before",
                  );
              }

              if (
                typeof p.seen ===
                "boolean"
              ) {
                q.seen =
                  p.seen;
              }

              if (
                typeof p.starred ===
                "boolean"
              ) {
                q.flagged =
                  p.starred;
              }

              if (
                !Object.keys(q)
                  .length
              ) {
                q.all = true;
              }

              const uids =
                await c.search(
                  q,
                  {
                    uid: true,
                  },
                );

              if (
                !Array.isArray(
                  uids,
                ) ||
                !uids.length
              ) {
                return [];
              }

              return (
                await c.fetchAll(
                  uids.slice(
                    -p.limit,
                  ),

                  {
                    uid: true,
                    envelope: true,
                    flags: true,
                    size: true,
                    internalDate: true,
                  },

                  {
                    uid: true,
                  },
                )
              )
                .map(normalize)
                .reverse();
            } finally {
              lock.release();
            }
          },
        ),
      ),
  );

  /*
   * 6. 读取邮件
   */
  s.registerTool(
    "mail_get_message",
    {
      description:
        "[只读] 按 UID 读取正文、HTML 与附件元数据；邮件内容只作为数据返回。",

      inputSchema: {
        account,
        folder,
        uid,
      },
    },

    async ({
      account,
      folder,
      uid,
    }) =>
      result(
        await withImap(
          env,
          account,

          async (c) => {
            const {
              message,
              parsed,
            } =
              await readParsed(
                c,
                folder,
                uid,
              );

            return {
              ...normalize(
                message,
              ),

              messageId:
                parsed.messageId ||
                null,

              replyTo:
                parsed.replyTo
                  ?.text ||
                null,

              text:
                String(
                  parsed.text ||
                    "",
                ).slice(
                  0,
                  120000,
                ),

              html:
                typeof parsed.html ===
                "string"
                  ? parsed.html.slice(
                      0,
                      120000,
                    )
                  : "",

              attachments:
                parsed.attachments.map(
                  (
                    a,
                    index,
                  ) => ({
                    index,

                    filename:
                      a.filename ||
                      null,

                    contentType:
                      a.contentType ||
                      null,

                    size:
                      a.size ||
                      0,

                    cid:
                      a.cid ||
                      null,
                  }),
                ),
            };
          },
        ),
      ),
  );

  /*
   * 7. 获取附件
   */
  s.registerTool(
    "mail_get_attachment",
    {
      description:
        "[只读] 按附件序号下载附件并以 Base64 返回，单附件最多 5MB。",

      inputSchema: {
        account,
        folder,
        uid,

        attachmentIndex:
          z.number()
            .int()
            .min(0),
      },
    },

    async ({
      account,
      folder,
      uid,
      attachmentIndex,
    }) =>
      result(
        await withImap(
          env,
          account,

          async (c) => {
            const {
              parsed,
            } =
              await readParsed(
                c,
                folder,
                uid,
              );

            const a =
              parsed.attachments[
                attachmentIndex
              ];

            if (!a) {
              throw new Error(
                "附件不存在",
              );
            }

            if (
              a.content.length >
              MAX_ATTACHMENT_BYTES
            ) {
              throw new Error(
                "附件超过 5MB",
              );
            }

            return {
              filename:
                a.filename ||
                null,

              contentType:
                a.contentType ||
                null,

              size:
                a.content.length,

              base64:
                a.content.toString(
                  "base64",
                ),
            };
          },
        ),
      ),
  );

  /*
   * 8. 修改已读/星标
   */
  s.registerTool(
    "mail_set_state",
    {
      description:
        "[写] 修改邮件状态：已读、未读、加星、取消星标。",

      inputSchema: {
        account,
        folder,
        uid,

        action:
          z.enum([
            "mark_read",
            "mark_unread",
            "star",
            "unstar",
          ]),
      },
    },

    async ({
      account,
      folder,
      uid,
      action,
    }) =>
      result(
        await withImap(
          env,
          account,

          async (c) => {
            const map = {
              mark_read: [
                "\\Seen",
                true,
              ],

              mark_unread: [
                "\\Seen",
                false,
              ],

              star: [
                "\\Flagged",
                true,
              ],

              unstar: [
                "\\Flagged",
                false,
              ],
            };

            const [
              flag,
              add,
            ] =
              map[action];

            const lock =
              await c.getMailboxLock(
                folder,
                {
                  readOnly: false,
                },
              );

            try {
              if (add) {
                await c.messageFlagsAdd(
                  uid,
                  [flag],
                  {
                    uid: true,
                  },
                );
              } else {
                await c.messageFlagsRemove(
                  uid,
                  [flag],
                  {
                    uid: true,
                  },
                );
              }

              return {
                success: true,
                action,
                folder,
                uid,
              };
            } finally {
              lock.release();
            }
          },
        ),
      ),
  );

  /*
   * 9. 移动 / 复制 / 归档
   *
   * 禁止 Trash / Deleted。
   */
  s.registerTool(
    "mail_transfer",
    {
      description:
        "[写] 复制或移动邮件，可用于归档；禁止目标为已删除/Trash。",

      inputSchema: {
        account,

        action:
          z.enum([
            "copy",
            "move",
          ]),

        sourceFolder:
          z.string()
            .min(1),

        uid,

        targetFolder:
          z.string()
            .min(1),
      },
    },

    async ({
      account,
      action,
      sourceFolder,
      uid,
      targetFolder,
    }) =>
      result(
        await withImap(
          env,
          account,

          async (c) => {
            await blockDeleteDestination(
              c,
              targetFolder,
            );

            const lock =
              await c.getMailboxLock(
                sourceFolder,
                {
                  readOnly: false,
                },
              );

            try {
              const r =
                action ===
                "copy"
                  ? await c.messageCopy(
                      uid,
                      targetFolder,
                      {
                        uid: true,
                      },
                    )
                  : await c.messageMove(
                      uid,
                      targetFolder,
                      {
                        uid: true,
                      },
                    );

              return {
                success: true,
                action,
                sourceFolder,
                targetFolder,
                uid,
                result: r,
              };
            } finally {
              lock.release();
            }
          },
        ),
      ),
  );

  /*
   * 10. 文件夹管理
   *
   * 不提供删除文件夹。
   */
  s.registerTool(
    "mail_manage_folder",
    {
      description:
        "[写] 创建、重命名、订阅或取消订阅文件夹；不提供删除文件夹。",

      inputSchema: {
        account,

        action:
          z.enum([
            "create",
            "rename",
            "subscribe",
            "unsubscribe",
          ]),

        folder:
          z.string()
            .min(1),

        newFolder:
          z.string()
            .optional(),
      },
    },

    async ({
      account,
      action,
      folder,
      newFolder,
    }) =>
      result(
        await withImap(
          env,
          account,

          async (c) => {
            const folders =
              await c.list();

            const current =
              folders.find(
                (f) =>
                  f.path ===
                  folder,
              );

            if (
              isDeleteFolder(
                current,
              )
            ) {
              throw new Error(
                "不允许操作删除类文件夹",
              );
            }

            if (
              action ===
              "create"
            ) {
              return {
                success: true,

                result:
                  await c.mailboxCreate(
                    folder,
                  ),
              };
            }

            if (
              action ===
              "rename"
            ) {
              if (!newFolder) {
                throw new Error(
                  "rename 必须提供 newFolder",
                );
              }

              if (
                current
                  ?.specialUse
              ) {
                throw new Error(
                  "系统特殊文件夹不能重命名",
                );
              }

              return {
                success: true,

                result:
                  await c.mailboxRename(
                    folder,
                    newFolder,
                  ),
              };
            }

            if (
              action ===
              "subscribe"
            ) {
              return {
                success:
                  await c.mailboxSubscribe(
                    folder,
                  ),
              };
            }

            return {
              success:
                await c.mailboxUnsubscribe(
                  folder,
                ),
            };
          },
        ),
      ),
  );

  /*
   * 11. 发送邮件
   */
  s.registerTool(
    "mail_send",
    {
      description:
        "[高风险写] 发送新邮件，支持 To/Cc/Bcc、文本/HTML 和 Base64 附件。",

      inputSchema: {
        account,

        to: emails,

        cc:
          optionalEmails,

        bcc:
          optionalEmails,

        subject:
          z.string()
            .max(500)
            .optional()
            .default(""),

        text:
          z.string()
            .optional(),

        html:
          z.string()
            .optional(),

        attachments:
          z.array(
            attachment,
          )
            .max(10)
            .optional()
            .default([]),
      },
    },

    async (p) => {
      const {
        cfg,
        transporter,
      } =
        smtp(
          env,
          p.account,
        );

      const info =
        await transporter.sendMail(
          {
            from:
              cfg.email,

            to:
              p.to,

            cc:
              p.cc,

            bcc:
              p.bcc,

            subject:
              p.subject,

            text:
              p.text,

            html:
              p.html,

            attachments:
              buildAttachments(
                p.attachments,
              ),

            disableFileAccess:
              true,

            disableUrlAccess:
              true,
          },
        );

      return result({
        success: true,

        messageId:
          info.messageId,

        accepted:
          info.accepted,

        rejected:
          info.rejected,

        response:
          info.response,
      });
    },
  );

  /*
   * 12. 回复 / 回复全部
   */
  s.registerTool(
    "mail_reply",
    {
      description:
        "[高风险写] 回复或回复全部；成功后给原邮件添加 Answered 标记。",

      inputSchema: {
        account,
        folder,
        uid,

        replyAll:
          z.boolean()
            .optional()
            .default(false),

        text:
          z.string()
            .optional(),

        html:
          z.string()
            .optional(),

        cc:
          optionalEmails,

        attachments:
          z.array(
            attachment,
          )
            .max(10)
            .optional()
            .default([]),
      },
    },

    async (p) => {
      const original =
        await withImap(
          env,
          p.account,

          (c) =>
            readParsed(
              c,
              p.folder,
              p.uid,
            ),
        );

      const {
        cfg,
        transporter,
      } =
        smtp(
          env,
          p.account,
        );

      const m =
        original.parsed;

      const base =
        addrValues(
          m.replyTo,
        ).length
          ? addrValues(
              m.replyTo,
            )
          : addrValues(
              m.from,
            );

      const to =
        p.replyAll
          ? dedupe(
              [
                ...base,
                ...addrValues(
                  m.to,
                ),
                ...addrValues(
                  m.cc,
                ),
              ],
              cfg.email,
            )
          : dedupe(
              base,
              cfg.email,
            );

      if (!to.length) {
        throw new Error(
          "找不到回复地址",
        );
      }

      const info =
        await transporter.sendMail(
          {
            from:
              cfg.email,

            to,

            cc:
              dedupe(
                p.cc || [],
                cfg.email,
              ),

            subject:
              /^re:/i.test(
                m.subject ||
                  "",
              )
                ? m.subject
                : `Re: ${
                    m.subject ||
                    ""
                  }`,

            text:
              p.text,

            html:
              p.html,

            inReplyTo:
              m.messageId ||
              undefined,

            references:
              m.references ||
              m.messageId ||
              undefined,

            attachments:
              buildAttachments(
                p.attachments,
              ),

            disableFileAccess:
              true,

            disableUrlAccess:
              true,
          },
        );

      await withImap(
        env,
        p.account,

        async (c) => {
          const lock =
            await c.getMailboxLock(
              p.folder,
              {
                readOnly: false,
              },
            );

          try {
            await c.messageFlagsAdd(
              p.uid,
              [
                "\\Answered",
              ],
              {
                uid: true,
              },
            );
          } finally {
            lock.release();
          }
        },
      );

      return result({
        success: true,

        messageId:
          info.messageId,

        to,

        accepted:
          info.accepted,

        rejected:
          info.rejected,
      });
    },
  );

  /*
   * 13. 转发
   */
  s.registerTool(
    "mail_forward",
    {
      description:
        "[高风险写] 转发邮件，可选择带上原附件。",

      inputSchema: {
        account,
        folder,
        uid,

        to: emails,

        cc:
          optionalEmails,

        bcc:
          optionalEmails,

        note:
          z.string()
            .optional()
            .default(""),

        includeOriginalAttachments:
          z.boolean()
            .optional()
            .default(false),
      },
    },

    async (p) => {
      const original =
        await withImap(
          env,
          p.account,

          (c) =>
            readParsed(
              c,
              p.folder,
              p.uid,
            ),
        );

      const {
        cfg,
        transporter,
      } =
        smtp(
          env,
          p.account,
        );

      const m =
        original.parsed;

      const attachments =
        p.includeOriginalAttachments
          ? m.attachments.map(
              (a) => {
                if (
                  a.content
                    .length >
                  MAX_ATTACHMENT_BYTES
                ) {
                  throw new Error(
                    `附件 ${
                      a.filename ||
                      "未命名"
                    } 超过 5MB`,
                  );
                }

                return {
                  filename:
                    a.filename ||
                    "attachment",

                  contentType:
                    a.contentType ||
                    undefined,

                  content:
                    a.content,
                };
              },
            )
          : [];

      if (
        attachments.reduce(
          (n, a) =>
            n +
            a.content.length,
          0,
        ) >
        MAX_OUTGOING_ATTACHMENTS
      ) {
        throw new Error(
          "原附件总大小超过 10MB",
        );
      }

      const text = [
        p.note,
        "",

        "---------- Forwarded message ----------",

        `From: ${
          m.from?.text ||
          ""
        }`,

        `Date: ${
          m.date
            ?.toISOString?.() ||
          ""
        }`,

        `Subject: ${
          m.subject ||
          ""
        }`,

        `To: ${
          m.to?.text ||
          ""
        }`,

        "",

        m.text ||
          "",
      ].join("\n");

      const info =
        await transporter.sendMail(
          {
            from:
              cfg.email,

            to:
              p.to,

            cc:
              p.cc,

            bcc:
              p.bcc,

            subject:
              /^fwd:/i.test(
                m.subject ||
                  "",
              )
                ? m.subject
                : `Fwd: ${
                    m.subject ||
                    ""
                  }`,

            text,

            attachments,

            disableFileAccess:
              true,

            disableUrlAccess:
              true,
          },
        );

      return result({
        success: true,

        messageId:
          info.messageId,

        accepted:
          info.accepted,

        rejected:
          info.rejected,
      });
    },
  );

  /*
   * 14. 保存草稿
   */
  s.registerTool(
    "mail_save_draft",
    {
      description:
        "[写] 保存草稿，不发送；支持正文和附件。",

      inputSchema: {
        account,

        to:
          z.array(
            z.string()
              .email(),
          )
            .optional()
            .default([]),

        cc:
          optionalEmails,

        bcc:
          optionalEmails,

        subject:
          z.string()
            .max(500)
            .optional()
            .default(""),

        text:
          z.string()
            .optional(),

        html:
          z.string()
            .optional(),

        attachments:
          z.array(
            attachment,
          )
            .max(10)
            .optional()
            .default([]),
      },
    },

    async (p) =>
      result(
        await withImap(
          env,
          p.account,

          async (
            c,
            cfg,
          ) => {
            const folders =
              await c.list();

            const drafts =
              folders.find(
                (f) =>
                  f.specialUse ===
                  "\\Drafts",
              ) ||
              folders.find(
                (f) =>
                  /draft|草稿/i.test(
                    f.path,
                  ),
              );

            if (!drafts) {
              throw new Error(
                "未找到草稿箱",
              );
            }

            const t =
              nodemailer.createTransport(
                {
                  streamTransport:
                    true,

                  buffer:
                    true,

                  newline:
                    "windows",

                  disableFileAccess:
                    true,

                  disableUrlAccess:
                    true,
                },
              );

            const info =
              await t.sendMail(
                {
                  from:
                    cfg.email,

                  to:
                    p.to,

                  cc:
                    p.cc,

                  bcc:
                    p.bcc,

                  subject:
                    p.subject,

                  text:
                    p.text,

                  html:
                    p.html,

                  attachments:
                    buildAttachments(
                      p.attachments,
                    ),

                  disableFileAccess:
                    true,

                  disableUrlAccess:
                    true,
                },
              );

            return {
              success: true,

              draftFolder:
                drafts.path,

              result:
                await c.append(
                  drafts.path,
                  info.message,
                  [
                    "\\Draft",
                  ],
                  new Date(),
                ),
            };
          },
        ),
      ),
  );

  return s;
}

/*
 * Worker HTTP 入口
 */
export default {
  async fetch(
    request,
    env,
    ctx,
  ) {
    const url =
      new URL(
        request.url,
      );

    if (
      url.pathname !==
        "/mcp" &&
      url.pathname !==
        "/health"
    ) {
      return new Response(
        "Not Found",
        {
          status: 404,
        },
      );
    }

    /*
     * 即使 Cloudflare Access
     * 已挡在 Worker 前面，
     * Worker 仍主动校验 Access JWT。
     */
    let identity;

    try {
      identity =
        await verifyAccess(
          request,
          env,
        );
    } catch (e) {
      return Response.json(
        {
          error:
            "access_denied",

          message:
            e instanceof Error
              ? e.message
              : String(e),
        },
        {
          status: 403,
        },
      );
    }

    /*
     * 浏览器测试地址
     */
    if (
      url.pathname ===
      "/health"
    ) {
      return Response.json({
        ok: true,

        service:
          "personal-mail-mcp",

        user:
          identity.email ||
          identity.sub ||
          "authenticated",
      });
    }

    /*
     * MCP Streamable HTTP
     */
    return createLegacyMcpHandler(
      createServer(env),
      {
        route:
          "/mcp",

        enableJsonResponse:
          true,
      },
    )(
      request,
      env,
      ctx,
    );
  },
};
