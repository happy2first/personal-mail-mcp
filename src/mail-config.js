const PROVIDERS = {
  qq: {
    label: "QQ邮箱",
    imap: { host: "imap.qq.com", port: 993, security: "tls" },
    smtp: { host: "smtp.qq.com", port: 465, security: "tls" },
  },
  "163": {
    label: "163邮箱",
    imap: { host: "imap.163.com", port: 993, security: "tls" },
    smtp: { host: "smtp.163.com", port: 465, security: "tls" },
  },
  gmail: {
    label: "Gmail",
    imap: { host: "imap.gmail.com", port: 993, security: "tls" },
    smtp: { host: "smtp.gmail.com", port: 465, security: "tls" },
  },
};

const ID_RE = /^[a-z0-9_]+$/i;
const SECURITY = new Set(["tls", "starttls"]);

function must(value, name) {
  if (value === undefined || value === null || String(value).trim() === "") {
    throw new Error(`缺少配置：${name}`);
  }
  return String(value).trim();
}

function parsePort(value, name) {
  const port = Number(must(value, name));
  if (!Number.isInteger(port) || port < 1 || port > 65535 || port === 25) {
    throw new Error(`${name} 端口无效或不允许`);
  }
  return port;
}

function parseSecurity(value, name) {
  const security = must(value, name).toLowerCase();
  if (!SECURITY.has(security)) {
    throw new Error(`${name} 仅支持 tls 或 starttls`);
  }
  return security;
}

function prefixFor(id) {
  return `MAIL_${id.toUpperCase()}`;
}

export function listAccountIds(env) {
  let ids;
  if (env.MAIL_ACCOUNTS && String(env.MAIL_ACCOUNTS).trim()) {
    ids = String(env.MAIL_ACCOUNTS)
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
  } else if (env.MAIL_QQ_EMAIL && env.MAIL_QQ_AUTH_CODE) {
    // 旧版兼容：未配置 MAIL_ACCOUNTS 时继续使用现有 QQ 变量。
    ids = ["qq"];
  } else {
    ids = [];
  }

  const seen = new Set();
  for (const id of ids) {
    if (!ID_RE.test(id)) throw new Error(`邮箱账号 ID 无效：${id}`);
    if (id.toLowerCase() === "all") throw new Error("邮箱账号 ID 不能使用保留字 all");
    const key = id.toLowerCase();
    if (seen.has(key)) throw new Error(`邮箱账号 ID 重复：${id}`);
    seen.add(key);
  }
  return ids;
}

export function getAccount(env, id) {
  const accountId = must(id, "account");
  const ids = listAccountIds(env);
  const actualId = ids.find((x) => x.toLowerCase() === accountId.toLowerCase());
  if (!actualId) throw new Error(`未配置邮箱账号：${accountId}`);

  // 旧版 QQ 兼容模式。
  if (!env.MAIL_ACCOUNTS && actualId.toLowerCase() === "qq") {
    return {
      id: "qq",
      label: "QQ邮箱",
      provider: "qq",
      email: must(env.MAIL_QQ_EMAIL, "MAIL_QQ_EMAIL"),
      credential: must(env.MAIL_QQ_AUTH_CODE, "MAIL_QQ_AUTH_CODE"),
      imap: { ...PROVIDERS.qq.imap },
      smtp: { ...PROVIDERS.qq.smtp },
      legacy: true,
    };
  }

  const prefix = prefixFor(actualId);
  const legacyQq = actualId.toLowerCase() === "qq" && env.MAIL_QQ_AUTH_CODE;
  const provider = String(env[`${prefix}_PROVIDER`] || (legacyQq ? "qq" : "")).trim().toLowerCase();
  if (!["qq", "163", "gmail", "custom"].includes(provider)) {
    throw new Error(`不支持的邮箱 Provider：${provider || "未配置"}`);
  }

  const email = must(env[`${prefix}_EMAIL`], `${prefix}_EMAIL`);
  const credential = must(
    env[`${prefix}_CREDENTIAL`] || (legacyQq ? env.MAIL_QQ_AUTH_CODE : undefined),
    `${prefix}_CREDENTIAL`,
  );
  const label = String(env[`${prefix}_LABEL`] || PROVIDERS[provider]?.label || actualId).trim();

  let imap;
  let smtp;
  if (provider === "custom") {
    imap = {
      host: must(env[`${prefix}_IMAP_HOST`], `${prefix}_IMAP_HOST`),
      port: parsePort(env[`${prefix}_IMAP_PORT`], `${prefix}_IMAP_PORT`),
      security: parseSecurity(env[`${prefix}_IMAP_SECURITY`], `${prefix}_IMAP_SECURITY`),
    };
    smtp = {
      host: must(env[`${prefix}_SMTP_HOST`], `${prefix}_SMTP_HOST`),
      port: parsePort(env[`${prefix}_SMTP_PORT`], `${prefix}_SMTP_PORT`),
      security: parseSecurity(env[`${prefix}_SMTP_SECURITY`], `${prefix}_SMTP_SECURITY`),
    };
  } else {
    imap = { ...PROVIDERS[provider].imap };
    smtp = { ...PROVIDERS[provider].smtp };
  }

  return {
    id: actualId,
    label: label || actualId,
    provider,
    email,
    credential,
    imap,
    smtp,
    legacy: false,
  };
}

export function listAccounts(env) {
  return listAccountIds(env).map((id) => {
    try {
      const cfg = getAccount(env, id);
      return {
        id: cfg.id,
        label: cfg.label,
        provider: cfg.provider,
        configured: true,
        imap: true,
        smtp: true,
        imapSecurity: cfg.imap.security,
        smtpSecurity: cfg.smtp.security,
      };
    } catch (error) {
      const prefix = prefixFor(id);
      return {
        id,
        label: String(env[`${prefix}_LABEL`] || id),
        provider: String(env[`${prefix}_PROVIDER`] || "unknown").toLowerCase(),
        configured: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  });
}
