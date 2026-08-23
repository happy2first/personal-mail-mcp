import "./netease-imap-id.js";

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
  proton: {
    label: "Proton Mail",
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
  const ids = must(env.MAIL_ACCOUNTS, "MAIL_ACCOUNTS")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

  if (!ids.length) {
    throw new Error("MAIL_ACCOUNTS 至少需要配置一个邮箱账号 ID");
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

  const prefix = prefixFor(actualId);
  const provider = must(env[`${prefix}_PROVIDER`], `${prefix}_PROVIDER`).toLowerCase();
  if (!["qq", "163", "gmail", "custom", "proton"].includes(provider)) {
    throw new Error(`不支持的邮箱 Provider：${provider}`);
  }

  const email = must(env[`${prefix}_EMAIL`], `${prefix}_EMAIL`);
  const credential = must(env[`${prefix}_CREDENTIAL`], `${prefix}_CREDENTIAL`);
  const label = String(env[`${prefix}_LABEL`] || PROVIDERS[provider]?.label || actualId).trim();

  if (provider === "proton") {
    return {
      id: actualId,
      label: label || actualId,
      provider,
      email,
      credential,
      imap: null,
      smtp: null,
    };
  }

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
  };
}

export function listAccounts(env) {
  return listAccountIds(env).map((id) => {
    try {
      const cfg = getAccount(env, id);
      if (cfg.provider === "proton") {
        return {
          id: cfg.id,
          label: cfg.label,
          provider: cfg.provider,
          configured: true,
          protonApi: true,
          imap: false,
          smtp: false,
          readOnly: true,
        };
      }
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
