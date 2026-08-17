import { connect } from "cloudflare:sockets";
import nodemailer from "nodemailer";
import { simpleParser } from "mailparser";

const CONNECT_TIMEOUT = 15_000;
const GREETING_TIMEOUT = 10_000;
const COMMAND_TIMEOUT = 30_000;
const decoder = new TextDecoder();
const encoder = new TextEncoder();

function logStage(protocol, stage, details = {}) {
  console.info(JSON.stringify({ component: protocol.toLowerCase(), stage, ...details }));
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function timeout(promise, milliseconds, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label)), milliseconds);
    }),
  ]).finally(() => clearTimeout(timer));
}

function concatBytes(left, right) {
  if (!left.length) return right;
  const output = new Uint8Array(left.length + right.length);
  output.set(left);
  output.set(right, left.length);
  return output;
}

class SocketIO {
  constructor(socket) {
    this.socket = socket;
    this.reader = socket.readable.getReader();
    this.writer = socket.writable.getWriter();
    this.buffer = new Uint8Array();
    this.closed = false;
  }

  async fill(milliseconds, label) {
    const { value, done } = await timeout(this.reader.read(), milliseconds, label);
    if (done) throw new Error("Remote socket closed");
    this.buffer = concatBytes(this.buffer, value);
  }

  async readLine(milliseconds = COMMAND_TIMEOUT, label = "Socket read timeout") {
    for (;;) {
      for (let i = 0; i + 1 < this.buffer.length; i += 1) {
        if (this.buffer[i] === 13 && this.buffer[i + 1] === 10) {
          const line = this.buffer.slice(0, i);
          this.buffer = this.buffer.slice(i + 2);
          return decoder.decode(line);
        }
      }
      await this.fill(milliseconds, label);
    }
  }

  async readExact(length, milliseconds = COMMAND_TIMEOUT, label = "Socket literal timeout") {
    while (this.buffer.length < length) await this.fill(milliseconds, label);
    const output = this.buffer.slice(0, length);
    this.buffer = this.buffer.slice(length);
    return output;
  }

  async write(value) {
    const bytes = typeof value === "string"
      ? encoder.encode(value)
      : value instanceof Uint8Array
        ? value
        : new Uint8Array(value);
    await timeout(this.writer.write(bytes), COMMAND_TIMEOUT, "Socket write timeout");
  }

  releaseLocks() {
    try { this.reader.releaseLock(); } catch {}
    try { this.writer.releaseLock(); } catch {}
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    try { await this.socket.close(); } catch {}
    this.releaseLocks();
  }
}

function imapQuote(value) {
  return `"${String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function encodeModifiedUtf7(value) {
  let output = "";
  let unicode = "";
  const flush = () => {
    if (!unicode) return;
    const bytes = new Uint8Array(unicode.length * 2);
    for (let i = 0; i < unicode.length; i += 1) {
      const code = unicode.charCodeAt(i);
      bytes[i * 2] = code >> 8;
      bytes[i * 2 + 1] = code & 0xff;
    }
    output += `&${Buffer.from(bytes).toString("base64").replace(/\//g, ",").replace(/=+$/g, "")}-`;
    unicode = "";
  };
  for (const ch of String(value)) {
    const code = ch.charCodeAt(0);
    if (code >= 0x20 && code <= 0x7e) {
      flush();
      output += ch === "&" ? "&-" : ch;
    } else unicode += ch;
  }
  flush();
  return output;
}

function decodeModifiedUtf7(value) {
  return String(value).replace(/&([^-]*)-/g, (_, encoded) => {
    if (!encoded) return "&";
    const base64 = encoded.replace(/,/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const bytes = Buffer.from(padded, "base64");
    let output = "";
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      output += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    }
    return output;
  });
}

function mailboxArg(value) {
  return imapQuote(encodeModifiedUtf7(value));
}

function unquote(value) {
  const text = String(value).trim();
  if (text.toUpperCase() === "NIL") return null;
  if (text.startsWith('"') && text.endsWith('"')) {
    return text.slice(1, -1).replace(/\\(["\\])/g, "$1");
  }
  return text;
}

function splitImapTokens(value) {
  const tokens = [];
  let current = "";
  let quoted = false;
  let escaped = false;
  for (const ch of value.trim()) {
    if (escaped) { current += ch; escaped = false; continue; }
    if (quoted && ch === "\\") { escaped = true; continue; }
    if (ch === '"') { quoted = !quoted; current += ch; continue; }
    if (!quoted && /\s/.test(ch)) {
      if (current) { tokens.push(current); current = ""; }
      continue;
    }
    current += ch;
  }
  if (current) tokens.push(current);
  return tokens;
}

function parseAddresses(value) {
  return (value?.value || []).map((address) => ({
    name: address.name || "",
    address: address.address || "",
  }));
}

async function messageEnvelope(source) {
  const parsed = await simpleParser(Buffer.from(source), {
    skipHtmlToText: true,
    skipTextToHtml: true,
    skipImageLinks: true,
  });
  return {
    subject: parsed.subject || "",
    from: parseAddresses(parsed.from),
    to: parseAddresses(parsed.to),
    cc: parseAddresses(parsed.cc),
    date: parsed.date || null,
  };
}

function formatImapDate(value) {
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return `${String(value.getUTCDate()).padStart(2, "0")}-${months[value.getUTCMonth()]}-${value.getUTCFullYear()}`;
}

function searchTerm(key, value) {
  return `${key} ${imapQuote(value)}`;
}

function buildSearch(criteria) {
  const terms = [];
  if (criteria.all) terms.push("ALL");
  if (typeof criteria.seen === "boolean") terms.push(criteria.seen ? "SEEN" : "UNSEEN");
  if (typeof criteria.flagged === "boolean") terms.push(criteria.flagged ? "FLAGGED" : "UNFLAGGED");
  if (criteria.from) terms.push(searchTerm("FROM", criteria.from));
  if (criteria.to) terms.push(searchTerm("TO", criteria.to));
  if (criteria.subject) terms.push(searchTerm("SUBJECT", criteria.subject));
  if (criteria.body) terms.push(searchTerm("BODY", criteria.body));
  if (criteria.since) terms.push(`SINCE ${formatImapDate(criteria.since)}`);
  if (criteria.before) terms.push(`BEFORE ${formatImapDate(criteria.before)}`);
  if (criteria.or?.length) {
    const children = criteria.or.map(buildSearch);
    let expression = children.pop();
    while (children.length) expression = `OR ${children.pop()} ${expression}`;
    terms.push(expression);
  }
  return terms.length ? terms.join(" ") : "ALL";
}

export class WorkerImapClient {
  constructor(options) {
    this.options = options;
    this.socket = null;
    this.io = null;
    this.tag = 0;
    this.mailbox = null;
    this.authenticated = false;
    this.secureConnection = false;
    this.capabilities = new Map();
    this.errorHandler = null;
  }

  on(event, handler) {
    if (event === "error") this.errorHandler = handler;
    return this;
  }

  emitError(error) {
    if (this.errorHandler) this.errorHandler(error);
  }

  async connect() {
    const startedAt = Date.now();
    const { host, port, auth } = this.options;
    const security = this.options.security || (this.options.secure === false ? "starttls" : "tls");
    const secureTransport = security === "starttls" ? "starttls" : "on";
    logStage("IMAP", "connecting", { host, port, security });

    try {
      this.socket = connect({ hostname: host, port }, { secureTransport, allowHalfOpen: false });
      await timeout(this.socket.opened, this.options.connectionTimeout || CONNECT_TIMEOUT, "IMAP TCP open timeout");
      this.io = new SocketIO(this.socket);
      this.secureConnection = security === "tls";
      logStage("IMAP", security === "tls" ? "tcp_tls_opened" : "tcp_opened", {
        host, port, durationMs: Date.now() - startedAt,
      });

      const greeting = await this.io.readLine(
        this.options.greetingTimeout || GREETING_TIMEOUT,
        "IMAP greeting timeout",
      );
      if (!/^\*\s+(OK|PREAUTH)\b/i.test(greeting)) {
        throw new Error(`IMAP invalid greeting: ${greeting.slice(0, 160)}`);
      }
      logStage("IMAP", "server_greeting_received", { durationMs: Date.now() - startedAt });
      const advertised = greeting.match(/\[CAPABILITY\s+([^\]]+)\]/i);
      if (advertised) this.setCapabilities(advertised[1]);
      if (!this.capabilities.size) await this.refreshCapabilities();

      if (security === "starttls") {
        if (!this.capabilities.has("STARTTLS")) throw new Error("IMAP server does not advertise STARTTLS");
        await this.command("STARTTLS", { operation: "STARTTLS" });
        this.io.releaseLocks();
        this.socket = this.socket.startTls();
        await timeout(this.socket.opened, this.options.connectionTimeout || CONNECT_TIMEOUT, "IMAP STARTTLS open timeout");
        this.io = new SocketIO(this.socket);
        this.secureConnection = true;
        this.capabilities.clear();
        await this.refreshCapabilities();
        logStage("IMAP", "starttls_upgraded", { durationMs: Date.now() - startedAt });
      }

      if (/^\*\s+PREAUTH\b/i.test(greeting)) {
        this.authenticated = true;
      } else {
        logStage("IMAP", "authenticating");
        await this.authenticate(auth.user, auth.pass);
        this.authenticated = true;
      }
      await this.refreshCapabilities();
      if (this.options.clientId && this.capabilities.has("ID")) {
        await this.identify(this.options.clientId);
      }
      logStage("IMAP", "authenticated", { durationMs: Date.now() - startedAt });
    } catch (error) {
      logStage("IMAP", "failed", { durationMs: Date.now() - startedAt, error: errorMessage(error) });
      this.emitError(error);
      await this.close();
      throw error;
    }
  }

  setCapabilities(value) {
    for (const item of String(value).trim().split(/\s+/)) {
      if (item) this.capabilities.set(item.toUpperCase(), true);
    }
  }

  async refreshCapabilities() {
    const response = await this.command("CAPABILITY", { operation: "CAPABILITY" });
    for (const record of response.records) {
      const match = record.text.match(/^\*\s+CAPABILITY\s+(.+)$/i);
      if (match) this.setCapabilities(match[1]);
    }
  }

  async identify(info) {
    const pairs = Object.entries(info || {})
      .filter(([, value]) => value !== undefined && value !== null && String(value) !== "")
      .flatMap(([key, value]) => [imapQuote(key), imapQuote(value)]);
    if (!pairs.length) return false;
    await this.command(`ID (${pairs.join(" ")})`, { operation: "ID" });
    logStage("IMAP", "client_identified", { name: String(info.name || "") });
    return true;
  }

  async authenticate(user, pass) {
    if (!this.capabilities.has("LOGINDISABLED")) {
      try {
        await this.command(`LOGIN ${imapQuote(user)} ${imapQuote(pass)}`, { operation: "LOGIN" });
        return;
      } catch (error) {
        if (!this.capabilities.has("AUTH=PLAIN")) throw error;
      }
    }
    if (!this.capabilities.has("AUTH=PLAIN")) throw new Error("IMAP server does not support LOGIN or AUTH=PLAIN");
    const tag = `A${String(++this.tag).padStart(4, "0")}`;
    await this.io.write(`${tag} AUTHENTICATE PLAIN\r\n`);
    const continuation = await this.io.readLine(COMMAND_TIMEOUT, "IMAP AUTH PLAIN continuation timeout");
    if (!continuation.startsWith("+")) throw new Error(`IMAP AUTH PLAIN rejected: ${continuation.slice(0, 160)}`);
    const payload = Buffer.from(`\0${user}\0${pass}`).toString("base64");
    await this.io.write(`${payload}\r\n`);
    await this.readTagged(tag, COMMAND_TIMEOUT);
  }

  async readRecord(milliseconds = COMMAND_TIMEOUT) {
    let line = await this.io.readLine(milliseconds, "IMAP response timeout");
    const parts = [line];
    const literals = [];
    for (;;) {
      const literal = line.match(/\{(\d+)\+?\}$/);
      if (!literal) break;
      literals.push(await this.io.readExact(Number(literal[1]), milliseconds, "IMAP literal timeout"));
      line = await this.io.readLine(milliseconds, "IMAP response timeout");
      parts.push(line);
    }
    return { text: parts.join("\n"), parts, literals };
  }

  async readTagged(tag, milliseconds = COMMAND_TIMEOUT) {
    const records = [];
    for (;;) {
      const record = await this.readRecord(milliseconds);
      if (record.parts[0].startsWith(`${tag} `)) {
        const match = record.parts[0].match(/^\S+\s+(OK|NO|BAD)\b\s*(.*)$/i);
        if (!match) throw new Error("Malformed IMAP tagged response");
        if (match[1].toUpperCase() !== "OK") {
          const error = new Error(`IMAP ${match[1].toUpperCase()}: ${match[2].slice(0, 240)}`);
          error.code = match[1].toUpperCase();
          throw error;
        }
        return { records, status: match[1].toUpperCase(), text: match[2] };
      }
      records.push(record);
    }
  }

  async command(command, options = {}) {
    const tag = `A${String(++this.tag).padStart(4, "0")}`;
    try {
      await this.io.write(`${tag} ${command}\r\n`);
      return await this.readTagged(tag, options.timeout || COMMAND_TIMEOUT);
    } catch (error) {
      if (!["NO", "BAD"].includes(error?.code)) {
        this.emitError(error);
        await this.close();
      }
      throw error;
    }
  }

  async logout() {
    if (!this.io) return;
    try { await this.command("LOGOUT", { operation: "LOGOUT", timeout: 5_000 }); }
    finally { await this.close(); }
  }

  async close() {
    const io = this.io;
    this.io = null;
    this.authenticated = false;
    this.mailbox = null;
    if (io) await io.close();
    this.socket = null;
  }

  async list(options = {}) {
    const listed = await this.command('LIST "" "*"', { operation: "LIST" });
    let subscribedRecords = [];
    try {
      subscribedRecords = (await this.command('LSUB "" "*"', { operation: "LSUB" })).records;
    } catch {}
    const subscribedPaths = new Set(
      subscribedRecords.map((r) => this.parseListRecord(r, true)).filter(Boolean).map((f) => f.path),
    );
    const folders = listed.records.map((r) => this.parseListRecord(r, false)).filter(Boolean);
    for (const folder of folders) {
      folder.subscribed = subscribedPaths.has(folder.path);
      if (options.statusQuery) {
        try { folder.status = await this.status(folder.path, options.statusQuery); }
        catch (error) {
          logStage("IMAP", "folder_status_failed", { folder: folder.path, error: errorMessage(error) });
          folder.status = null;
        }
      }
    }
    return folders;
  }

  parseListRecord(record, fromLsub) {
    const match = record.text.match(/^\*\s+(?:LIST|LSUB)\s+\(([^)]*)\)\s+(.+)$/i);
    if (!match) return null;
    const tokens = splitImapTokens(match[2]);
    if (tokens.length < 2) return null;
    const flags = new Set(match[1].split(/\s+/).filter(Boolean));
    const rawPath = record.literals[0] ? decoder.decode(record.literals[0]) : unquote(tokens.slice(1).join(" "));
    const path = decodeModifiedUtf7(rawPath);
    const specialUse = [...flags].find((flag) => /^\\(?:All|Archive|Drafts|Flagged|Junk|Sent|Trash)$/i.test(flag))
      || (path.toUpperCase() === "INBOX" ? "\\Inbox" : null);
    return {
      path,
      name: path.split(unquote(tokens[0]) || "/").pop() || path,
      delimiter: unquote(tokens[0]),
      flags,
      specialUse,
      subscribed: fromLsub,
    };
  }

  async status(path, query = {}) {
    const names = [];
    if (query.messages) names.push("MESSAGES");
    if (query.unseen) names.push("UNSEEN");
    if (query.uidNext) names.push("UIDNEXT");
    if (query.uidValidity) names.push("UIDVALIDITY");
    if (query.size) names.push("SIZE");
    const run = (items) => this.command(`STATUS ${mailboxArg(path)} (${items.join(" ")})`, { operation: "STATUS" });
    let response;
    try { response = await run(names); }
    catch (error) {
      if (!query.size) throw error;
      response = await run(names.filter((name) => name !== "SIZE"));
    }
    const record = response.records.find((item) => /^\*\s+STATUS\b/i.test(item.text));
    const values = record?.text.match(/\(([^)]*)\)/)?.[1] || "";
    const tokens = values.trim().split(/\s+/);
    const output = {};
    const keyMap = { MESSAGES: "messages", UNSEEN: "unseen", UIDNEXT: "uidNext", UIDVALIDITY: "uidValidity", SIZE: "size" };
    for (let i = 0; i + 1 < tokens.length; i += 2) {
      const key = keyMap[tokens[i].toUpperCase()];
      if (key) output[key] = Number(tokens[i + 1]);
    }
    return output;
  }

  async getQuota(path) {
    let response;
    try { response = await this.command(`GETQUOTAROOT ${mailboxArg(path)}`, { operation: "GETQUOTAROOT" }); }
    catch { return false; }
    const record = response.records.find((item) => /^\*\s+QUOTA\b/i.test(item.text));
    if (!record) return false;
    const values = record.text.match(/\(([^)]*)\)/)?.[1]?.trim().split(/\s+/) || [];
    const output = {};
    for (let i = 0; i + 2 < values.length; i += 3) {
      output[values[i].toLowerCase()] = { used: Number(values[i + 1]), limit: Number(values[i + 2]) };
    }
    return output;
  }

  async getMailboxLock(path, options = {}) {
    const command = options.readOnly ? "EXAMINE" : "SELECT";
    const response = await this.command(`${command} ${mailboxArg(path)}`, { operation: command });
    let exists = 0;
    let uidNext;
    let uidValidity;
    for (const record of response.records) {
      const count = record.text.match(/^\*\s+(\d+)\s+EXISTS\b/i);
      if (count) exists = Number(count[1]);
      const next = record.text.match(/\[UIDNEXT\s+(\d+)\]/i);
      if (next) uidNext = Number(next[1]);
      const validity = record.text.match(/\[UIDVALIDITY\s+(\d+)\]/i);
      if (validity) uidValidity = Number(validity[1]);
    }
    this.mailbox = { path, exists, uidNext, uidValidity, readOnly: !!options.readOnly };
    return { path, release: () => {} };
  }

  normalizeRange(range, uidMode) {
    if (Array.isArray(range)) return range.join(",");
    if (typeof range === "number") return String(range);
    if (typeof range === "string" && range.startsWith(":-") && !uidMode) {
      const count = Number(range.slice(2));
      const end = this.mailbox?.exists || 0;
      if (!end) return null;
      return `${Math.max(1, end - count + 1)}:${end}`;
    }
    return String(range);
  }

  async fetchAll(range, query = {}, options = {}) {
    const normalizedRange = this.normalizeRange(range, !!options.uid);
    if (!normalizedRange) return [];
    const attributes = ["UID", "FLAGS", "RFC822.SIZE", "INTERNALDATE"];
    if (query.source) attributes.push("BODY.PEEK[]");
    else if (query.envelope) attributes.push("BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO CC DATE)]");
    const prefix = options.uid ? "UID " : "";
    const response = await this.command(`${prefix}FETCH ${normalizedRange} (${attributes.join(" ")})`, { operation: "FETCH" });
    const messages = [];
    for (const record of response.records) {
      const sequence = record.text.match(/^\*\s+(\d+)\s+FETCH\b/i);
      if (!sequence) continue;
      const uid = record.text.match(/\bUID\s+(\d+)\b/i);
      const size = record.text.match(/\bRFC822\.SIZE\s+(\d+)\b/i);
      const internalDate = record.text.match(/\bINTERNALDATE\s+"([^"]+)"/i);
      const flags = record.text.match(/\bFLAGS\s+\(([^)]*)\)/i);
      const literal = record.literals[0];
      const message = {
        seq: Number(sequence[1]),
        uid: uid ? Number(uid[1]) : undefined,
        size: size ? Number(size[1]) : 0,
        internalDate: internalDate ? new Date(internalDate[1]) : null,
        flags: new Set(flags ? flags[1].split(/\s+/).filter(Boolean) : []),
      };
      if (literal) {
        if (query.source) message.source = Buffer.from(literal);
        message.envelope = await messageEnvelope(literal);
      }
      messages.push(message);
    }
    return messages;
  }

  async fetchOne(range, query = {}, options = {}) {
    const messages = await this.fetchAll(range, query, options);
    return messages[0] || false;
  }

  async search(criteria, options = {}) {
    const prefix = options.uid ? "UID " : "";
    const expression = buildSearch(criteria);
    const charset = /[^\x00-\x7f]/.test(expression) ? "CHARSET UTF-8 " : "";
    const response = await this.command(`${prefix}SEARCH ${charset}${expression}`, { operation: "SEARCH" });
    const record = response.records.find((item) => /^\*\s+SEARCH\b/i.test(item.text));
    if (!record) return [];
    return record.text.replace(/^\*\s+SEARCH\s*/i, "").trim().split(/\s+/).filter(Boolean).map(Number).filter(Number.isFinite);
  }

  async messageFlagsAdd(uid, flags) {
    await this.command(`UID STORE ${uid} +FLAGS.SILENT (${flags.join(" ")})`, { operation: "STORE" });
    return true;
  }

  async messageFlagsRemove(uid, flags) {
    await this.command(`UID STORE ${uid} -FLAGS.SILENT (${flags.join(" ")})`, { operation: "STORE" });
    return true;
  }

  async messageCopy(uid, targetFolder) {
    return (await this.command(`UID COPY ${uid} ${mailboxArg(targetFolder)}`, { operation: "COPY" })).text;
  }

  async messageMove(uid, targetFolder) {
    if (this.capabilities.has("MOVE")) {
      return (await this.command(`UID MOVE ${uid} ${mailboxArg(targetFolder)}`, { operation: "MOVE" })).text;
    }
    await this.messageCopy(uid, targetFolder);
    await this.messageFlagsAdd(uid, ["\\Deleted"]);
    return (await this.command("EXPUNGE", { operation: "EXPUNGE" })).text;
  }

  async mailboxCreate(path) {
    return (await this.command(`CREATE ${mailboxArg(path)}`, { operation: "CREATE" })).text;
  }

  async mailboxRename(path, newPath) {
    return (await this.command(`RENAME ${mailboxArg(path)} ${mailboxArg(newPath)}`, { operation: "RENAME" })).text;
  }

  async mailboxSubscribe(path) {
    await this.command(`SUBSCRIBE ${mailboxArg(path)}`, { operation: "SUBSCRIBE" });
    return true;
  }

  async mailboxUnsubscribe(path) {
    await this.command(`UNSUBSCRIBE ${mailboxArg(path)}`, { operation: "UNSUBSCRIBE" });
    return true;
  }

  async append(path, message, flags = [], date = null) {
    const bytes = message instanceof Uint8Array ? message : new Uint8Array(message);
    const tag = `A${String(++this.tag).padStart(4, "0")}`;
    const flagPart = flags.length ? ` (${flags.join(" ")})` : "";
    const datePart = date ? ` ${imapQuote(date.toUTCString())}` : "";
    await this.io.write(`${tag} APPEND ${mailboxArg(path)}${flagPart}${datePart} {${bytes.length}}\r\n`);
    const continuation = await this.io.readLine(COMMAND_TIMEOUT, "IMAP APPEND continuation timeout");
    if (!continuation.startsWith("+")) throw new Error(`IMAP APPEND rejected: ${continuation.slice(0, 160)}`);
    await this.io.write(bytes);
    await this.io.write("\r\n");
    return (await this.readTagged(tag, COMMAND_TIMEOUT)).text;
  }
}

export class WorkerSmtpTransport {
  constructor(options) {
    this.options = options;
  }

  createTransport() {
    const { host, port, security, email, credential } = this.options;
    const secure = security === "tls";
    const transporter = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: { user: email, pass: credential },
      tls: { servername: host },
      connectionTimeout: CONNECT_TIMEOUT,
      greetingTimeout: GREETING_TIMEOUT,
      socketTimeout: COMMAND_TIMEOUT,
    });
    return transporter;
  }

  async verify() {
    return this.createTransport().verify();
  }

  async sendMail(message) {
    return this.createTransport().sendMail(message);
  }
}
