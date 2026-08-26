import { ProtonClient } from "./client-v2.js";

const SYSTEM_LABELS = {
  INBOX: "0",
  "ALL DRAFTS": "1",
  "ALL SENT": "2",
  TRASH: "3",
  SPAM: "4",
  "ALL MAIL": "5",
  ARCHIVE: "6",
  SENT: "7",
  DRAFTS: "8",
  OUTBOX: "9",
  STARRED: "10",
  SCHEDULED: "12",
};

const list = (value) => Array.isArray(value) ? value : [];
const bool = (value) => value === true || value === 1;

function address(value) {
  if (!value) return null;
  if (typeof value === "string") return { name: "", address: value };
  return {
    name: String(value.Name ?? value.name ?? ""),
    address: String(value.Address ?? value.address ?? value.Email ?? value.email ?? ""),
  };
}

function addresses(values) {
  return list(values).map(address).filter((x) => x?.address);
}

function labelForFolder(folder = "INBOX") {
  const raw = String(folder || "INBOX").trim();
  if (/^\d+$/.test(raw)) return raw;
  return SYSTEM_LABELS[raw.toUpperCase()] ?? "0";
}

function messageFlags(meta) {
  const flags = [];
  if (!bool(meta.Unread)) flags.push("\\Seen");
  if (list(meta.LabelIDs).map(String).includes("10")) flags.push("\\Flagged");
  if (bool(meta.IsReplied) || bool(meta.IsRepliedAll)) flags.push("\\Answered");
  return flags;
}

function metaToMail(meta, cfg, folder = "INBOX") {
  const id = String(meta.ID || "");
  const sender = address(meta.Sender);
  return {
    account: cfg.id,
    accountLabel: cfg.label,
    provider: "proton",
    folder,
    protonId: id,
    subject: String(meta.Subject || ""),
    from: sender ? [sender] : [],
    to: addresses(meta.ToList),
    cc: addresses(meta.CCList),
    date: meta.Time ? new Date(Number(meta.Time) * 1000).toISOString() : null,
    size: Number(meta.Size || 0),
    flags: messageFlags(meta),
    unread: bool(meta.Unread),
    addressId: String(meta.AddressID || ""),
    attachmentCount: Number(meta.NumAttachments || 0),
  };
}

function messageQueryPath({ folder = "INBOX", limit = 20 } = {}) {
  const params = new URLSearchParams();
  params.set("LabelID", labelForFolder(folder));
  params.set("Desc", "1");
  params.set("Page", "0");
  params.set("PageSize", String(Math.min(Math.max(Number(limit) || 20, 1), 100)));
  params.set("Sort", "Time");
  return `/mail/v4/messages?${params.toString()}`;
}

// Proton WebClients queries message metadata with GET + query parameters.
// POST /mail/v4/messages is the create-draft endpoint and requires Message.
ProtonClient.prototype.listMessages = async function listMessages({ folder = "INBOX", limit = 20 } = {}) {
  const payload = await this.request(messageQueryPath({ folder, limit }), { method: "GET" });
  return list(payload.Messages).map((message) => metaToMail(message, this.cfg, folder));
};

export { messageQueryPath };
