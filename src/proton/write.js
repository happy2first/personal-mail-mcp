import {
  createMessage,
  encrypt,
  encryptSessionKey,
  generateSessionKey,
  readKey,
  sign,
} from "@protontech/openpgp";

const SEND_INTERNAL = 1;
const SEND_CLEAR = 4;
const SIGNATURE_NONE = 0;
const SIGNATURE_DETACHED = 1;

const list = (v) => Array.isArray(v) ? v : [];
const b64 = (v) => Buffer.from(v).toString("base64");
const unb64 = (v) => Uint8Array.from(Buffer.from(String(v || ""), "base64"));
const apiAddress = (v) => typeof v === "string"
  ? { Name: "", Address: v }
  : { Name: String(v?.name || v?.Name || ""), Address: String(v?.address || v?.Address || "") };
const packSessionKey = (k) => ({ Key: b64(k.data), Algorithm: k.algorithm });

async function senderContext(client) {
  await client.ensureKeys();
  const addr = client.addresses.find((x) => String(x.Email || "").toLowerCase() === String(client.cfg.email).toLowerCase())
    || client.addresses.find((x) => Number(x.Send) === 1)
    || client.addresses[0];
  if (!addr?.ID) throw new Error("找不到可发送的 Proton 地址");
  const keys = client.addressKeys.get(String(addr.ID)) || [];
  if (!keys.length) throw new Error("发送地址没有可用的已解锁密钥");
  return { address: addr, key: keys[0] };
}

function draftTemplate(client, params, sender) {
  const body = params.html !== undefined && params.html !== null ? String(params.html) : String(params.text || "");
  const mimeType = params.html !== undefined && params.html !== null ? "text/html" : "text/plain";
  return {
    body,
    mimeType,
    template: {
      Subject: String(params.subject || ""),
      Sender: { Name: String(sender.DisplayName || ""), Address: String(sender.Email || client.cfg.email) },
      ToList: list(params.to).map(apiAddress),
      CCList: list(params.cc).map(apiAddress),
      BCCList: list(params.bcc).map(apiAddress),
      Body: body,
      MIMEType: mimeType,
      Unread: 0,
    },
  };
}

async function encryptDraftTemplate(template, senderKey) {
  return {
    ...template,
    Body: await encrypt({
      message: await createMessage({ text: String(template.Body || "") }),
      encryptionKeys: [senderKey.toPublic()],
      format: "armored",
    }),
  };
}

async function uploadAttachment(client, messageId, item, senderKey) {
  const bytes = item.content instanceof Uint8Array ? item.content : Uint8Array.from(item.content || []);
  const sessionKey = await generateSessionKey({ encryptionKeys: [senderKey.toPublic()] });
  const dataPacket = await encrypt({
    message: await createMessage({ binary: bytes, filename: item.filename || "attachment" }),
    sessionKey,
    format: "binary",
  });
  const keyPacket = await encryptSessionKey({
    data: sessionKey.data,
    algorithm: sessionKey.algorithm,
    encryptionKeys: [senderKey.toPublic()],
    format: "binary",
  });
  const signature = await sign({
    message: await createMessage({ binary: bytes }),
    signingKeys: [senderKey],
    detached: true,
    format: "binary",
  });
  const form = new FormData();
  form.set("MessageID", messageId);
  form.set("Filename", item.filename || "attachment");
  form.set("MIMEType", item.contentType || "application/octet-stream");
  form.set("Disposition", item.disposition || "attachment");
  form.set("ContentID", item.cid || "");
  form.set("KeyPackets", new Blob([keyPacket], { type: "application/octet-stream" }), "blob");
  form.set("DataPacket", new Blob([dataPacket], { type: "application/octet-stream" }), "blob");
  form.set("Signature", new Blob([signature], { type: "application/octet-stream" }), "blob");
  const payload = await client.request("/mail/v4/attachments", { method: "POST", body: form });
  const attachment = payload.Attachment;
  if (!attachment?.ID) throw new Error("Proton 上传附件成功响应缺少 Attachment.ID");
  return { attachment, sessionKey, keyPacket };
}

async function createDraft(client, params = {}) {
  const { address: sender, key: senderKey } = await senderContext(client);
  const { body, mimeType, template } = draftTemplate(client, params, sender);
  const encryptedTemplate = await encryptDraftTemplate(template, senderKey);
  const req = {
    Message: encryptedTemplate,
    AttachmentKeyPackets: [],
    ...(params.parentId ? { ParentID: params.parentId, Action: Number(params.action || 0) } : {}),
  };
  const created = await client.request("/mail/v4/messages", { method: "POST", body: req });
  const draft = created.Message;
  if (!draft?.ID) throw new Error("Proton 创建草稿成功响应缺少 Message.ID");
  const uploaded = [];
  for (const item of list(params.attachments)) uploaded.push(await uploadAttachment(client, draft.ID, item, senderKey));
  if (uploaded.length) {
    await client.request(`/mail/v4/messages/${encodeURIComponent(draft.ID)}`, {
      method: "PUT",
      body: { Message: encryptedTemplate, AttachmentKeyPackets: uploaded.map((x) => b64(x.keyPacket)) },
    });
  }
  return { draft, senderKey, body, mimeType, uploaded };
}

async function recipientInfo(client, email) {
  const payload = await client.request(`/core/v4/keys?Email=${encodeURIComponent(email)}`);
  const recipientType = Number(payload.RecipientType || 2);
  const active = list(payload.Keys).filter((x) => (Number(x.Flags || 0) & 2) !== 0 && x.PublicKey);
  const publicKeys = [];
  for (const k of active) {
    try { publicKeys.push(await readKey({ armoredKey: k.PublicKey })); } catch { /* ignore malformed key */ }
  }
  return { recipientType, publicKeys };
}

async function makeSendPackage(client, context, recipients) {
  const infos = new Map();
  const internalKeys = [];
  for (const recipient of recipients) {
    const info = await recipientInfo(client, recipient);
    infos.set(recipient.toLowerCase(), info);
    if (info.recipientType === 1 && info.publicKeys.length) internalKeys.push(...info.publicKeys);
  }
  const sessionKey = await generateSessionKey({ encryptionKeys: internalKeys.length ? internalKeys : [context.senderKey.toPublic()] });
  const encryptedBody = await encrypt({
    message: await createMessage({ text: String(context.body || "") }),
    sessionKey,
    signingKeys: [context.senderKey],
    format: "binary",
  });
  const pkg = { Addresses: {}, MIMEType: context.mimeType, Type: 0, Body: b64(encryptedBody), AttachmentKeys: {} };
  let needsClearKeys = false;
  for (const recipient of recipients) {
    const info = infos.get(recipient.toLowerCase()) || { recipientType: 2, publicKeys: [] };
    if (info.recipientType === 1 && info.publicKeys.length) {
      const bodyKeyPacket = await encryptSessionKey({
        data: sessionKey.data, algorithm: sessionKey.algorithm,
        encryptionKeys: info.publicKeys, format: "binary",
      });
      const attachmentPackets = {};
      for (const { attachment, sessionKey: attachmentKey } of context.uploaded) {
        attachmentPackets[attachment.ID] = b64(await encryptSessionKey({
          data: attachmentKey.data, algorithm: attachmentKey.algorithm,
          encryptionKeys: info.publicKeys, format: "binary",
        }));
      }
      pkg.Addresses[recipient] = {
        Type: SEND_INTERNAL, Signature: SIGNATURE_DETACHED,
        BodyKeyPacket: b64(bodyKeyPacket), AttachmentKeyPackets: attachmentPackets,
      };
      pkg.Type |= SEND_INTERNAL;
    } else {
      pkg.Addresses[recipient] = { Type: SEND_CLEAR, Signature: SIGNATURE_NONE };
      pkg.Type |= SEND_CLEAR;
      needsClearKeys = true;
    }
  }
  if (needsClearKeys) {
    pkg.BodyKey = packSessionKey(sessionKey);
    for (const { attachment, sessionKey: attachmentKey } of context.uploaded) pkg.AttachmentKeys[attachment.ID] = packSessionKey(attachmentKey);
  }
  if (!Object.keys(pkg.AttachmentKeys).length) delete pkg.AttachmentKeys;
  return pkg;
}

async function sendDraft(client, context, recipients) {
  const unique = [...new Set(recipients.map((x) => String(x || "").trim()).filter(Boolean))];
  if (!unique.length) throw new Error("没有收件人");
  const pkg = await makeSendPackage(client, context, unique);
  const payload = await client.request(`/mail/v4/messages/${encodeURIComponent(context.draft.ID)}`, {
    method: "POST", body: { Packages: [pkg] },
  });
  return payload.Sent || payload.Message || payload;
}

export async function sendMail(client, params = {}) {
  const context = await createDraft(client, params);
  const sent = await sendDraft(client, context, [...list(params.to), ...list(params.cc), ...list(params.bcc)]);
  return { success: true, account: client.cfg.id, draftId: context.draft.ID, sentId: sent?.ID || null, message: sent };
}

export async function saveDraft(client, params = {}) {
  const context = await createDraft(client, params);
  return { success: true, account: client.cfg.id, draftId: context.draft.ID, message: context.draft };
}

export async function reply(client, messageId, params = {}) {
  const original = await client.getMessage(messageId, params.folder || "INBOX");
  const own = String(client.cfg.email).toLowerCase();
  const base = original.replyTo?.length ? original.replyTo : original.from;
  let to = base.map((x) => x.address).filter(Boolean);
  if (params.replyAll) {
    to = [...to, ...original.to.map((x) => x.address), ...original.cc.map((x) => x.address)]
      .filter((x) => String(x).toLowerCase() !== own);
  }
  to = [...new Set(to)];
  const subject = /^re:/i.test(original.subject || "") ? original.subject : `Re: ${original.subject || ""}`;
  const context = await createDraft(client, { ...params, to, cc: list(params.cc), subject, parentId: messageId, action: params.replyAll ? 1 : 0 });
  const sent = await sendDraft(client, context, [...to, ...list(params.cc)]);
  return { success: true, account: client.cfg.id, parentId: messageId, draftId: context.draft.ID, sentId: sent?.ID || null, to };
}

export async function forward(client, messageId, params = {}) {
  const original = await client.getMessage(messageId, params.folder || "INBOX");
  let originalAttachments = [];
  if (params.includeOriginalAttachments) {
    originalAttachments = await Promise.all(original.attachments.map(async (_, index) => {
      const a = await client.getAttachment(messageId, index);
      return { filename: a.filename || "attachment", contentType: a.contentType || undefined, content: unb64(a.base64) };
    }));
  }
  const body = [
    String(params.note || ""), "", "---------- Forwarded message ----------",
    `From: ${original.from.map((x) => x.address).join(", ")}`,
    `Date: ${original.date || ""}`, `Subject: ${original.subject || ""}`,
    `To: ${original.to.map((x) => x.address).join(", ")}`, "",
    original.text || (original.html ? "[HTML message]" : ""),
  ].join("\n");
  const subject = /^fwd:/i.test(original.subject || "") ? original.subject : `Fwd: ${original.subject || ""}`;
  const context = await createDraft(client, {
    to: list(params.to), cc: list(params.cc), bcc: list(params.bcc), subject,
    text: body, attachments: originalAttachments, parentId: messageId, action: 2,
  });
  const sent = await sendDraft(client, context, [...list(params.to), ...list(params.cc), ...list(params.bcc)]);
  await client.request("/mail/v4/messages/forward", { method: "PUT", body: { IDs: [messageId] } }).catch(() => {});
  return { success: true, account: client.cfg.id, parentId: messageId, draftId: context.draft.ID, sentId: sent?.ID || null };
}
