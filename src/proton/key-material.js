import {
  createMessage,
  decrypt,
  decryptKey,
  readMessage,
  readPrivateKey,
  readSignature,
  verify,
} from "@protontech/openpgp";
import { ProtonClient } from "./client-v2.js";
import { computeKeyPassword } from "./srp.js";

const decoder = new TextDecoder();
const list = (value) => Array.isArray(value) ? value : [];
const bool = (value) => value === true || value === 1;

function normalizeKeySalts(value) {
  let current = value;
  if (typeof current === "string") {
    const raw = current.trim();
    if (!raw) return null;
    try { current = JSON.parse(raw); }
    catch { return null; }
  }
  if (!current || typeof current !== "object" || Array.isArray(current)) return null;
  for (const key of ["data", "result", "response"]) {
    if (current[key] && typeof current[key] === "object" && !Array.isArray(current[key])) current = current[key];
  }
  const rows = current.KeySalts ?? current.keySalts;
  if (!Array.isArray(rows) || !rows.length) return null;
  const out = [];
  const seen = new Set();
  for (const row of rows) {
    const ID = String(row?.ID ?? row?.id ?? "").trim();
    const KeySalt = String(row?.KeySalt ?? row?.keySalt ?? "").trim();
    if (!ID || !KeySalt || KeySalt.length > 4096 || seen.has(ID)) continue;
    seen.add(ID);
    out.push({ ID, KeySalt });
  }
  return out.length ? out.slice(0, 32) : null;
}

async function unlockPrivateKey(armoredKey, passphrase) {
  const key = await readPrivateKey({ armoredKey });
  return key.isDecrypted() ? key : decryptKey({ privateKey: key, passphrase });
}

async function decryptToken(key, userKeys) {
  const message = await readMessage({ armoredMessage: key.Token });
  const decrypted = await decrypt({ message, decryptionKeys: userKeys, format: "binary" });
  const token = decrypted.data instanceof Uint8Array ? decrypted.data : new Uint8Array(decrypted.data);
  if (key.Signature) {
    const signature = await readSignature({ armoredSignature: key.Signature });
    const checked = await verify({
      message: await createMessage({ binary: token }),
      signature,
      verificationKeys: userKeys.map((item) => item.toPublic()),
    });
    if (!checked.signatures?.length) throw new Error("Proton address key token 缺少签名");
    await checked.signatures[0].verified;
  }
  return decoder.decode(token);
}

ProtonClient.prototype.ensureKeys = async function ensureKeysWithImportedSalt() {
  if (this.userKeys.length && this.addressKeys.size) return;
  await this.ensureAuthenticated();

  const [userPayload, addressesPayload] = await Promise.all([
    this.request("/core/v4/users"),
    this.request("/core/v4/addresses"),
  ]);
  this.user = userPayload.User;
  this.addresses = list(addressesPayload.Addresses);

  let salts = normalizeKeySalts({ KeySalts: this.auth?.KeySalts });
  if (!salts) {
    try {
      const saltsPayload = await this.request("/core/v4/keys/salts");
      salts = normalizeKeySalts(saltsPayload);
      if (salts) this.auth = { ...this.auth, KeySalts: salts };
    } catch (error) {
      if (Number(error?.protonCode) === 9101) {
        error.keySaltsRequired = true;
        error.message = `${error.message}；当前 Cookie Session 无法读取 KeySalt。请在 /proton/import 粘贴浏览器 GET /core/v4/keys/salts 的 Response JSON 后再次测试正文`;
      }
      throw error;
    }
  }
  if (!salts?.length) {
    const error = new Error("Proton 缺少 KeySalt；请在 /proton/import 导入浏览器 keys/salts Response JSON");
    error.keySaltsRequired = true;
    throw error;
  }

  const userApiKeys = list(this.user?.Keys).filter((item) => bool(item.Active));
  const primary = userApiKeys.find((item) => bool(item.Primary)) || userApiKeys[0];
  const salt = salts.find((item) => String(item.ID) === String(primary?.ID));
  if (!primary?.PrivateKey || !salt?.KeySalt) {
    const error = new Error("导入的 Proton KeySalt 与当前用户主密钥不匹配，请重新从同一账号浏览器会话导入 keys/salts Response");
    error.keySaltsRequired = true;
    throw error;
  }

  const mailboxPassword = Number(this.auth?.PasswordMode || 1) === 2 ? this.cfg.mailboxPassword : this.cfg.credential;
  if (!mailboxPassword) {
    const error = new Error("该 Proton 账号使用双密码模式，需要配置 MAIL_<ACCOUNT>_MAILBOX_PASSWORD");
    error.mailboxPasswordRequired = true;
    throw error;
  }
  const keyPass = await computeKeyPassword(mailboxPassword, salt.KeySalt);
  const userKeys = [];
  for (const key of userApiKeys) {
    try { userKeys.push(await unlockPrivateKey(key.PrivateKey, keyPass)); }
    catch (error) { console.warn(`Proton user key ${key.ID} unlock failed:`, error?.message || String(error)); }
  }
  if (!userKeys.length) throw new Error("无法解锁 Proton 用户密钥；请确认 Worker 中的 Proton 密码与当前账号一致");
  this.userKeys = userKeys;

  const addressKeys = new Map();
  for (const addr of this.addresses) {
    const unlocked = [];
    for (const key of list(addr.Keys).filter((item) => bool(item.Active))) {
      try {
        const passphrase = key.Token && key.Signature ? await decryptToken(key, userKeys) : keyPass;
        unlocked.push(await unlockPrivateKey(key.PrivateKey, passphrase));
      } catch (error) {
        console.warn(`Proton address key ${key.ID} unlock failed:`, error?.message || String(error));
      }
    }
    if (unlocked.length) addressKeys.set(String(addr.ID), unlocked);
  }
  if (!addressKeys.size) throw new Error("无法解锁任何 Proton 地址密钥");
  this.addressKeys = addressKeys;
};

export { normalizeKeySalts };
