const encoder = new TextEncoder();
const decoder = new TextDecoder();

function b64(bytes) {
  return Buffer.from(bytes).toString("base64");
}
function unb64(value) {
  return Uint8Array.from(Buffer.from(String(value || ""), "base64"));
}
async function keyMaterial(secret) {
  const raw = encoder.encode(String(secret || ""));
  if (!raw.length) return null;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
}
async function aesKey(secret, usage) {
  const material = await keyMaterial(secret);
  if (!material) return null;
  return crypto.subtle.importKey("raw", material, { name: "AES-GCM" }, false, usage);
}
export async function encryptJson(value, secret, additionalData = "") {
  const key = await aesKey(secret, ["encrypt"]);
  if (!key) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode(String(additionalData || ""));
  const plaintext = encoder.encode(JSON.stringify(value));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({
    name: "AES-GCM",
    iv,
    additionalData: aad,
  }, key, plaintext));
  return { v: 1, iv: b64(iv), data: b64(ciphertext) };
}
export async function decryptJson(envelope, secret, additionalData = "") {
  if (!envelope) return null;
  if (Number(envelope.v) !== 1) throw new Error(`不支持的 Proton session 密文版本：${envelope.v}`);
  const key = await aesKey(secret, ["decrypt"]);
  if (!key) throw new Error("缺少 PROTON_SESSION_KEY，无法恢复已加密的 Proton session");
  const plaintext = await crypto.subtle.decrypt({
    name: "AES-GCM",
    iv: unb64(envelope.iv),
    additionalData: encoder.encode(String(additionalData || "")),
  }, key, unb64(envelope.data));
  return JSON.parse(decoder.decode(plaintext));
}
export function hasSessionEncryption(env) {
  return Boolean(String(env?.PROTON_SESSION_KEY || "").trim());
}
