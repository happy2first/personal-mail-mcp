import bcrypt from "bcryptjs";
import {
  readCleartextMessage,
  readKey,
  verify,
} from "@protontech/openpgp";

const SRP_BYTES = 256;
const BCRYPT_PREFIX = "$2y$10$";
const encoder = new TextEncoder();

const SRP_MODULUS_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
=Y4Mw
-----END PGP PUBLIC KEY BLOCK-----`;

function concat(...arrays) {
  const length = arrays.reduce((n, x) => n + x.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const array of arrays) {
    out.set(array, offset);
    offset += array.length;
  }
  return out;
}

function base64ToBytes(value) {
  return Uint8Array.from(Buffer.from(String(value), "base64"));
}

function bytesToBase64(value) {
  return Buffer.from(value).toString("base64");
}

async function sha512(input) {
  return new Uint8Array(await crypto.subtle.digest("SHA-512", input));
}

async function expandHash(input) {
  const pieces = [];
  for (let i = 0; i < 4; i += 1) {
    pieces.push(await sha512(concat(input, new Uint8Array([i]))));
  }
  return concat(...pieces);
}

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function bigIntToBytes(value, length = SRP_BYTES) {
  if (value < 0n) throw new Error("negative bigint");
  const out = new Uint8Array(length);
  let n = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new Error("SRP integer overflow");
  return out;
}

function mod(value, modulus) {
  const r = value % modulus;
  return r >= 0n ? r : r + modulus;
}

function modPow(base, exponent, modulus) {
  if (modulus <= 0n) throw new Error("invalid modulus");
  let b = mod(base, modulus);
  let e = exponent;
  let result = 1n;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

async function verifyAndDecodeModulus(armored) {
  const message = await readCleartextMessage({ cleartextMessage: armored });
  const verificationKey = await readKey({ armoredKey: SRP_MODULUS_KEY });
  const check = await verify({ message, verificationKeys: verificationKey });
  if (!check.signatures?.length) throw new Error("Proton SRP modulus 未签名");
  await check.signatures[0].verified;
  const modulus = base64ToBytes(message.getText().trim());
  if (modulus.length !== SRP_BYTES) throw new Error(`Proton SRP modulus 长度异常：${modulus.length}`);
  return modulus;
}

async function hashPasswordV3Plus(password, salt, modulus) {
  const saltBytes = base64ToBytes(salt);
  const bcryptSaltBytes = concat(saltBytes, encoder.encode("proton"));
  if (bcryptSaltBytes.length < 16) throw new Error("Proton SRP salt 长度异常");
  const encodedSalt = bcrypt.encodeBase64(Array.from(bcryptSaltBytes.slice(0, 16)), 16);
  const bcryptHash = await bcrypt.hash(password, `${BCRYPT_PREFIX}${encodedSalt}`);
  return expandHash(concat(encoder.encode(bcryptHash), modulus));
}

function randomClientSecret() {
  for (let i = 0; i < 1000; i += 1) {
    const bytes = crypto.getRandomValues(new Uint8Array(SRP_BYTES));
    const value = bytesToBigInt(bytes);
    if (value > 4096n) return value;
  }
  throw new Error("无法生成安全 SRP client secret");
}

export async function getSrp(authInfo, credentials) {
  const version = Number(authInfo.Version);
  if (version !== 3 && version !== 4) {
    throw new Error(`当前仅支持 Proton SRP v3/v4，服务器返回 v${version}`);
  }
  const modulusBytes = await verifyAndDecodeModulus(authInfo.Modulus);
  const serverEphemeralBytes = base64ToBytes(authInfo.ServerEphemeral);
  if (serverEphemeralBytes.length !== SRP_BYTES) throw new Error("Proton ServerEphemeral 长度异常");
  const passwordHashBytes = await hashPasswordV3Plus(credentials.password, authInfo.Salt, modulusBytes);

  const N = bytesToBigInt(modulusBytes);
  const NMinusOne = N - 1n;
  const g = 2n;
  const B = bytesToBigInt(serverEphemeralBytes);
  if (B <= 1n || B >= NMinusOne) throw new Error("Proton SRP server ephemeral 越界");

  const k = bytesToBigInt(await expandHash(concat(bigIntToBytes(g), modulusBytes)));
  const kReduced = k % N;
  if (kReduced <= 1n || kReduced >= NMinusOne) throw new Error("Proton SRP multiplier 越界");

  const x = bytesToBigInt(passwordHashBytes);
  let a;
  let A;
  let u;
  for (let i = 0; i < 1000; i += 1) {
    a = randomClientSecret();
    A = modPow(g, a, N);
    u = bytesToBigInt(await expandHash(concat(bigIntToBytes(A), serverEphemeralBytes)));
    if (u !== 0n) break;
  }
  if (!a || !A || !u) throw new Error("无法生成安全 SRP 参数");

  const gx = modPow(g, x, N);
  const base = mod(B - ((kReduced * gx) % N), N);
  const exponent = mod(a + u * x, NMinusOne);
  const shared = modPow(base, exponent, N);

  const ABytes = bigIntToBytes(A);
  const sharedBytes = bigIntToBytes(shared);
  const clientProof = await expandHash(concat(ABytes, serverEphemeralBytes, sharedBytes));
  const expectedServerProof = await expandHash(concat(ABytes, clientProof, sharedBytes));

  return {
    clientEphemeral: bytesToBase64(ABytes),
    clientProof: bytesToBase64(clientProof),
    expectedServerProof: bytesToBase64(expectedServerProof),
  };
}

export async function computeKeyPassword(password, keySaltBase64) {
  const salt = base64ToBytes(keySaltBase64);
  if (salt.length !== 16) throw new Error(`Proton KeySalt 长度异常：${salt.length}`);
  const encodedSalt = bcrypt.encodeBase64(Array.from(salt), 16);
  const hash = await bcrypt.hash(password, `${BCRYPT_PREFIX}${encodedSalt}`);
  return hash.slice(29);
}
