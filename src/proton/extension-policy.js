const email = value => String(value || '').trim().toLowerCase();
export async function tokenHash(token) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2,'0')).join('');
}
export async function issuePair(storage, {actorId, uid, email: requestedEmail}, expectedEmail, now = Date.now()) {
  if (!actorId || !/^[A-Za-z0-9_-]{1,256}$/.test(uid || '') || email(requestedEmail) !== email(expectedEmail)) throw new Error('pair_rejected');
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const token = Array.from(bytes, b => b.toString(16).padStart(2,'0')).join('');
  const expiresAt = now + 5 * 60 * 1000;
  // One outstanding pairing per account; replacing it invalidates the previous token.
  await storage.put('proton:extensionPair:v1',{hash:await tokenHash(token),actorId,uid,email:email(expectedEmail),expiresAt});
  return {token,expiresAt};
}
export async function consumePair(storage, {actorId,token,bundle}, now = Date.now()) {
  if (!/^[a-f0-9]{64}$/.test(token || '')) throw new Error('pair_rejected');
  const hash = await tokenHash(token);
  return storage.transaction(async tx => {
    const pair = await tx.get('proton:extensionPair:v1');
    if (!pair || pair.hash !== hash || pair.actorId !== actorId || pair.uid !== bundle?.uid ||
      pair.email !== email(bundle?.email) || pair.expiresAt <= now) throw new Error('pair_rejected');
    await tx.delete('proton:extensionPair:v1');
    return pair;
  });
}
export function validateBundle(bundle, expectedEmail, now = Date.now()) {
  if (bundle?.version !== 1 || bundle.source !== 'https://mail.proton.me' ||
    email(bundle.email) !== email(expectedEmail) || !/^[A-Za-z0-9_-]{1,256}$/.test(bundle.uid || '') ||
    !Number.isFinite(bundle.capturedAt) || Math.abs(now - bundle.capturedAt) > 5 * 60 * 1000) throw new Error('bundle_rejected');
  if (!Array.isArray(bundle.cookies) || !bundle.cookies.length || bundle.cookies.length > 64) throw new Error('cookies_rejected');
  const seen = new Set();
  const cookies = bundle.cookies.map(c => {
    const domain = String(c.domain || '').replace(/^\./,'').toLowerCase();
    if (!(domain === 'mail.proton.me' || (domain === 'proton.me' && c.hostOnly === false)) ||
      !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(c.name || '') ||
      typeof c.value !== 'string' || c.value.length > 8192 || /[\x00-\x20\x7f;]/.test(c.value) ||
      typeof c.path !== 'string' || !c.path.startsWith('/') || /[\r\n]/.test(c.path) || c.partitionKey ||
      typeof c.secure !== 'boolean' || typeof c.httpOnly !== 'boolean' || typeof c.hostOnly !== 'boolean' ||
      (c.expiresAt !== null && (!Number.isFinite(c.expiresAt) || c.expiresAt <= now))) throw new Error('cookie_rejected');
    if (/^(AUTH|REFRESH)-/i.test(c.name) && ![`AUTH-${bundle.uid}`,`REFRESH-${bundle.uid}`].includes(c.name)) throw new Error('mixed_sessions');
    const key = `${c.name}\n${domain}\n${c.path}`;
    if (seen.has(key)) throw new Error('duplicate_cookie');
    seen.add(key);
    return {name:c.name,value:c.value,domain,hostOnly:c.hostOnly,path:c.path,secure:c.secure,httpOnly:c.httpOnly,
      sameSite:c.sameSite,expiresAt:c.expiresAt,session:c.session,expirationDate:c.expirationDate};
  });
  if (!cookies.some(c => c.name === `AUTH-${bundle.uid}` && c.value && c.secure)) throw new Error('auth_required');
  if (!bundle.user?.ID || !Array.isArray(bundle.keySalts) || !bundle.keySalts.length || bundle.keySalts.length > 32 ||
    bundle.keySalts.some(k => typeof k.ID !== 'string' || typeof k.KeySalt !== 'string' || !k.KeySalt || k.KeySalt.length > 4096)) throw new Error('keys_rejected');
  return {cookies,uid:bundle.uid,userId:bundle.user.ID,keySalts:bundle.keySalts.map(k => ({ID:k.ID,KeySalt:k.KeySalt}))};
}
