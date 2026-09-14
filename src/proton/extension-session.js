import './key-material-session.js';
import {ProtonSession} from './session.js';
import {ProtonClient} from './client-v2.js';
import {hasSessionEncryption} from './session-crypto.js';
import {issuePair,consumePair,validateBundle} from './extension-policy.js';

const originalFetch = ProtonSession.prototype.fetch;
ProtonSession.prototype.fetch = async function(request) {
  const parsed = request.method === 'POST' ? await request.clone().json().catch(() => null) : null;
  if (!['extensionPair','extensionImport'].includes(parsed?.action)) return originalFetch.call(this,request);
  return this.state.blockConcurrencyWhile(async () => {
  try {
    if (!hasSessionEncryption(this.env)) throw new Error('encryption_required');
    const previous = this.getClient(parsed.account);
    const payload = parsed.payload || {};
    if (parsed.action === 'extensionPair') return Response.json({ok:true,data:await issuePair(this.state.storage,payload,previous.cfg.email)});
    const input = validateBundle(payload.bundle,previous.cfg.email);
    await consumePair(this.state.storage,payload);
    // Independent candidate: unsuccessful validation must not overwrite the working session.
    const candidate = new ProtonClient(previous.cfg,this.env);
    if (candidate.baseUrl !== 'https://mail.proton.me/api') throw new Error('unsupported_proton_host');
    candidate.setAuth({UID:input.uid,cookies:true,RefreshToken:'__BROWSER_COOKIE_SESSION__'});
    candidate.setCookieState(input.cookies);
    // raw(auth:true) validates the imported session without password login or explicit refresh.
    const users = await candidate.raw('/core/v4/users',{auth:true});
    const addresses = await candidate.raw('/core/v4/addresses',{auth:true});
    if (users.User?.ID !== input.userId || !(addresses.Addresses || []).some(a =>
      String(a.Email).toLowerCase() === String(previous.cfg.email).toLowerCase())) throw new Error('account_mismatch');
    const ids = new Set((users.User?.Keys || []).filter(k => k.Active === 1 || k.Active === true).map(k => k.ID));
    const salts = input.keySalts.filter(k => ids.has(k.ID));
    if (!salts.length) throw new Error('key_mismatch');
    candidate.setAuth({...candidate.auth,UserID:users.User.ID,KeySalts:salts});
    // Reuse encryption envelopes, atomically commit both auth and cookie state.
    const {encryptJson} = await import('./session-crypto.js');
    const auth = await encryptJson(candidate.auth,this.env.PROTON_SESSION_KEY,`${previous.cfg.id}:proton:session:v2`);
    const cookies = await encryptJson(candidate.getCookieState(),this.env.PROTON_SESSION_KEY,`${previous.cfg.id}:proton:cookies:v1`);
    await this.state.storage.transaction(async tx => {
      await tx.put('proton:session:v2',auth);
      await tx.put('proton:cookies:v1',cookies);
      await tx.delete('proton:eventCursor:v1');
      await tx.put('proton:sessionMeta:v1',{source:'browser_extension',importedAt:Date.now(),lastValidatedAt:Date.now(),
        uidSuffix:input.uid.slice(-6),keySaltCount:salts.length,keySaltsImportedAt:Date.now()});
      const state = (await tx.get('proton:authState:v1')) || {};
      await tx.put('proton:authState:v1',{...state,reauthRequired:false,twoFactorPending:false});
    });
    // Force a fresh client and hydrate the new encrypted state on the next normal call.
    this.client = null; this.hydrated = false;
    return Response.json({ok:true,data:{success:true,account:previous.cfg.id,keySaltCount:salts.length}});
  } catch {
    // Never return upstream errors that could reflect request credentials.
    return Response.json({ok:false,error:'extension_import_rejected'},{status:400});
  }
  });
};
