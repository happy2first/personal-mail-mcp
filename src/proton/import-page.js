import { getAccount, listAccountIds } from "../mail-config.js";
import {
  isProtonAccount,
  protonAuthStatus,
  protonCall,
  protonClearSession,
  protonImportKeySalts,
  protonResetRisk,
  protonTestConnection,
} from "./provider.js";

const BASE = "/proton/import";
const API = `${BASE}/api`;
const MAX_BODY_BYTES = 128 * 1024;

function actorIdentity(actor) {
  return String(actor?.sub || actor?.email || "").trim();
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("base64url");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function maskEmail(email) {
  const raw = String(email || "");
  const at = raw.indexOf("@");
  if (at <= 0) return "已配置";
  const local = raw.slice(0, at);
  const domain = raw.slice(at + 1);
  const masked = local.length <= 2 ? `${local[0] || "*"}*` : `${local.slice(0, 2)}***${local.slice(-1)}`;
  return `${masked}@${domain}`;
}

function protonAccounts(env) {
  const rows = [];
  for (const id of listAccountIds(env)) {
    try {
      const cfg = getAccount(env, id);
      if (!isProtonAccount(cfg)) continue;
      rows.push({ id: cfg.id, label: cfg.label, email: maskEmail(cfg.email) });
    } catch {
      // Do not expose invalid configuration details.
    }
  }
  return rows;
}

function account(env, value) {
  const cfg = getAccount(env, String(value || "").trim());
  if (!isProtonAccount(cfg)) throw new Error("所选账号不是 Proton Provider");
  return cfg;
}

function safeError(error) {
  const out = { error: error instanceof Error ? error.message : String(error) };
  for (const key of [
    "protonCode", "serverRetryAfterSeconds", "localCooldownSeconds", "manualResetRequired",
    "sessionAccountMismatch", "requestPath", "requestMethod", "reauthRequired", "refreshFailed",
  ]) if (error?.[key] !== undefined) out[key] = error[key];
  return out;
}

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store, max-age=0",
      pragma: "no-cache",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
    },
  });
}

function parseCookies(request) {
  const result = {};
  for (const part of String(request.headers.get("cookie") || "").split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) continue;
    result[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return result;
}

function verifyCsrf(request) {
  const url = new URL(request.url);
  const origin = String(request.headers.get("origin") || "");
  if (origin && origin !== url.origin) throw new Error("请求 Origin 不匹配");
  const cookies = parseCookies(request);
  const cookie = cookies.proton_import_csrf;
  const header = String(request.headers.get("x-csrf-token") || "");
  if (!cookie || !header || cookie !== header) throw new Error("CSRF 校验失败，请刷新页面后重试");
}

async function readJson(request) {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > MAX_BODY_BYTES) throw new Error("请求内容超过 128KB");
  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) throw new Error("请求内容超过 128KB");
  try { return JSON.parse(text || "{}"); }
  catch { throw new Error("请求 JSON 无效"); }
}

function pageHtml(csrf, nonce) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="proton-extension-csrf" content="${escapeHtml(csrf)}">
<title>Proton Mail 连接</title>
<style nonce="${nonce}">
:root{font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;color:#172033;background:#f5f7fa}*{box-sizing:border-box}body{margin:0}.wrap{max-width:860px;margin:0 auto;padding:28px 18px 56px}.head{margin-bottom:18px}.head h1{font-size:26px;margin:0 0 6px}.muted{color:#667085;font-size:13px;line-height:1.6}.card{background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 2px rgba(16,24,40,.04)}label{display:block;font-weight:650;font-size:14px;margin-bottom:8px}select,textarea{width:100%;border:1px solid #d0d5dd;border-radius:8px;background:#fff;color:#172033;font:inherit}select{height:42px;padding:0 12px}textarea{min-height:130px;padding:12px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:1.5}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.item{border:1px solid #eaecf0;border-radius:8px;padding:12px}.item b{display:block;font-size:12px;color:#667085;margin-bottom:4px}.item span{font-size:14px;word-break:break-word}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}button{appearance:none;border:1px solid #d0d5dd;border-radius:8px;background:#fff;color:#344054;padding:9px 14px;font-weight:650;cursor:pointer;min-height:40px}button.primary{background:#1677ff;border-color:#1677ff;color:#fff}button.danger{color:#b42318;border-color:#fda29b}button:disabled{opacity:.55;cursor:not-allowed}.notice{border-left:3px solid #1677ff;padding:10px 12px;background:#f0f6ff;border-radius:6px;font-size:13px;line-height:1.6;margin-top:10px}.notice.warn{border-left-color:#f79009;background:#fffaeb}.result{white-space:pre-wrap;word-break:break-word;background:#101828;color:#f2f4f7;border-radius:8px;padding:12px;min-height:56px;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.ok{color:#067647}.bad{color:#b42318}.warnText{color:#b54708}.summary{font-size:16px;font-weight:700;margin:12px 0;padding:12px 14px;border-radius:8px;background:#f2f4f7}.summary.ok{background:#ecfdf3}.summary.warnText{background:#fffaeb}.summary.bad{background:#fef3f2}.step{display:inline-flex;width:25px;height:25px;align-items:center;justify-content:center;border-radius:50%;background:#1677ff;color:#fff;font-size:13px;margin-right:7px}.footer{margin-top:12px;color:#98a2b3;font-size:12px}details{border-top:1px solid #eaecf0;margin-top:16px;padding-top:12px}summary{cursor:pointer;font-weight:650;color:#475467}code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#f2f4f7;padding:1px 4px;border-radius:4px}.compact{margin-top:8px}.hidden{display:none}@media(max-width:760px){.grid{grid-template-columns:1fr 1fr}}@media(max-width:560px){.wrap{padding:18px 12px 40px}.head h1{font-size:22px}.grid{grid-template-columns:1fr 1fr}.card{padding:16px}button{width:100%}}
</style>
</head>
<body>
<div class="wrap">
  <div class="head">
    <h1>Proton Mail 连接</h1>
    <div class="muted">管理 Proton 浏览器会话。推荐使用桌面扩展；手工导入仅用于故障排查。</div>
  </div>

  <div class="card">
    <label>浏览器扩展（推荐）</label>
    <div class="notice">扩展会自动获取 <code>AUTH</code>、<code>REFRESH</code>、<code>Session-Id</code> 和 <code>KeySalt</code>。提交前会显示导入内容，可先导出 JSON；只有确认后才会上传。</div>
    <div class="muted compact">使用方法：桌面 Chrome / Edge 登录 Proton Mail，同时保持本页已通过 Cloudflare Access 登录，然后打开扩展。</div>
  </div>

  <div class="card">
    <label for="account">Proton 账号</label>
    <select id="account"></select>
    <div id="summary" class="summary">正在加载…</div>
    <div id="status" class="grid"><div class="muted">正在加载…</div></div>
    <div class="actions"><button id="refreshStatus">刷新</button><button id="testSession">测试读取</button><button id="testRefresh">测试续期</button></div>
    <div class="muted compact">“测试续期”会真实刷新一次会话，并保存 Proton 返回的新 Cookie。</div>
    <details>
      <summary>技术状态</summary>
      <div id="technicalStatus" class="grid" style="margin-top:12px"></div>
    </details>
  </div>

  <div class="card">
    <details>
      <summary>高级：手工导入 / 故障排查</summary>

      <label for="sessionCookie" style="margin-top:14px"><span class="step">1</span>普通 Session Cookie</label>
      <textarea id="sessionCookie" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="Cookie: AUTH-&lt;UID&gt;=...; Session-Id=...; ..."></textarea>
      <div class="muted compact">从最新成功的 <code>/core/v4/addresses</code> 请求复制完整 <code>Cookie:</code> 请求头。</div>

      <label for="refreshCookie" style="margin-top:16px"><span class="step">2</span>REFRESH Cookie</label>
      <textarea id="refreshCookie" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="REFRESH-&lt;UID&gt;=... 或完整 Set-Cookie 行"></textarea>
      <div class="muted compact">从登录请求 <code>/api/core/v4/auth/cookies</code> 的 Response Headers 复制对应 <code>REFRESH-&lt;UID&gt;</code>。</div>
      <div class="actions"><button id="importCookies" class="primary">导入 Session</button><button id="clearCookies">清空</button></div>

      <label for="keySalts" style="margin-top:16px"><span class="step">3</span>KeySalt</label>
      <textarea id="keySalts" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder='粘贴 {"Code":1000,"KeySalts":[...]}'></textarea>
      <div class="muted compact">仅手工排障需要。扩展会自动获取 KeySalt。</div>
      <div class="actions"><button id="importKeySalts">导入 KeySalt</button><button id="clearKeySalts">清空</button></div>
    </details>
  </div>

  <div class="card">
    <details>
      <summary>维护操作</summary>
      <div class="actions"><button id="clear" class="danger">清除已保存 Session</button><button id="resetRisk" class="danger">清除本地 2028 登录锁</button></div>
      <div class="muted compact">2028 登录锁只影响 Worker 密码重新登录，不影响已导入的浏览器 Session。</div>
    </details>
  </div>

  <div id="resultCard" class="card hidden"><label>操作结果</label><div id="result" class="result"></div></div>
  <div class="footer">Session、Cookie 和 KeySalt 在 Worker 中加密保存；本页不写入 localStorage。</div>
</div>
<script nonce="${nonce}">
const csrf=${JSON.stringify(csrf)};const $=id=>document.getElementById(id);let busy=false;
function setBusy(v){busy=v;document.querySelectorAll('button').forEach(b=>b.disabled=v)}
function fmtTime(v){if(!v)return '—';try{return new Date(Number(v)).toLocaleString()}catch{return String(v)}}
function safe(v){return v===undefined||v===null||v===''?'—':String(v)}
function esc(v){return safe(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function yesNo(v){return v?'✅ 正常':'❌ 缺失'}
function rowsHtml(rows){return rows.map(([k,v])=>'<div class="item"><b>'+esc(k)+'</b><span>'+esc(v)+'</span></div>').join('')}
function renderStatus(s){
  const session=s.session||{},risk=s.risk||{},attempt=s.lastAuthAttempt||{},refresh=s.refresh||{},keys=s.keyMaterial||{};
  let summary='';let cls='summary ';
  if(!s.hasSession){summary='尚未导入 Proton Session';cls+='bad'}
  else if(s.reauthRequired){summary='Session 需要重新导入';cls+='warnText'}
  else if(session.cookieAuth&&refresh.capable&&refresh.verified&&keys.imported){summary='连接正常';cls+='ok'}
  else if(session.cookieAuth&&refresh.capable&&keys.imported){summary='已导入，建议测试一次自动续期';cls+='warnText'}
  else{summary='已导入，但材料不完整';cls+='warnText'}
  $('summary').className=cls;$('summary').textContent=summary;
  $('status').innerHTML=rowsHtml([
    ['Session',s.hasSession?'✅ 已保存':'❌ 未保存'],
    ['自动续期',refresh.verified?'✅ 已验证':refresh.capable?'待测试':'❌ 不完整'],
    ['邮件解密',keys.imported?'✅ KeySalt 已保存':'❌ 缺少 KeySalt'],
    ['最后导入',fmtTime(session.importedAt)]
  ]);
  $('technicalStatus').innerHTML=rowsHtml([
    ['Cookie Auth',yesNo(session.cookieAuth)],
    ['AUTH',refresh.authCookieCount??s.transport?.authCookieCount],
    ['Session-Id',refresh.sessionIdCookieCount??s.transport?.sessionIdCookieCount],
    ['REFRESH',refresh.cookieCount??s.transport?.refreshCookieCount],
    ['Cookie 总数',s.transport?.cookieCount],
    ['UID 尾号',session.uidSuffix],
    ['最后续期',fmtTime(refresh.lastAttemptAt)],
    ['续期结果',refresh.lastResult],
    ['最后校验',fmtTime(session.lastValidatedAt)],
    ['需要恢复',s.reauthRequired?'是':'否'],
    ['2028 本地锁',risk.manualResetRequired?'已锁定':risk.attempt?'有记录':'无'],
    ['授权阶段',attempt.stage||'—']
  ]);
}
async function call(path,{method='GET',body}={}){const headers={'accept':'application/json'};if(method!=='GET'){headers['content-type']='application/json';headers['x-csrf-token']=csrf}const r=await fetch(path,{method,headers,body:body===undefined?undefined:JSON.stringify(body),credentials:'same-origin',cache:'no-store'});let data;try{data=await r.json()}catch{data={error:'服务器返回不可解析响应'}}if(!r.ok)throw Object.assign(new Error(data.error||('HTTP '+r.status)),{data});return data}
async function loadAccounts(){const data=await call('${API}/accounts');$('account').innerHTML=data.accounts.map(a=>'<option value="'+esc(a.id)+'">'+esc(a.label)+' · '+esc(a.email)+'</option>').join('');if(data.accounts.length)await loadStatus();else{$('summary').textContent='没有已配置的 Proton 账号';$('status').innerHTML=''}}
async function loadStatus(){const id=$('account').value;if(!id)return;const data=await call('${API}/status?account='+encodeURIComponent(id));renderStatus(data.status);return data}
async function act(fn){if(busy)return;setBusy(true);try{const data=await fn();$('resultCard').classList.remove('hidden');$('result').textContent=JSON.stringify(data,null,2);await loadStatus();return data}catch(e){$('resultCard').classList.remove('hidden');$('result').textContent=JSON.stringify(e.data||{error:e.message},null,2)}finally{setBusy(false)}}
$('account').addEventListener('change',()=>act(loadStatus));
$('refreshStatus').onclick=()=>act(loadStatus);
$('testSession').onclick=()=>act(()=>call('${API}/validate',{method:'POST',body:{account:$('account').value}}));
$('testRefresh').onclick=()=>{if(confirm('执行一次真实会话续期？Proton 会返回并替换新的 Session Cookie。'))act(()=>call('${API}/test-refresh',{method:'POST',body:{account:$('account').value}}))};
$('importCookies').onclick=()=>act(async()=>{const sessionCookie=$('sessionCookie').value.trim(),refreshCookie=$('refreshCookie').value.trim();if(!sessionCookie)throw new Error('请粘贴普通 Session Cookie');if(!refreshCookie)throw new Error('请粘贴同一 UID 的 REFRESH Cookie');const data=await call('${API}/import-cookies',{method:'POST',body:{account:$('account').value,sessionCookie,refreshCookie}});$('sessionCookie').value='';$('refreshCookie').value='';return data});
$('clearCookies').onclick=()=>{$('sessionCookie').value='';$('refreshCookie').value='';$('sessionCookie').focus()};
$('importKeySalts').onclick=()=>act(async()=>{const input=$('keySalts').value.trim();if(!input)throw new Error('请粘贴 KeySalt JSON');let keySalts;try{const parsed=JSON.parse(input);keySalts=parsed?.KeySalts??parsed?.keySalts??parsed}catch{throw new Error('KeySalt JSON 无效')}const data=await call('${API}/import-key-salts',{method:'POST',body:{account:$('account').value,keySalts}});$('keySalts').value='';return data});
$('clearKeySalts').onclick=()=>{$('keySalts').value='';$('keySalts').focus()};
$('clear').onclick=()=>{if(confirm('清除所选 Proton 账号已保存的 Session 和 KeySalt？'))act(()=>call('${API}/clear',{method:'POST',body:{account:$('account').value}}))};
$('resetRisk').onclick=()=>{if(confirm('仅清除 Worker 本地 2028 密码登录保护锁？'))act(()=>call('${API}/reset-risk',{method:'POST',body:{account:$('account').value}}))};
loadAccounts().catch(e=>{$('resultCard').classList.remove('hidden');$('result').textContent=e.message});
</script>
</body></html>`;
}

function pageResponse(actor) {
  const csrf = randomToken();
  const nonce = randomToken();
  const html = pageHtml(csrf, nonce);
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store, max-age=0",
      "set-cookie": `proton_import_csrf=${csrf}; Path=${BASE}; Max-Age=3600; HttpOnly; Secure; SameSite=Strict`,
      "content-security-policy": `default-src 'none'; connect-src 'self'; img-src 'self'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    },
  });
}

export async function handleProtonImport(request, env, actor = {}) {
  const url = new URL(request.url);
  if (url.pathname === BASE && request.method === "GET") return pageResponse(actor);
  if (!url.pathname.startsWith(`${API}/`)) return null;

  try {
    if (url.pathname === `${API}/accounts` && request.method === "GET") {
      return json({ accounts: protonAccounts(env) });
    }
    if (url.pathname === `${API}/status` && request.method === "GET") {
      const cfg = account(env, url.searchParams.get("account"));
      return json({ status: await protonAuthStatus(env, cfg) });
    }

    if (request.method !== "POST") return json({ error: "Method Not Allowed" }, 405);
    verifyCsrf(request);
    const body = await readJson(request);
    const cfg = account(env, body.account);

    if (url.pathname === `${API}/extension-pair`) {
      const uid = String(body.uid || "").trim();
      const email = String(body.email || "").trim();
      if (!uid || !email) throw new Error("缺少扩展配对 UID / email");
      return json(await protonCall(env, cfg, "extensionPair", {
        uid,
        email,
        actorId: actorIdentity(actor),
      }));
    }
    if (url.pathname === `${API}/extension-import`) {
      if (!body.token || !body.bundle || typeof body.bundle !== "object") throw new Error("缺少扩展配对 token / bundle");
      return json(await protonCall(env, cfg, "extensionImport", {
        token: String(body.token),
        bundle: body.bundle,
        actorId: actorIdentity(actor),
      }));
    }
    if (url.pathname === `${API}/import-cookies`) {
      if (typeof body.sessionCookie !== "string" || !body.sessionCookie.trim()) throw new Error("缺少浏览器 Session Cookie");
      const refreshCookie = ["string", "object"].includes(typeof body.refreshCookie) ? body.refreshCookie : null;
      return json(await protonCall(env, cfg, "importCookieBundle", {
        sessionCookie: body.sessionCookie,
        refreshCookie,
      }));
    }
    if (url.pathname === `${API}/test-refresh`) return json(await protonCall(env, cfg, "testRefresh"));
    if (url.pathname === `${API}/import-key-salts`) {
      if (!Array.isArray(body.keySalts) || !body.keySalts.length) throw new Error("缺少 KeySalt 列表");
      return json(await protonImportKeySalts(env, cfg, body.keySalts));
    }
    if (url.pathname === `${API}/validate`) return json(await protonTestConnection(env, cfg));
    if (url.pathname === `${API}/clear`) return json(await protonClearSession(env, cfg));
    if (url.pathname === `${API}/reset-risk`) return json(await protonResetRisk(env, cfg));
    return json({ error: "Not Found" }, 404);
  } catch (error) {
    const status = error?.sessionAccountMismatch ? 409 : Number(error?.protonCode) === 2028 ? 429 : 400;
    return json(safeError(error), status);
  }
}
