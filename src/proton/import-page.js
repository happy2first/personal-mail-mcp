import { getAccount, listAccountIds } from "../mail-config.js";
import {
  isProtonAccount,
  protonAuthStatus,
  protonCall,
  protonClearSession,
  protonImportSession,
  protonResetRisk,
  protonTestConnection,
} from "./provider.js";

const BASE = "/proton/import";
const API = `${BASE}/api`;
const MAX_BODY_BYTES = 128 * 1024;

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

function pageHtml(csrf, nonce, actor) {
  const actorText = escapeHtml(actor?.email || actor?.sub || "Cloudflare Access 用户");
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Proton Session 管理</title>
<style nonce="${nonce}">
:root{font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;color:#172033;background:#f5f7fa}*{box-sizing:border-box}body{margin:0}.wrap{max-width:960px;margin:0 auto;padding:28px 18px 56px}.head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:20px}.head h1{font-size:26px;margin:0 0 8px}.muted{color:#667085;font-size:13px;line-height:1.6}.card{background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 2px rgba(16,24,40,.04)}label{display:block;font-weight:650;font-size:14px;margin-bottom:8px}select,textarea{width:100%;border:1px solid #d0d5dd;border-radius:8px;background:#fff;color:#172033;font:inherit}select{height:42px;padding:0 12px}textarea{min-height:130px;padding:12px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:1.5}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.item{border:1px solid #eaecf0;border-radius:8px;padding:12px}.item b{display:block;font-size:12px;color:#667085;margin-bottom:4px}.item span{font-size:14px;word-break:break-word}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}button{appearance:none;border:1px solid #d0d5dd;border-radius:8px;background:#fff;color:#344054;padding:9px 14px;font-weight:650;cursor:pointer;min-height:40px}button.primary{background:#1677ff;border-color:#1677ff;color:#fff}button.danger{color:#b42318;border-color:#fda29b}button:disabled{opacity:.55;cursor:not-allowed}.notice{border-left:3px solid #1677ff;padding:10px 12px;background:#f0f6ff;border-radius:6px;font-size:13px;line-height:1.65;margin-top:10px}.notice.warn{border-left-color:#f79009;background:#fffaeb}.result{white-space:pre-wrap;word-break:break-word;background:#101828;color:#f2f4f7;border-radius:8px;padding:12px;min-height:56px;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.ok{color:#067647}.bad{color:#b42318}.warnText{color:#b54708}.pill{display:inline-block;border-radius:999px;padding:3px 8px;background:#f2f4f7;font-size:12px}.summary{font-size:17px;font-weight:700;margin-bottom:14px;padding:12px 14px;border-radius:8px;background:#f2f4f7}.summary.ok{background:#ecfdf3}.summary.warnText{background:#fffaeb}.summary.bad{background:#fef3f2}.step{display:inline-flex;width:25px;height:25px;align-items:center;justify-content:center;border-radius:50%;background:#1677ff;color:#fff;font-size:13px;margin-right:7px}.footer{margin-top:12px;color:#98a2b3;font-size:12px}details{border-top:1px solid #eaecf0;margin-top:18px;padding-top:14px}summary{cursor:pointer;font-weight:650;color:#475467}code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#f2f4f7;padding:1px 4px;border-radius:4px}@media(max-width:760px){.grid{grid-template-columns:1fr 1fr}}@media(max-width:560px){.wrap{padding:18px 12px 40px}.head{display:block}.head h1{font-size:22px}.grid{grid-template-columns:1fr}.card{padding:16px}button{width:100%}}
</style>
</head>
<body>
<div class="wrap">
  <div class="head"><div><h1>Proton Session 管理</h1><div class="muted">由 Cloudflare Access 保护。Cookie、Token 和 KeySalt 只用于加密持久化与校验；页面不会完整回显，也不会写入 localStorage。</div></div><div class="pill">${actorText}</div></div>

  <div class="card">
    <label for="account">Proton 账号</label>
    <select id="account"></select>
    <div class="actions"><button id="refreshStatus">刷新状态</button><button id="testSession">测试当前读取权限</button><button id="testRefresh">测试自动续期</button></div>
    <div class="notice warn">“测试自动续期”会真实调用一次 <code>POST /auth/refresh</code>。当前 Proton 浏览器 Cookie 模式依赖 <code>AUTH-&lt;UID&gt;</code>；只要它的 Path 能覆盖 <code>/api/auth/refresh</code>（例如浏览器当前常见的 <code>/api/</code>），就具备刷新请求所需的 Cookie 路径条件。</div>
  </div>

  <div class="card">
    <label>当前状态</label>
    <div id="summary" class="summary">正在加载…</div>
    <div id="status" class="grid"><div class="muted">正在加载…</div></div>
  </div>

  <div class="card">
    <label for="sessionCookie"><span class="step">1</span>浏览器 Session Cookie（必填）</label>
    <textarea id="sessionCookie" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="Cookie: AUTH-&lt;UID&gt;=...; Session-Id=...; ..."></textarea>
    <div class="notice">在 Proton Mail 打开 DevTools → Network，选择一个成功的 Proton API 请求（例如 <code>/core/v4/addresses</code>），从 Request Headers 复制完整 <code>Cookie:</code> 请求头。Worker 会识别 <code>AUTH-&lt;UID&gt;</code>，并按当前浏览器实际模型将 AUTH Cookie 视为 <code>/api/</code> Cookie；它本身即可覆盖 <code>/api/auth/refresh</code>。</div>
    <div class="actions"><button id="importCookies" class="primary">校验并导入 Cookie Session</button><button id="clearCookies">清空 Cookie 输入</button></div>

    <details>
      <summary>可选：额外的专用刷新 Cookie</summary>
      <div class="muted" style="margin:10px 0">当前浏览器通常看不到单独的 Refresh Cookie，不需要强行寻找。只有以后 Proton 实际下发了额外 Cookie，且其 Path 能覆盖 <code>/api/auth/refresh</code> 时才需要填写。</div>
      <textarea id="refreshCookie" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="可留空；支持 NAME=VALUE、Set-Cookie 行或 JSON"></textarea>
    </details>
  </div>

  <div class="card">
    <label for="keySalts"><span class="step">2</span>邮件解密材料 KeySalt（通常只需一次）</label>
    <textarea id="keySalts" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder='粘贴 GET /core/v4/keys/salts 的 Response JSON，例如 {"Code":1000,"KeySalts":[...]}'></textarea>
    <div class="notice">KeySalt 用于本地解锁 Proton 私钥，不是短期 Session 凭证。若状态显示 KeySalt 已保存，可跳过此步。</div>
    <div class="actions"><button id="importKeySalts">导入 KeySalt</button><button id="clearKeySalts">清空 KeySalt 输入框</button></div>

    <details>
      <summary>高级兼容：旧 Session JSON / REFRESH-* Cookie 导入</summary>
      <div class="muted" style="margin:10px 0">仅用于兼容旧流程。正常浏览器 Cookie Session 建议使用上面的必填 Cookie 输入。</div>
      <textarea id="legacySession" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="Session JSON 或旧 REFRESH-* Cookie"></textarea>
      <div class="actions"><button id="importLegacy">兼容导入</button><button id="clearLegacy">清空</button></div>
    </details>
  </div>

  <div class="card">
    <label>维护操作</label>
    <div class="actions"><button id="clear" class="danger">清除已保存 Session</button><button id="resetRisk" class="danger">清除本地 2028 密码登录锁</button></div>
    <div class="muted" style="margin-top:10px">本地 2028 锁只限制 Worker 密码 reauthorize，不影响已导入 Cookie Session。清除本地锁不会解除 Proton 服务端风控，通常不需要操作。</div>
  </div>

  <div class="card"><label>操作结果</label><div id="result" class="result">尚未执行操作。</div></div>
  <div class="footer">安全策略：no-store · SameSite=Strict CSRF · Access JWT 二次校验 · Session/Cookie/KeySalt AES-GCM 加密持久化</div>
</div>
<script nonce="${nonce}">
const csrf=${JSON.stringify(csrf)};const $=id=>document.getElementById(id);let busy=false;
function setBusy(v){busy=v;document.querySelectorAll('button').forEach(b=>b.disabled=v)}
function fmtTime(v){if(!v)return '—';try{return new Date(Number(v)).toLocaleString()}catch{return String(v)}}
function safe(v){return v===undefined||v===null||v===''?'—':String(v)}
function esc(v){return safe(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function yes(v){return v?'✅ 是':'❌ 否'}
function renderStatus(s){
  const session=s.session||{},risk=s.risk||{},attempt=s.lastAuthAttempt||{},refresh=s.refresh||{},keys=s.keyMaterial||{};
  let summary='';let cls='summary ';
  if(!s.hasSession){summary='❌ 未保存有效 Proton Session，需要从浏览器导入 Cookie';cls+='bad'}
  else if(s.reauthRequired){summary='⚠️ Session 材料仍已保存，但当前认证需要恢复；不要使用 Worker 密码 reauthorize';cls+='warnText'}
  else if(session.cookieAuth&&refresh.capable&&refresh.verified&&keys.imported){summary='✅ Cookie Session、自动续期和邮件解密均已验证';cls+='ok'}
  else if(session.cookieAuth&&refresh.capable&&!refresh.verified){summary='⚠️ AUTH Cookie 可用于刷新路径，但还没有成功执行自动续期测试';cls+='warnText'}
  else if(session.cookieAuth&&!refresh.capable){summary='⚠️ 当前 Cookie Session 可用，但没有可发送到 /api/auth/refresh 的 AUTH Cookie';cls+='warnText'}
  else{summary='⚠️ Session 已保存，请检查自动续期和 KeySalt 状态';cls+='warnText'}
  $('summary').className=cls;$('summary').textContent=summary;
  const rows=[
    ['Session',s.hasSession?'已保存':'未保存'],['需要恢复',yes(s.reauthRequired)],['Cookie Auth',yes(session.cookieAuth)],
    ['其他 Cookie 数',session.normalCookieCount??s.transport?.normalCookieCount],['可用于刷新 AUTH Cookie 数',refresh.cookieCount??s.transport?.refreshCookieCount],['自动续期材料',yes(refresh.capable)],
    ['自动续期已验证',yes(refresh.verified)],['最后续期结果',refresh.lastResult],['最后续期时间',fmtTime(refresh.lastAttemptAt)],
    ['KeySalt 数',keys.keySaltCount],['邮件解密材料',yes(keys.imported)],['最后导入',fmtTime(session.importedAt)],
    ['最后校验',fmtTime(session.lastValidatedAt)],['UID 尾号',session.uidSuffix],['总 Cookie 数',s.transport?.cookieCount],
    ['本地 2028 锁',risk.manualResetRequired?'人工锁定':risk.attempt?'第 '+risk.attempt+' 次记录':'无'],['风险锁范围',risk.scope||'—'],['历史最后授权阶段',attempt.stage||'—']
  ];
  $('status').innerHTML=rows.map(([k,v])=>'<div class="item"><b>'+esc(k)+'</b><span>'+esc(v)+'</span></div>').join('');
}
async function call(path,{method='GET',body}={}){const headers={'accept':'application/json'};if(method!=='GET'){headers['content-type']='application/json';headers['x-csrf-token']=csrf}const r=await fetch(path,{method,headers,body:body===undefined?undefined:JSON.stringify(body),credentials:'same-origin',cache:'no-store'});let data;try{data=await r.json()}catch{data={error:'服务器返回不可解析响应'}}if(!r.ok)throw Object.assign(new Error(data.error||('HTTP '+r.status)),{data});return data}
async function loadAccounts(){const data=await call('${API}/accounts');$('account').innerHTML=data.accounts.map(a=>'<option value="'+esc(a.id)+'">'+esc(a.label)+' · '+esc(a.id)+' · '+esc(a.email)+'</option>').join('');if(data.accounts.length)await loadStatus();else $('status').innerHTML='<div class="bad">没有已配置的 Proton 账号</div>'}
async function loadStatus(){const id=$('account').value;if(!id)return;const data=await call('${API}/status?account='+encodeURIComponent(id));renderStatus(data.status);return data}
async function act(fn){if(busy)return;setBusy(true);try{const data=await fn();$('result').textContent=JSON.stringify(data,null,2);await loadStatus();return data}catch(e){$('result').textContent=JSON.stringify(e.data||{error:e.message},null,2)}finally{setBusy(false)}}
$('account').addEventListener('change',()=>act(loadStatus));
$('refreshStatus').onclick=()=>act(loadStatus);
$('testSession').onclick=()=>act(()=>call('${API}/validate',{method:'POST',body:{account:$('account').value}}));
$('testRefresh').onclick=()=>{if(confirm('将真实执行一次 Proton POST /auth/refresh，以验证当前 AUTH Cookie 能否自动续期并保存服务器返回的新 Cookie。继续？'))act(()=>call('${API}/test-refresh',{method:'POST',body:{account:$('account').value}}))};
$('importCookies').onclick=()=>act(async()=>{const sessionCookie=$('sessionCookie').value.trim(),refreshCookie=$('refreshCookie').value.trim();if(!sessionCookie)throw new Error('请先粘贴浏览器 Session Cookie');const data=await call('${API}/import-cookies',{method:'POST',body:{account:$('account').value,sessionCookie,refreshCookie:refreshCookie||null}});$('sessionCookie').value='';$('refreshCookie').value='';return data});
$('clearCookies').onclick=()=>{$('sessionCookie').value='';$('refreshCookie').value='';$('sessionCookie').focus()};
$('importKeySalts').onclick=()=>act(async()=>{const input=$('keySalts').value.trim();if(!input)throw new Error('请先粘贴 keys/salts Response JSON');const data=await call('${API}/import',{method:'POST',body:{account:$('account').value,session:input}});$('keySalts').value='';return data});
$('clearKeySalts').onclick=()=>{$('keySalts').value='';$('keySalts').focus()};
$('importLegacy').onclick=()=>act(async()=>{const input=$('legacySession').value.trim();if(!input)throw new Error('请先粘贴旧 Session JSON 或 REFRESH-* Cookie');const data=await call('${API}/import',{method:'POST',body:{account:$('account').value,session:input}});$('legacySession').value='';return data});
$('clearLegacy').onclick=()=>{$('legacySession').value='';$('legacySession').focus()};
$('clear').onclick=()=>{if(confirm('确认清除所选账号在 Worker 中保存的 Proton Session、Cookie 和随 Session 保存的解密材料？'))act(()=>call('${API}/clear',{method:'POST',body:{account:$('account').value}}))};
$('resetRisk').onclick=()=>{if(confirm('只清除 Worker 本地 2028 密码登录保护锁？这不会解除 Proton 服务端限制。'))act(()=>call('${API}/reset-risk',{method:'POST',body:{account:$('account').value}}))};
loadAccounts().catch(e=>{$('result').textContent=e.message});
</script>
</body></html>`;
}

function pageResponse(actor) {
  const csrf = randomToken();
  const nonce = randomToken();
  const html = pageHtml(csrf, nonce, actor);
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

    if (url.pathname === `${API}/import-cookies`) {
      if (typeof body.sessionCookie !== "string" || !body.sessionCookie.trim()) throw new Error("缺少浏览器 Session Cookie");
      const refreshCookie = ["string", "object"].includes(typeof body.refreshCookie) ? body.refreshCookie : null;
      return json(await protonCall(env, cfg, "importCookieBundle", {
        sessionCookie: body.sessionCookie,
        refreshCookie,
      }));
    }
    if (url.pathname === `${API}/test-refresh`) return json(await protonCall(env, cfg, "testRefresh"));
    if (url.pathname === `${API}/import`) {
      if (!body.session || !["string", "object"].includes(typeof body.session)) throw new Error("缺少 Session / Cookie / KeySalt 输入");
      return json(await protonImportSession(env, cfg, body.session));
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
