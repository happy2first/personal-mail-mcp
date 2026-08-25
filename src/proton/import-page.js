import { getAccount, listAccountIds } from "../mail-config.js";
import {
  isProtonAccount,
  protonAuthStatus,
  protonClearSession,
  protonImportSession,
  protonResetRisk,
  protonValidateSession,
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
      // Invalid non-Proton account configuration should not expose secrets here.
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
    "sessionAccountMismatch", "requestPath", "requestMethod", "reauthRequired",
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
:root{font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;color:#172033;background:#f5f7fa}*{box-sizing:border-box}body{margin:0}.wrap{max-width:920px;margin:0 auto;padding:28px 18px 56px}.head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:20px}.head h1{font-size:26px;margin:0 0 8px}.muted{color:#667085;font-size:13px;line-height:1.55}.card{background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 2px rgba(16,24,40,.04)}label{display:block;font-weight:600;font-size:14px;margin-bottom:8px}select,textarea{width:100%;border:1px solid #d0d5dd;border-radius:8px;background:#fff;color:#172033;font:inherit}select{height:42px;padding:0 12px}textarea{min-height:220px;padding:12px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:1.5}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.item{border:1px solid #eaecf0;border-radius:8px;padding:12px}.item b{display:block;font-size:12px;color:#667085;margin-bottom:4px}.item span{font-size:14px;word-break:break-word}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}button{appearance:none;border:1px solid #d0d5dd;border-radius:8px;background:#fff;color:#344054;padding:9px 14px;font-weight:600;cursor:pointer;min-height:40px}button.primary{background:#1677ff;border-color:#1677ff;color:#fff}button.danger{color:#b42318;border-color:#fda29b}button:disabled{opacity:.55;cursor:not-allowed}.notice{border-left:3px solid #1677ff;padding:10px 12px;background:#f0f6ff;border-radius:6px;font-size:13px;line-height:1.6;margin-top:12px}.result{white-space:pre-wrap;word-break:break-word;background:#101828;color:#f2f4f7;border-radius:8px;padding:12px;min-height:56px;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.ok{color:#067647}.bad{color:#b42318}.pill{display:inline-block;border-radius:999px;padding:3px 8px;background:#f2f4f7;font-size:12px}.footer{margin-top:12px;color:#98a2b3;font-size:12px}@media(max-width:640px){.wrap{padding:18px 12px 40px}.head{display:block}.head h1{font-size:22px}.grid{grid-template-columns:1fr}.card{padding:16px}button{width:100%}}
</style>
</head>
<body>
<div class="wrap">
  <div class="head"><div><h1>Proton Session 管理</h1><div class="muted">由 Cloudflare Access 保护。Token 仅用于覆盖更新，页面不会完整回显、不会写入 localStorage，也不会返回到 ChatGPT。</div></div><div class="pill">${actorText}</div></div>
  <div class="card">
    <label for="account">Proton 账号</label>
    <select id="account"></select>
    <div class="actions"><button id="refresh">刷新状态</button><button id="test">测试现有 Session</button></div>
  </div>
  <div class="card">
    <label>当前状态</label>
    <div id="status" class="grid"><div class="muted">正在加载…</div></div>
  </div>
  <div class="card">
    <label for="session">粘贴 Proton 登录 Session JSON</label>
    <textarea id="session" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder='包含 UID、AccessToken、RefreshToken、ExpiresIn 等字段的 Proton 登录响应 JSON'></textarea>
    <div class="notice">提交前会先在内存中校验 Token，并通过 Proton 地址列表核对是否属于所选账号。校验失败时不会覆盖原有 Session；AccessToken 已过期时，允许使用 RefreshToken 尝试一次刷新。</div>
    <div class="actions"><button id="import" class="primary">校验并更新 Session</button><button id="clearText">清空输入</button></div>
  </div>
  <div class="card">
    <label>维护操作</label>
    <div class="actions"><button id="clear" class="danger">清除已保存 Session</button><button id="resetRisk" class="danger">清除本地 2028 密码登录锁</button></div>
    <div class="muted" style="margin-top:10px">清除本地 2028 锁只影响 Worker 是否允许再次执行密码 reauthorize，不会解除 Proton 服务端风控；已导入 Session 的正常使用不受该本地锁影响。</div>
  </div>
  <div class="card"><label>操作结果</label><div id="result" class="result">尚未执行操作。</div></div>
  <div class="footer">安全策略：no-store · SameSite=Strict CSRF · Access JWT 二次校验 · Session AES-GCM 加密持久化</div>
</div>
<script nonce="${nonce}">
const csrf=${JSON.stringify(csrf)};const $=id=>document.getElementById(id);let busy=false;
function setBusy(v){busy=v;document.querySelectorAll('button').forEach(b=>b.disabled=v)}
function fmtTime(v){if(!v)return '—';try{return new Date(Number(v)).toLocaleString()}catch{return String(v)}}
function safe(v){return v===undefined||v===null||v===''?'—':String(v)}
function renderStatus(s){const session=s.session||{};const risk=s.risk||{};const attempt=s.lastAuthAttempt||{};const rows=[['Session',s.hasSession?'已保存':'未保存'],['来源',session.source],['AccessToken',session.hasAccessToken?'已保存（不回显）':'未保存'],['RefreshToken',session.hasRefreshToken?'已保存（不回显）':'未保存'],['AccessToken 到期',fmtTime(s.expiresAt)],['最后导入',fmtTime(session.importedAt)],['最后校验',fmtTime(session.lastValidatedAt)],['UID 尾号',session.uidSuffix],['Cookie 数',s.transport?.cookieCount],['本地风险锁',risk.manualResetRequired?'人工锁定':risk.attempt?'第 '+risk.attempt+' 次记录':'无'],['风险锁范围',risk.scope||'—'],['最后授权阶段',attempt.stage||'—']];$('status').innerHTML=rows.map(([k,v])=>'<div class="item"><b>'+k+'</b><span>'+safe(v)+'</span></div>').join('')}
async function call(path,{method='GET',body}={}){const headers={'accept':'application/json'};if(method!=='GET'){headers['content-type']='application/json';headers['x-csrf-token']=csrf}const r=await fetch(path,{method,headers,body:body===undefined?undefined:JSON.stringify(body),credentials:'same-origin',cache:'no-store'});let data;try{data=await r.json()}catch{data={error:'服务器返回不可解析响应'}}if(!r.ok)throw Object.assign(new Error(data.error||('HTTP '+r.status)),{data});return data}
async function loadAccounts(){const data=await call('${API}/accounts');$('account').innerHTML=data.accounts.map(a=>'<option value="'+a.id+'">'+a.label+' · '+a.id+' · '+a.email+'</option>').join('');if(data.accounts.length)await loadStatus();else $('status').innerHTML='<div class="bad">没有已配置的 Proton 账号</div>'}
async function loadStatus(){const id=$('account').value;if(!id)return;const data=await call('${API}/status?account='+encodeURIComponent(id));renderStatus(data.status)}
async function act(fn){if(busy)return;setBusy(true);try{const data=await fn();$('result').textContent=JSON.stringify(data,null,2);await loadStatus()}catch(e){$('result').textContent=JSON.stringify(e.data||{error:e.message},null,2)}finally{setBusy(false)}}
$('account').addEventListener('change',()=>act(loadStatus));$('refresh').onclick=()=>act(loadStatus);$('test').onclick=()=>act(()=>call('${API}/validate',{method:'POST',body:{account:$('account').value}}));$('import').onclick=()=>act(async()=>{const text=$('session').value.trim();if(!text)throw new Error('请先粘贴 Session JSON');let session;try{session=JSON.parse(text)}catch{throw new Error('Session JSON 格式无效')}const data=await call('${API}/import',{method:'POST',body:{account:$('account').value,session}});$('session').value='';return data});$('clearText').onclick=()=>{$('session').value='';$('session').focus()};$('clear').onclick=()=>{if(confirm('确认清除所选账号在 Worker 中保存的 Proton Session？此操作不会删除 Proton 账号本身。'))act(()=>call('${API}/clear',{method:'POST',body:{account:$('account').value}}))};$('resetRisk').onclick=()=>{if(confirm('只清除 Worker 本地 2028 密码登录保护锁？这不会解除 Proton 服务端限制。'))act(()=>call('${API}/reset-risk',{method:'POST',body:{account:$('account').value}}))};loadAccounts().catch(e=>{$('result').textContent=e.message});
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

    if (url.pathname === `${API}/import`) {
      if (!body.session || typeof body.session !== "object") throw new Error("缺少 Session JSON 对象");
      return json(await protonImportSession(env, cfg, body.session));
    }
    if (url.pathname === `${API}/validate`) return json(await protonValidateSession(env, cfg));
    if (url.pathname === `${API}/clear`) return json(await protonClearSession(env, cfg));
    if (url.pathname === `${API}/reset-risk`) return json(await protonResetRisk(env, cfg));
    return json({ error: "Not Found" }, 404);
  } catch (error) {
    const status = error?.sessionAccountMismatch ? 409 : Number(error?.protonCode) === 2028 ? 429 : 400;
    return json(safeError(error), status);
  }
}
