import { protonCall } from "./provider.js";

const DEFAULT_API = "https://mail.proton.me/api";
const DEFAULT_APP_VERSION = "macos-bridge@3.24.1";

function parseRoute(url) {
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts[0] !== "proton" || parts[1] !== "verify" || !parts[2] || !parts[3]) return null;
  return {
    account: decodeURIComponent(parts[2]),
    state: decodeURIComponent(parts[3]),
    kind: parts[4] || "challenge",
    rest: parts.slice(5).join("/"),
  };
}

function assetBase(apiBase) {
  const u = new URL(apiBase);
  u.pathname = "/";
  u.search = "";
  const bits = u.hostname.split(".");
  if (bits[0] && !bits[0].endsWith("-api")) bits[0] += "-api";
  u.hostname = bits.join(".");
  return u;
}

function prefix(account, state) {
  return `/proton/verify/${encodeURIComponent(account)}/${encodeURIComponent(state)}`;
}

function proxyBootstrap(account, state) {
  const p = prefix(account, state);
  return `<script>
(function(){
  var prefix=${JSON.stringify(p)};
  var nativeFetch=window.fetch;
  window.fetch=function(input, init){
    try {
      var raw=typeof input==='string'?input:(input&&input.url)||'';
      if(raw.charAt(0)==='/' && raw.indexOf(prefix)!==0){
        var mapped=prefix+(raw.indexOf('/core/')===0?'/api':'/asset')+raw;
        if(typeof input==='string') input=mapped;
        else input=new Request(mapped,input);
      }
    }catch(e){}
    return nativeFetch.call(this,input,init);
  };
  var nativeOpen=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(method,url){
    if(typeof url==='string' && url.charAt(0)==='/' && url.indexOf(prefix)!==0){
      url=prefix+(url.indexOf('/core/')===0?'/api':'/asset')+url;
    }
    arguments[1]=url;
    return nativeOpen.apply(this,arguments);
  };
  window.addEventListener('message',function(event){
    if(!event.data || event.data.type!=='pm_captcha' || !event.data.token) return;
    fetch(prefix+'/token',{method:'POST',headers:{'content-type':'text/plain'},body:event.data.token})
      .then(function(r){if(!r.ok) throw new Error('verification save failed'); return r.text();})
      .then(function(){document.body.innerHTML='<main style="font-family:system-ui;padding:32px;max-width:640px;margin:auto"><h2>Proton 验证已完成</h2><p>可以关闭此页面，回到 ChatGPT 再执行 Proton 重新授权。</p></main>';})
      .catch(function(e){document.body.insertAdjacentHTML('beforeend','<p>保存验证结果失败：'+String(e)+'</p>');});
  },false);
})();
</script>`;
}

function rewriteHtml(html, account, state) {
  const p = prefix(account, state);
  const injection = `<base href="${p}/asset/">${proxyBootstrap(account, state)}`;
  let out = String(html || "");
  if (/<head[^>]*>/i.test(out)) out = out.replace(/<head([^>]*)>/i, `<head$1>${injection}`);
  else out = injection + out;
  out = out
    .replace(/(src|href)=(['"])\/(?!\/)/gi, `$1=$2${p}/asset/`)
    .replace(/url\((['"]?)\/(?!\/)/gi, `url($1${p}/asset/`);
  return out;
}

async function challengeRecord(env, route) {
  return protonCall(env, route.account, "getHumanVerificationChallenge", { state: route.state });
}

async function proxyUpstream(request, env, route, kind) {
  await challengeRecord(env, route);
  const api = String(env.PROTON_API_BASE || DEFAULT_API).replace(/\/$/, "");
  const base = kind === "api" ? new URL(`${api}/`) : assetBase(api);
  const upstream = new URL(route.rest || "", base);
  upstream.search = new URL(request.url).search;

  const headers = new Headers(request.headers);
  for (const name of ["host", "cookie", "origin", "referer", "cf-access-jwt-assertion", "content-length"]) headers.delete(name);
  headers.set("x-pm-appversion", String(env.PROTON_APP_VERSION || DEFAULT_APP_VERSION));
  headers.set("x-pm-apiversion", "3");

  const response = await fetch(upstream, {
    method: request.method,
    headers,
    body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
    redirect: "follow",
  });
  const outHeaders = new Headers(response.headers);
  for (const name of ["content-security-policy", "content-security-policy-report-only", "x-frame-options", "set-cookie"]) outHeaders.delete(name);
  outHeaders.set("access-control-allow-origin", "*");
  outHeaders.set("cache-control", "no-store");

  const type = String(outHeaders.get("content-type") || "").toLowerCase();
  if (type.includes("text/css")) {
    let text = await response.text();
    const p = prefix(route.account, route.state);
    text = text.replace(/url\((['"]?)\/(?!\/)/gi, `url($1${p}/asset/`);
    return new Response(text, { status: response.status, headers: outHeaders });
  }
  return new Response(response.body, { status: response.status, headers: outHeaders });
}

async function serveChallenge(request, env, route) {
  if (request.method !== "GET") return new Response("Method Not Allowed", { status: 405 });
  const record = await challengeRecord(env, route);
  if (!record.methods?.includes("captcha")) {
    return new Response(`Proton 要求人机验证，但当前只支持 CAPTCHA。服务器提供：${(record.methods || []).join(", ")}`, { status: 409 });
  }
  const api = String(env.PROTON_API_BASE || DEFAULT_API).replace(/\/$/, "");
  const u = new URL(`${api}/core/v4/captcha`);
  u.searchParams.set("Token", record.challengeToken);
  u.searchParams.set("ForceWebMessaging", "1");
  const response = await fetch(u, {
    headers: {
      accept: "text/html,*/*",
      "x-pm-appversion": String(env.PROTON_APP_VERSION || DEFAULT_APP_VERSION),
      "x-pm-apiversion": "3",
    },
  });
  const html = await response.text();
  const headers = new Headers(response.headers);
  for (const name of ["content-security-policy", "content-security-policy-report-only", "x-frame-options", "set-cookie", "content-length"]) headers.delete(name);
  headers.set("content-type", "text/html; charset=utf-8");
  headers.set("cache-control", "no-store");
  headers.set("referrer-policy", "no-referrer");
  return new Response(rewriteHtml(html, route.account, route.state), { status: response.status, headers });
}

async function acceptToken(request, env, route) {
  if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  const token = (await request.text()).trim();
  if (!token || token.length > 4096) return new Response("Invalid token", { status: 400 });
  await protonCall(env, route.account, "completeHumanVerification", { state: route.state, token });
  return new Response("OK", { status: 200, headers: { "cache-control": "no-store" } });
}

export async function handleProtonVerification(request, env) {
  const url = new URL(request.url);
  const route = parseRoute(url);
  if (!route) return null;
  try {
    if (route.kind === "challenge") return serveChallenge(request, env, route);
    if (route.kind === "token") return acceptToken(request, env, route);
    if (route.kind === "api") return proxyUpstream(request, env, route, "api");
    if (route.kind === "asset") return proxyUpstream(request, env, route, "asset");
    return new Response("Not Found", { status: 404 });
  } catch (error) {
    return new Response(`Proton verification error: ${error instanceof Error ? error.message : String(error)}`, {
      status: 400,
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
    });
  }
}
