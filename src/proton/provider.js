function requireBinding(env) {
  if (!env.PROTON_SESSIONS) {
    throw new Error("缺少 Cloudflare Durable Object 绑定：PROTON_SESSIONS");
  }
  return env.PROTON_SESSIONS;
}

async function call(env, cfg, action, payload = {}) {
  const namespace = requireBinding(env);
  const id = namespace.idFromName(String(cfg.id).toLowerCase());
  const stub = namespace.get(id);
  const response = await stub.fetch("https://proton-session.internal/action", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ account: cfg.id, action, payload }),
  });
  const body = await response.json();
  if (!response.ok || !body?.ok) throw new Error(body?.error || `Proton DO 调用失败（HTTP ${response.status}）`);
  return body.data;
}

export const isProtonAccount = (cfg) => cfg?.provider === "proton";
export const protonTestConnection = (env, cfg) => call(env, cfg, "test");
export const protonListFolders = (env, cfg) => call(env, cfg, "listFolders");
export const protonFolderStatus = (env, cfg, folder) => call(env, cfg, "folderStatus", { folder });
export const protonListMessages = (env, cfg, folder, limit) => call(env, cfg, "listMessages", { folder, limit });
export const protonSearchMessages = (env, cfg, params) => call(env, cfg, "searchMessages", params);
export const protonGetMessage = (env, cfg, messageId, folder) => call(env, cfg, "getMessage", { messageId, folder });
