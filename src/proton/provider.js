function requireBinding(env) {
  if (!env.PROTON_SESSIONS) {
    throw new Error("缺少 Cloudflare Durable Object 绑定：PROTON_SESSIONS");
  }
  return env.PROTON_SESSIONS;
}

function protonCallTimeoutMs(env, action) {
  const configured = Number(env.PROTON_CALL_TIMEOUT_MS || 0);
  if (Number.isFinite(configured) && configured >= 5000 && configured <= 120000) return configured;
  return action === "reauthorize" ? 20000 : 25000;
}

export function protonSessionStub(env, accountId) {
  const namespace = requireBinding(env);
  const id = namespace.idFromName(String(accountId).toLowerCase());
  return namespace.get(id);
}

export async function protonCall(env, cfgOrAccount, action, payload = {}) {
  const account = typeof cfgOrAccount === "string" ? cfgOrAccount : cfgOrAccount.id;
  const stub = protonSessionStub(env, account);
  const timeoutMs = protonCallTimeoutMs(env, action);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await stub.fetch("https://proton-session.internal/action", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ account, action, payload }),
      signal: controller.signal,
    });
  } catch (error) {
    if (controller.signal.aborted) {
      const timeout = new Error(`Proton ${action} 调用超过 ${timeoutMs}ms，已停止等待；请先调用 mail_proton_auth action=status 查看 lastAuthAttempt，不要直接重试登录`);
      timeout.protonCallTimeout = true;
      timeout.timeoutMs = timeoutMs;
      throw timeout;
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }

  let body;
  try {
    body = await response.json();
  } catch {
    throw new Error(`Proton DO 返回不可解析响应（HTTP ${response.status}）`);
  }
  if (!response.ok || !body?.ok) {
    const error = new Error(body?.error || `Proton DO 调用失败（HTTP ${response.status}）`);
    for (const key of [
      "protonCode", "serverRetryAfterSeconds", "localCooldownSeconds", "localPolicy",
      "requestPath", "requestMethod", "circuitOpen", "manualResetRequired",
      "twoFactorRequired", "reauthRequired", "mailboxPasswordRequired", "sessionAccountMismatch",
      "humanVerificationRequired", "humanVerificationMethods", "verificationUrl", "verificationState",
    ]) {
      if (body?.[key] !== undefined) error[key] = body[key];
    }
    throw error;
  }
  return body.data;
}

export const isProtonAccount = (cfg) => cfg?.provider === "proton";
export const protonTestConnection = (env, cfg) => protonCall(env, cfg, "test");
export const protonListFolders = (env, cfg) => protonCall(env, cfg, "listFolders");
export const protonFolderStatus = (env, cfg, folder) => protonCall(env, cfg, "folderStatus", { folder });
export const protonListMessages = (env, cfg, folder, limit) => protonCall(env, cfg, "listMessages", { folder, limit });
export const protonSearchMessages = (env, cfg, params) => protonCall(env, cfg, "searchMessages", params);
export const protonGetMessage = (env, cfg, messageId, folder) => protonCall(env, cfg, "getMessage", { messageId, folder });
export const protonGetAttachment = (env, cfg, messageId, attachmentIndex) => protonCall(env, cfg, "getAttachment", { messageId, attachmentIndex });
export const protonSetState = (env, cfg, messageId, action) => protonCall(env, cfg, "setState", { messageId, action });
export const protonTransfer = (env, cfg, messageId, sourceFolder, targetFolder, action) => protonCall(env, cfg, "transfer", {
  messageId, sourceFolder, targetFolder, action,
});
export const protonSend = (env, cfg, params) => protonCall(env, cfg, "send", params);
export const protonReply = (env, cfg, messageId, params) => protonCall(env, cfg, "reply", { messageId, ...params });
export const protonForward = (env, cfg, messageId, params) => protonCall(env, cfg, "forward", { messageId, ...params });
export const protonSaveDraft = (env, cfg, params) => protonCall(env, cfg, "saveDraft", params);
export const protonPollEvents = (env, cfg) => protonCall(env, cfg, "pollEvents");
export const protonAuthStatus = (env, cfg) => protonCall(env, cfg, "authStatus");
export const protonReauthorize = (env, cfg) => protonCall(env, cfg, "reauthorize");
export const protonSubmit2FA = (env, cfg, code) => protonCall(env, cfg, "submit2fa", { code });
export const protonResetRisk = (env, cfg) => protonCall(env, cfg, "resetRisk");
export const protonImportSession = (env, cfg, session) => protonCall(env, cfg, "importSession", { session });
export const protonValidateSession = (env, cfg) => protonCall(env, cfg, "validateSession");
export const protonClearSession = (env, cfg) => protonCall(env, cfg, "clearSession");
