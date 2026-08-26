# Proton Session 管理

从 v1.4 起，Worker 提供一个长期可复用的 Proton Session 管理页面：

```text
https://<Worker 自定义域名>/proton/import
```

该页面用于在正常浏览器/正常网络完成 Proton 登录后，将浏览器 Session 安全导入 Worker，从而避免 Cloudflare Worker 再次执行密码/SRP 登录。

## 安全模型

- `/proton/import` 和其 `/api/*` 路由必须经过 Cloudflare Access。
- Worker 仍会校验 `cf-access-jwt-assertion`，不是只依赖前置页面。
- 页面使用 SameSite=Strict 的 CSRF Cookie + `x-csrf-token` 双重校验。
- 页面和 API 均使用 `Cache-Control: no-store`。
- AccessToken / RefreshToken 只允许提交和覆盖，不提供完整回显或复制功能。
- 页面不使用 localStorage 保存 Session 数据。
- 提交成功后浏览器立即清空输入框。
- Session 使用现有 `PROTON_SESSION_KEY` 做 AES-GCM 加密后写入对应账号的 Durable Object。
- 导入失败时不会覆盖原有 Session。

## 页面能力

页面自动读取 `MAIL_ACCOUNTS` 中 `provider=proton` 的账号，不写死 `protone`、`proton2` 等 ID。

支持：

1. 选择 Proton 账号。
2. 查看本地 Session 状态、来源、到期时间、最后导入/校验时间、UID 尾号和 Token 是否已保存。
3. 粘贴并导入 Proton Session JSON，或当前 WebClient 的 `REFRESH-*` Cookie。
4. 测试现有 Session。
5. 清除已保存 Session。
6. 清除 Worker 本地 2028 密码登录保护锁。

本地 2028 风险锁只限制密码 `reauthorize`，不阻止已导入 Session 的正常 API 调用或 RefreshToken 刷新。

## 推荐导入方式：REFRESH-* Cookie

当前 Proton WebClient 会把持久刷新会话放在浏览器 Cookie 中。页面可以直接接受：

```text
REFRESH-<UID>=<cookie value>
```

也可以只粘贴该 Cookie 的 `value`。

Worker 会在服务端完成：

```text
解析 Cookie 中的 UID / RefreshToken
→ 建立临时候选客户端
→ 从 Cloudflare 端执行一次 /auth/v4/refresh
→ 得到 AccessToken / 旋转后的 RefreshToken
→ GET /core/v4/addresses
→ 核对 MAIL_<ACCOUNT>_EMAIL
→ 校验成功后 AES-GCM 加密并替换旧 Session
```

如果 Cloudflare 出口在 RefreshToken 阶段也被 Proton 风控拒绝，导入会失败，旧 Session 不会被覆盖。

## 兼容导入方式：Token JSON

如果已经获得包含下列字段的 Proton Session JSON，也可以直接粘贴：

```json
{
  "UID": "...",
  "AccessToken": "...",
  "RefreshToken": "...",
  "ExpiresIn": 1200
}
```

如果 JSON 只有 `UID + RefreshToken`，页面同样可以导入；Worker 会先执行一次标准 Token refresh 获取 AccessToken。

## Cloudflare Access

建议把现有自定义域名作为 Access Self-hosted Application 的 Hostname，并确保 `/proton/import*` 位于 Access 保护范围内。如果整个 `mail.mcp.example.com` 已经受同一个 Access Application 保护，不需要再创建第二个应用。

Worker 依赖现有：

```text
TEAM_DOMAIN=https://<team>.cloudflareaccess.com
POLICY_AUD=<Access Application AUD>
```

`POLICY_AUD` 必须与实际保护该 Hostname 的 Access Application 对应。

## 如何从当前 Proton 网页复制 REFRESH Cookie

不要把 Cookie、Token 发到 ChatGPT、GitHub Issue、日志或聊天记录。

在桌面 Chrome/Edge 中：

1. 保持 Proton 官方网页处于正常登录状态。
2. 按 `F12` 打开开发者工具。
3. 打开 **应用 / Application**。
4. 左侧展开 **存储 → Cookie → https://mail.proton.me**。
5. 在 Cookie 表格的过滤框输入 `REFRESH-`。
6. 找到名称形如 `REFRESH-<UID>` 的 Cookie。
7. 右键复制该 Cookie 的 **Value**；不要复制密码，也不需要 `AUTH-*` Cookie。
8. 新标签页打开 `https://<Worker 自定义域名>/proton/import`。
9. 完成 Cloudflare Access 登录。
10. 选择对应 Proton 账号。
11. 将刚才复制的 REFRESH Cookie Value 粘贴到输入框，点击“校验并更新 Session”。
12. 成功后确认状态为 `hasSession=true`，再使用“测试现有 Session”验证。

也可以从 Network 请求的 Cookie 面板复制同一个 `REFRESH-*` Cookie；Application 面板通常更直观。

## Session 失效后的维护

如果 RefreshToken 将来失效：

1. 在 Proton 官方网页重新正常登录。
2. 从浏览器复制新的 `REFRESH-*` Cookie Value。
3. 打开 `/proton/import`。
4. 选择相同账号并覆盖更新。

无需修改 Cloudflare 环境变量，也无需重新部署 Worker。

## 2028 说明

Worker 本地的 6 小时、24 小时和 manual reset 都只是防止重复密码登录的本地保护策略，不是 Proton 服务端的 Retry-After。

导入成功后可以保留本地 2028 风险记录；它不会阻止 Token Session 的正常使用。只有在确实准备再次从 Cloudflare 执行密码 `reauthorize` 时，才需要考虑“清除本地 2028 密码登录锁”。
