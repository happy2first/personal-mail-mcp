# Proton Session 管理

从 v1.4 起，Worker 提供一个长期可复用的 Proton Session 管理页面：

```text
https://<Worker 自定义域名>/proton/import
```

该页面用于在正常浏览器/正常网络完成 Proton 登录后，将登录响应中的 Session 安全导入 Worker，从而避免 Cloudflare Worker 再次执行密码/SRP 登录。

## 安全模型

- `/proton/import` 和其 `/api/*` 路由必须经过 Cloudflare Access。
- Worker 仍会校验 `cf-access-jwt-assertion`，不是只依赖前置页面。
- 页面使用 SameSite=Strict 的 CSRF Cookie + `x-csrf-token` 双重校验。
- 页面和 API 均使用 `Cache-Control: no-store`。
- AccessToken / RefreshToken 只允许提交和覆盖，不提供完整回显或复制功能。
- 页面不使用 localStorage 保存 Session JSON。
- 提交成功后浏览器立即清空输入框。
- Session 使用现有 `PROTON_SESSION_KEY` 做 AES-GCM 加密后写入对应账号的 Durable Object。
- 导入失败时不会覆盖原有 Session。

## 页面能力

页面自动读取 `MAIL_ACCOUNTS` 中 `provider=proton` 的账号，不写死 `protone`、`proton2` 等 ID。

支持：

1. 选择 Proton 账号。
2. 查看本地 Session 状态、来源、到期时间、最后导入/校验时间、UID 尾号和 Token 是否已保存。
3. 粘贴并导入新的 Proton 登录 Session JSON。
4. 测试现有 Session。
5. 清除已保存 Session。
6. 清除 Worker 本地 2028 密码登录保护锁。

本地 2028 风险锁从 v1.4 起只限制密码 `reauthorize`，不阻止已导入 Session 的正常 API 调用或 RefreshToken 刷新。

## 导入校验

提交 JSON 后，Worker 不会立即覆盖旧值，而是：

```text
解析 UID / AccessToken / RefreshToken
→ 建立临时候选客户端
→ GET /core/v4/addresses
→ 核对所选账号的 MAIL_<ACCOUNT>_EMAIL
→ 如 AccessToken 已过期且收到 401，仅尝试一次 RefreshToken 刷新
→ 再次核对账号
→ 校验成功后 AES-GCM 加密并原子替换旧 Session
```

如果邮箱地址与所选账号不一致，返回 `sessionAccountMismatch=true`，旧 Session 保留。

如果 RefreshToken 在 Cloudflare 出口也被 Proton 拒绝，导入失败，旧 Session 同样保留。

## Cloudflare Access

建议把现有自定义域名作为 Access Self-hosted Application 的 Hostname，并确保 `/proton/import*` 位于 Access 保护范围内。如果整个 `mail.mcp.example.com` 已经受同一个 Access Application 保护，不需要再创建第二个应用。

Worker 依赖现有：

```text
TEAM_DOMAIN=https://<team>.cloudflareaccess.com
POLICY_AUD=<Access Application AUD>
```

`POLICY_AUD` 必须与实际保护该 Hostname 的 Access Application 对应。

## 如何从 Proton 浏览器登录获取 Session JSON

不要把 Token 发到 ChatGPT、GitHub Issue、日志或聊天记录。

在桌面 Chrome/Edge 中：

1. 使用普通家庭/办公网络或移动网络打开 Proton 官方网页登录页。
2. 打开开发者工具 → Network。
3. 正常登录 Proton；如有 2FA/Human Verification，按 Proton 官方页面完成。
4. 在 Network 中找到成功建立登录 Session 的认证请求。当前 Proton WebClients 使用 `POST /api/core/v4/auth`；客户端版本变化时路径可能调整。
5. 打开该请求的 Response/Preview。
6. 只在本机复制包含 `UID`、`AccessToken`、`RefreshToken`、`ExpiresIn` 等字段的完整 JSON 响应。
7. 新标签页打开 `https://<Worker 自定义域名>/proton/import`。
8. 完成 Cloudflare Access 登录。
9. 选择对应账号。
10. 将 JSON 粘贴到输入框，点击“校验并更新 Session”。
11. 成功后确认状态为 `hasSession=true`，并使用“测试现有 Session”验证。

不要把浏览器 Cookie、密码或完整 Authorization Header 粘贴到管理页；页面只需要 Proton Session JSON。

## Session 失效后的维护

如果 RefreshToken 将来失效：

1. 在 Proton 官方网页重新正常登录。
2. 获取新的 Session JSON。
3. 再打开 `/proton/import`。
4. 选择相同账号并覆盖更新。

无需修改 Cloudflare 环境变量，也无需重新部署 Worker。

## 2028 说明

Worker 本地的 6 小时、24 小时和 manual reset 都只是防止重复密码登录的本地保护策略，不是 Proton 服务端的 Retry-After。

导入成功后可以保留本地 2028 风险记录；它不会阻止 Token Session 的正常使用。只有在确实准备再次从 Cloudflare 执行密码 `reauthorize` 时，才需要考虑“清除本地 2028 密码登录锁”。
