# Proton 浏览器扩展配对导入

配套扩展：https://github.com/happy2first/protonmail-chrome-extension

部署此变更后，刷新受 Cloudflare Access 保护的 `/proton/import` 管理页，保持页面打开。加载扩展的 `extension/` 目录，切回已登录的 Proton Mail，核对邮箱与 MCP 账号，再点击连接。

新增同源 POST `extension-pair` / `extension-import`（前缀 `/proton/import/api/`），仍通过 Access 和 CSRF。配对 token 为随机 256 bit，服务端仅存 SHA-256，5 分钟有效；绑定 Access 身份、账号、邮箱和 Proton UID，并用 Durable Object 事务消费一次。不会创建绕过 Access 的导入端点。

完整 Cookie 属性和 KeySalt 用既有 `PROTON_SESSION_KEY` 加密，复用 Session 和 Cookie 存储键及 AAD，无需新增 Secret、存储绑定或迁移。不设置加密密钥则拒绝配对；不会退回明文存储。导入成功会替换所选账号的 Session、清除事件游标，其他账号不受影响。

扩展不处理密码；邮件正文解密仍依赖服务器原有密码/邮箱密码配置。扩展不会自动刷新或执行密码登录。服务端独立核对邮箱和用户密钥，通过后原子替换，失败保留旧 Session。错误响应使用固定错误码，不回显上游敏感细节。

`npm run check` 包含配对策略测试；另运行 `node --experimental-test-module-mocks --test test/proton-extension.integration.js` 检查加密写入、重放、失败保留及原有 action 委派。CI 同时执行这些测试和 Workers dry-run。

真实浏览器 Session 联调需由用户在桌面完成。操作中保持 Popup 打开；若响应超时，先刷新管理页检查状态再操作，不自动重试导入。
