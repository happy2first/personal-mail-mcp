# personal-mail-mcp

一个运行在 **Cloudflare Workers** 上的多账号 IMAP/SMTP MCP Server，将常见邮箱以统一的 MCP Tools 暴露给 ChatGPT、Claude 等支持 MCP 的客户端。

当前版本采用“**一个 Worker + 多个邮箱账号 + 配置驱动 Provider**”的设计。邮箱地址、授权码、应用专用密码等敏感信息全部通过 Cloudflare Worker Secrets / Variables 注入，不需要写进代码。

> 本项目面向个人自托管场景。请不要把真实邮箱密码、授权码、Cloudflare Access JWT、Application Audience 或其他凭证提交到 Git。

## 功能

- 一个 MCP Server 管理多个邮箱账号。
- 内置 Provider：QQ 邮箱、163 邮箱、Gmail。
- 支持自定义标准 IMAP/SMTP 邮箱。
- 支持查询全部账号，并允许单个账号失败时返回部分成功结果。
- 支持邮件列表、搜索、正文、附件、已读/星标状态、移动/复制、文件夹管理、发送、回复、转发、草稿等能力。
- 每封邮件返回 `messageRef`，后续操作可优先使用该引用。
- **明确禁用删除能力**：不提供删除邮件或删除文件夹 Tool，也阻止移动/复制到 Trash、Deleted、废纸篓等删除类目录。
- 使用 Cloudflare Access JWT 保护 `/mcp` 和 `/health`。

## 设计概览

```text
MCP Client
   │
   │ HTTPS / MCP Streamable HTTP
   ▼
Cloudflare Access
   │  Cf-Access-Jwt-Assertion
   ▼
personal-mail-mcp Worker
   ├─ MCP Tool layer
   ├─ account / provider config
   ├─ cloudflare:sockets → IMAP
   └─ cloudflare:sockets → SMTP
```

Cloudflare Access 负责客户端身份与边缘访问控制；Worker 还会再次校验 Access JWT 的 issuer、audience 和签名。

邮箱本身使用 IMAP/SMTP 授权码或应用专用密码。本版本不实现 Gmail OAuth2、POP3 或 Proton Mail Bridge。

## 支持的邮箱 Provider

| Provider | IMAP | SMTP | 凭证 |
|---|---|---|---|
| `qq` | `imap.qq.com:993` TLS | `smtp.qq.com:465` TLS | QQ 邮箱授权码 |
| `163` | `imap.163.com:993` TLS | `smtp.163.com:465` TLS | 163 邮箱客户端授权码 |
| `gmail` | `imap.gmail.com:993` TLS | `smtp.gmail.com:465` TLS | Google App Password |
| `custom` | 自定义 | 自定义 | 邮箱服务商提供的 IMAP/SMTP 凭证 |

163 邮箱连接时会发送 IMAP `ID` 命令，以兼容网易邮箱的客户端识别要求。

## 环境要求

- Node.js 20+（建议使用当前 LTS）
- Cloudflare 账号
- 已启用 IMAP/SMTP 的邮箱账号
- Wrangler 4.x
- 一个 Cloudflare Access Application，用于保护 Worker

## 安装

```bash
git clone https://github.com/happy2first/personal-mail-mcp.git
cd personal-mail-mcp
npm install
```

本地配置可以从示例文件开始：

```bash
cp .dev.vars.example .dev.vars
```

`.dev.vars` 已加入 `.gitignore`，不要提交真实凭证。

## Cloudflare Access 配置

Worker 需要两个 Access 相关变量：

```text
TEAM_DOMAIN=https://<your-team>.cloudflareaccess.com
POLICY_AUD=<your-access-application-audience-tag>
```

其中：

- `TEAM_DOMAIN` 是 Cloudflare Zero Trust Team Domain 的 origin，不要填写 `/cdn-cgi/access/certs` 路径。
- `POLICY_AUD` 是对应 Access Application 的 Application Audience (AUD) Tag。

对于 MCP 客户端，可根据需要在 Cloudflare Access 中配置 Managed OAuth 或其他适合的 Access Policy。Worker 本身只信任 Cloudflare Access 签发并通过校验的 JWT。

## 邮箱账号配置

### 1. 账号列表

必须设置：

```text
MAIL_ACCOUNTS=qq,163main,gmail
```

账号 ID 代表“具体邮箱账号实例”，不是 Provider。一个 Provider 可以配置多个账号，例如：

```text
MAIL_ACCOUNTS=163main,163backup,qq,gmail
```

账号 ID 只能使用英文字母、数字和下划线；`all` 为保留字。

### 2. 内置 Provider

每个账号至少需要：

```text
MAIL_<ID>_PROVIDER=qq|163|gmail
MAIL_<ID>_LABEL=显示名称
MAIL_<ID>_EMAIL=邮箱地址
MAIL_<ID>_CREDENTIAL=授权码或应用专用密码
```

建议：

- `MAIL_<ID>_PROVIDER`、`MAIL_<ID>_LABEL` 可使用普通 Variable。
- `MAIL_<ID>_EMAIL` 建议使用 Secret。
- `MAIL_<ID>_CREDENTIAL` **必须使用 Secret**。

QQ 示例：

```text
MAIL_QQ_PROVIDER=qq
MAIL_QQ_LABEL=QQ邮箱
MAIL_QQ_EMAIL=your-address@example.com
MAIL_QQ_CREDENTIAL=replace-with-app-password
```

163 示例：

```text
MAIL_163MAIN_PROVIDER=163
MAIL_163MAIN_LABEL=163邮箱
MAIL_163MAIN_EMAIL=your-address@example.com
MAIL_163MAIN_CREDENTIAL=replace-with-client-authorization-code
```

Gmail 示例：

```text
MAIL_GMAIL_PROVIDER=gmail
MAIL_GMAIL_LABEL=Gmail
MAIL_GMAIL_EMAIL=your-address@gmail.com
MAIL_GMAIL_CREDENTIAL=replace-with-google-app-password
```

Gmail 当前使用 App Password，不使用 Google OAuth。

### 3. Custom Provider

```text
MAIL_WORK_PROVIDER=custom
MAIL_WORK_LABEL=工作邮箱
MAIL_WORK_EMAIL=your-address@example.com
MAIL_WORK_CREDENTIAL=replace-with-app-password
MAIL_WORK_IMAP_HOST=imap.example.com
MAIL_WORK_IMAP_PORT=993
MAIL_WORK_IMAP_SECURITY=tls
MAIL_WORK_SMTP_HOST=smtp.example.com
MAIL_WORK_SMTP_PORT=465
MAIL_WORK_SMTP_SECURITY=tls
```

`*_SECURITY` 只允许：

- `tls`：连接建立时直接 TLS。
- `starttls`：明文连接后升级 TLS。

SMTP 端口 25 被显式禁止。

## 推荐的 Cloudflare 配置方式

非敏感配置可以在 Worker Dashboard 中设置 Variables；敏感配置使用 Secrets。

例如：

```bash
npx wrangler secret put MAIL_QQ_EMAIL
npx wrangler secret put MAIL_QQ_CREDENTIAL
npx wrangler secret put MAIL_163MAIN_EMAIL
npx wrangler secret put MAIL_163MAIN_CREDENTIAL
npx wrangler secret put POLICY_AUD
```

`TEAM_DOMAIN`、`MAIL_ACCOUNTS`、Provider、Label 等也可以通过 Dashboard Variables 配置。

`wrangler.jsonc` 使用 `keep_vars: true`，部署代码时不会要求把这些运行环境配置写入仓库。

## MCP Tools

主要 Tool：

| Tool | 类型 | 用途 |
|---|---|---|
| `mail_list_accounts` | 只读 | 列出已配置账号，不返回邮箱地址或凭证 |
| `mail_test_connection` | 只读 | 测试 IMAP/SMTP 登录 |
| `mail_list_folders` | 只读 | 列出邮箱文件夹 |
| `mail_folder_status` | 只读 | 查看文件夹状态和配额 |
| `mail_list_messages` | 只读 | 获取邮件列表 |
| `mail_search_messages` | 只读 | 搜索邮件 |
| `mail_get_message` | 只读 | 获取邮件正文和元数据 |
| `mail_get_attachment` | 只读 | 获取附件 |
| `mail_set_state` | 写入 | 修改已读、星标等状态 |
| `mail_transfer` | 写入 | 移动/复制邮件，删除类目标被禁止 |
| `mail_manage_folder` | 写入 | 创建、重命名等文件夹操作，不提供删除 |
| `mail_send` | 写入 | 发送邮件 |
| `mail_reply` | 写入 | 回复邮件 |
| `mail_forward` | 写入 | 转发邮件 |
| `mail_save_draft` | 写入 | 保存草稿 |

查询类 Tool 不传 `account` 时通常默认 `all`。发送、文件夹管理等写操作必须明确指定账号。

## 本地检查与部署

语法检查：

```bash
npm run check
```

部署：

```bash
npx wrangler login
npm run deploy
```

部署完成后：

- `/`：公共服务状态入口（具体响应以当前代码为准）。
- `/health`：受 Cloudflare Access 保护的健康检查。
- `/mcp`：MCP Streamable HTTP 入口。

## 安全说明

1. **不要提交真实凭证。** `.dev.vars`、`.env` 等文件应始终保持在 Git 之外。
2. **邮箱授权码不等于登录密码，但仍应按密码级别保护。** 泄露后应立即在邮箱服务商处撤销并重新生成。
3. **Cloudflare Access 是第一层边界，Worker JWT 校验是第二层边界。** 不建议直接暴露一个未受 Access 保护的 Worker。
4. Tool 返回不会主动暴露账号密码或授权码；连接日志也不应记录认证命令内容。
5. 项目刻意不实现删除类操作，但写操作仍可能改变邮箱状态，部署前请自行审查权限范围。
6. 如果凭证曾经被提交进 Git 历史，仅删除当前文件不够，应先撤销凭证，再重写 Git 历史后再公开仓库。

## 已知限制

- Gmail OAuth2 尚未实现。
- 不支持 Proton Mail Bridge / Proton Mail API。
- 不支持 POP3。
- Cloudflare Workers 到部分邮箱服务商的 TCP/TLS 行为可能受网络环境或服务商安全策略影响。
- 不同邮箱服务商对 IMAP 扩展、文件夹命名和限流策略存在差异。

## 开源与贡献

欢迎提交 Issue / Pull Request，尤其是：

- 新邮箱 Provider 适配。
- OAuth2 邮箱认证。
- 更完善的 IMAP/SMTP 兼容性测试。
- MCP Tool 权限分级与更细粒度的只读模式。
- Cloudflare Access / Managed OAuth 的部署文档完善。

## License

MIT
