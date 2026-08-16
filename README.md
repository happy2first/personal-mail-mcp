# personal-mail-mcp

Cloudflare Worker 上的多账号、配置驱动 IMAP/SMTP MCP 服务。

## V1.1 设计

- 一套 MCP Tool 服务多个邮箱账号；邮箱账号是参数，不按邮箱复制 Tool。
- 内置 Provider：`qq`、`163`、`gmail`。
- 支持 `custom` 标准 IMAP/SMTP 邮箱。
- 一个 Provider 可以配置多个 Account。
- 查询类 Tool 支持 `account=all`，并在单个账号失败时返回部分成功结果。
- 每封邮件返回 `messageRef`，具体邮件操作优先使用该引用。
- 不提供删除邮件或删除文件夹能力，也禁止移动/复制到 Trash/Deleted 类目录。
- V1.1 不支持 OAuth2、Proton Mail、POP3。

## Cloudflare 环境变量

### 1. 账号列表

普通 Variable：

```text
MAIL_ACCOUNTS=qq,163main,gmail
```

账号 ID 只使用英文字母、数字和下划线；`all` 为保留字。

### 2. 内置 Provider

每个账号最少配置：

```text
MAIL_<ID>_PROVIDER=qq|163|gmail
MAIL_<ID>_LABEL=显示名称        # 可选，普通 Variable
MAIL_<ID>_EMAIL=邮箱地址        # 建议 Secret
MAIL_<ID>_CREDENTIAL=授权码或应用专用密码  # Secret
```

示例：

```text
MAIL_163MAIN_PROVIDER=163
MAIL_163MAIN_LABEL=我的163邮箱
MAIL_163MAIN_EMAIL=***
MAIL_163MAIN_CREDENTIAL=***
```

Gmail 本版使用 App Password；不使用 Google OAuth。

### 3. Custom Provider

```text
MAIL_WORK_PROVIDER=custom
MAIL_WORK_LABEL=工作邮箱
MAIL_WORK_EMAIL=***
MAIL_WORK_CREDENTIAL=***
MAIL_WORK_IMAP_HOST=imap.example.com
MAIL_WORK_IMAP_PORT=993
MAIL_WORK_IMAP_SECURITY=tls
MAIL_WORK_SMTP_HOST=smtp.example.com
MAIL_WORK_SMTP_PORT=465
MAIL_WORK_SMTP_SECURITY=tls
```

`*_SECURITY` 只允许 `tls` 或 `starttls`。SMTP 端口 25 不允许。

## 旧 QQ 配置兼容

如果没有配置 `MAIL_ACCOUNTS`，仍兼容原来的：

```text
MAIL_QQ_EMAIL
MAIL_QQ_AUTH_CODE
```

如果开始使用 `MAIL_ACCOUNTS` 且包含 `qq`，原 `MAIL_QQ_EMAIL` 与 `MAIL_QQ_AUTH_CODE` 仍可继续作为 QQ 的兼容配置，因此可逐步迁移。

## MCP Tool

主要 Tool：

- `mail_list_accounts`
- `mail_test_connection`
- `mail_list_folders`
- `mail_folder_status`
- `mail_list_messages`
- `mail_search_messages`
- `mail_get_message`
- `mail_get_attachment`
- `mail_set_state`
- `mail_transfer`
- `mail_manage_folder`
- `mail_send`
- `mail_reply`
- `mail_forward`
- `mail_save_draft`

查询类 Tool 不传 `account` 时默认 `all`。发送、文件夹管理等写操作必须明确指定账号。
