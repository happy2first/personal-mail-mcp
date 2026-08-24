# Proton Mail support (v1.3)

`personal-mail-mcp` v1.3 upgrades the Proton provider from a read-only, memory-only session adapter to a durable Proton API client designed for Cloudflare Workers/Durable Objects.

> Proton Mail does not publish this private mail API as a stable third-party contract. The implementation follows current Proton open-source clients (`go-proton-api`, Bridge/WebClients) and deliberately fails closed when Proton changes authentication, human verification, or cryptographic requirements.

## What changed

### P0 — durable session lifecycle and risk control

- `UID`, `AccessToken`, `RefreshToken`, expiry and auth metadata are encrypted with AES-256-GCM before Durable Object storage.
- A cold Durable Object restores the encrypted session instead of performing another password/SRP login.
- Access tokens are proactively refreshed shortly before expiry.
- Rotated access/refresh tokens are immediately persisted after refresh.
- Normal MCP/background operations **never fall back to password login** when a durable session is missing or refresh fails. Password/SRP login is only performed by explicit `mail_proton_auth(action="reauthorize")`.
- Proton code `2028` uses persistent backoff: first strike 6 hours, second 24 hours, third requires an explicit risk reset/re-auth attempt. Scheduled reads do not keep retrying the password endpoint.
- Proton API errors retain `Details`, including human-verification metadata.

Decrypted OpenPGP private keys are still memory-only. They are rebuilt when message bodies or attachments need decryption.

### P1 — Human Verification and incremental Events

- Proton `9001` human-verification responses are parsed and stored as a short-lived challenge.
- If CAPTCHA is offered, the auth error contains a one-time `verificationUrl` based on `PROTON_VERIFY_BASE_URL`.
- The verification page proxies Proton CAPTCHA resources, captures Proton's completed `pm_captcha` token, and stores it encrypted in the account Durable Object.
- The completed human-verification token is sent on subsequent Proton requests through:
  - `X-Pm-Human-Verification-Token`
  - `X-Pm-Human-Verification-Token-Type`
- `mail_proton_poll_changes` persists the Proton EventID cursor and uses `/core/v4/events/...` for incremental change retrieval. The first call initializes the cursor and intentionally does not replay the entire mailbox history.

### P2 — attachments and 2FA

- `mail_get_attachment` supports Proton attachment download and OpenPGP decryption, returning Base64 like the IMAP providers.
- TOTP 2FA is supported through `mail_proton_auth(action="submit_2fa")` and `/auth/v4/2fa`.
- A two-password Proton account can provide `MAIL_<ACCOUNT>_MAILBOX_PASSWORD` for mailbox-key decryption.

FIDO2/passkey completion is not automated. If Proton requires a FIDO2-only login, use a Proton-supported interactive client or enable/use TOTP for this integration.

### P3 — Proton writes

The common MCP tools now route Proton accounts through Proton v4 APIs instead of IMAP/SMTP:

- `mail_set_state`: read/unread/star/unstar
- `mail_transfer`: label-based copy/move (Trash/Spam destinations remain blocked)
- `mail_save_draft`
- `mail_send`
- `mail_reply` / reply-all
- `mail_forward`

For sending, the adapter creates an encrypted Proton draft, uploads encrypted attachments, builds current Proton send packages, uses end-to-end encrypted packages for Proton-internal recipients with available public keys, and uses Proton clear-delivery packages for ordinary external recipients.

The adapter does not attempt encrypted-to-outside password mail or custom OpenPGP contact-policy emulation. Those require additional recipient-preference APIs beyond the common send path.

## Required Cloudflare configuration

Keep existing Worker variables/secrets. `wrangler.jsonc` keeps `"keep_vars": true` and does not define a dashboard-overwriting `vars` block.

### 1. Accounts

Example:

```text
MAIL_ACCOUNTS=qq,163main,gmail,proton1,proton2
```

For each Proton account:

```text
MAIL_PROTON1_PROVIDER=proton
MAIL_PROTON1_LABEL=Proton 1
MAIL_PROTON1_EMAIL=<Proton login email>
MAIL_PROTON1_CREDENTIAL=<Proton login password>
```

`MAIL_PROTON*_EMAIL` and `MAIL_PROTON*_CREDENTIAL` should be Cloudflare Secrets in production.

For a legacy/two-password account only:

```text
MAIL_PROTON1_MAILBOX_PASSWORD=<mailbox password>
```

### 2. `PROTON_SESSION_KEY` — required Secret

This encrypts durable Proton session and human-verification state with AES-GCM.

```text
PROTON_SESSION_KEY=<random high-entropy secret>
```

Generate a value locally with a cryptographically secure generator (for example 32 random bytes encoded as Base64). **Do not commit the value to GitHub.** Changing this value makes previously persisted Proton sessions unreadable and requires reauthorization.

### 3. `PROTON_VERIFY_BASE_URL` — required for clickable CAPTCHA

Set this to the public origin that reaches this Worker, without a trailing slash:

```text
PROTON_VERIFY_BASE_URL=https://mail.mcp.example.com
```

When Proton asks for CAPTCHA, `mail_proton_auth(action="reauthorize")` returns a URL such as:

```text
https://mail.mcp.example.com/proton/verify/proton1/<random-state>
```

The state is random and expires after 30 minutes. Treat the URL as a temporary bearer link; do not publish it.

## Optional Proton compatibility overrides

Normally leave these unset:

```text
PROTON_API_BASE=https://mail.proton.me/api
PROTON_APP_VERSION=macos-bridge@3.24.1
```

`PROTON_APP_VERSION` remains configurable because Proton checks app metadata, but this project **does not treat changing AppVersion as a reliable CAPTCHA/2028 bypass**. Use the default unless current Proton clients require an update.

## First deployment / migration from v1.2

v1.2 deliberately kept Proton tokens only in memory. Therefore there is no durable token to migrate after deployment. Each Proton account needs one explicit initialization:

1. Configure `PROTON_SESSION_KEY` and `PROTON_VERIFY_BASE_URL`.
2. Deploy v1.3.
3. Call `mail_proton_auth(account="proton1", action="status")`.
4. Call `mail_proton_auth(account="proton1", action="reauthorize")` once.
5. If `twoFactorRequired=true`, immediately call `mail_proton_auth(..., action="submit_2fa", twoFactorCode="123456")`.
6. If `humanVerificationRequired=true`, open the returned `verificationUrl`, complete Proton's CAPTCHA, then call `reauthorize` again.
7. Call `mail_test_connection(account="proton1")` and `mail_list_messages(account="proton1", limit=5)`.
8. Repeat for the second Proton account.
9. Initialize EventID with `mail_proton_poll_changes(account="proton1")`.

After a durable session exists, normal background jobs restore/refresh it and do not perform password/SRP login.

## 2028 behavior

A `2028` response means Proton has restricted the account/request for unusual activity. It is not equivalent to CAPTCHA `9001`.

- Background operations stop before another Proton request while the risk state is blocked.
- First occurrence: 6-hour block.
- Second occurrence: 24-hour block.
- Third occurrence: manual-reset state.
- `mail_proton_auth(action="reset_risk")` only clears the local circuit breaker; it does **not** remove Proton's server-side restriction.
- Prefer fixing/appealing the Proton account first, then explicitly use `reauthorize` once.

## Security notes

- Proton passwords remain Cloudflare Secrets; they are not copied into Durable Object storage.
- Durable auth/session data is encrypted before storage using `PROTON_SESSION_KEY` and account/key-bound AES-GCM additional authenticated data.
- Decrypted OpenPGP private keys remain memory-only.
- Human-verification challenge/completion tokens are encrypted in Durable Object storage.
- CAPTCHA URLs are short-lived random-state URLs. Do not log or share them.
- Delete/Trash operations remain intentionally restricted by the MCP safety model.

## Current operational limits

- The Proton mail API is private and can change.
- FIDO2-only authentication is not implemented.
- Encrypted-to-outside password mail and arbitrary external PGP preference negotiation are not implemented.
- `mail_proton_poll_changes` returns raw Proton event structures; higher-level scheduled logic should inspect create/update events and fetch only relevant new messages.
