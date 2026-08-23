# Proton Mail read-only support

`personal-mail-mcp` v1.2 adds a read-only Proton Mail provider backed by a Cloudflare Durable Object. The authenticated Proton session and unlocked OpenPGP keys are kept only in memory; Proton passwords, access tokens, refresh tokens, and decrypted keys are not persisted to Durable Object storage.

The Durable Object does persist one non-secret safety value when Proton returns API code `2028`: a cooldown timestamp. This prevents a Durable Object restart from immediately repeating a password login while Proton is rate/risk limiting the account.

## Cloudflare configuration

Keep all existing Worker variables and secrets. `wrangler.jsonc` intentionally keeps `"keep_vars": true` and does not define a `vars` block, so Wrangler/GitHub deployment will not replace dashboard-managed values.

For two accounts, append the Proton account IDs to the existing `MAIL_ACCOUNTS` value instead of replacing the existing IDs, for example:

```text
MAIL_ACCOUNTS=qq,163main,gmail,proton1,proton2
```

Add account 1:

```text
MAIL_PROTON1_PROVIDER=proton
MAIL_PROTON1_LABEL=Proton 1
MAIL_PROTON1_EMAIL=<Proton login email>
MAIL_PROTON1_CREDENTIAL=<Proton password>
```

Add account 2:

```text
MAIL_PROTON2_PROVIDER=proton
MAIL_PROTON2_LABEL=Proton 2
MAIL_PROTON2_EMAIL=<Proton login email>
MAIL_PROTON2_CREDENTIAL=<Proton password>
```

Recommended: configure `MAIL_PROTON*_EMAIL` and `MAIL_PROTON*_CREDENTIAL` as Cloudflare Secrets. No Proton API key, OAuth client, 2FA secret, or mailbox password is required for normal one-password accounts without 2FA.

No additional environment variables are required for the session-refresh or 2028-circuit-breaker behavior.

## Session and risk-control behavior

- Concurrent requests that need an initial SRP login share one in-flight login instead of submitting several password logins.
- A normal authenticated request that receives HTTP `401` first uses Proton `/auth/v4/refresh` with the current `UID` and `RefreshToken`; it does not immediately fall back to a password login.
- Concurrent `401` responses share one in-flight refresh.
- If Proton reports that the refresh token is invalid (`400`, `401`, or `422`), the failed request stops there and clears the in-memory session. A later request may perform one fresh password login.
- Proton API code `2028` opens a 30-minute circuit breaker. While it is open, the Worker does not send another Proton API request for that account.
- The `2028` cooldown timestamp is stored in the account's Durable Object storage so a DO restart cannot bypass the cooldown. The timestamp contains no credentials or message data.

## Supported in v1.2

- `mail_test_connection`
- `mail_list_accounts`
- `mail_list_folders` for Proton system folders
- `mail_folder_status` (limited fields)
- `mail_list_messages`
- `mail_search_messages` (metadata search only for Proton; `text` does not scan decrypted bodies)
- `mail_get_message` including OpenPGP body decryption and attachment metadata

Not yet supported for Proton: attachment-content download/decryption, sending/replying/forwarding, state changes, moves, or folder writes. Existing IMAP/SMTP providers keep their previous behavior.

## First validation

1. `mail_test_connection(account="proton1")`
2. `mail_list_messages(account="proton1", limit=5)`
3. `mail_get_message(messageRef="...")` using a returned `messageRef`
4. Repeat for `proton2`

If Proton requests human verification, returns an unsupported auth version, changes its private API, or returns `2028`, the adapter returns an explicit error instead of silently retrying password authentication.
