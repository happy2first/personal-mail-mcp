# Proton Mail read-only support

`personal-mail-mcp` v1.2 adds a read-only Proton Mail provider backed by a Cloudflare Durable Object. The first version keeps the authenticated Proton session and unlocked OpenPGP keys only in memory; it does not persist Proton passwords, tokens, or decrypted keys to Durable Object storage.

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

If Proton requests human verification, returns an unsupported auth version, or changes its private API, the adapter returns an explicit error instead of silently falling back.
