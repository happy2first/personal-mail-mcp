# Proton core authentication flow

The default explicit-password authorization path follows the current Proton WebClients SRP endpoint family:

1. `POST /core/v4/auth/info` with `Username` and `Intent=Proton`.
2. Compute the SRP proof locally.
3. `POST /core/v4/auth` with `Username`, `ClientProof`, `ClientEphemeral`, `SRPSession`, and `PersistentCookies=0`.
4. Verify `ServerProof` locally.
5. If required, submit TOTP to `POST /core/v4/auth/2fa`.

`PROTON_AUTH_FLOW=legacy` restores the Bridge/go-proton-api family (`/auth/v4/info`, `/auth/v4`, `/auth/v4/2fa`). The Worker does not automatically switch flows after an authentication error, particularly Proton code 2028, because one user-initiated authorization must result in at most one password-login attempt.

Cookie continuity remains enabled for either flow. Proton API `Set-Cookie` values are encrypted in the per-account Durable Object with `PROTON_SESSION_KEY` and are never exposed through MCP status output.

This flow selection does not bypass Proton Human Verification or network/account risk controls. A Proton 2028 response remains terminal for that authorization attempt and is recorded with the exact `requestPath` and `requestMethod` that produced it.
