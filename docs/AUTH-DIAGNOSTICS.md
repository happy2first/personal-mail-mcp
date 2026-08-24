# Proton authentication diagnostics

`mail_proton_auth(action="status")` exposes `lastAuthAttempt` so an interrupted MCP call does not erase the evidence of what happened.

Typical values:

- `status=running`, `stage=auth_info_request`: POST `/auth/v4/info` is the current authentication stage.
- `status=running`, `stage=srp_compute`: auth-info succeeded and the Worker is computing the SRP proof locally.
- `status=running`, `stage=auth_submit`: the Worker is POSTing the SRP proof to `/auth/v4`.
- `status=running`, `stage=server_proof_verify`: Proton returned an auth response and the Worker is verifying the server proof.
- `status=succeeded`, `stage=authenticated`: a durable Proton session was established.
- `status=waiting_2fa`: submit TOTP with `action=submit_2fa`.
- `status=human_verification_required`: use the returned Human Verification URL/state.
- `status=blocked_2028`: Proton returned risk code 2028. Inspect `lastAuthAttempt.error.requestPath` to see which API call produced it.
- `status=failed`: the attempt ended with another explicit error; inspect `lastAuthAttempt.error`.

Proton HTTP `Retry-After`, when actually present, is exposed as `serverRetryAfterSeconds`. The Worker's own protective delay after a 2028 is exposed separately as `localCooldownSeconds` and the persisted `risk.policy` is `local`. The local delay is not a statement from Proton about when server-side restrictions will clear.

The Worker also persists Proton API cookies encrypted with `PROTON_SESSION_KEY` and reuses applicable cookies on later Proton requests. Cookie values are never returned by `status`; only `transport.cookieCount` is exposed for diagnostics. This matches the stateful cookie-jar pattern used by Proton's Go API/Bridge stack without importing browser cookies or bypassing Human Verification.

The MCP-to-Durable-Object call is bounded by a caller-side timeout (20 seconds for explicit reauthorization, 25 seconds for other Proton actions by default). An optional `PROTON_CALL_TIMEOUT_MS` variable can override this between 5,000 and 120,000 ms. A caller timeout does not mean a new password login should be started immediately; always check `status` first.
