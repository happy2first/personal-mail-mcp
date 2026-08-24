# Proton authentication diagnostics

`mail_proton_auth(action="status")` exposes `lastAuthAttempt` so an interrupted MCP call does not erase the evidence of what happened.

Typical values:

- `status=running`, `stage=password_login`: the explicit reauthorization started but the caller stopped waiting before a terminal Proton result was persisted. Do not immediately retry; inspect the Worker logs and status first.
- `status=succeeded`, `stage=authenticated`: a durable Proton session was established.
- `status=waiting_2fa`: submit TOTP with `action=submit_2fa`.
- `status=human_verification_required`: use the returned Human Verification URL/state.
- `status=blocked_2028`: Proton returned risk code 2028; observe the persisted risk backoff and do not retry automatically.
- `status=failed`: the attempt ended with another explicit error; inspect `lastAuthAttempt.error`.

The MCP-to-Durable-Object call is bounded by a caller-side timeout (20 seconds for explicit reauthorization, 25 seconds for other Proton actions by default). An optional `PROTON_CALL_TIMEOUT_MS` variable can override this between 5,000 and 120,000 ms. A caller timeout does not mean a new password login should be started immediately; always check `status` first.
