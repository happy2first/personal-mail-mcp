# Proton browser cookie session

Current Proton WebClients may upgrade a freshly issued token session to cookie authentication via `core/v4/auth/cookies`. In cookie mode, authenticated API requests use `x-pm-uid` plus the browser cookies, and `/auth/refresh` is called without a token request body. The `/proton/import` backend accepts a copied browser `Cookie:` request header containing `AUTH-<UID>` and imports it as an encrypted cookie-auth session.
