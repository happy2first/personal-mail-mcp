# Proton message metadata query compatibility

Proton WebClients currently queries `mail/v4/messages` with HTTP GET and URL query parameters. HTTP POST on the same collection endpoint is the draft-creation route and expects a `Message` object.

The compatibility layer in `src/proton/mail-query.js` overrides the inherited legacy `listMessages` implementation to use GET with `LabelID`, `Desc`, `Page`, `PageSize`, and `Sort` query parameters. `searchMessages` and `folderStatus` call `listMessages`, so they inherit the corrected behavior.

This change does not modify Proton authentication, Cookie Session persistence, key decryption, or message-body retrieval.
