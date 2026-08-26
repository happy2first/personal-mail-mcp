# Proton 浏览器 Refresh Cookie 说明

当前 Proton WebClient 的 `POST /api/auth/refresh` 是浏览器 Cookie 刷新入口；其 Response 不应被假定为包含可复制的 AccessToken/RefreshToken JSON。

`/proton/import` 因此支持直接导入浏览器 `REFRESH-*` Cookie 的 value。Worker 只在服务端解析 UID/RefreshToken，并执行一次标准 `/auth/v4/refresh` 来获取 API Token，再校验账号后持久化。

不要把 REFRESH Cookie、AccessToken 或 RefreshToken 发到聊天、Issue 或日志中。
