# 应用统一身份接入（App SSO）接入指南

> 面向对象：在企业内自研 AI 应用（Web / H5 / 小程序 / 桌面 / API 服务）中接入平台统一身份的开发者。
> 本文档随服务发布，可直接访问 `http://<平台地址>/docs/app-sso-integration.md`（`/docs` 目录索引页可列全部文档）。
> 目标路径：**注册应用 → 拿凭据 → 按规范一行 SDK 式接入 → 业务权限自己管**。

平台作为企业内统一身份源（OIDC Provider）对外提供身份服务；应用完成接入后：

- 用户在应用中点击「登录」→ 跳转平台授权页 → 平台会话或登录面板（账号密码 / 钉钉免密，按平台连接器配置显隐）→ 确认授权 → 携 `code` 回跳应用；
- 钉钉用户无需预登录平台控制台：授权页登录面板内即可「钉钉扫码」免密登录（首次身份走绑定/注册分支），随后直接进入授权确认；
- 应用后端用 `code` + `client_secret`（或纯前端用 PKCE）换取 `id_token` / `access_token`；
- 应用用 `access_token` 调 `userinfo` 拿到用户身份（`sub` / 组织 / 角色 / 租户），**业务权限由应用自理**；
- 账号在平台被冻结 / 离职 → 应用侧下一次 `userinfo` / `refresh` 即时失效，无需等令牌过期。

## 一、接入五步

| 步骤 | 操作 | 位置 |
|---|---|---|
| 1. 注册应用 | 「AI 应用」→ 注册应用（形态、访问地址、编排 Agent） | 控制台 |
| 2. 签发凭据 | 应用详情 → 「SSO 配置」tab → 签发 SSO 客户端（`client_id` + `client_secret`，secret 仅展示一次） | 控制台 |
| 3. 上线门禁 | `web` / `h5` 形态应用未完成签发无法上线（`APP_SSO_ENFORCE` 可调）；审批通过执行期还会复核客户端状态 | 控制台 + 审批中心 |
| 4. 应用侧接入 | 按下方「SDK 一行接入」或端点直连完成授权码模式（强制 PKCE S256） | 应用代码 |
| 5. 业务权限自理 | `userinfo` 的 `sub` 是稳定关联键；应用内自主映射业务角色 | 应用代码 |

## 二、SDK 一行式接入（推荐）

### 后端 / BFF（confidential 客户端，默认形态）

Node.js（[openid-client](https://github.com/panva/openid-client) v6，与平台自测同款）：

```js
import * as oc from 'openid-client'

// ① 一行 discovery 驱动：issuer 换成平台地址即可
const config = await oc.discovery(
  new URL('https://sso.yourcompany.com'),        // OIDC_ISSUER（见下）
  process.env.SSO_CLIENT_ID,                     // 控制台签发的 client_id
  undefined,
  new oc.ClientSecretBasic(process.env.SSO_CLIENT_SECRET),
)

// ② 登录入口：拼授权地址并 302（state/PKCE 平台强制校验）
const verifier = oc.randomPKCECodeVerifier()
const challenge = await oc.calculatePKCECodeChallenge(verifier)
const redirectTo = oc.buildAuthorizationUrl(config, {
  redirect_uri: 'https://your-app.com/auth/cb',  // 必须与控制台登记的 redirect_uris 完全一致
  scope: 'openid profile email',
  state: oc.randomState(), nonce: oc.randomNonce(),
  code_challenge: challenge, code_challenge_method: 'S256',
})

// ③ 回调处：code 换令牌（id_token 已由 SDK 用 JWKS 验签）
const tokens = await oc.authorizationCodeGrant(config, callbackUrl, {
  code_verifier: verifier, state, nonce,
})
const user = await oc.fetchUserInfo(config, tokens.access_token, tokens.claims().sub)
// user = { sub, name, preferred_username, email?, org: {id,name,tenantId}, roles, tenant }
```

- 静默续期：`oc.refreshTokenGrant(config, tokens.refresh_token)`（轮转一次一换，旧值重放会吊销整链）。
- 登出联动：`oc.buildEndSessionUrl(config, { id_token_hint, post_logout_redirect_uri, state })`，平台会同时吊销该用户在本应用下的 refresh 链。未携带 `post_logout_redirect_uri` 时，若该客户端仅登记了一个登出回跳地址，平台按其登记地址回跳（推荐仍显式传参，多环境登记时不受此兜底影响）。
- 主动吊销：`oc.tokenRevocation(config, tokens.access_token)`（RFC 7009）。

### 纯前端 SPA（public 客户端，D-a 决策：支持 public 形态）

无后端、无法持有 secret 的 H5 / SPA：签发时选择 **public** 客户端类型——免 `client_secret`、**强制 PKCE**、**不签发 refresh token**（access token 过期后静默重走授权）。前端库可用 [oidc-client-ts](https://github.com/authts/oidc-client-ts)：

```js
const mgr = new UserManager({
  authority: 'https://sso.yourcompany.com',       // 平台 discovery 地址
  client_id: 'oc-xxxxxxxx',                        // public 客户端
  redirect_uri: 'http://localhost:5173/cb',        // localhost 调试地址白名单放行
  response_type: 'code', scope: 'openid profile',
  code_challenge_method: 'S256',                   // 平台强制
})
await mgr.signinRedirect()                          // 登录入口
const user = await mgr.signinRedirectCallback()     // 回调处，id_token 已验签
```

> 安全提示：public 客户端的令牌暴露面更大，仅建议用于内网工具 / 无敏感数据的应用；能上 BFF 的尽量走 confidential。

#### CORS（纯前端跨域直调，平台已内置放行）

浏览器内 JS 跨域直调 `POST /oauth/token`、`GET /oauth/userinfo`、`POST /oauth/revoke` 与两个 discovery 端点时，平台自动返回 CORS 放行头，**无需任何界面配置**：

- 允许来源 = 已登记客户端 `redirect_uri` 的 origin（scheme://host:port）∪ 环境变量 `OIDC_CORS_ORIGINS`（逗号分隔，追加非登记来源）。登记回调 `http://192.168.0.4:8092/cb` 即自动放行 `http://192.168.0.4:8092`。
- `OPTIONS` 预检统一 204，`Access-Control-Allow-Headers: authorization, content-type`；成功与错误响应都携带 `Access-Control-Allow-Origin`（浏览器可读错误体）。
- 未登记来源不发放放行头（仅 `Vary: Origin`）；授权第一跳 `/oauth/authorize` 与登出 `/oauth/end_session` 是浏览器顶级跳转，不涉及 CORS。

## 三、端点与 discovery

| 端点 | 路径 |
|---|---|
| discovery | `GET /​.well-known/openid-configuration` |
| JWKS 公钥 | `GET /​.well-known/jwks.json` |
| 授权 | `GET /oauth/authorize`（302 平台授权页） |
| 换牌 | `POST /oauth/token`（`client_secret_basic` / `client_secret_post`；form-encoded 与 JSON 均接受） |
| 用户信息 | `GET /oauth/userinfo`（Bearer access token） |
| 刷新 | `POST /oauth/token`（`grant_type=refresh_token`，轮转 + scope 只收窄） |
| 吊销 | `POST /oauth/revoke`（RFC 7009，恒 200） |
| 登出 | `GET /oauth/end_session`（`id_token_hint` + `post_logout_redirect_uri`） |

**`OIDC_ISSUER` 与内网 / HTTPS 反代**：默认 issuer 为 `http://127.0.0.1:<port>`，仅供本机调试。生产/内网部署时必须显式声明对外地址（反代场景取 `x-forwarded-host` 语义对应的对外域名）：

```bash
OIDC_ISSUER=https://sso.yourcompany.com   # discovery/JWKS/端点全部按此拼址
```

应用与用户浏览器都必须能访问该地址；反向代理需放行 `/oauth/*`、`/.well-known/*` 与 SPA 路由 `/#/oauth/*`。注意：更换 issuer 会使存量令牌 `iss` 校验失败，属预期（令牌生命周期短）。

## 四、claims 契约

| claim / 字段 | 语义 |
|---|---|
| `sub` | 平台用户 ID，**稳定不变，唯一关联键**（应用内账号映射以此为准，勿用 username） |
| `preferred_username` / `name` | 用户名 / 显示名（可能改名，勿作主键） |
| `email` | 仅当授权 scope 含 `email` 才返回 |
| `org` / `tenant` | 用户所属组织 `{id,name,tenantId}` / 租户 ID（多租户分域参考） |
| `roles` | 用户在平台的平台级角色 code（`super_admin` 等）——**平台治理角色，不是应用业务角色** |
| `id_token.token_use='id'` / `access.token_use='access'` | 令牌类型打标：`id_token` 只做身份证明，不能调 `userinfo` |

「业务权限自己管」：平台只负责「你是谁」（身份）与平台资源的平台级权限；应用内菜单 / 数据 / 功能权限由应用基于 `sub` 自行建模（建议在应用内维护 `sub → 业务角色` 映射表）。

## 五、安全清单

- **state**：平台强制必填并原样回传（CSRF 防护）；SDK 自动处理，直连时自行生成并校验。
- **PKCE S256**：平台对所有客户端强制；`code_challenge` 43–128 位 base64url。
- **client_secret 保管**：仅存应用后端（环境变量 / KMS）；轮换入口在应用详情「SSO 配置」，旧值立即失效。
- **HTTPS**：redirect_uri 允许 `https://` 任意主机；`http://` 仅放行内网地址（`localhost` / `127.0.0.1` / `10.x.x.x` / `172.16-31.x.x` / `192.168.x.x`，含内网 IPv6 ULA）。纯内网部署可设 `APP_SSO_ALLOW_HTTP=1` 放开全部 http 主机。
- **登出联动**：应用登出时应调 `end_session`，平台会吊销该用户在本应用下的 refresh 链（否则登出后应用仍可静默续期）。回跳规则：显式携带 `post_logout_redirect_uri` 必须命中客户端登记的登出白名单（未命中拒绝）；未携带时，客户端仅登记一个登出地址则按该地址回跳，未登记或登记多个则停留在平台登出页。
- **冻结即时失效**：平台账号冻结 / 离职 → `userinfo` 与 `refresh` 立即拒绝（实时校验用户状态）。
- **门禁**：`web`/`h5` 应用上线前必须持有 active SSO 客户端；审批挂单期间客户端被禁用会在执行期复核失败。

## 六、令牌 TTL 说明（双 TTL 折中）

| 令牌 | TTL | 说明 |
|---|---|---|
| 平台控制台会话 access | 30 min | 平台自身安全基线（refresh 7d 轮转） |
| OIDC access token | 默认 2h（`OIDC_ACCESS_TTL_SECONDS`） | 折中：应用后端/JWKS 本地验签为主，过长放大泄漏面、过短导致 userinfo 窗口太碎 |
| OIDC refresh token | 默认 7d（`OIDC_REFRESH_TTL_SECONDS`） | 一次一换 + 重放整链吊销；冻结/禁用/登出即时失效 |

## 七、secret / 密钥轮换 runbook

- **应用 secret 轮换**：应用详情 → SSO 配置 → 「轮换 secret」→ 新值一次性展示 → 应用侧更新配置（旧值立即 401）。建议每季度或在疑似泄漏时执行。
- **平台 JWKS 签名密钥轮换**：「认证与令牌」→ 「轮换 OIDC 签名密钥」（需 `authn.oidc.write`）。新 key 立即签名，旧 key 24h 宽限内保留验签与 JWKS 公布（在途令牌不掉线）；SDK 会按 `kid` 自动选 key，无需应用改动。
- **应急处置**：疑似令牌泄漏 → 禁用客户端（授权/换牌/刷新立即失败，refresh 链吊销）→ 轮换 secret → 重新启用。

## 八、FAQ

- **本机调试**：redirect_uri 用 `http://localhost:<port>/cb` 即可过白名单；issuer 保持默认 `http://127.0.0.1:<port>`。
- **多环境 issuer**：一套应用对接多套平台环境时，按环境变量注入不同 issuer / client；`iss` 回跳参数与 id_token `iss` 可用于 mix-up 防护校验。
- **id_token vs userinfo**：只关心登录身份 → 验 `id_token`（本地 JWKS 验签）即可；需要最新组织/角色/状态 → 调 `userinfo`（实时、且能感知冻结）。
- **回调后拿到的 roles 是业务角色吗**：不是。`roles` 是平台治理角色；业务角色请应用内自理。

## 九、平台直达（entry-ticket，与应用 OIDC 接入互补）

控制台「打开应用 / 带平台身份打开应用」不再裸跳转 `attrs.url`：登录用户先向平台领取一次性入场票据，
再以 `<url>#entry_ticket=<票据>` 打开应用；应用前端读取 fragment 后回平台兑换平台身份：

```
POST /api/authn/entry-tickets/redeem          （公开端点，无须 Bearer）
body {"ticket":"etk_…"}
→ 200 { refType:"app", refId:"<应用ID>", identity:{ sub, username, name, org, roles, tenant } }
```

- 适合**未做 OIDC 接入**的应用/交互界面零改造获得平台身份；已按本指南接入的应用不受影响，两种通道并存。
- 票据一次性（重放被拒）、默认 120s 过期（`ENTRY_TICKET_TTL_SECONDS` 可调 30~600）、兑换时实时校验账号状态；
  签发与兑换均入审计（`app.entry.ticket.*`）。
- 与标准授权码流的分工：需要**长期令牌/refresh/标准 RP 语义**走 `/oauth/authorize`（授权码 + PKCE S256）；
  只需要**单次进入时的用户身份**用 entry-ticket（无 secret、无换牌，应用后端可后置接入）。
- **报错回跳**：授权失败一律 302 平台错误页（`/#/oauth/error`），不会重定向到外部地址（防开放重定向）；拒绝授权（`consent=false`）会按标准以 `error=access_denied` 回跳。

## 十、全员名册（组织数据通道，服务端到服务端）

应用要做「全员填报」类业务时，需要一份在职员工名册来铺排任务（给谁发填报、谁是部门汇总人）。
平台提供受权限保护的名册端点，应用后端以**机器凭证**拉取（与 §二 的用户登录 OIDC 通道互补：
登录解决「单个人是谁」，名册解决「全部人有谁」）：

```
GET /api/iam/roster          （Bearer 机器凭证令牌，须含 iam.roster.read 权限点）
→ 200 {
  generatedAt: "…",
  orgs:  [{ id, name, parentId, status, leaderUserIds: ["<平台用户ID>"] }],   // leaderUserIds 来自钉钉 dept_manager_userid_list 同步链
  users: [{ id, username, displayName, email, jobNumber, title,
            orgId, orgName, primaryOrgId?, status, accountType? }]
}
```

**接入三步**：

1. **拿机器凭证**：应用注册时自动签发（`refType:'app'`）；管理员在「统一认证中心 → 身份主体」为该凭证
   追加 scope `iam.roster.read`（调整 scopes 会联动吊销存量令牌，换牌后生效）。
2. **换牌**：`POST /api/auth/client-credentials`，body `{clientId, clientSecret}` → `token`（Bearer）。
3. **拉取**：`GET /api/iam/roster`。建议按填报周期拉取（组织变动经连接器定时自动同步进平台，
   见 README「连接器定时自动同步」），勿高频轮询。

**契约要点**：

- `users[].id` 即 userinfo 的 `sub`——**同一稳定关联键**，名册铺的任务与登录回流的身份直接对上；
- `orgs[].leaderUserIds` 给出各部门负责人（钉钉「部门负责人」字段同步），应用可直接识别汇总/审批人，无需自建名单；
- PII 最小化：不含手机号；已注销（deactivated）账号不出现在名册；`status` 字段照常返回，应用应只对 `active` 账号铺任务；
- 每次拉取记 invoke 审计（谁在何时拉了多少），越权访问 403 并触发 `audit.authz.denied`。

> 与 OIDC 的分工记忆：**登录用人（§一~九）管"一个人来"，名册（本节）管"全部人有"**；
> 两者都以用户 `id`/`sub` 为唯一关联键，应用内建一张 `sub → 业务角色` 映射表即可把两条通道拼起来。

## 十一、访客指标自动折算（平台侧）与 beacon 埋点（应用侧）

平台侧已把「SSO 身份到访」与「页面浏览」自动折算进应用指标，接入方**不做任何事也能得到 DAU**；
做一行 beacon 埋点可再得到 PV/UV。

### 平台侧自动折算（零改造）

| 到访行为 | 折算 | 口径 |
|----------|------|------|
| entry-ticket 兑换（§九） | DAU +1 | 按平台 `sub` 同日去重 |
| OIDC 发码（授权页确认，§一~二） | DAU +1 | 按平台 `sub` 同日去重 |
| 浏览器 beacon（下述） | PV +1 / UV +1 | PV 逐次累加；UV 按 `vid` 同日去重 |

同日多次到访集合只增不减，经 `recordUsage` 的 max/累加语义与接入方主动上报
（`POST /api/apps/:id/metrics-report`）自然合并，互不覆盖。

### 应用侧 beacon（一行埋点，免机器鉴权、免 secret）

页面加载/SPA 路由切换时上报一次即可（`<appId>` 为应用 ID，即 `app_` 前缀资源 ID）：

```html
<!-- 方式一：<img> 像素（最简，天然跨域） -->
<img src="http://<平台地址>/api/apps/beacon?app=<appId>&vid=<访客ID>" hidden alt="">
```

```js
// 方式二：fetch / sendBeacon（POST JSON；vid 缺省时平台按 IP+UA 哈希兜底）
const vid = localStorage['rq:vid'] ??= crypto.randomUUID().replace(/-/g, '') // 8-64 位 base64url
navigator.sendBeacon?.('/api/apps/beacon',
  new Blob([JSON.stringify({ app: '<appId>', vid })], { type: 'application/json' }))
```

- 端点公开（PUBLIC_PATHS），返回恒为 1x1 GIF / `{ok:true}`——未知应用同样响应，不泄露应用存在性；
- `vid`：8-64 位 base64url 字符串，建议 `localStorage` 持久随机 ID（同一浏览器同日只计一次 UV）；
- 可选 `uid`：应用已知平台身份（如 entry-ticket 兑换到的 `sub`）时携带，帮助 UV/DAU 口径对齐；
- 防滥用：同 IP 同应用 60 次/分钟内计数，超限静默忽略（响应照常，不影响页面）；
- CORS：`*` 放行（GET/POST/OPTIONS），任意 entryUrl 的前端均可直报。
