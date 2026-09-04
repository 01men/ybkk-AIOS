# 榕器 · 企业AI资源管理平台

基于 **DeepSeek Harness（dsh）「一切皆插件」** 架构实现的企业级 AI 资源管理平台。
对应设计方案：《企业服务资源统一管理方案 V1.0》与《技术实现规划》；生态平台演进设计见
[docs/ecosystem-design-v1.2.md](docs/ecosystem-design-v1.2.md)，后续路线见 [docs/roadmap-9-10.md](docs/roadmap-9-10.md)。

> 组织账号（IAM）· 统一认证（Authn + OIDC Provider）· MCP 部署服务 · Skill/插件市场 · Agent 本体 ·
> AI 应用本体 · 计量计费（usage）· 钱包与复式分账（billing）· 模型转售网关（modelgw）· 审计与告警
> ——多类资源，一套身份、一套权限、一套计量、一套审计。

---

## 一、快速开始

```bash
npm install          # 安装依赖（@deepseek-ai/cordis）
npm start            # 启动平台（默认 http://127.0.0.1:7300）
```

打开 **http://127.0.0.1:7300** 进入管理控制台。首次启动在空数据目录上执行**基线初始化**（生产形态）：
内置角色 + 根组织 + 平台管理员 `admin`（无任何演示业务数据）。

- `admin` 口令取 `ADMIN_PASSWORD` 环境变量；未设置则随机生成，一次性写入 `data/admin-initial-password.txt` 并打印在启动日志（请立即登录并妥善保管）。
- 忘记口令：清空数据目录重启，或由持有 `iam.user.write` 的管理员在「组织与账号 → 账号详情 → 重置口令」重置。

**演示模式**（评估/培训，自动生成完整演示数据与演示账号，口令均为 `Ybk@2026`）：

```bash
DEMO_SEED=1 npm start   # 首次启动注入演示数据（组织树/演示账号/MCP/Skill/Agent/应用/28 天历史）
```

| 演示账号 | 角色 | 用途 |
|---|---|---|
| `admin` | 平台超级管理员 | 全功能 |
| `ops` | 资源管理员 | MCP/Skill/Agent/应用管理 |
| `hr` | 组织管理员 | 组织/账号/三方同步 |
| `dev` | 开发者 | 提交 Skill、注册 Agent |
| `audit` | 审计员（只读） | 审计与告警 |

演示模式下钉钉免密登录可用（mock 连接器）：登录页「钉钉扫码」输入工号 `DD0002`（林小满）；生产基线不配置连接器，三方登录入口自动隐藏。

```bash
npm run selftest      # 功能自测：隔离实例（DEMO_SEED）700 项端到端断言
npm run lint:manifests  # 插件清单五面 YAML 校验（75 项）
DSHCTL_USER=admin DSHCTL_PASS=*** node cli/dshctl.mjs help    # CLI 帮助（凭据经环境变量或 DSHCTL_TOKEN 提供）
```

### 平台自更新（v1.1+）

两类安装形态（GitHub 源码检出 / dsh 插件市场安装）都能感知上游仓库新版本，**是否升级永远由管理员决定**：

- **自动检查**：默认每 24h 一次（启动 15s 后首查），比对远端 `package.json` 版本 + GitHub compare 提交差；
  发现新版本 → 控制台顶栏「可更新」徽标 + `platform.update.available` 事件（audit 留痕）。控制台抽屉可开关/调频。
- **手动升级**：控制台顶栏徽标 → 抽屉「一键升级」（source 形态：`git pull --ff-only` + `npm install`，支持
  dry-run 预演、原因留痕、完成后提示重启）；CLI：`dshctl update status | check | apply [--dry-run]`；
  Agent 工具：`update_status` / `update_check` / `update_apply`。bundle 形态给出 `dsh plugin update` 指引。
- **内网/限流**：`GITHUB_TOKEN` 提升限额；`DSH_UPDATE_API_BASE` / `DSH_UPDATE_RAW_BASE` 指向私有镜像；
  `DSH_UPDATE_AUTO_CHECK=off` 关闭自动检查。权限点：`platform.update.read`（查看/检查）、`platform.update.apply`（升级）。

> **企业部署 / Agent 一键接入**：部署 runbook、dsh 运行时接入与「可直接下达给 dsh 自带 Agent 的一键部署指引」
> 见 [docs/deploy-enterprise.md](docs/deploy-enterprise.md)；日常运维 Agent 指引见 `skills/dsh-ops-admin/SKILL.md`。

## 二、架构：一切皆插件

运行中的平台就是一棵 **cordis 插件树**（与 dsh 同一插件框架，`@deepseek-ai/cordis`）。
每个业务域 = 一个插件包，独立声明依赖/权限点/事件，可独立启停：

```
接入层   dsh-plugin-console        REST 网关 + 控制台 SPA + 工具桥 + 种子数据
业务域   dsh-plugin-iam            组织/账号/角色/用户组/三方连接器（钉钉演示）
         dsh-plugin-authn          双轨身份 + 令牌 + on-behalf-of 链
         dsh-plugin-mcp            部署/灰度/回滚/健康熔断/权限组/调用网关/监控（真实 HTTP 传输层）
         dsh-plugin-skillhub       提交→静态扫描→两级审批→版本化上架
         dsh-plugin-agent          Agent 本体（resource-core 底座 + 机器凭证）
         dsh-plugin-app            AI 应用（编排拓扑 + 应用指标 + 成本穿透）
         dsh-plugin-usage          计量管道（schema v1 / 幂等 / 死信重放 / 价格簿 / 三方对账 / 能力漂移）
         dsh-plugin-billing        钱包 + 只追加流水 + 复式分账 ledger（结转/试算平衡/红字冲正）
         dsh-plugin-modelgw        模型转售网关（OpenAI 兼容真实转发 / 预检 / 实测 tokens 计量）
         dsh-plugin-market         第三方与自营插件市场（契约五面 / Ed25519 验签 / L0 运行时 / 订阅代收）
         dsh-plugin-audit          四类审计日志 + 告警规则 + 成本归集 + 审批中心
         dsh-plugin-connect        远程 dsh 接入（宿主角色：接入码/enroll/客户端管理；客户端角色：凭证申请 + 工具远程代理 + 本机配置页）
         dsh-plugin-update         平台自更新：上游版本检查（自动+手动）→ 通知 → source 形态一键升级（git pull + npm install，dry-run/审计/权限点）
         dsh-plugin-portal         门户数据通道（外部拉取端点·非核心：企业门户免鉴权只读拉取已上线应用/Agent/技能，CORS + 可见性留痕，PORTAL_SYNC=off 可停用，见 docs/portal-integration.md）
底座     dsh-plugin-resource-core  资源本体：属性 schema + 生命周期状态机 + 依赖图
基础层   dsh-plugin-platform-core  存储(JSON集合/原子落盘) + SQLite 事务存储 + YAML 解析 + 事件总线 + ToolRuntime-lite + HTTP
```

**插件协作铁律**：状态变更必发事件；跨插件联动只通过事件总线或扩展点（`ctx.platformBus`），
禁止直连对方数据。例：`iam.user.frozen → authn 吊销全部令牌`、`agent.offlined → 凭证吊销 + 绑定用户通知`、
`skill.deprecated → 引用 Agent 告警`、`mcp.unhealthy → 熔断 + 审计`。

### 一份插件代码，两种宿主

- **独立宿主**（本项目默认）：`node src/main.ts` 启动完整平台（控制台 + API + 工具）。
- **完整 dsh 运行时**：`cordis.yml` 把同一批插件挂载进 `dsh web`——此时平台注册的
  **运维工具**直接进入 dsh 原生 ToolRuntime、对模型可见可调用（`provideToolRuntime: false`），
  Agent 即可按自然语言运维整个平台（「列出所有 MCP 服务和健康状态」→ `mcp_service_list`，
  「Skill 市场里能装什么」→ `skill_search`）。

**源码检出模式（本地开发）**——两条硬性要求，缺一不可：

1. `cordis.yml` 中 `<PROJECT_ROOT>` 必须替换为 `file:///` URL 形式的绝对路径
   （Windows 下裸盘符路径会被 ESM 判为 `ERR_UNSUPPORTED_ESM_URL_SCHEME`）；
2. 本项目 `node_modules/@deepseek-ai/cordis` 必须指向 dsh 源码树的 `vendor/cordis`
   （junction），保证插件与宿主加载**同一个 cordis 实例**——两份实例会导致
   `ctx.plugin(类插件)` 静默失效、服务链（iam→usage→audit…）全部 `pending`：

```powershell
# 一次性设置（PowerShell，替换两处路径为你的实际检出位置）：
Remove-Item -Recurse -Force node_modules/@deepseek-ai/cordis
New-Item -ItemType Junction -Path node_modules/@deepseek-ai/cordis -Target D:\dsh-harness\vendor\cordis

# 之后每次（在 deepseek-harness 源码检出中）：
pnpm dsh web --patch <本项目绝对路径>/cordis.yml
```

**安装模式（发布使用）**——`dsh plugin add` 走 pnpm 安装，补丁里的 entry 以
「包名 + 子路径」声明（Node 从 profile 目录沿 node_modules 解析，无需感知安装位置）：

```bash
dsh plugin --profile web add github:01men/ybkk-AIOS
# 验证：dsh --profile web --dump-config 应列出全部 ops-* entry；
# 会话中问「列出所有 MCP 服务和健康状态」，模型应调用 mcp_service_list 而非静态作答。
```

安装模式的关键约束：`@deepseek-ai/cordis` 只在 `devDependencies`（本地开发/独立宿主用），
**绝不能进 `dependencies`**——否则 pnpm 会把它 hoist 进 profile 的 node_modules，
插件解析到第二份 cordis 实例，服务链整体失效（同上）。安装后插件沿
`<profile>/node_modules → $DSH_HOME/profiles/node_modules`（dsh 自建的宿主闭包 symlink）
解析到宿主自己的 cordis。

**平台服务键已做宿主去冲突**：JSON 存储服务键为 `opsStorage`（不是 `storage`——
dsh 宿主自带同名 `storage` 服务，曾导致 iam 等插件构造时拿到宿主服务、方法不存在而崩溃）。
`tools` 键是**刻意共享**的接缝：独立宿主下由 ToolRuntimeLite 提供，dsh 下即原生
ToolRuntime——37 个运维工具由此进入 dsh。

**领域 Skill 手册**（`skills/dsh-ops-*/SKILL.md`）默认不随插件自动进入 dsh 技能系统
（dsh 只扫描 `<project>/.dsh/skills`、`~/.dsh/skills` 等根目录）。要让 Agent 获得
分领域操作手册，复制或链接一份：

```bash
# 用户级（所有会话可用）：
cp -r skills/dsh-ops-* ~/.dsh/skills/
# 或项目级（仅当前项目）：
mkdir -p .dsh/skills && cp -r skills/dsh-ops-* .dsh/skills/
```

### 远程 dsh 接入（第三种形态：免源码、免同机共享 data）

其他电脑经插件市场安装本平台后（安装模式见上），无需源码检出、也无需与宿主共享
`data/` 目录——插件树中的 `plugin-connect` 以 **client 角色**运行，向宿主平台申请
机器凭证并把全部运维工具的执行**远程代理**到宿主（权限按模板收敛、全程审计）：

```text
宿主侧（管理员，一次性）            远程电脑（使用者，两条通道任选）
────────────────────────          ─────────────────────────────────
控制台「平台接入」页创建接入码   →   ① dsh 界面对 Agent 说：
（一次性，默认 15 分钟有效，           「接入宿主 http://宿主IP:7300，
 模板：readonly/operator/full）        接入码 enr_xxx…」
                                   Agent 调 connect_setup 自动申请口令
                                   ② 浏览器打开 http://127.0.0.1:7390
                                      本机配置页可视化填写/更新/断开
```

接入成功后：远程 dsh 里的 37 个运维工具自动切换为**转发宿主执行**（本地不再持有数据），
另新增 `connect_status / connect_setup / connect_login / connect_test / connect_reset`
5 个接入工具供 Agent 自助管理；客户端接入后默认每 5 分钟向 `POST /api/connect/heartbeat`
**主动推送心跳**（存活 + 工具数/运行版本/uptime 元信息，`heartbeatIntervalMinutes=0` 可关闭），
宿主控制台「平台接入」页可查看已接入客户端、最近使用与最近心跳，
并可随时禁用（联动吊销全部机器令牌，立即生效）。宿主侧另有 4 个接入管理工具
（`connect_code_create / connect_codes / connect_clients / connect_client_disable`）。

安全基线：接入码只存哈希（创建时一次性展示）、一次性消费、TTL 可配、按来源 IP
接入宿主既有失败锁定（15 分钟窗口 5 次锁定）；机器凭证等价口令仅保存在远程电脑本机
（0600）；`enroll` 端点公开但接入码本身即凭证。

详细流程与验收清单见 [docs/deploy-enterprise.md](docs/deploy-enterprise.md) 第四节。

### 已融合 OS-skill 模块设计（v1.1）

选择性吸收了 [01men/OS-skill](https://github.com/01men/OS-skill) 两个模块中具有长远价值的设计（决策全记录见 [docs/roadmap.md](docs/roadmap.md)）：

- **IdentityProviderAdapter 统一身份源抽象**（auth-identity docs/03）：三方登录主流程面向接口编程，钉钉/飞书/企微差异收敛在 Adapter 内
- **引擎级唯一约束**（红线工程化）：`collection.uniqueOn()` 模拟数据库部分唯一索引，「一人一号」等业务唯一性由存储引擎兜底，取代「先查后插」
- **refresh_token 轮转链 + sid 会话**（docs/06）：access 30min + refresh 7d 仅存哈希、单次轮转，重放即整链吊销；前端 401 静默续期
- **state 防 CSRF + code 一次性消费 + 未命中绑定/注册分支**（docs/04/05/07）：完整的三方登录产品化流程
- 自测含安全攻击演练（state/code/refresh 重放、唯一约束冲突），详见 `npm run selftest`

## 三A、生态平台 v1.2 交付（第 0–8 步，本迭代）

在 v1.0 基础上完成生态化演进（实施依据 [docs/ecosystem-design-v1.2.md](docs/ecosystem-design-v1.2.md)）：

- **执行层/连接器真实化（第 0 步）**：MCP 真实 HTTP JSON-RPC 传输层（探活/超时/错误路径/实测 tokens）、
  钉钉真实 OpenAPI 连接器（corp token → 部门 BFS → 成员分页）、SQLite 事务存储（WAL/幂等唯一索引/只追加表）。
- **令牌收紧（第 1 步）**：`aud` 受众校验 + 插件 scope 命名空间强制（唯一收敛面）。
- **多租户最小集 + 计量管道（第 2/4 步）**：租户建模、schema v1 计量事件、先写后发、引擎级幂等、
  死信重放、价格簿（计价时点费率快照）、三方对账、运行时能力漂移检测。
- **契约五面 + L0 市场（第 3/7 步）**：第三方开发者身份域、契约五面 Ed25519 验签、内容扫描、
  L1 门禁、审批上架/安装/卸载、L0 提示词运行时与计量、自营首批供给与订阅代收登记。
- **钱包与模型网关（第 5 步）**：余额+流水同事务、乐观锁、幂等键、月度预算预检、余额恒等式全量重放；
  模型转售网关真实 OpenAI 兼容转发（无 endpoint 拒绝调用，不造假 completion）。
- **OIDC Provider（第 6 步）**：RS256/JWKS/discovery/authorize（一次性 code）/token/id_token/userinfo，
  账号冻结令牌即时失效。
- **复式分账 ledger（第 8 步）**：账期汇总结转（费率版本快照、尾差归平台）、试算平衡、红字冲正、开发者应收。
- **资金红线（v1.2 §六过渡）**：对公收款/开票/开发者付款通道未就位——充值仅管理员手工录入（幂等键=转账单号），
  订阅代收为 manual-settlement 登记，平台不自动扣外部资金。
- 验收：`npm run selftest` **244/244**、`npm run lint:manifests` **60/60**；KBaaS/连接器市场/合规门户与
  L1 有码沙箱为下一迭代（设计见 [docs/roadmap-9-10.md](docs/roadmap-9-10.md)）。

## 三B、评审缺陷修复与资产运营（本迭代，v1.3）

针对外部技术评审（严重 S1–S4 / 中等 M1–M5 / 轻微 L1–L4）逐项整改：

- **S1 账期结算硬缺陷**：`settle()` 改 keyset 分页全量归集（不再单页 limit:1000 截断），
  归集条数与 SQL COUNT 对账不符即拒绝结转；同一账期二次红字冲正被拒；钱包幂等键绑定主体（同键异主体拒绝）。
- **S2 密钥轮换宽限期**：轮换不再立即吊销全部令牌——旧密钥进入 24h 验签宽限期，在途请求不掉线，
  refresh 随时换取新密钥令牌，全局无感轮换。
- **S3 暴力破解防护**：登录 / Client Credentials / SSO 绑定 / OIDC 授权与换牌全部接入失败锁定
  （15 分钟窗口 5 次失败锁定，时长逐次升级至 24h，持久化防重启绕过，触发即告警）。
- **崩溃恢复**：认证类集合（令牌/主体/锁定计数）即时落盘并 fsync，登出/吊销返回 200 后被杀不丢失；
  坏 JSON 集合文件自动备份为 `*.corrupt-*` 并显式告警，不再静默当空集合。
- **计量消费幂等（重放不双计）**：引擎级消费水位（usage_consumptions 唯一索引）——replay/死信重投
  对 billing/audit 投影零重复副作用；消费失败真实即时重试 3 次后入死信，支持一键重投。
- **OIDC 收敛**：scope 白名单（openid/profile/email）、PKCE S256 全链路、JWT 校验 iss/aud/kid；
  issuer 支持 `OIDC_ISSUER` 环境变量对外声明。
- **MCP 熔断业务化**：真实调用失败与探活失败共用连续失败计数（连续 3 次开熔断，业务成功即半闭合）；
  回滚目标版本校验（当前版本/已回滚版本不可作为目标）。
- **多租户隔离补全（M1）**：钱包流水查询支持 tenant_id 过滤；审计/计量口径一致。
- **M2 撤销列表收敛**：吊销状态全量走持久化令牌记录（去掉进程内无限增长集合），
  过期令牌 7 天后物理清理（启动 + 每日巡检）；refresh 哈希索引化查询。
- **企业 AI 资产运营（新）**：`资产运营` 控制台页 + REST——统一台账（MCP/Agent/应用/Skill/模型路由
  五类资产一处盘点，含归属组织、负责人、健康、近 N 天调用与消耗）、一键健康巡检（批量探活留审计）、
  成本报表（Top 资产 / 主体分摊 / 日趋势，计量口径）、效益分析（毛利=列表价收入−采购成本、
  单位 DAU 成本）与下架分析（弃用/下线原因聚合）。
- **商业化放缓（决策）**：真实支付网关/对公收款/开票/开发者付款等资金通道**保持手工过渡态暂缓实施**，
  插件市场变现（订阅代收/分账结算自动化）同样暂缓——本迭代优先企业内资产治理与运营能力。

## 三C、应用统一身份接入 App SSO（本迭代，v1.4）

企业内自研 AI 应用上线前完成身份纳管——「注册应用 → 签发 SSO 凭据 → 上线门禁 → 跳转登录」闭环
（设计：[docs/dev-plan-app-sso.md](docs/dev-plan-app-sso.md) · 执行版：[docs/app-sso-实施计划-执行版.md](docs/app-sso-实施计划-执行版.md) · 接入文档：[docs/app-sso-integration.md](docs/app-sso-integration.md)）：

- **浏览器授权流（协议合规面）**：`GET /oauth/authorize` 校验（response_type/client/redirect_uri 白名单/scope
  白名单/强制 PKCE S256）→ 落授权请求（5 分钟单次消费）→ 302 平台授权页 `/#/oauth/authorize?req=`；
  失败一律 302 平台错误页（绝不携带外部 redirect_uri，防开放重定向）；`POST /api/authn/oidc/authorize`
  用户确认（human-only，consent 卡片）→ code/state/iss（RFC 9207）回跳。
  **旧账密式 `POST /oauth/authorize` 已删除**。
- **授权页登录面板支持钉钉免密**：无平台会话的授权页内嵌登录面板提供「账号密码 / 钉钉扫码」双入口
  （钉钉入口按 `/api/auth/providers` 连接器配置显隐）——钉钉用户在授权页内即可完成免密登录
  （首次身份走绑定/注册分支），无需预登录控制台，随后直接进入授权确认，全程闭环在 SSO 流内。
- **换牌协议面**：`client_secret_basic` + `client_secret_post` 双认证 × form/JSON 双编码；错误码状态码
  归位（invalid_grant→400、invalid_client→401+WWW-Authenticate）；access/id token 打标 `token_use`；
  userinfo 校验 token 类型与 aud 受众，email claim 按 scope 裁剪；JWKS 数组化（kid 匹配验签）。
- **应用 ↔ SSO 打通**：应用详情「SSO 配置」tab——owner 签发（secret 一次性）、回调行内编辑、轮换、
  禁用/启用、discovery 一键复制；`GET /api/apps/:id` 附 `sso` 块。「认证与令牌」新增 OIDC 客户端全局
  管理面。**owner-based 授权为全库首例**（human 且 `app.ownerId === userId`，或持 `authn.oidc.write`；
  机器一律 403）。
- **上线门禁双点**：`requestOnline()` 早反馈（`APP_SSO_ENFORCE` 默认 `web,h5` 形态须有 active 客户端，
  审批单快照 `ssoClientId`）+ `app.online` 审批执行器执行期复核（挂单期间禁用 → 上线失败留痕）。
- **生命周期联动**：`app.offlined`/`app.archived` → 客户端禁用（refresh 链吊销）；`app.onlined` → 启用；
  `app.updated` → 客户端名称同步（plugin-app 补发历史缺失事件）。
- **会话补全与安全闭环（P3）**：refresh_token 轮转 grant（一次一换、重放整链吊销、scope 只收窄、
  实时校验用户状态）；`/oauth/end_session`（id_token_hint 定位 client + postLogoutUris 白名单 + 登出即
  吊销 refresh 链）；`/oauth/revoke`（RFC 7009，access jti 黑名单 / refresh 整链，恒 200）；JWKS 密钥
  轮换端点（新 key 签名、旧 key 24h 宽限验签）；冻结/禁用客户端全链即时失效。
- **public 客户端（D-a 决策）**：纯前端 SPA 可签发 public 形态（免 secret + 强制 PKCE + 不发 refresh），
  BFF 架构仍为 confidential 推荐形态（文档双指引）。
- **双 TTL**：OIDC access 默认 2h（`OIDC_ACCESS_TTL_SECONDS`）/ refresh 默认 7d（`OIDC_REFRESH_TTL_SECONDS`），
  与平台会话（30min/7d）独立可调；授权码与授权请求 5 分钟单次消费。
- **「平台接入」外部接入总览**：机器凭证（按绑定资源分组）+ OIDC 客户端（含关联应用）+ 远程 dsh
  客户端一处盘点，跳转对应管理页。
- **应用指标主动上报（接入即监测）**：外部应用可向宿主推送产品指标——`POST /api/apps/:id/metrics-report`
  （`app.write`）/ `app_metrics_report` 工具 / CLI `app report` 三端同契约（**PV/UV/DAU/会话/会话深度/7 日留存**，
  同日 PV 累加、UV/DAU 取最大，可指定 `date` 补录历史）；计量事件推送走 `POST /api/usage/record`
  （`usage.write`，schema v1 + 幂等键，CLI `usage record`，resource 支持 `mcp:<slug>` / `skill:<id>` /
  `nas:<id>` / `model:<slug>` / `plugin:<id>`；meter key 须与价格簿一致——mcp:* 用 tokens、model:* 用
  output_tokens，不符硬拒绝且报错直接给出期望键），宿主侧据此外部应用全生命周期监测。
- **一行 SDK 式接入验证**：selftest 内置 openid-client（v6）冒烟——discovery 驱动走通 authorize →
  token → userinfo → refresh → revoke → end_session 全链（标准客户端真实姿势回归）。

## 三D、NAS 资产纳管 + Skill 包 NAS 存储 + 平台三端调用（本迭代，v1.5）

NAS 成为第六类受管资产（FS 文件存储类），Skill 上架产物可直传 NAS，平台能力对 CLI / REST / MCP 三端同构开放
（设计与可行性结论：[docs/dev-plan-nas.md](docs/dev-plan-nas.md)）：

- **plugin-nas（resource-core Pattern A）**：以 synology-filestation-mcp 这类「MCP 文件网关」为访问通道——
  平台持有网关地址 + Bearer 令牌 + `X-NAS-IP` 设备路由头，全部文件操作经网关 `tools/call` 完成
  （fs_list/fs_upload/fs_delete/fs_search 等），不直连 DSM 私有 API。属性表三组（基本/接入/治理）、
  生命周期 `draft → online → offline → archived`（上线前 initialize 探活护栏）、健康巡检接入资产运营、
  写类操作审计留痕、令牌回显脱敏。
- **mcpServers JSON 一键纳管**：`POST /api/nas/import`（CLI `nas import` / 控制台导入弹窗）直接吃
  synology-filestation 形态的 mcpServers 配置 → 创建资产 → 探活 → 上线 → 工具发现。
- **Skill 包 NAS 存储**：`GET/PUT /api/skill-storage`（`skill.storage.write`）配置包后端
  `local | nas`（引用已纳管 NAS 资产 + basePath，凭证不重复配置）。上架时：提交携带的
  `packageBase64`（CLI `skill submit --package=<zip>` / 控制台附件）原样上传；无包时由
  platform-core 零依赖 ZIP 打包器（`zip.ts`，deflate + CRC32）从 SKILL.md 现场打包 →
  平台 staging → 网关 `fs_upload` → 版本记录回写 `package { storage, nasId, path, sizeBytes }`。
  **fail-closed**：上传失败即上架失败。**部署约束**：`fs_upload` 在网关进程侧读本地路径，
  平台与网关需同机或共享卷（资产 `stagingDir` 可配共享挂载点）。
- **平台即 MCP Server**：`POST /mcp`（Streamable HTTP 纯 JSON 形态）——initialize（会话头 +
  serverInfo）/ tools/list（全部运维工具 40+）/ tools/call / ping；复用平台 Bearer 令牌与
  工具级权限点（含身份注入防参数伪造），ZCode / Claude / Cursor 等任意 MCP 客户端可直接纳管平台。
- **三端同构**：`nas_*` 八个工具对 dsh 插件 / REST 工具桥 / `/mcp` 端点同一契约；CLI 新增
  `nas` 命令组（list/get/create/import/health/online/offline/shares/files/mkdir/delete/upload/search）
  与 `skill storage get|set`；控制台新增「NAS 存储」页（列表/详情/文件浏览器/导入），
  资产台账与一键巡检覆盖 nas 类型。

## 三E、观测与分析补齐：Skill/NAS 计量 + PV/UV + 效益分析 + 技能热力图 + 下架分析（本迭代）

围绕「接入后自主提报 + 宿主自动监测」与「分析看板」两条主线补齐观测口径：

- **Skill/NAS 进计量管道**：skill 下载/安装、nas 全部文件操作（读写在 `fsCall` 单点埋点）自动产生
  usage 事件（`skill:<ID>` / `nas:<ID>`，calls/bytes 口径）；价格簿逐条幂等播种 `skill:*` / `nas:*`
  零费率默认规则（观测先行，是否计费由运营调价决定，存量部署升级自动补齐）。
  跨机部署与中文 slug 兼容：skill 资源键用资产 ID（中文名 slug 含非 ASCII，过不了 resource 校验）。
- **应用指标 PV/UV 口径**：`metrics-report` / `app_metrics_report` / `app report` 三端新增 `--pv/--uv`
  （同日 PV 累加、UV 取最大，与 DAU 同语义）；应用详情指标页展示 PV 柱图与 UV/DAU 双线。
- **访客指标平台侧自动折算（指标口径补全）**：entry-ticket 兑换 / OIDC 发码经事件总线自动折算应用
  **DAU**（按平台 `sub` 同日去重），零改造即有数据；新增**公开访客埋点 beacon** `GET/POST /api/apps/beacon`
  （`?app=&vid=&uid=`，1x1 GIF / JSON，CORS `*`，未知应用不泄露存在性，IP+应用 60 次/分钟限流）——
  应用一行埋点即得 **PV/UV**（PV 逐次累加、UV 按 `vid` 同日去重），与主动上报经 max/累加语义自然合并
  （详见 [docs/app-sso-integration.md §十一](docs/app-sso-integration.md)）。
- **效益分析**：`GET /api/assets/benefit`——按资产聚合 列表价收入/采购成本/**毛利**，应用类资产关联
  窗口 DAU 派生**单位 DAU 成本**（指标×成本首次打通）；「资产运营」页新增效益表 + 主体分摊
  （谁在花钱，byPrincipal 前端首次渲染）。
- **技能热力图**：`GET /api/skills/usage-heatmap`——skill × 日使用矩阵（usage 事件为主、计量接入前的
  下载流水按日回填去重）；Skill 市场页顶部热力图卡片（色深=当日使用次数）。
- **下架分析闭环**：skill 弃用/MCP 下线 REST 层原因必填（与服务层 Agent/App 护栏对齐）；Skill 弃用原因
  落库持久化（详情抽屉可见）；`GET /api/assets/retire-reasons` 聚合 弃用/下线 原因（审计 change 日志 +
  生命周期留痕 + Skill 落库原因三源合一、去重），「资产运营」页新增下架分析卡片。
- 验收：`npm run selftest` **405/405**（新增 10 项：skill/nas 计量入账与外部上报放行、PV/UV 累加语义、
  毛利恒等、热力矩阵、弃用护栏与落库、下架原因聚合）。

## 三F、接入链路四项加固：凭证补权/计量硬校验/凭证治理/机器留痕（本迭代，v1.6）

对外接入提示词（Agent 注册接入 / AI 应用接入）评审发现的四个平台侧缺口逐一封堵：

- **Agent 凭证默认授 `usage.write`**：注册签发的机器凭证 scopes 由
  `['mcp.invoke','skill.read','agent.read']` 扩为含 `usage.write`——Agent 按提示词自推直连消耗的计量
  不再必然 403。存量部署一次性迁移（幂等标记 `agent-scopes-usage-write-v1`，只跑一次防覆盖后续人工
  收权；迁移动作逐条入 change 审计 `agent.credential.scopes-backfill`）。
- **计量键与价格簿不符 → 硬拒绝**：`usage.record` 校验事件必含价格簿 `meter_key`，缺失 400 且错误信息
  直接携带期望键（价格簿对调用方不可见，错误信息是唯一自纠线索）——消灭「静默按 0 计费入库」这一
  比报错更危险的漏计费面。skillhub 内部管道同步对齐（meters 补价格簿计价键 `calls`，downloads/installs
  观测维度保留，热力图口径不变）。
- **机器凭证治理三端齐备**：`PATCH /api/authn/principals/:id`（scopes 调整，须全部命中权限目录或恰为
  `['*']`）+ `POST /api/authn/principals/:id/rotate-secret`（clientId 不变、旧 secret 立即失效、新值仅此
  一次返回）+ enable 端点补齐；**调整/轮换联动吊销全部存量令牌**（令牌 scopes 为签发时快照，不吊销
  则收权不生效）。控制台「认证与令牌」principals 表新增 scopes 列与「编辑权限（按权限目录分组勾选）/
  轮换密钥（一次性展示）」行操作；CLI `credential list | scopes | rotate` + `create --scope` 逗号多值；
  工具 `authn_credential_scopes` / `authn_credential_rotate`。凭证丢失/泄露的补救从「重新注册 Agent」
  变为「管理员一键轮换」。`GET /api/authn/principals` 与治理响应一律剔除 `clientSecretHash`。
- **机器身份读台账入审计（`agent.verify`）**：机器令牌调 `GET /api/agents`（list 与 get）在审计留痕
  （auth 类、含 act 链）——接入提示词「发一句话即接入验证且平台留痕」成为事实；人类控制台读操作
  不记录（噪音控制）。
- 验收：`npm run selftest` **445/445**（新增 19 项：凭证默认含 usage.write 与机器令牌自推计量、
  计量键不符拒绝/匹配路径计价不变/skill 事件含计价键、scopes 调整联动吊销/拼错与 `*` 混用拒绝/
  轮换旧值即废/列表 hash 脱敏、机器读台账留痕与人类噪音控制）。

## 三G、连接器纳管：open-connector 融合（本迭代）

SaaS 数据面网关（roadmap 第 9 步之二「连接器市场」执行缺口）：榕器=治理控制面，open-connector v1.4.0 sidecar=数据面 + 凭证保险库（AES-256-GCM）。能力零重叠强互补——不自研 provider 目录（1,000+ Provider / 10,000+ Action）、不自研 OAuth、不自研密钥库。

- **新插件 `packages/plugin-connector`**：OcClient 版本锁定适配层（契约面单文件）+ ConnectorHubService。六个集合 `connector:gateway|connections|catalog|permGroups|tokens|runs`；强制 env fail-closed（`OOMOL_CONNECT_ENCRYPTION_KEY`/`OOMOL_CONNECT_ADMIN_TOKEN` 缺失即拒绝一切 invoke 并告警）；30s 探活熔断。
- **三层调用同契约**：REST `/api/connector/*` guarded 路由段 + 5 个工具 `connector_catalog_search/connector_connection_list/connector_execute/connector_perm_group_list/connector_run_list`（REST 工具桥与 POST /mcp 自动暴露）+ CLI `dshctl connector …` 全树。
- **双层授权镜像**：连接器权限组（pattern/riskCap/readOnly/**denyParams 强制拦截**）↔ 每组一枚 oct_ 运行时令牌（策略快照 PUT 四数组全发；org 巡检保证「令牌绑定连接 ⊆ 组内 org 连接」）；401/connection_not_allowed 自动恢复重试一次。
- **连接三形态**：OAuth 代理全流程（自备 App 护栏 `oauth_client_config_required` 带向导指引）/ API Key 表单**过手不落盘**（回显脱敏 slice(0,6)+'…'）/ no_auth 虚拟登记；别名强制 `org:<orgId>:` 前缀；删除做权限组引用级联检查。
- **审批双场景**：admin 级 action 出 `connector.action.admin` 单（批准后 executor 自动完成调用，同图 pending 复用）；受控连接两段式 `connector.connect`（审批负载零凭证字段，approve 后携 approvalId 提交实际凭证）。
- **计量对账**：`usage.record(resource='connector:<service>', meter=calls, trace_id=meta.executionId, 幂等键=connector:<runId>)`，价格簿 `connector:*` 零费率起步；runs 按 runtimeTokenId 与 usage trace_id 交叉校验，「有 run 无 meter」即绕行 critical 告警；`Idempotency-Key` 写类自动生成（24h 重放窗口）。
- **M0 桥接过渡**：sidecar `/mcp` 经既有 `POST /api/mcp/import` 一键纳管（header `x-bridged-from: open-connector` 打「桥接过渡」徽章）；治理降级语义显式声明（无 action 级授权/连接绑定/令牌镜像），仅用于连通性验证。
- **权限点**：`connector.gateway.write/catalog.read/connection.read/write/invoke/permgroup.write/runs.read/market.publish(M3)`；内置角色迁移幂等补齐（resource_admin `connector.*`、developer catalog+invoke、auditor runs+connection 读）；Agent 机器凭证默认 scopes 补 `connector.invoke`（存量一次性迁移）。
- **控制台 `#/connectors`**：网关设置（env 门禁预演探针可视化）/ 目录浏览（provider 卡片 + action schema & agent.md 预览 & riskLevel 徽章）/ 连接卡片墙 + 三形态向导（OAuth 授权页跳转+状态轮询）/ 权限组管理（JSON 策略编辑器 + 影响面预览「N 令牌/M 连接」+ 只读模板二次确认）/ 运行日志抽屉 + oct_ 台账（永不显示令牌值）/ 对账按钮。
- **红线**：凭证零进平台（selftest 以数据目录全文扫描兜底 T-24）；授权双出验证（绕开平台直连 sidecar 同样被令牌策略拒绝 T-29）；actChain 审计 + 计量对账。
- 文档：部署两拓扑 runbook/OAuth 自备 App/故障排查见 **docs/connector-integration.md**；设计全文与评审修正自查表见 **docs/dev-plan-connector.md**。
- 验收：`npm run selftest` 新增 section 全绿（stub 覆盖 open-connector v1.4.0 全契约面，断言组 T-01~T-25/T-28/T-29 共 26 组）。

## 三H、NAS 数据权限：组织位置 + 角色层级 RBAC（本迭代）

对应开发计划 `dev-plan-nas-authz v1.1`（附件方案 + saas-permission-service 判定语义移植 + 网关强制点收敛）。实施说明全文见 **docs/nas-authz.md**。

- **决策服务 `NasAuthzService`（plugin-nas，服务键 `nasAuthz`）**：判定引擎纯函数化（`src/authz/engine.ts`，无容器/无 IO，selftest 直接单测）——五步判定序：账号特殊规则（外部白名单只读/可疑标记 deny 转人工/挂根 deny/未落班组只读/**兼任子树只读**）→ 显式 deny（尾通配）→ 显式 allow（可过期）→ 角色矩阵 × 作用域边界 → 默认 deny，每步产出 reasons。
- **角色推导零名单**：P/D/T = 组织链负责人（钉钉连接器同步 `dept_manager_userid_list` → `OrgRecord.leaderUserIds`，多负责人 co-leader 全推导），M = 班组成员；C 叠加 = 动态用户组（组重算快照 + cGroupDrift 告警）。作用域映射表 `orgPathOverrides` 优先（组织改名不漂移，R1）+ 每日组织↔目录对账（dirOrphan/leaderVacant 告警）。
- **REST 全套**（`/api/nas/authz/*`）：check/scope/rules/import/exceptions/decisions + 权限点 `nas.authz.check|read|write`；rules `ifVersion` 乐观锁（冲突 409）；share 审批闭环（T/M 申请 → 审批人沿组织链自动路由、resource_admin 兜底 → 通过写 7 天例外 → 到期自动拒绝，全程留痕）；破窗 `override=true` 强制留痕。
- **身份硬约束（P0-2）**：平台调网关一律 `X-On-Behalf-User` 头透传真实用户（优先钉钉 userId），`nas_fs_*` 工具身份改 `exec.principal`（schema 零身份参数，缺失 fail-closed）。
- **强制点改造件（仅产出代码未部署）**：网关 `integrations/synology-filestation-mcp`（AuthzClient：读缓存 300s/写实判 + scope 快照→readonly→deny 三级降级 + 熔断 + on-behalf 防伪，authz-smoke 24/24）；hermes `integrations/hermes-patch`（guard hook 化 + hash 锚点 + 幂等备份 py_compile，--selftest 通过）。DSM 原生权限为粗粒度兜底层（运维配置，零代码）。
- **灰度**：rules 单例 `observeOnly`（缺省 true，G0 双通道同步观察）/`degradeAllToReadonly`（G3）+ 网关 `AUTHZ_ENFORCE` 全局 kill-switch + 逐令牌 enforce；任一阶段秒级回退。
- **控制台 `#/nas-authz`**：灰度开关 / 矩阵（含覆盖项）/ 例外列表（过期倒计时）/ C 关联组 / NAS 锚点映射编辑 / check 试算 / 判定留痕 / 对账与悬空扫描。CLI：`dshctl nas authz check|scope|rules|decisions`。
- 验收：selftest 658/658（新增「NAS 数据权限引擎」与「NAS 数据权限 API」两分节，覆盖 35 格矩阵/兼任/跨分支领导/改名不漂移/审批闭环/C 组漂移/伪造拒绝等 §四 全部用例）；lint:manifests 70/70。

## 三I、连接器定时自动同步 + 全员名册组织数据通道（本迭代，v1.7）

> 面向「企业 AI 应用接入宿主平台」场景（如人事绩效填报：全员工身份纳管 + 组织名册铺任务）：
> 组织同步不再依赖人工点按钮，接入应用有了合规的全员名册拉取通道。

- **连接器定时自动同步（intervalMinutes 落地）**：控制台「同步频率」此前只存不跑——现在 `IamService`
  构造期启动巡检定时器（每分钟 tick，启动 15s 后首跑补同步超期配置），已启用配置按各自
  `intervalMinutes`（下限 5 分钟防误配拖垮钉钉配额；**0=仅手动**）到期即全量同步；
  actor 记 `auto-sync` 与手动区分，单配置失败不阻断其余（失败照常落 `lastSyncResult`）。
  `IAM_CONNECTOR_AUTO_SYNC=off` 一键停用定时器（对齐 PORTAL_SYNC 惯例，可改由外部调度调
  `POST /api/iam/connectors/auto-sync` 手动触发口，`iam.connector.write`）。控制台接入卡片
  同步频率区分「自动/仅手动」，编辑表单提示 0 值语义。
- **全员名册 `GET /api/iam/roster`（组织数据通道，权限点 `iam.roster.read`）**：已接入应用
  （人事/绩效等）以机器凭证一次性拉取在职账号 + 组织树，铺排填报任务与 sub → 业务角色映射。
  契约：users[]（`id`=userinfo 的 sub 稳定关联键/username/displayName/email/jobNumber/title/
  orgId/orgName/primaryOrgId/status/accountType）+ orgs[]（id/name/parentId/status/
  **leaderUserIds**——钉钉 dept_manager_userid_list 同步链，应用可直接识别部门汇总审批人）。
  PII 最小化：不含手机号；已注销账号不出名册；每次拉取记 invoke 审计（谁在何时拉了多少）。
  授权：org_admin 经 `iam.*` 通配自带；应用注册凭证经「统一认证中心」追加 scope 授权。
  接入示例见 docs/app-sso-integration.md §十。
- 验收：selftest 700/700（新增「连接器自动同步与全员名册」分节 16 项：到期判定/0=仅手动不巡检/
  不重复处理/名册契约/负责人链/PII 最小化/401/403/机器凭证拉取/审计留痕）；lint:manifests 75/75。

## 三、目录结构（插件标准解剖）

```
packages/
  platform-core/            基础层插件
  plugin-iam/src/providers.ts  IdentityProviderAdapter 统一身份源抽象
  plugin-<name>/            每个业务插件：
    plugin.yaml             声明：id/version/depends/permissions
    manifest/
      api.yaml              REST + 工具 + 服务键（三端对齐的事实源）
      permissions.yaml      权限点（注册进统一 RBAC）
      events.yaml           发布/订阅事件
      ui.yaml               路由 + 菜单
    src/index.ts            服务 + 插件装配
    src/tools.ts            对模型暴露的工具（dsh ToolRuntime 契约）
  plugin-connect/           远程 dsh 接入插件（宿主端点 + 客户端代理 + 本机配置页，一份代码两种角色）
  plugin-console/public/    控制台 SPA（原生 ES Modules，零构建）
cli/dshctl.mjs              CLI（--output json|table / --dry-run / --yes；含 connect 接入管理）
skills/dsh-ops-*/SKILL.md   8 个运维 Skill（含 dsh-ops-admin 总控索引）
scripts/selftest.mjs        功能自测（445 项断言，含安全攻击演练、App SSO 全链与 openid-client 冒烟、NAS 文件网关 stub 与 /mcp 端点；隔离实例 + DEMO_SEED）
docs/roadmap.md             OS-skill 融合决策与演进路线
scripts/gen-manifests.mjs   插件声明生成器
src/main.ts                 独立宿主入口
cordis.yml                  dsh 接入 overlay（源码检出 + --patch）
cordis.patch.yml            dsh.bundle 安装补丁（dsh plugin add）
```

## 四、核心能力对照（方案 → 实现）

| 方案条目 | 实现 |
|---|---|
| 组织/账号/角色/用户组（§2） | 多级组织树、批量导入、账号状态机、动态/静态用户组、权限点矩阵 |
| 三方同步与冲突（§2.1/2.3） | OrgConnector 接口 + 钉钉模拟连接器、全量同步、三种冲突策略、对比式冲突工单；**intervalMinutes 定时自动同步**（到期巡检，0=仅手动，`IAM_CONNECTOR_AUTO_SYNC=off` 停用） |
| 组织数据通道（接入应用拉名册） | `GET /api/iam/roster`（`iam.roster.read`）：在职账号 + 组织树 + 部门负责人，机器凭证授权、invoke 审计留痕、PII 最小化（无手机号/无注销账号） |
| 统一认证（§7） | 双轨身份、HMAC 短期令牌（默认 2h）、吊销/轮换、Client Credentials、机器凭证 scopes 编辑与 secret 轮换（联动吊销令牌） |
| on-behalf-of（§5.5/6.5） | 用户→Agent 令牌链（act 叠加），审计可还原完整链路 |
| MCP 部署/灰度/回滚（§3.2） | 草稿→验证→灰度→全量，版本不可变，一键回滚 |
| MCP 令牌网关（§3.3/3.4） | 统一鉴权（权限组 + Tool 粒度 + 只读约束）、限流、熔断、调用监控（P95/成功率/Token） |
| Skill 市场（§4） | 静态扫描（恶意代码/密钥泄露自动驳回）、两级审批（高风险安全加签）、版本化、安装登记依赖、弃用告警 |
| Agent 本体（§5） | 属性表三组（基本/技术/治理）、注册颁发机器凭证、用户绑定、监测指标、生命周期 L4 |
| AI 应用本体（§6） | 应用 schema、编排拓扑（SVG 一图穿透）、DAU/留存、成本穿透 |
| 应用 SSO 纳管（§6/App SSO） | OIDC Provider 浏览器授权流、owner 自助签发、上线门禁双点、refresh/end_session/revoke、冻结即时失效 |
| 安全与审计（§7） | 四类日志、告警规则引擎、越权计数告警、成本多维报表 |
| L4 护栏（§4.4） | 上线/下线/下架/吊销强制审批单，有审批权限者单人通过即执行，执行结果回写 |

## 五、控制台交互（飞书式）

- **⌘K 命令面板**：搜资源（Skill/Agent/应用/MCP）、跳页面、执行高频动作
- **角色化工作台**：待办审批 + 告警 + 事件流 + 成本趋势
- **任务式导航**：按"要做什么"组织（市场/本体/治理/组织）
- **详情一律右侧抽屉**：列表不跳页；Agent/应用详情六页签（概览/监控/权限/拓扑/审计/生命周期）
- **渐进式表单**：必填最小集创建草稿，上线前强制补全治理属性
- **危险操作可逆感知**：dry-run 影响面预览、L4 审批时间线、原因必填
- **空状态即引导**：插画 + 一句话 + 主按钮
- 统一徽章体系 / 红绿灯健康 / 灰度进度条 / SVG 图表（无第三方依赖）

## 六、常用 API 与 CLI

```bash
# CLI（机器可读优先）
node cli/dshctl.mjs mcp list --output json
node cli/dshctl.mjs mcp deploy <id> --dry-run --changelog="优化召回"
node cli/dshctl.mjs agent offline <id> --reason="连续异常"    # 生成 L4 审批单
node cli/dshctl.mjs approval decide <id> --decision=approve --opinion="已确认"
node cli/dshctl.mjs tool exec --name=agent_list --args='{"status":"online"}'
node cli/dshctl.mjs plugin init --id=com.demo.hello --dir=./my-plugin   # 脚手架（契约五面 + 发布者密钥对）
node cli/dshctl.mjs plugin sign --dir=./my-plugin && node cli/dshctl.mjs plugin submit --dir=./my-plugin
node cli/dshctl.mjs nas import --config='{"mcpServers":{"synology-filestation":{"url":"http://192.168.0.7:3000/mcp","headers":{"Authorization":"Bearer <令牌>","X-NAS-IP":"192.168.0.196"}}}}'
node cli/dshctl.mjs nas files <id> --path=/skillhub    # 文件浏览（shares/mkdir/upload/delete/search 同组）
node cli/dshctl.mjs skill submit --name=<名> --content-file=SKILL.md --package=skill.zip
node cli/dshctl.mjs skill storage set --mode=nas --nas-id=<id> --base-path=/skillhub
node cli/dshctl.mjs app report <id> --pv=1200 --uv=320 --dau=280 --sessions=580 --retention7=0.45   # 应用指标主动上报（可 --date= 补录）
node cli/dshctl.mjs usage record --org=<orgId> --subject=agent:<id> --principal=org:<orgId> \
     --resource=skill:<skillId> --meter=calls:3:次,tokens:1200:token --idempotency-key=<业务单号>   # resource 亦支持 mcp:<slug> / nas:<id>；meter key 须与价格簿一致（mcp:*→tokens、model:*→output_tokens），不符 400 且报错给出期望键
node cli/dshctl.mjs credential list                       # 机器凭证盘点（principalId/scopes/活跃令牌）
node cli/dshctl.mjs credential scopes <principalId> --scopes=agent.read,usage.write   # 调整权限范围（存量令牌联动吊销）
node cli/dshctl.mjs credential rotate <principalId>       # 轮换 clientSecret（clientId 不变、旧值立即失效、新值仅此一次）
```

```bash
# REST（Bearer 令牌）
curl -X POST localhost:7300/api/auth/login -H 'content-type: application/json' \
     -d '{"username":"admin","password":"<你的口令>"}'
curl localhost:7300/api/overview -H "authorization: Bearer <token>"
# 平台即 MCP Server（任意 MCP 客户端可接入）
curl -X POST localhost:7300/mcp -H "authorization: Bearer <token>" -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
# /docs 静态发布：docs 目录随服务可读（接入指南等，浏览器直接打开）
curl http://localhost:7300/docs/app-sso-integration.md
```

## 七、自测

`npm run selftest` 在独立端口 + 独立数据目录启动隔离实例，覆盖 **445 项端到端断言**：
v1.0 全量（登录/RBAC 越权、冻结→令牌联动吊销、机器凭证与 scope 越权、MCP 灰度/回滚/网关鉴权（含只读约束拦截）、
Skill 恶意提交驳回与两级审批、Agent 属性校验与 L4 单人审批（发起人可自审）、on-behalf-of 链、
审计四类日志与筛选、告警、成本穿透、工具桥执行、安全演练）+ v1.2 新增
（真实 MCP/钉钉/OpenAI stub 往返、计量幂等与对账、钱包扣费与预算拦截、OIDC RS256/JWKS 全链路、
市场验签/安装/卸载、复式分账试算平衡与红字冲正）+ 远程 dsh 接入
（接入码创建/掩码存储/伪造拒绝/一次性消费、机器凭证换牌、operator 模板越权拦截、
工具桥代理路径、客户端禁用联动吊销、管理工具 RBAC）+ **App SSO 全链**
（浏览器授权流：校验失败一律平台错误页不开放重定向、授权请求单次消费/TTL/consent 门禁、
换牌 Basic+Post × form+JSON、PKCE 正误、code 重放、token_use 收敛、JWKS 本地验签、
MVP 闭环：门禁双点（含审批期间禁用→执行失败留痕）、owner 校验（非 owner/机器 403）、
secret 轮换旧值即废、offline/online/updated/archived 四事件联动、openid-client 冒烟
authorize→token→userinfo→refresh→revoke→end_session、钉钉身份驱动授权流
（providers 入口探测 → 授权页 sso 免密登录 → consent → 换牌 → userinfo 身份一致））+ **NAS 与平台 MCP 端点**
（进程内真实 synology-filestation stub（校验 Bearer + X-NAS-IP，fs_upload 真实读盘）：
mcpServers JSON 导入→探活→上线→工具发现、文件全链与审计留痕、RBAC 读写分离、
Skill 包上架自动上传（字节级校验 / 无包现场打包 / NAS 未上线 fail-closed）、台账巡检覆盖、
`/mcp` 端点 401/initialize/tools-list/tools-call/工具级越权/-32601）+ **接入方主动推送**
（应用指标上报：当日写入/历史补录累加/日期格式与应用存在性校验/RBAC 403/`app_metrics_report` 工具；
接入客户端心跳：机器令牌上报与宿主可见、非客户端身份 404、无令牌 401）+ **观测与分析补齐**
（Skill 下载/安装与 NAS 文件操作进计量管道（calls/bytes）、`skill:`/`nas:` 资源外部上报放行、
PV 同日累加与 UV/DAU 取最大、效益分析毛利恒等、技能热力矩阵、skill 弃用原因必填与落库、
下架原因三源聚合并去重）+ **接入链路加固**
（Agent 凭证默认含 usage.write 且机器令牌自推计量 200、计量键与价格簿不符 400（错误携带期望键）
与匹配路径计价恒等、skill 事件 meters 含计价键 calls、scopes 调整后旧令牌联动吊销/拼错权限点与
`*` 混用拒绝、clientSecret 轮换旧值即废新值即用、身份列表与治理响应不外发 clientSecretHash、
机器身份读台账入审计 agent.verify 而人类读不产生（噪音控制））。
测试内 stub 均为进程内真实 HTTP 服务，不降级为 mock。

## 八、说明与边界

- 生产部署默认**基线初始化**（内置角色 + 根组织 + `admin`，零演示数据）；完整演示数据仅在 `DEMO_SEED=1` 时注入，请勿在生产环境启用
- 业务配置存储为 JSON 集合（原子落盘）；计量/资金/分账类数据存 SQLite（`data/txnstore.db`，WAL + 事务 + 幂等唯一索引）
- MCP 执行层支持真实 HTTP 传输（`exec: real`，JSON-RPC tools/call + initialize 探活）；`exec: demo` 为显式降级演示传输层（确定性模拟、不计费不计 SLO）
- 钉钉连接器支持真实 OpenAPI（`mode: real` + `apiBase`）与 mock 演示（显式标注）；通讯录按连接器
  「同步频率」定时自动同步（下限 5 分钟，填 0 仅手动；`IAM_CONNECTOR_AUTO_SYNC=off` 停用定时器）
- 模型网关仅转发 OpenAI 兼容 chat/completions；模型未配置 endpoint 时拒绝调用（不生成假 completion）
- 资金通道为手工过渡形态（见「三A」资金红线）；OIDC 私钥存 data 目录，生产建议迁 KMS
- NAS 文件操作全部经 MCP 文件网关（不直连 DSM 私有 API）；`fs_upload/fs_download` 在网关进程侧读写本地路径——平台与网关需同机部署，或把资产 `stagingDir` 配置为共享挂载点；`/mcp` 端点为无会话纯 JSON 形态（不提供 GET SSE 长流，主流客户端兼容）
- Node ≥ 22.6（原生 TypeScript 运行，无需构建步骤；node:sqlite 在 Node 24 下为 Experimental，无害）
