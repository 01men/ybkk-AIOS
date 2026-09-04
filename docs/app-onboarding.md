# AI 应用接入宿主平台指引

> 面向对象：接入平台的企业自研 AI 应用（运维接入 → SSO 登录打通 → 指标提报与计量对齐）。
> 本文档随服务发布，可直接访问 `http://<平台地址>/docs/app-onboarding.md`。

【任务】接入宿主平台 http://192.168.0.7:7300，完成运维接入、SSO 登录打通与用量提报。

0. 前置：向平台管理员索取一次性接入码（enr_ 开头），并说明需要 operator 模板
   （含 app.write / usage.write；默认 readonly 模板只读，第 3/4 步会 403）。
   接入码一次性消费、默认 15 分钟过期：随用随取，禁止保存复用、禁止写入代码或提示词。

1. 远程接入：调用 connect_setup { hubUrl: "http://192.168.0.7:7300", enrollmentCode: "<向我索取>" }，
   成功后用 connect_test 自检（健康检查 + 换牌 + 一次只读调用）。
   若报"接入码已被使用/已过期"：本机已接入过就直接 connect_test；未接入则向我要新码，不要反复试
   （enroll 失败按来源 IP 计数，5 次锁 15 分钟起逐次升级）。
   这一步拿到的是平台运维机器凭证（机器令牌 2 小时有效；插件侧自动续换，
   直接走 REST 时收到 401 过期就重新换牌一次再重试）。
   应用注册（app_ 开头 id）是另一回事：本应用尚未注册时先向我确认注册信息，不要自行换名重复注册。
   应用 attrs 为白名单制（description/appType/icon/url/channels/publishVersion/riskLevel/dataClass/
   developerName/developerId/agentIds，没有 tags 字段）：白名单外字段（含 version）静默丢弃——返回 200
   但不落库；版本号用 publishVersion；icon 填 emoji 或图片 http(s) 地址（展示为应用头像）；
   开发者用 developerId（平台用户 ID，校验存在并自动回填 developerName）或直接给 developerName。

2. 登录打通：按 http://192.168.0.7:7300/docs/app-sso-integration.md 接入 OIDC
   （授权码 + 强制 PKCE S256，redirect_uri 必须与控制台登记值完全一致），身份以宿主账号体系（sub）为准。
   SSO 客户端必须由我在控制台「AI应用→应用详情→SSO配置」签发：你先把应用侧回调地址（redirect_uri）给我，
   我签发后给你 client_id / client_secret。机器身份自签一律 403（平台硬校验，仅应用 owner 用户身份可操作）。
   用户授权确认页必须真人完成，属正常流程。
   注意：web/h5 形态应用未完成 SSO 签发无法上线（上线门禁），SSO 不是可选项。
   钉钉扫码等三方登录由平台登录页承接，应用不直接对接钉钉 SDK；钉钉组织通讯录由平台连接器
   定时自动同步（README「连接器定时自动同步」），应用按需消费即可，不必自己拉通讯录。
   组织名册：人事/绩效类应用可经机器凭证拉取全员名册 GET /api/iam/roster
   （需管理员为凭证追加 iam.roster.read scope；users[].id 即 sub 同一关联键、orgs[].leaderUserIds
   为部门负责人同步链），接入示例见 docs/app-sso-integration.md §十。

3. 指标提报：应用上线（含试运行）后，每天 09:00 提报前一日指标（必须带 --date=昨日，不带会记到当天）：
   dshctl app report <appId> --date=<昨日YYYY-MM-DD> --dau=<n> --sessions=<n> --retention7=<n> [--avg-depth=<n>]
   （或 app_metrics_report 工具）。同日重报安全：DAU/UV 取最大值、会话数/PV 累加。

4. 计量事件：仅对绕过平台网关的直连消耗推送（经平台网关的调用已自动计量，重复推送会双计费）；
   无对应 dsh 工具，走 CLI/REST：
   export DSHCTL_URL=http://192.168.0.7:7300
   export DSHCTL_TOKEN=<机器令牌>
   （Windows PowerShell 用 $env: 前缀，cmd 用 set）
   dshctl usage record --org=<组织ID> --subject=user:<用户ID> --principal=org:<组织ID>
     --resource=mcp:<slug> --meter=tokens:<数量>:tokens --idempotency-key=<本应用名>:<业务单号>
   （直连模型时 resource=model:<slug>、meter 用 output_tokens；用错键会 400 并给出期望键，按提示改键重报）。
   resource 无计价规则会 400，届时来问我，不要自行换 resource 或编造 meter。

5. 权限自检：接入完成后先试跑一次 app report 和 usage record；
   403 = 接入码模板权限不足（响应体会指明缺的权限点），向我报告，不要换账号或重试硬闯。
   403 本身不触发锁定；登录/换牌类连续失败才计锁定（按用户名/clientId 或来源 IP 计，5 次起）。

6. 数据权限红线（应用代用户操作平台资源时适用，2026-08-30 起）：
   应用代用户调用 NAS 文件等平台数据面接口时，真实用户身份一律经请求头
   X-On-Behalf-User: <平台 userId 或钉钉 userId> 透传，禁止拼进参数、路径或 body；
   未授权令牌携带该头一律 403 FORGED_ON_BEHALF（防伪造，留痕）。
   越权操作返回 JSON-RPC -32403「数据权限拒绝：<reasons>」（前缀 path.out-of-scope / matrix.deny /
   org.* / account.* / degraded.*），把原文透传给用户即可，不要变形重试；
   degraded.* 表示平台判定服务短暂不可达已降级，提示用户稍后重试。
