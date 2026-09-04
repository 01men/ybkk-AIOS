/**
 * AI 应用接入提示词生成（方案：注册同款指引下沉平台侧，单一事实源）。
 *
 * 控制台注册弹窗仍用前端模板（onboarding.js buildAppOnboardingText）；
 * 本模块服务「注册后随时重新生成」场景：
 *   - POST /api/apps/:id/onboarding-prompt {rotate} → 控制台详情页「生成接入提示词」按钮
 *   - 外部推送方（hermes rongqi-asset-push 技能）注册成功后拉取全文并推送钉钉 connector webhook
 * 首行含「接入提示词」关键词：钉钉 connector 流程按该关键词触发记录。
 */
import type { ResourceEntity } from '../../platform-core/src/index.ts'

export interface AppOnboardingCredential {
  clientId: string
  /** 仅 rotate 时返回；缺省时提示词内以占位符标注。 */
  clientSecret?: string
}

export function buildAppOnboardingPrompt(app: ResourceEntity, credential: AppOnboardingCredential, origin: string): string {
  const clientId = credential.clientId
  const secret = credential.clientSecret
  const secretLine = secret
    ? `- client_secret：${secret}`
    : '- client_secret：（本提示词未包含 secret——生成时未轮换密钥；需要完整凭证请在生成时选择「重新生成密钥」）'
  const secretCurl = secret ?? '<填入你的 client_secret>'
  const secretNote = secret
    ? `1. client_secret 等价口令：仅本提示词展示这一次，平台不可再查询，请务必妥善保存；
   不慎丢失可在控制台「AI 应用 → 应用详情 → 生成接入提示词」重新生成（旧 secret 立即失效）。`
    : `1. client_secret 未随本提示词下发：首次接入或密钥丢失时，在控制台
   「AI 应用 → 应用详情 → 生成接入提示词」选择「重新生成密钥」获取完整凭证（旧 secret 立即失效）。`
  return `【接入提示词 · 任务】按《榕器平台 · AI 应用接入指引》完成下方应用的接入验证、用户登录打通（SSO）与指标提报。平台地址：${origin}

【资源与凭证】（client_secret 仅此一次展示，请立即安全保存，不落明文日志）
- 应用 ID：${app.id}
- 唯一标识：${app.slug}
- 应用名称：${app.name}
- client_id：${clientId}（平台运维机器凭证，调平台 API 用；与后续 SSO 的 OIDC client 是两套凭据，勿混用）
${secretLine}

【第 1 步 · 机器凭证换牌】（令牌 2 小时有效，可随时重复换取）
curl -s -X POST ${origin}/api/auth/client-credentials \\
  -H 'content-type: application/json' \\
  -d '{"clientId":"${clientId}","clientSecret":"${secretCurl}"}'
→ 取响应 data.token，后续请求头带：Authorization: Bearer <token>

【第 2 步 · 接入验证（"发一句话"：首次指标提报）】
curl -s -X POST ${origin}/api/apps/${app.id}/metrics-report \\
  -H "Authorization: Bearer <token>" -H 'content-type: application/json' \\
  -d '{"dau":1,"sessions":1,"avgDepth":1,"retention7":0}'
→ 返回 200 即接入成功；GET ${origin}/api/apps/${app.id} 中 metrics.sessions ≥ 1 可复核。
建议每日定时提报（同日 DAU 取最大值、会话数累加，重复上报安全，可带 date 补录历史）。

【第 3 步 · 用户登录打通（SSO）】web/h5 形态必做（未签发无法上线，上线门禁）；其余形态建议接入。
终端用户登录一律走平台 OIDC（授权码 + 强制 PKCE S256），身份以平台账号体系 sub 为准；
钉钉扫码等三方登录由平台登录页承接，应用不直接对接钉钉 SDK。接入文档（含 SDK 一行接入示例）：
${origin}/docs/app-sso-integration.md
a. 把应用侧回调地址（redirect_uri）交给平台管理员（应用 owner），由其在控制台
   「AI 应用 → 应用详情 → SSO 配置」签发 OIDC 客户端后取回 client_id / client_secret（机器身份自签一律 403）；
b. 应用按 discovery 接入：GET ${origin}/.well-known/openid-configuration
   （换牌 POST /oauth/token、用户身份 GET /oauth/userinfo；302 跳授权页 → 带 code 回回调地址）；
c. userinfo 返回的 sub/org 即用户唯一关联键，业务权限（谁能用哪些功能）由应用基于 sub 自建；
d. 未完成 OIDC 改造前，可先用平台「带平台身份打开」兜底（控制台发起，一次性 entry-ticket 票据换取身份）。

【第 4 步 · 计量自推（可选）】
仅绕过平台网关直连消耗才需要：POST ${origin}/api/usage/record（凭证默认含 usage.write）。
经平台网关的调用已自动计量，禁止双计。

【平台能力速查】（本凭证默认含 app.read/app.write/usage.write/mcp.invoke/agent.read/skill.read）
- 接入文档索引：GET ${origin}/docs（app-sso-integration.md、app-onboarding.md 等）
- 自身资料与指标复核：GET / PATCH ${origin}/api/apps/${app.id}（app.read/app.write）
- 上线申请：POST ${origin}/api/apps/${app.id}/transition（进入审批流，禁止绕过审批改状态）
- MCP 工具网关：mcp.invoke 调用平台已部署 MCP 服务；Skill/Agent 目录：skill.read / agent.read 浏览
- 全员名册（组织数据通道，人事/绩效类应用）：GET ${origin}/api/iam/roster
  （users[].id=sub 同一关联键、orgs[].leaderUserIds=部门负责人；默认凭证不含，需管理员为凭证追加 iam.roster.read scope）
- 模型网关：应用默认凭证不含 modelgw.invoke，需直连大模型时请管理员追加授权（经网关调用自动计量）

【注意】
${secretNote}
2. 幂等：重名注册返回 400「已存在」时，按名称查列表复用既有资源。
3. 失败锁定：换牌连续失败 5 次锁来源 IP 15 分钟，重试前先核对凭证。
4. 数据权限红线：应用代用户操作 NAS 文件等平台数据面接口时，用户身份一律经
   X-On-Behalf-User 请求头透传（禁止进参数/路径）；越权响应（-32403 数据权限拒绝）原文透传给用户，
   degraded.* 前缀表示平台短暂不可达已降级，提示稍后重试。`
}
