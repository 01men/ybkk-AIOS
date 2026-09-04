/**
 * Agent 接入提示词生成（与 plugin-app/src/onboarding.ts 同构）：注册同款指引下沉平台侧，单一事实源。
 *
 * 服务「注册后随时重新生成」场景：
 *   - POST /api/agents/:id/onboarding-prompt {rotate} → 控制台 Agent 详情页按钮
 *   - 外部推送方（hermes rongqi-asset-push 技能）注册成功后拉取全文并推送钉钉 connector webhook
 * 首行含「接入提示词」关键词：钉钉 connector 流程按该关键词触发记录。
 */
import type { ResourceEntity } from '../../platform-core/src/index.ts'

export interface AgentOnboardingCredential {
  clientId: string
  /** 仅 rotate 时返回；缺省时提示词内以占位符标注。 */
  clientSecret?: string
}

export function buildAgentOnboardingPrompt(agent: ResourceEntity, credential: AgentOnboardingCredential, origin: string): string {
  const clientId = credential.clientId
  const secret = credential.clientSecret
  const secretLine = secret
    ? `- client_secret：${secret}`
    : '- client_secret：（本提示词未包含 secret——生成时未轮换密钥；需要完整凭证请在生成时选择「重新生成密钥」）'
  const secretCurl = secret ?? '<填入你的 client_secret>'
  const secretNote = secret
    ? `1. client_secret 等价口令：仅本提示词展示这一次，平台不可再查询，请务必妥善保存；
   不慎丢失可在控制台「Agent 本体 → Agent 详情 → 生成接入提示词」重新生成（旧 secret 立即失效）。`
    : `1. client_secret 未随本提示词下发：首次接入或密钥丢失时，在控制台
   「Agent 本体 → Agent 详情 → 生成接入提示词」选择「重新生成密钥」获取完整凭证（旧 secret 立即失效）。`
  return `【接入提示词 · 任务】按《榕器平台 · Agent 接入指引》完成下方 Agent 的接入验证与运营数据提报。平台地址：${origin}

【资源与凭证】（client_secret 仅此一次展示，请立即安全保存，不落明文日志）
- Agent ID：${agent.id}
- 唯一标识：${agent.slug}
- Agent 名称：${agent.name}
- client_id：${clientId}
${secretLine}

【第 1 步 · 机器凭证换牌】（令牌 2 小时有效，可随时重复换取）
curl -s -X POST ${origin}/api/auth/client-credentials \\
  -H 'content-type: application/json' \\
  -d '{"clientId":"${clientId}","clientSecret":"${secretCurl}"}'
→ 取响应 data.token，后续请求头带：Authorization: Bearer <token>

【第 2 步 · 接入验证（"发一句话"：首次运营数据提报）】
curl -s -X POST ${origin}/api/agents/${agent.id}/metrics-report \\
  -H "Authorization: Bearer <token>" -H 'content-type: application/json' \\
  -d '{"dau":1,"sessions":1,"uniqueUsers":1}'
→ 返回 200 即接入成功；GET ${origin}/api/agents/${agent.id} 中 metrics.sessions ≥ 1 可复核。
【接入义务】每日定时提报运营数据是接入平台的强制要求（与 AI 应用同级），不是倡导：
- 必报字段：dau（日活跃用户数，同日取最大）、sessions（对话会话数，同日累加）、
  uniqueUsers（对话去重用户数）；有用户明细时随报 userIds 列表（平台侧哈希脱敏去重，不落明文）。
- 重复上报安全，可带 date（YYYY-MM-DD）补录历史；漏报将导致平台运营数据失真，接入验收以本接口 200 为准。
- 调用次数/成功率/Token 由平台网关自动归集，无须也无法替代上述提报，两者口径互补。

【第 3 步 · 计量自推（直连场景必做）】
仅绕过平台网关直连外部资源时需要：POST ${origin}/api/usage/record（凭自身凭证即可，凭证默认含 usage.write）。
经平台网关的调用已自动计量（MCP 网关经 mcp.invoked、模型网关 POST /api/modelgw/invoke 凭自身凭证可调，
计量事件 subject=agent:<id> 自动回灌调用台账），禁止双计。

【第 4 步 · NAS 文件能力与数据权限（需文件能力时必读）】
NAS 文件操作经文件网关（MCP：url=<网关地址>/mcp + Authorization: Bearer <管理员签发的网关令牌>）统一执法，
按组织位置 + 角色层级 RBAC 判定，全链 fail-closed：
- 身份红线（P0-2）：真实用户身份一律经请求头 X-On-Behalf-User: <平台或钉钉 userId> 透传，禁止进工具参数；
  令牌须由管理员标记 allowedOnBehalf 才允许携带该头，否则一律 403 FORGED_ON_BEHALF（伪造留痕）；
  无用户上下文的机器调用可不带头，由令牌绑定身份判定。
- 越权返回 JSON-RPC -32403「数据权限拒绝：<reasons>」，前缀可归因：path.out-of-scope（超作用域）/
  matrix.deny（角色无权）/ org.* / account.* / degraded.*（平台不可达已降级）——原文透传给用户，不要变形重试。
- share 被拒且提示"需走审批"时，代表用户发起申请：
  POST ${origin}/api/nas/authz/exceptions  body {"status":"pending","nasId":"<资产ID>","userId":"<用户ID>","path":"<路径>","reason":"<事由>"}
  → 审批单自动路由用户组织链最近负责人（兜底 resource_admin），通过后自动写 7 天例外，到期自动失效。
- PDP 不可达时网关按「作用域快照只读 → 全局只读 → 拒绝」降级：收到 degraded.* 理由提示用户稍后重试，
  不要连续重试。observeOnly 观察期越权放行但留痕告警，不代表越权合法。

【注意】
${secretNote}
2. 幂等：重名注册返回 400「已存在」时，按名称查列表复用既有资源，不得换名重复注册。
3. 上线/下线走审批流（POST ${origin}/api/agents/${agent.id}/transition → 审批中心 decision），禁止绕过审批改状态。`
}
