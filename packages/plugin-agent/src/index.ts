/**
 * @dsh-ops/plugin-agent —— Agent 本体管理（方案 §五）。
 *
 * 基于 resource-core 底座：属性表 schema + 生命周期状态机 + 依赖图全部复用，
 * 本插件只声明 Agent 差异 schema 与运营监测逻辑。
 * 注册即纳管：创建 Agent 颁发唯一 ID 与机器身份凭证（authn，含 usage.write，
 * Agent 可自推直连消耗的计量），上线走 L4 审批，下线联动吊销凭证、通知绑定用户、保留审计数据。
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { createHash } from 'node:crypto'
import {
  PlatformEvents, newId,
  type Collection, type RecordBase, type ResourceTypeSpec,
} from '../../platform-core/src/index.ts'
import * as agentTools from './tools.ts'
import { AGENT_TYPE_SPEC } from './schema.ts'
import { buildAgentOnboardingPrompt, type AgentOnboardingCredential } from './onboarding.ts'

// ---------------------------------------------------------------------------
// 数据模型（Agent 专属扩展记录）
// ---------------------------------------------------------------------------

export interface AgentBindingRecord extends RecordBase {
  agentId: string
  userId: string
  userName: string
  boundAt: string
  boundBy: string
}

export interface AgentUsageRecord extends RecordBase {
  agentId: string
  date: string
  sessions: number
  calls: number
  okCalls: number
  tokens: number
  totalLatencyMs: number
  /** 来源维度：usage.recorded 回灌归集的调用数（模型网关等，无延迟数据）；calls 含该部分。 */
  gwCalls?: number
  /** 日活跃用户数（提报语义：同日多次上报取最大；网关归集不产生该字段）。 */
  dau?: number
  /** 对话用户去重统计（提报侧传 userIds，平台侧即刻哈希脱敏，同日取并集；不落明文）。 */
  userHashes?: string[]
}

// ---------------------------------------------------------------------------
// 服务
// ---------------------------------------------------------------------------

export class AgentRegistryService extends Service {
  static readonly provide = 'agentRegistry'

  private usageCounter = new Map<string, number[]>()

  constructor(ctx: Context) {
    super(ctx, 'agentRegistry')
    ctx.resourceCore.registerType(AGENT_TYPE_SPEC)

    // 调用监测：MCP 网关以 Agent 为主体调用时自动归集运行指标
    ctx.platformBus.on(PlatformEvents.McpInvoked, (payload) => {
      const p = payload as { callerType: string; callerId: string; ok: boolean; tokens: number; latencyMs: number }
      if (p.callerType !== 'agent') return
      this.recordUsage(p.callerId, { calls: 1, okCalls: p.ok ? 1 : 0, tokens: p.tokens, latencyMs: p.latencyMs }, 'mcp')
      // 行为监测：频次突增检测（10 分钟窗口超过 120 次）
      const nowMs = Date.now()
      const times = (this.usageCounter.get(p.callerId) ?? []).filter((t) => nowMs - t < 10 * 60_000)
      times.push(nowMs)
      this.usageCounter.set(p.callerId, times)
      if (times.length === 120) {
        const agent = ctx.resourceCore.collection('agent').get(p.callerId)
        ctx.audit.fire({
          severity: 'warning',
          title: `Agent「${agent?.name ?? p.callerId}」调用频次突增`,
          message: `10 分钟内调用 ${times.length} 次，超过异常阈值 120，请检查是否存在死循环或滥用。`,
          resourceType: 'agent',
          resourceId: p.callerId,
        })
      }
    })

    // 调用统计口径补全：订阅 usage.recorded 回灌模型网关等非 MCP 调用（McpInvoked 只覆盖 MCP 网关）。
    // 防双计规则（三条，缺一即双计/脏计）：
    //   1. 只认 subject=agent:<id> 且 Agent 存在的事件——seed 历史数据与悬空主体不计；
    //   2. resource mcp:* 一律跳过——MCP 网关对同一调用双发 McpInvoked（上方监听已计），
    //      自推计量误报 mcp:* 时同样跳过（网关已计，宁缺勿重）；
    //   3. meters 含 downloads/installs 观测键跳过——Skill 下载/安装是生命周期事件而非调用。
    // 消费幂等：经 usage.consume 消费水位（INSERT OR IGNORE），replay/死信重投不会重复回灌；
    // 投影义务：所有消费方必须 project（usage.reconcile 全量比对，缺投影即「对账不平」告警）。
    ctx.usage.consume('agent-registry', (event) => {
      ctx.usage.project('agent-registry', event)
      if (!event.subject.startsWith('agent:')) return
      const agentId = event.subject.slice('agent:'.length)
      if (!ctx.resourceCore.collection('agent').get(agentId)) return
      if (event.resource.startsWith('mcp:')) return
      if (event.meters.some((meter) => meter.key === 'downloads' || meter.key === 'installs')) return
      // 网关仅在成功返回后计量：回灌事件按成功调用计；延迟无数据不摊薄均值（见 metrics）
      const tokens = event.meters
        .filter((meter) => meter.key === 'input_tokens' || meter.key === 'output_tokens' || meter.key === 'tokens')
        .reduce((sum, meter) => sum + meter.value, 0)
      this.recordUsage(agentId, { calls: 1, okCalls: 1, tokens, latencyMs: 0 }, 'gateway')
    })

    // Skill 弃用 → 通知引用 Agent 的负责人（存量引用告警）
    ctx.platformBus.on(PlatformEvents.SkillDeprecated, (payload) => {
      const p = payload as { skillId: string; name: string }
      for (const record of ctx.resourceCore.dependencies().find((item) => item.kind === 'skill' && item.toId === p.skillId)) {
        const agent = ctx.resourceCore.collection('agent').get(record.fromId)
        if (!agent) continue
        ctx.audit.fire({
          severity: 'info',
          title: `Agent「${agent.name}」引用的 Skill 已弃用`,
          message: `Skill「${p.name}」已弃用，请尽快迁移至替代版本，避免下次构建失败。`,
          resourceType: 'agent',
          resourceId: agent.id,
        })
      }
    })
  }

  bindings(): Collection<AgentBindingRecord> {
    return this.ctx.opsStorage.collection<AgentBindingRecord>('agent:bindings')
  }

  usage(): Collection<AgentUsageRecord> {
    return this.ctx.opsStorage.collection<AgentUsageRecord>('agent:usage')
  }

  // -- 注册 -------------------------------------------------------------

  register(input: {
    name: string
    slug?: string
    attrs?: Record<string, unknown>
    ownerId: string
    ownerName: string
    orgId: string
    withCredential?: boolean
  }): { agent: import('../../platform-core/src/index.ts').RecordBase & Record<string, unknown>; credential?: { principalId: string; clientId: string; clientSecret: string } } {
    const attrs = {
      ownerName: input.ownerName,
      ...(input.attrs ?? {}),
    }
    const agent = this.ctx.resourceCore.create('agent', { ...input, attrs })
    let credential
    if (input.withCredential !== false) {
      // usage.write：Agent 绕过平台网关直连外部资源时须自推计量（POST /api/usage/record）
      credential = this.ctx.authn.createMachineCredential({
        name: `agent:${(agent as any).slug}`,
        refType: 'agent',
        refId: agent.id,
      // connector.invoke：连接器纳管（open-connector 融合）与 mcp.invoke 同级的独立调用权限点
      // agent.write：注册后凭自身凭证即可完成接入验证后的资料提报更新（PATCH /api/agents/:id）
      // modelgw.invoke：模型网关调用（LLM 是 Agent 的第一消耗品；计量经 usage.recorded 回灌本台账）
      scopes: ['mcp.invoke', 'skill.read', 'agent.read', 'agent.write', 'usage.write', 'connector.invoke', 'modelgw.invoke'],
      })
    }
    this.ctx.platformBus.emit(PlatformEvents.AgentRegistered, {
      id: agent.id, name: agent.name, slug: agent.slug, actor: input.ownerId, type: 'agent',
    })
    return { agent, credential }
  }

  machinePrincipal(agentId: string) {
    return this.ctx.authn.principals().findOne((item) => item.refType === 'agent' && item.refId === agentId)
  }

  /**
   * 生成 Agent 接入提示词（注册同款模板，平台侧单一事实源，与 app 同构）：
   * rotate=true 轮换机器凭证 secret（旧值立即失效）并随提示词返回；rotate=false 仅含 client_id。
   */
  buildOnboardingPrompt(agentId: string, origin: string, opts: { rotate?: boolean } = {}): {
    agentName: string
    prompt: string
    credential: AgentOnboardingCredential
    rotated: boolean
  } {
    const agent = this.ctx.resourceCore.get('agent', agentId)
    if (!agent) throw new Error(`Agent 不存在：${agentId}`)
    const principal = this.machinePrincipal(agentId)
    if (!principal) throw new Error(`Agent 机器凭证不存在（可能已被禁用或删除），无法生成接入提示词`)
    let credential: AgentOnboardingCredential
    let rotated = false
    if (opts.rotate) {
      const next = this.ctx.authn.rotateMachineCredential(principal.id)
      credential = { clientId: next.principal.clientId, clientSecret: next.clientSecret }
      rotated = true
    } else {
      credential = { clientId: principal.clientId }
    }
    return { agentName: agent.name, prompt: buildAgentOnboardingPrompt(agent, credential, origin), credential, rotated }
  }

  /** 用户绑定：记录"哪些用户可使用该 Agent"，使用即授权留痕。 */
  bindUser(agentId: string, userId: string, actor: string): AgentBindingRecord {
    const agent = this.ctx.resourceCore.get('agent', agentId)
    if (!agent) throw new Error(`Agent 不存在：${agentId}`)
    const user = this.ctx.iam.users().get(userId)
    if (!user) throw new Error(`用户不存在：${userId}`)
    if (this.bindings().findOne((item) => item.agentId === agentId && item.userId === userId)) {
      throw new Error(`${user.displayName} 已绑定该 Agent`)
    }
    return this.bindings().insert({
      id: newId('agb'),
      agentId,
      userId,
      userName: user.displayName,
      boundAt: new Date().toISOString(),
      boundBy: actor,
    })
  }

  unbindUser(agentId: string, userId: string): boolean {
    const binding = this.bindings().findOne((item) => item.agentId === agentId && item.userId === userId)
    if (!binding) return false
    return this.bindings().remove(binding.id)
  }

  boundUsers(agentId: string): AgentBindingRecord[] {
    return this.bindings().find((item) => item.agentId === agentId)
  }

  /** on-behalf-of：用户通过 Agent 行事时签发身份透传令牌。 */
  issueOnBehalfOfToken(agentId: string, verifiedUser: import('../../plugin-authn/src/index.ts').VerifiedPrincipal): { token: string; actChain: unknown[] } {
    const principal = this.machinePrincipal(agentId)
    if (!principal) throw new Error('该 Agent 尚未注册机器身份，请先在注册时勾选颁发凭证')
    const { token, record } = this.ctx.authn.issueOnBehalfOf(verifiedUser, principal.id)
    return { token, actChain: record.actChain }
  }

  // -- 生命周期（L4 审批流）----------------------------------------------

  requestOnline(agentId: string, requester: { id: string; name: string }) {
    const agent = this.ctx.resourceCore.get('agent', agentId)
    if (!agent) throw new Error(`Agent 不存在：${agentId}`)
    const errors = this.ctx.resourceCore.validateAttrs('agent', agent.attrs, 'online')
    if (errors.length > 0) throw new Error(`上线条件不满足：${errors.join('；')}`)
    return this.ctx.audit.createApproval({
      kind: 'agent.online',
      title: `Agent 上线：${agent.name}`,
      payload: { agentId, requesterId: requester.id },
      requesterId: requester.id,
      requesterName: requester.name,
    })
  }

  requestOffline(agentId: string, requester: { id: string; name: string }, reason: string) {
    const agent = this.ctx.resourceCore.get('agent', agentId)
    if (!agent) throw new Error(`Agent 不存在：${agentId}`)
    if (!reason?.trim()) throw new Error('下线必须填写原因（护栏要求）')
    const impact = this.ctx.resourceCore.impact('agent', agentId)
    return this.ctx.audit.createApproval({
      kind: 'agent.offline',
      title: `Agent 下线：${agent.name}`,
      payload: { agentId, reason, impact: impact.map((item) => `${item.name}（${item.type}）`) },
      requesterId: requester.id,
      requesterName: requester.name,
    })
  }

  online(agentId: string, actor: string) {
    const result = this.ctx.resourceCore.transition('agent', agentId, 'online', actor)
    this.ctx.platformBus.emit(PlatformEvents.AgentOnlined, { id: agentId, name: result.entity.name, actor, type: 'agent', slug: result.entity.slug })
    return result.entity
  }

  offline(agentId: string, actor: string, reason: string) {
    const result = this.ctx.resourceCore.transition('agent', agentId, 'offline', actor, reason)
    this.ctx.platformBus.emit(PlatformEvents.AgentOfflined, { id: agentId, name: result.entity.name, actor, reason, type: 'agent', slug: result.entity.slug })
    // 下线联动：吊销机器凭证（authn 事件监听执行）、通知绑定用户
    const principal = this.machinePrincipal(agentId)
    if (principal) this.ctx.authn.disablePrincipal(principal.id, 'Agent 下线联动')
    for (const binding of this.boundUsers(agentId)) {
      this.ctx.audit.fire({
        severity: 'info',
        title: `你绑定的 Agent「${result.entity.name}」已下线`,
        message: `绑定关系保留，恢复上线后可继续使用。原因：${reason}`,
        resourceType: 'agent',
        resourceId: agentId,
      })
      void binding
    }
    return result.entity
  }

  archive(agentId: string, actor: string) {
    return this.ctx.resourceCore.transition('agent', agentId, 'archive', actor).entity
  }

  trial(agentId: string, actor: string, groups: string[]) {
    void groups
    return this.ctx.resourceCore.transition('agent', agentId, 'submit_trial', actor).entity
  }

  /** 删除后的关联清理：用户绑定、依赖边与机器凭证（禁用即吊销全部令牌）；用量记录与审计数据保留。 */
  purge(agentId: string): void {
    for (const binding of this.bindings().find((item) => item.agentId === agentId)) this.bindings().remove(binding.id)
    for (const record of this.ctx.resourceCore.dependencies().find((item) => item.fromId === agentId || item.toId === agentId)) {
      this.ctx.resourceCore.dependencies().remove(record.id)
    }
    const principal = this.machinePrincipal(agentId)
    if (principal && principal.status === 'active') this.ctx.authn.disablePrincipal(principal.id, 'Agent 删除联动')
  }

  // -- 监测 -------------------------------------------------------------

  /** 归集/回灌入口：source=mcp（McpInvoked，带延迟）| gateway（usage.recorded 回灌，无延迟）。 */
  recordUsage(agentId: string, usage: { sessions?: number; calls: number; okCalls: number; tokens: number; latencyMs: number }, source: 'mcp' | 'gateway' = 'mcp'): void {
    const date = new Date().toISOString().slice(0, 10)
    const gwDelta = source === 'gateway' ? usage.calls : 0
    const existing = this.usage().findOne((item) => item.agentId === agentId && item.date === date)
    if (existing) {
      this.usage().update(existing.id, {
        sessions: existing.sessions + (usage.sessions ?? 0),
        calls: existing.calls + usage.calls,
        okCalls: existing.okCalls + usage.okCalls,
        tokens: existing.tokens + usage.tokens,
        totalLatencyMs: existing.totalLatencyMs + usage.latencyMs,
        gwCalls: (existing.gwCalls ?? 0) + gwDelta,
      })
    } else {
      this.usage().insert({
        id: newId('agu'),
        agentId,
        date,
        sessions: usage.sessions ?? 0,
        calls: usage.calls,
        okCalls: usage.okCalls,
        tokens: usage.tokens,
        totalLatencyMs: usage.latencyMs,
        gwCalls: gwDelta,
      })
    }
    if (usage.tokens > 0) {
      this.ctx.audit.addCost({
        date,
        agentId,
        llmTokens: usage.tokens,
        toolCalls: usage.calls,
        costYuan: Math.round(usage.tokens * 0.0000015 * 1000) / 1000,
      })
    }
  }

  /**
   * Agent 自主提报运营指标（REST /api/agents/:id/metrics-report、工具 agent_metrics_report 汇入）。
   * 接入义务（与 AI 应用 metrics-report 同级）：语义对齐——同日 dau 取最大、会话数累加、
   * 用户去重集取并集；userIds 平台侧即刻哈希脱敏后入库，不落明文；可指定 date 补录历史（YYYY-MM-DD）。
   */
  reportUsage(agentId: string, report: { dau?: number; sessions?: number; userIds?: string[]; uniqueUsers?: number; date?: string }): void {
    if (!this.ctx.resourceCore.get('agent', agentId)) throw new Error(`Agent 不存在：${agentId}`)
    const date = report.date ?? new Date().toISOString().slice(0, 10)
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error(`date 格式非法：${date}（应为 YYYY-MM-DD）`)
    for (const [key, value] of [['dau', report.dau], ['sessions', report.sessions], ['uniqueUsers', report.uniqueUsers]] as const) {
      if (value !== undefined && (!Number.isInteger(value) || value < 0)) throw new Error(`${key} 必须是非负整数（收到：${value}）`)
    }
    const hashes = (report.userIds ?? []).map((id) => createHash('sha256').update(String(id)).digest('hex').slice(0, 16))
    if (report.uniqueUsers !== undefined && hashes.length > report.uniqueUsers) {
      throw new Error(`userIds 数量（${hashes.length}）不应大于 uniqueUsers（${report.uniqueUsers}）`)
    }
    const existing = this.usage().findOne((item) => item.agentId === agentId && item.date === date)
    if (existing) {
      const merged = new Set([...(existing.userHashes ?? []), ...hashes])
      this.usage().update(existing.id, {
        dau: Math.max(existing.dau ?? 0, report.dau ?? 0, merged.size),
        sessions: existing.sessions + (report.sessions ?? 0),
        ...(merged.size > 0 ? { userHashes: [...merged] } : {}),
      })
    } else {
      this.usage().insert({
        id: newId('agu'),
        agentId,
        date,
        sessions: report.sessions ?? 0,
        calls: 0,
        okCalls: 0,
        tokens: 0,
        totalLatencyMs: 0,
        dau: Math.max(report.dau ?? 0, hashes.length),
        ...(hashes.length > 0 ? { userHashes: hashes } : {}),
      })
    }
  }

  metrics(agentId: string): {
    sessions: number
    calls: number
    successRate: number
    tokens: number
    avgLatencyMs: number
    lastActiveAt: string
    dau: number
    uniqueUsers: number
    gwCalls: number
    series: Array<{ date: string; calls: number; tokens: number; sessions: number; dau: number }>
  } {
    const rows = this.usage().find((item) => item.agentId === agentId).sort((a, b) => a.date.localeCompare(b.date))
    const today = rows.at(-1)
    const calls = rows.reduce((sum, row) => sum + row.calls, 0)
    const okCalls = rows.reduce((sum, row) => sum + row.okCalls, 0)
    const tokens = rows.reduce((sum, row) => sum + row.tokens, 0)
    const latency = rows.reduce((sum, row) => sum + row.totalLatencyMs, 0)
    const gwCalls = rows.reduce((sum, row) => sum + (row.gwCalls ?? 0), 0)
    // 均值分母只取带延迟数据的调用（MCP 网关口径）：网关回灌事件无延迟，摊薄会失真
    const latencyCalls = Math.max(calls - gwCalls, 0)
    return {
      sessions: rows.reduce((sum, row) => sum + row.sessions, 0),
      calls,
      successRate: calls === 0 ? 1 : Math.round((okCalls / calls) * 1000) / 1000,
      tokens,
      avgLatencyMs: latencyCalls === 0 ? 0 : Math.round(latency / latencyCalls),
      lastActiveAt: rows.at(-1)?.updatedAt ?? '',
      // 运营口径（提报）：今日 DAU 与今日对话用户去重数
      dau: today?.dau ?? 0,
      uniqueUsers: today?.userHashes?.length ?? 0,
      gwCalls,
      series: rows.slice(-14).map((row) => ({ date: row.date, calls: row.calls, tokens: row.tokens, sessions: row.sessions, dau: row.dau ?? 0 })),
    }
  }

  overview(): { total: number; online: number; trial: number; draft: number; offline: number } {
    const agents = this.ctx.resourceCore.list('agent')
    return {
      total: agents.length,
      online: agents.filter((item) => item.status === 'online').length,
      trial: agents.filter((item) => item.status === 'trial').length,
      draft: agents.filter((item) => item.status === 'draft').length,
      offline: agents.filter((item) => ['offline', 'archived'].includes(item.status)).length,
    }
  }
}

// ---------------------------------------------------------------------------
// 插件
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    agentRegistry: AgentRegistryService
  }
}

export const name = 'agent'
export const inject = ['opsStorage', 'platformBus', 'resourceCore', 'authn', 'iam', 'audit', 'usage']

export function apply(ctx: Context) {
  const registry = new AgentRegistryService(ctx)
  ctx.plugin(agentTools)
  // L4 审批执行器（闭包直持实例，避免插件注入自身服务的循环等待）
  ctx.effect(() => ctx.audit.registerExecutor('agent.online', async (payload) => {
    return registry.online(String(payload.agentId), 'approval-center')
  }))
  ctx.effect(() => ctx.audit.registerExecutor('agent.offline', async (payload) => {
    return registry.offline(String(payload.agentId), 'approval-center', String(payload.reason ?? '审批通过下线'))
  }))
  migrateAgentCredentialScopes(ctx)
  migrateAgentCredentialConnectorInvoke(ctx)
  migrateAgentCredentialAgentWrite(ctx)
  migrateAgentCredentialModelgwInvoke(ctx)
}

/** 一次性迁移：为存量 Agent 机器凭证补 connector.invoke（幂等标记，先例 agent-scopes-usage-write-v1）。 */
function migrateAgentCredentialConnectorInvoke(ctx: Context): void {
  const markers = ctx.opsStorage.collection<{ id: string; doneAt: string }>('agent:migrations')
  const MARK = 'agent-scopes-connector-invoke-v1'
  if (markers.get(MARK)) return
  let patched = 0
  for (const principal of ctx.authn.principals().find(
    (item) => item.type === 'machine' && item.refType === 'agent' && item.status === 'active' && !item.scopes.includes('connector.invoke'),
  )) {
    ctx.authn.principals().update(principal.id, { scopes: [...principal.scopes, 'connector.invoke'] })
    ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'agent-migration', actorName: '凭证范围迁移',
      action: 'agent.credential.connector-invoke-backfill', resourceType: 'agent',
      resourceId: principal.refId ?? '', resourceName: principal.name, result: 'ok',
      detail: '补入 connector.invoke（连接器纳管数据面对齐）',
    })
    patched++
  }
  markers.insert({ id: MARK, doneAt: new Date().toISOString() })
  if (patched > 0) ctx.logger('agent').info(`存量 Agent 凭证迁移完成：${patched} 条补入 connector.invoke`)
}

/** 一次性迁移：为存量 Agent 机器凭证补 usage.write（幂等标记，防止覆盖后续人工调整的 scopes）。 */
function migrateAgentCredentialScopes(ctx: Context): void {
  const markers = ctx.opsStorage.collection<{ id: string; doneAt: string }>('agent:migrations')
  const MARK = 'agent-scopes-usage-write-v1'
  if (markers.get(MARK)) return
  let patched = 0
  for (const principal of ctx.authn.principals().find(
    (item) => item.type === 'machine' && item.refType === 'agent' && item.status === 'active' && !item.scopes.includes('usage.write'),
  )) {
    ctx.authn.principals().update(principal.id, { scopes: [...principal.scopes, 'usage.write'] })
    ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'agent-migration', actorName: '凭证范围迁移',
      action: 'agent.credential.scopes-backfill', resourceType: 'agent',
      resourceId: principal.refId ?? '', resourceName: principal.name, result: 'ok',
      detail: '补入 usage.write（Agent 自推计量能力对齐）',
    })
    patched++
  }
  markers.insert({ id: MARK, doneAt: new Date().toISOString() })
  if (patched > 0) ctx.logger('agent').info(`存量 Agent 凭证迁移完成：${patched} 条补入 usage.write`)
}

/** 一次性迁移：为存量 Agent 机器凭证补 agent.write（注册后可凭自身凭证提报更新资料，先例 agent-scopes-usage-write-v1）。 */
function migrateAgentCredentialAgentWrite(ctx: Context): void {
  const markers = ctx.opsStorage.collection<{ id: string; doneAt: string }>('agent:migrations')
  const MARK = 'agent-scopes-agent-write-v1'
  if (markers.get(MARK)) return
  let patched = 0
  for (const principal of ctx.authn.principals().find(
    (item) => item.type === 'machine' && item.refType === 'agent' && item.status === 'active' && !item.scopes.includes('agent.write'),
  )) {
    ctx.authn.principals().update(principal.id, { scopes: [...principal.scopes, 'agent.write'] })
    ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'agent-migration', actorName: '凭证范围迁移',
      action: 'agent.credential.agent-write-backfill', resourceType: 'agent',
      resourceId: principal.refId ?? '', resourceName: principal.name, result: 'ok',
      detail: '补入 agent.write（注册后自主提报更新能力对齐）',
    })
    patched++
  }
  markers.insert({ id: MARK, doneAt: new Date().toISOString() })
  if (patched > 0) ctx.logger('agent').info(`存量 Agent 凭证迁移完成：${patched} 条补入 agent.write`)
}

/** 一次性迁移：为存量 Agent 机器凭证补 modelgw.invoke（先例 agent-scopes-connector-invoke-v1）。 */
function migrateAgentCredentialModelgwInvoke(ctx: Context): void {
  const markers = ctx.opsStorage.collection<{ id: string; doneAt: string }>('agent:migrations')
  const MARK = 'agent-scopes-modelgw-invoke-v1'
  if (markers.get(MARK)) return
  let patched = 0
  for (const principal of ctx.authn.principals().find(
    (item) => item.type === 'machine' && item.refType === 'agent' && item.status === 'active' && !item.scopes.includes('modelgw.invoke'),
  )) {
    ctx.authn.principals().update(principal.id, { scopes: [...principal.scopes, 'modelgw.invoke'] })
    ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'agent-migration', actorName: '凭证范围迁移',
      action: 'agent.credential.modelgw-invoke-backfill', resourceType: 'agent',
      resourceId: principal.refId ?? '', resourceName: principal.name, result: 'ok',
      detail: '补入 modelgw.invoke（模型网关调用 + usage.recorded 回灌口径补全）',
    })
    patched++
  }
  markers.insert({ id: MARK, doneAt: new Date().toISOString() })
  if (patched > 0) ctx.logger('agent').info(`存量 Agent 凭证迁移完成：${patched} 条补入 modelgw.invoke`)
}
