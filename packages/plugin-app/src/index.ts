/**
 * @dsh-ops/plugin-app —— AI 应用本体管理（方案 §六）。
 *
 * 复用 resource-core 底座与生命周期，差异部分以扩展 schema 实现：
 * 应用形态/访问入口/发布渠道/Agent 编排拓扑（应用 → Agent → MCP/Skill 一图穿透）。
 * 应用层指标：DAU/MAU、会话深度、留存；成本链路：应用 → Agent → MCP/模型 穿透归集。
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import {
  PlatformEvents, newId,
  type Collection, type RecordBase, type ResourceTypeSpec, type TopologyNode,
} from '../../platform-core/src/index.ts'
import { OidcService } from '../../plugin-authn/src/oidc.ts'
import * as appTools from './tools.ts'
import { APP_TYPE_SPEC } from './schema.ts'
import { buildAppOnboardingPrompt, type AppOnboardingCredential } from './onboarding.ts'

export interface AppUsageRecord extends RecordBase {
  appId: string
  date: string
  dau: number
  sessions: number
  avgDepth: number
  retention7: number
  /** 页面浏览量（同日多次上报累加；接入方主动上报口径）。 */
  pv?: number
  /** 日独立访客（同日多次上报取最大，与 DAU 同语义的 UV 口径）。 */
  uv?: number
}

/**
 * 平台侧自动折算的当日访客底册（trackVisit 维护，与接入方主动上报的 usage 行分离）：
 * 同日 DAU/UV = 集合规模（只增不减），PV 每次到访 +1，汇入 usage 行时经 max/累加语义天然合并。
 */
export interface AppVisitRecord extends RecordBase {
  appId: string
  date: string
  /** 当日经平台身份到访的去重用户（entry-ticket 兑换 / OIDC 发码折算 DAU）。 */
  userIds: string[]
  /** 当日浏览器匿名访客标识（beacon 折算 UV；缺失时平台按 IP+UA 哈希兜底）。 */
  vids: string[]
}

export class AppRegistryService extends Service {
  static readonly provide = 'appRegistry'

  constructor(ctx: Context) {
    super(ctx, 'appRegistry')
    ctx.resourceCore.registerType(APP_TYPE_SPEC)
  }

  usage(): Collection<AppUsageRecord> {
    return this.ctx.opsStorage.collection<AppUsageRecord>('app:usage')
  }

  visits(): Collection<AppVisitRecord> {
    return this.ctx.opsStorage.collection<AppVisitRecord>('app:visits')
  }

  register(input: {
    name: string
    slug?: string
    attrs?: Record<string, unknown>
    ownerId: string
    ownerName: string
    orgId: string
    agentIds?: string[]
    withCredential?: boolean
  }) {
    const agentIds = input.agentIds ?? (Array.isArray(input.attrs?.['agentIds']) ? input.attrs!['agentIds'] as string[] : [])
    for (const agentId of agentIds) {
      const agent = this.ctx.resourceCore.get('agent', agentId)
      if (!agent) throw new Error(`编排的 Agent 不存在：${agentId}`)
      if (agent.status !== 'online') throw new Error(`Agent「${agent.name}」未上线，不能被应用编排`)
    }
    const attrs = { ownerName: input.ownerName, ...(input.attrs ?? {}) }
    const app = this.ctx.resourceCore.create('app', { ...input, attrs })
    this.syncAgentDependencies(app.id, agentIds)
    let credential
    if (input.withCredential !== false) {
      credential = this.ctx.authn.createMachineCredential({
        name: `app:${(app as any).slug}`,
        refType: 'app',
        refId: app.id,
        // app.read/app.write：注册后凭自身凭证即可完成接入验证（读自身）与指标提报/资料更新
        //   （metrics-report、PATCH /api/apps/:id 均要求 app.write）；usage.write：直连消耗自推计量
        scopes: ['mcp.invoke', 'agent.read', 'skill.read', 'app.read', 'app.write', 'usage.write'],
      })
    }
    this.ctx.platformBus.emit(PlatformEvents.AppRegistered, { id: app.id, name: app.name, actor: input.ownerId, type: 'app', slug: app.slug })
    return { app, credential }
  }

  updateApp(appId: string, patch: { name?: string; attrs?: Record<string, unknown> }) {
    const updated = this.ctx.resourceCore.update('app', appId, patch)
    const agentIds = Array.isArray(updated.attrs['agentIds']) ? updated.attrs['agentIds'] as string[] : []
    this.syncAgentDependencies(appId, agentIds)
    this.ctx.platformBus.emit(PlatformEvents.AppUpdated, { id: appId, name: updated.name, actor: 'console' })
    return updated
  }

  /**
   * 生成接入提示词（注册同款模板，平台侧单一事实源）：
   * rotate=true 时轮换机器凭证 secret（旧值立即失效、存量令牌吊销）并随提示词返回；
   * rotate=false 仅含 client_id，secret 以占位符呈现（密钥丢失场景必须 rotate 才能拿到可用凭证）。
   */
  buildOnboardingPrompt(appId: string, origin: string, opts: { rotate?: boolean } = {}): {
    appName: string
    prompt: string
    credential: AppOnboardingCredential
    rotated: boolean
  } {
    const app = this.ctx.resourceCore.get('app', appId)
    if (!app) throw new Error(`应用不存在：${appId}`)
    const principal = this.ctx.authn.principals().findOne((item) => item.refType === 'app' && item.refId === appId)
    if (!principal) throw new Error(`应用机器凭证不存在（可能已被禁用或删除），无法生成接入提示词`)
    let credential: AppOnboardingCredential
    let rotated = false
    if (opts.rotate) {
      const next = this.ctx.authn.rotateMachineCredential(principal.id)
      credential = { clientId: next.principal.clientId, clientSecret: next.clientSecret }
      rotated = true
    } else {
      credential = { clientId: principal.clientId }
    }
    return { appName: app.name, prompt: buildAppOnboardingPrompt(app, credential, origin), credential, rotated }
  }

  /** 应用 → Agent 依赖图维护（编排拓扑数据源）。 */
  private syncAgentDependencies(appId: string, agentIds: string[]): void {
    const existing = this.ctx.resourceCore.dependencies().find((record) => record.fromType === 'app' && record.fromId === appId && record.kind === 'agent')
    const keep = new Set(agentIds)
    for (const record of existing) {
      if (!keep.has(record.toId)) {
        this.ctx.resourceCore.removeDependency({ fromType: 'app', fromId: appId, toType: 'agent', toId: record.toId })
      } else {
        keep.delete(record.toId)
      }
    }
    for (const agentId of keep) {
      this.ctx.resourceCore.addDependency({ fromType: 'app', fromId: appId, toType: 'agent', toId: agentId, kind: 'agent' })
    }
  }

  /** 依赖拓扑可视化：应用 → Agent → MCP/Skill 一图穿透，异常节点可标注。 */
  topology(appId: string): TopologyNode {
    return this.ctx.resourceCore.topology('app', appId, 3)
  }

  // -- 生命周期（同 Agent：L4 审批） --------------------------------------

  requestOnline(appId: string, requester: { id: string; name: string }) {
    const app = this.ctx.resourceCore.get('app', appId)
    if (!app) throw new Error(`应用不存在：${appId}`)
    const errors = this.ctx.resourceCore.validateAttrs('app', app.attrs, 'online')
    if (errors.length > 0) throw new Error(`上线条件不满足：${errors.join('；')}`)
    // 上线门禁（点 1，早反馈）：门禁形态（默认 web,h5）必须有 active SSO 客户端
    const ssoClientId = this.checkSsoGate(app)
    return this.ctx.audit.createApproval({
      kind: 'app.online',
      title: `AI 应用上线：${app.name}`,
      payload: { appId, requesterId: requester.id, ...(ssoClientId !== undefined ? { ssoClientId } : {}) },
      requesterId: requester.id,
      requesterName: requester.name,
    })
  }

  /** SSO 门禁校验：返回 active 客户端 clientId（供审批单快照），违规抛错并指路。 */
  private checkSsoGate(app: { id: string; name: string; attrs: Record<string, unknown> }): string | undefined {
    const enforce = AppRegistryService.ssoEnforceTypes()
    if (enforce.length === 0) return this.activeSsoClient(app.id)?.clientId
    const appType = String(app.attrs['appType'] ?? '')
    if (!enforce.includes(appType)) return this.activeSsoClient(app.id)?.clientId
    const active = this.activeSsoClient(app.id)
    if (!active) {
      throw new Error(`上线门禁：${appType} 形态应用上线前必须完成身份纳管——请在「AI 应用 → 应用详情 → SSO 配置」签发 OIDC 客户端（当前门禁形态：${enforce.join('/')}）`)
    }
    return active.clientId
  }

  requestOffline(appId: string, requester: { id: string; name: string }, reason: string) {
    const app = this.ctx.resourceCore.get('app', appId)
    if (!app) throw new Error(`应用不存在：${appId}`)
    if (!reason?.trim()) throw new Error('下架必须填写原因（护栏要求）')
    return this.ctx.audit.createApproval({
      kind: 'app.offline',
      title: `AI 应用下架：${app.name}`,
      payload: { appId, reason },
      requesterId: requester.id,
      requesterName: requester.name,
    })
  }

  online(appId: string, actor: string) {
    const result = this.ctx.resourceCore.transition('app', appId, 'online', actor)
    this.ctx.platformBus.emit(PlatformEvents.AppOnlined, { id: appId, name: result.entity.name, actor, type: 'app', slug: result.entity.slug })
    return result.entity
  }

  offline(appId: string, actor: string, reason: string) {
    const result = this.ctx.resourceCore.transition('app', appId, 'offline', actor, reason)
    this.ctx.platformBus.emit(PlatformEvents.AppOfflined, { id: appId, name: result.entity.name, actor, reason, type: 'app', slug: result.entity.slug })
    return result.entity
  }

  /** 归档（终态）：下架后的应用彻底退出运营；关联 SSO 客户端经 app.archived 事件联动禁用。 */
  archive(appId: string, actor: string) {
    const result = this.ctx.resourceCore.transition('app', appId, 'archive', actor)
    this.ctx.platformBus.emit(PlatformEvents.AppArchived, { id: appId, name: result.entity.name, actor, type: 'app', slug: result.entity.slug })
    return result.entity
  }

  /** 删除后的关联清理：编排依赖边清除、SSO 客户端与机器凭证禁用；客户端记录与用量/审计数据保留。 */
  purge(appId: string): void {
    for (const record of this.ctx.resourceCore.dependencies().find((item) => item.fromType === 'app' && item.fromId === appId)) {
      this.ctx.resourceCore.dependencies().remove(record.id)
    }
    for (const client of this.ctx.oidc.clientsForApp(appId)) {
      if (OidcService.isClientActive(client)) this.ctx.oidc.disableClient(client.id, '应用删除联动')
    }
    const principal = this.ctx.authn.principals().findOne((item) => item.refType === 'app' && item.refId === appId)
    if (principal && principal.status === 'active') this.ctx.authn.disablePrincipal(principal.id, '应用删除联动')
  }

  // -- SSO 客户端（应用 ↔ 平台身份源打通；owner 自助签发） ----------------------

  /** 上线门禁覆盖的应用形态（APP_SSO_ENFORCE，默认 web,h5；空串可关闭门禁）。 */
  static ssoEnforceTypes(): string[] {
    return String(process.env.APP_SSO_ENFORCE ?? 'web,h5').split(',').map((item) => item.trim()).filter(Boolean)
  }

  /**
   * owner-based 授权（全库首例，非 permission-point 制）：
   * human 且 app.ownerId === userId，或持 authn.oidc.write（管理员兜底）；机器 principal 一律 403。
   */
  assertSsoManage(app: { id: string; name: string; ownerId: string }, caller: { kind: string; userId?: string; permissions: string[] }): void {
    if (caller.kind !== 'human' || !caller.userId) {
      throw new Error('SSO 客户端管理仅限用户身份（owner 校验），机器身份不可操作')
    }
    const isOwner = app.ownerId === caller.userId
    const hasAdmin = caller.permissions.includes('*') || caller.permissions.includes('authn.oidc.write')
    if (!isOwner && !hasAdmin) {
      throw new Error(`仅应用 owner 或持有 authn.oidc.write 的管理员可管理「${app.name}」的 SSO 客户端`)
    }
  }

  /**
   * 回跳地址护栏：https 任意主机；http 仅限内网（环回 / RFC1918 私网 / 链路本地 / IPv6 ULA）。
   * 纯内网部署可用 APP_SSO_ALLOW_HTTP=1 放开全部 http 主机（公网明文回调仍建议 https）。
   * 公共静态：plugin-console 的管理端 OIDC 客户端路由复用同一份口径。
   */
  static assertRedirectUris(uris: string[]): void {
    if (!Array.isArray(uris) || uris.length === 0) throw new Error('redirectUris 必填（至少一个回调地址）')
    const allowAnyHttp = String(process.env.APP_SSO_ALLOW_HTTP ?? '') === '1'
    for (const uri of uris) {
      let parsed: URL
      try { parsed = new URL(uri) } catch { throw new Error(`回调地址非法：${uri}`) }
      if (parsed.protocol === 'https:') continue
      if (parsed.protocol === 'http:' && (allowAnyHttp || AppRegistryService.isIntranetHost(parsed.hostname))) continue
      throw new Error(`回调地址必须为 https://，或 http:// 的内网地址（localhost / 127.0.0.1 / 10.x / 172.16-31.x / 192.168.x）（收到：${uri}）`)
    }
  }

  /** 内网主机判定：环回、RFC1918 私网、链路本地、IPv6 ULA。 */
  private static isIntranetHost(hostname: string): boolean {
    const host = hostname.toLowerCase().replace(/^\[|\]$/g, '')
    if (host === 'localhost' || host === '::1') return true
    if (host.includes(':')) return host.startsWith('f') || host.startsWith('fd') // fc00::/7 ULA
    const parts = host.split('.')
    if (parts.length !== 4 || parts.some((part) => !/^\d+$/.test(part))) return false // 非点分 IPv4 一律按公网处理
    const [a, b] = parts.map(Number) as [number, number]
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254)
  }

  activeSsoClient(appId: string) {
    return this.ctx.oidc.clientsForApp(appId).find((client) => OidcService.isClientActive(client))
  }

  /** 签发应用关联 OIDC 客户端（name=应用名，回填 refType/refId）；secret 仅本次返回。 */
  createSsoClient(appId: string, input: {
    redirectUris: string[]
    clientType?: 'confidential' | 'public'
    consentRequired?: boolean
    postLogoutUris?: string[]
    description?: string
  }): { client: ReturnType<OidcService['clientsForApp']>[number]; clientSecret: string } {
    const app = this.ctx.resourceCore.get('app', appId)
    if (!app) throw new Error(`应用不存在：${appId}`)
    AppRegistryService.assertRedirectUris(input.redirectUris)
    const existing = this.ctx.oidc.clientsForApp(appId)
    if (existing.length > 0) throw new Error(`该应用已签发 SSO 客户端（${existing[0]!.clientId}），请直接管理或先禁用后重新签发`)
    const created = this.ctx.oidc.createClient({
      name: app.name,
      redirectUris: input.redirectUris,
      ...(input.clientType !== undefined ? { clientType: input.clientType } : {}),
      ...(input.consentRequired !== undefined ? { consentRequired: input.consentRequired } : {}),
      ...(input.postLogoutUris !== undefined ? { postLogoutUris: input.postLogoutUris } : {}),
      ...(input.description !== undefined ? { description: input.description } : {}),
      refType: 'app',
      refId: appId,
    })
    return created
  }

  updateSsoClient(appId: string, patch: { redirectUris?: string[]; description?: string; consentRequired?: boolean; postLogoutUris?: string[] }) {
    this.requireSsoClient(appId)
    if (patch.redirectUris !== undefined) AppRegistryService.assertRedirectUris(patch.redirectUris)
    return this.ctx.oidc.updateClient(this.requireSsoClient(appId).id, patch)
  }

  rotateSsoSecret(appId: string) {
    return this.ctx.oidc.rotateSecret(this.requireSsoClient(appId).id)
  }

  disableSsoClient(appId: string, reason: string) {
    return this.ctx.oidc.disableClient(this.requireSsoClient(appId).id, reason)
  }

  enableSsoClient(appId: string) {
    return this.ctx.oidc.enableClient(this.requireSsoClient(appId).id)
  }

  private requireSsoClient(appId: string) {
    const clients = this.ctx.oidc.clientsForApp(appId)
    if (clients.length === 0) throw new Error(`该应用尚未签发 SSO 客户端`)
    return clients[0]!
  }

  // -- 应用层指标 ---------------------------------------------------------

  /**
   * 记录应用层指标（外部应用主动上报通道：REST /api/apps/:id/metrics-report、
   * 工具 app_metrics_report、CLI app report 均汇入此方法）。
   * 语义：同日 DAU/UV 取最大、会话数/PV 累加；可指定 date 补录历史（YYYY-MM-DD）。
   */
  recordUsage(appId: string, usage: { dau?: number; sessions?: number; avgDepth?: number; retention7?: number; pv?: number; uv?: number; date?: string }): void {
    if (!this.ctx.resourceCore.get('app', appId)) throw new Error(`应用不存在：${appId}`)
    const date = usage.date ?? new Date().toISOString().slice(0, 10)
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error(`date 格式非法：${date}（应为 YYYY-MM-DD）`)
    const existing = this.usage().findOne((item) => item.appId === appId && item.date === date)
    if (existing) {
      this.usage().update(existing.id, {
        dau: Math.max(existing.dau, usage.dau ?? existing.dau),
        sessions: existing.sessions + (usage.sessions ?? 0),
        avgDepth: usage.avgDepth ?? existing.avgDepth,
        retention7: usage.retention7 ?? existing.retention7,
        pv: (existing.pv ?? 0) + (usage.pv ?? 0),
        uv: Math.max(existing.uv ?? 0, usage.uv ?? 0),
      })
    } else {
      this.usage().insert({
        id: newId('apu'),
        appId,
        date,
        dau: usage.dau ?? 0,
        sessions: usage.sessions ?? 0,
        avgDepth: usage.avgDepth ?? 0,
        retention7: usage.retention7 ?? 0,
        pv: usage.pv ?? 0,
        uv: usage.uv ?? 0,
      })
    }
  }

  /**
   * 平台侧自动折算访客指标（区别于接入方主动上报 recordUsage）：
   *   - entry-ticket 兑换 / OIDC 发码 → 平台身份访客（按 userId 去重，折算 DAU）；
   *   - 浏览器 beacon → 匿名访客（按 vid 去重，折算 UV）+ PV 逐次累加。
   * 同一日集合只增不减，DAU/UV 以集合规模经 recordUsage 的 max 语义汇入、PV 走累加；
   * 未知应用静默忽略（公开 beacon 端点不得向调用方泄露应用存在性）。
   */
  trackVisit(appId: string, visitor: { userId?: string; vid?: string; pv?: number }): void {
    if (!this.ctx.resourceCore.get('app', appId)) return
    const userId = visitor.userId === undefined ? undefined : String(visitor.userId).trim().slice(0, 128)
    const vid = visitor.vid === undefined ? undefined : String(visitor.vid).trim().slice(0, 128)
    const pv = Math.max(0, Math.min(10, Math.floor(Number(visitor.pv ?? 0)) || 0))
    if (!userId && !vid && pv === 0) return
    const date = new Date().toISOString().slice(0, 10)
    const record = this.visits().findOne((item) => item.appId === appId && item.date === date)
      ?? this.visits().insert({ id: newId('apv'), appId, date, userIds: [], vids: [] })
    // 单应用单日底册封顶（公开端点写入面，防异常膨胀；正常内网流量远达不到）
    const CAP = 10_000
    const userIds = record.userIds ?? []
    const vids = record.vids ?? []
    if (userId && !userIds.includes(userId) && userIds.length < CAP) userIds.push(userId)
    if (vid && !vids.includes(vid) && vids.length < CAP) vids.push(vid)
    this.visits().update(record.id, { userIds, vids })
    this.pruneVisits()
    this.recordUsage(appId, {
      ...(pv > 0 ? { pv } : {}),
      dau: userIds.length,
      uv: userIds.length + vids.length,
    })
  }

  /** 访客底册保留 31 天（仅服务当日折算与对账，久置无价值）。 */
  private pruneVisits(): void {
    const cutoff = new Date(Date.now() - 31 * 86_400_000).toISOString().slice(0, 10)
    for (const record of this.visits().find((item) => item.date < cutoff)) this.visits().remove(record.id)
  }

  metrics(appId: string): {
    dau: number
    mau: number
    pv: number
    uv: number
    sessions: number
    avgDepth: number
    retention7: number
    series: Array<{ date: string; dau: number; pv: number; uv: number; sessions: number }>
  } {
    const rows = this.usage().find((item) => item.appId === appId).sort((a, b) => a.date.localeCompare(b.date))
    const today = rows.at(-1)
    const last30 = rows.slice(-30)
    return {
      dau: today?.dau ?? 0,
      mau: last30.reduce((sum, row) => sum + row.dau, 0),
      pv: today?.pv ?? 0,
      uv: today?.uv ?? 0,
      sessions: rows.reduce((sum, row) => sum + row.sessions, 0),
      avgDepth: Math.round((rows.reduce((sum, row) => sum + row.avgDepth, 0) / Math.max(1, rows.length)) * 10) / 10,
      retention7: today?.retention7 ?? 0,
      series: rows.slice(-14).map((row) => ({ date: row.date, dau: row.dau, pv: row.pv ?? 0, uv: row.uv ?? 0, sessions: row.sessions })),
    }
  }

  overview(): { total: number; online: number; trial: number } {
    const apps = this.ctx.resourceCore.list('app')
    return {
      total: apps.length,
      online: apps.filter((item) => item.status === 'online').length,
      trial: apps.filter((item) => item.status === 'trial').length,
    }
  }

  /** 成本穿透：应用 → Agent → MCP/模型。 */
  costBreakdown(appId: string): Array<{ agentName: string; llmTokens: number; toolCalls: number; costYuan: number }> {
    const rows: Array<{ agentName: string; llmTokens: number; toolCalls: number; costYuan: number }> = []
    const deps = this.ctx.resourceCore.dependencies().find((record) => record.fromType === 'app' && record.fromId === appId && record.kind === 'agent')
    for (const dep of deps) {
      const agent = this.ctx.resourceCore.get('agent', dep.toId)
      const costs = this.ctx.audit.costs().find((cost) => cost.agentId === dep.toId)
      rows.push({
        agentName: agent?.name ?? dep.toId,
        llmTokens: costs.reduce((sum, cost) => sum + cost.llmTokens, 0),
        toolCalls: costs.reduce((sum, cost) => sum + cost.toolCalls, 0),
        costYuan: Math.round(costs.reduce((sum, cost) => sum + cost.costYuan, 0) * 1000) / 1000,
      })
    }
    return rows.sort((a, b) => b.costYuan - a.costYuan)
  }
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    appRegistry: AppRegistryService
  }
}

export const name = 'app'
export const inject = ['opsStorage', 'platformBus', 'resourceCore', 'authn', 'oidc', 'audit']

export function apply(ctx: Context) {
  const registry = new AppRegistryService(ctx)
  ctx.plugin(appTools)
  // 平台侧自动折算（指标口径补全）：SSO 身份到访 → 应用 DAU，经事件总线解耦（不直连 authn/console）。
  // entry-ticket 兑换（console 发射）与 OIDC 发码（authn OidcService 发射）都代表用户已带平台身份进入应用。
  ctx.platformBus.on(PlatformEvents.EntryTicketRedeemed, (payload) => {
    const p = payload as { refType?: string; refId?: string; userId?: string }
    if (p.refType === 'app' && p.refId && p.userId) {
      try { registry.trackVisit(p.refId, { userId: p.userId }) } catch (error) { ctx.logger('app').warn('entry-ticket 兑换折算 DAU 失败', error) }
    }
  })
  ctx.platformBus.on(PlatformEvents.OidcAuthorizeGranted, (payload) => {
    const p = payload as { clientId?: string; userId?: string }
    const client = p.clientId !== undefined ? ctx.oidc.clientByClientId(p.clientId) : undefined
    if (client?.refType === 'app' && client.refId && p.userId) {
      try { registry.trackVisit(client.refId, { userId: p.userId }) } catch (error) { ctx.logger('app').warn('OIDC 发码折算 DAU 失败', error) }
    }
  })
  ctx.effect(() => ctx.audit.registerExecutor('app.online', async (payload) => {
    // 上线门禁（点 2，兜底）：审批挂单期间客户端可能被禁用——执行前复核，失效则执行失败留痕
    const app = ctx.resourceCore.get('app', String(payload['appId']))
    if (app) {
      const enforce = AppRegistryService.ssoEnforceTypes()
      const appType = String(app.attrs['appType'] ?? '')
      if (enforce.includes(appType) && !registry.activeSsoClient(app.id)) {
        throw new Error(`执行期复核失败：审批期间 SSO 客户端已失效（${appType} 形态门禁），请重新签发后再发起上线`)
      }
    }
    return registry.online(String(payload['appId']), 'approval-center')
  }))
  ctx.effect(() => ctx.audit.registerExecutor('app.offline', async (payload) => {
    return registry.offline(String(payload['appId']), 'approval-center', String(payload['reason'] ?? '审批通过下架'))
  }))
  migrateAppCredentialScopes(ctx)
}

/** 一次性迁移：为存量应用机器凭证补 app.read/app.write/usage.write（接入验证与指标提报/资料更新能力对齐）。 */
function migrateAppCredentialScopes(ctx: Context): void {
  const markers = ctx.opsStorage.collection<{ id: string; doneAt: string }>('app:migrations')
  const MARK = 'app-scopes-self-serve-v1'
  if (markers.get(MARK)) return
  const ADDITIONS = ['app.read', 'app.write', 'usage.write']
  let patched = 0
  for (const principal of ctx.authn.principals().find(
    (item) => item.type === 'machine' && item.refType === 'app' && item.status === 'active' && ADDITIONS.some((scope) => !item.scopes.includes(scope)),
  )) {
    const merged = [...principal.scopes, ...ADDITIONS.filter((scope) => !principal.scopes.includes(scope))]
    ctx.authn.principals().update(principal.id, { scopes: merged })
    ctx.audit.record({
      type: 'change', actorType: 'system', actorId: 'app-migration', actorName: '凭证范围迁移',
      action: 'app.credential.scopes-backfill', resourceType: 'app',
      resourceId: principal.refId ?? '', resourceName: principal.name, result: 'ok',
      detail: `补入 ${ADDITIONS.filter((scope) => !principal.scopes.includes(scope)).join('/')}（应用自主接入与提报更新能力对齐）`,
    })
    patched++
  }
  markers.insert({ id: MARK, doneAt: new Date().toISOString() })
  if (patched > 0) ctx.logger('app').info(`存量应用凭证迁移完成：${patched} 条补入 ${ADDITIONS.join('/')}`)
}
