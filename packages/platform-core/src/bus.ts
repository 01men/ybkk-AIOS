/**
 * 平台事件总线：插件协作的唯一胶水。
 * 原则：状态变更必发事件；跨插件联动只许通过事件或扩展点，禁止直连对方数据。
 *
 * 事件源校验（生态设计 v1.2 第 3 步，S3/F3 消解）：
 *   - 平台命名空间事件（iam.* / authn.* / mcp.* …）只允许平台内部发射——
 *     携带 plugin: 来源的发射一律拒绝，杜绝第三方插件伪造平台事件；
 *   - 第三方插件事件必须收敛在 plugin:<id>: 前缀内，且 source 必须与插件身份一致；
 *   - 校验落点在本总线（独立自实现 pub/sub，不经 cordis 事件系统），
 *     配合轻量代理 ctx（plugin-ctx.ts）与 lint/静态扫描三层防线。
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'

export interface PlatformEvent {
  id: number
  name: string
  payload: unknown
  at: string
  /** 事件来源：缺省=平台内部；plugin:<id>=第三方插件（强制与事件名前缀一致）。 */
  source?: string
}

export type BusListener = (payload: unknown, event: PlatformEvent) => void

/** 平台级事件名常量（与各插件 manifest/events.yaml 对应）。 */
export const PlatformEvents = {
  UserFrozen: 'iam.user.frozen',
  UserActivated: 'iam.user.activated',
  OrgChanged: 'iam.org.changed',
  PermissionChanged: 'iam.permission.changed',
  TokenIssued: 'authn.token.issued',
  TokenRevoked: 'authn.token.revoked',
  McpDeployed: 'mcp.deployed',
  McpOfflined: 'mcp.offlined',
  McpUnhealthy: 'mcp.unhealthy',
  McpInvoked: 'mcp.invoked',
  // 连接器纳管（open-connector 融合；前缀已在本文件预留清单）
  ConnectorGatewayChanged: 'connector.gateway.changed',
  ConnectorGatewaySynced: 'connector.gateway.synced',
  ConnectorGatewayUnhealthy: 'connector.gateway.unhealthy',
  ConnectorConnected: 'connector.connected',
  ConnectorDisconnected: 'connector.disconnected',
  ConnectorInvoked: 'connector.invoked',
  ConnectorPermGroupChanged: 'connector.permgroup.changed',
  NasRegistered: 'nas.registered',
  NasOnlined: 'nas.onlined',
  NasOfflined: 'nas.offlined',
  SkillSubmitted: 'skill.submitted',
  SkillPublished: 'skill.published',
  SkillDeprecated: 'skill.deprecated',
  SkillInstalled: 'skill.installed',
  SkillUpdated: 'skill.updated',
  SkillPackageReplaced: 'skill.package_replaced',
  AgentRegistered: 'agent.registered',
  AgentOnlined: 'agent.onlined',
  AgentOfflined: 'agent.offlined',
  AppRegistered: 'app.registered',
  AppOnlined: 'app.onlined',
  AppOfflined: 'app.offlined',
  AppUpdated: 'app.updated',
  AppArchived: 'app.archived',
  OidcAuthorizeGranted: 'oidc.authorize.granted',
  OidcAuthorizeDenied: 'oidc.authorize.denied',
  EntryTicketRedeemed: 'authn.entryticket.redeemed',
  ApprovalCreated: 'approval.created',
  ApprovalDecided: 'approval.decided',
  AlertFired: 'audit.alert.fired',
  ConnectorSynced: 'iam.connector.synced',
  PluginSubmitted: 'market.plugin.submitted',
  PluginListed: 'market.plugin.listed',
  PluginInstalledEvent: 'market.plugin.installed',
  WalletChanged: 'wallet.balance.changed',
  LedgerSettled: 'billing.ledger.settled',
  ConnectCodeCreated: 'connect.code.created',
  ConnectClientEnrolled: 'connect.client.enrolled',
  ConnectClientDisabled: 'connect.client.disabled',
  UpdateAvailable: 'platform.update.available',
  UpdateApplied: 'platform.update.applied',
} as const

/** 平台保留命名空间：第三方插件（source=plugin:*）禁止发射。 */
const PLATFORM_RESERVED_PREFIXES = [
  'iam.', 'authn.', 'oidc.', 'mcp.', 'nas.', 'audit.', 'skill.', 'agent.', 'app.',
  'usage.', 'billing.', 'model.', 'market.', 'developer.', 'wallet.',
  'platform.', 'approval.', 'connector.', 'console.', 'connect.',
]

export class PlatformBusService extends Service {
  static readonly provide = 'platformBus'

  private listeners = new Map<string, Set<BusListener>>()
  private wildcard = new Set<BusListener>()
  private seq = 0
  private ring: PlatformEvent[] = []

  constructor(ctx: Context) {
    super(ctx, 'platformBus')
  }

  on(event: string, cb: BusListener): () => void {
    const set = this.listeners.get(event) ?? new Set()
    set.add(cb)
    this.listeners.set(event, set)
    return () => set.delete(cb)
  }

  onAny(cb: BusListener): () => void {
    this.wildcard.add(cb)
    return () => this.wildcard.delete(cb)
  }

  emit(name: string, payload: unknown, options: { source?: string } = {}): PlatformEvent {
    const source = options.source
    if (source !== undefined && source.startsWith('plugin:')) {
      // 第三方发射：事件必须收敛在该插件命名空间，且不得触碰平台保留命名空间
      if (!name.startsWith(`${source}:`)) {
        throw new Error(`[bus] 插件 ${source} 不得发射非自有命名空间事件：${name}（允许前缀 ${source}:）`)
      }
      if (PLATFORM_RESERVED_PREFIXES.some((prefix) => name.startsWith(prefix))) {
        throw new Error(`[bus] 插件 ${source} 不得发射平台保留命名空间事件：${name}`)
      }
    } else if (name.startsWith('plugin:')) {
      // plugin: 命名空间事件必须有对应插件来源
      const pluginId = name.slice(0, name.indexOf(':', 8) === -1 ? name.length : name.indexOf(':', 8))
      throw new Error(`[bus] 插件命名空间事件 ${name} 必须携带来源（source: plugin:…，期望 ${pluginId}）`)
    }
    const event: PlatformEvent = { id: ++this.seq, name, payload, at: new Date().toISOString(), ...(source !== undefined ? { source } : {}) }
    this.ring.push(event)
    if (this.ring.length > 300) this.ring.shift()
    for (const cb of this.listeners.get(name) ?? []) {
      try {
        cb(payload, event)
      } catch (error) {
        console.error(`[bus] 监听器处理 ${name} 异常`, error)
      }
    }
    for (const cb of this.wildcard) {
      try {
        cb(payload, event)
      } catch (error) {
        console.error(`[bus] 通配监听器处理 ${name} 异常`, error)
      }
    }
    return event
  }

  /** 最近事件（平台事件流展示用）。 */
  recent(limit = 50): PlatformEvent[] {
    return this.ring.slice(-limit).reverse()
  }
}
