/**
 * @dsh-ops/plugin-authn —— 统一认证中心。
 *
 * 双轨身份：人（SSO/密码）与机器（Client Credentials）共用一套 Principal 体系。
 * 令牌：HMAC 签名的短期访问令牌（默认 2h，可刷新），支持吊销与密钥轮换。
 * 令牌链（on-behalf-of）：用户 → 应用 → Agent → MCP，act 链在令牌中叠加，审计可还原。
 */
import { createHmac, randomUUID } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import {
  PlatformEvents, generateSecret, newId, sha256Hex,
  type Collection, type RecordBase,
} from '../../platform-core/src/index.ts'
import { PermissionCatalog } from '../../plugin-iam/src/index.ts'
import * as authnTools from './tools.ts'
import { OidcService } from './oidc.ts'
import { EntryTicketService } from './entry-ticket.ts'

export * from './oidc.ts'
export * from './entry-ticket.ts'

// ---------------------------------------------------------------------------
// 数据模型
// ---------------------------------------------------------------------------

export interface PrincipalRecord extends RecordBase {
  type: 'human' | 'machine'
  /** human: userId；machine: 资源引用（agent:xxx / app:xxx）或自由主体。 */
  refType?: 'user' | 'agent' | 'app' | 'external'
  refId?: string
  name: string
  status: 'active' | 'disabled'
  clientId?: string
  clientSecretHash?: string
  /** 机器角色：引用 iam:roles 的角色 ID，权限随角色实时同步（human 走 user.roleIds，同一存储）。 */
  roleIds?: string[]
  /** 附加直接权限点（与 roleIds 并集生效；须命中权限目录，防拼错）。 */
  scopes: string[]
}

export interface ActEntry {
  principalId: string
  name: string
  type: 'human' | 'machine'
}

export interface TokenRecord extends RecordBase {
  jti: string
  principalId: string
  kind: 'access' | 'machine' | 'refresh'
  scopes: string[]
  /** 受众声明：该令牌只对指定服务/插件有效（生态设计 v1.2 第 1 步收紧）。 */
  audience?: string
  actChain: ActEntry[]
  issuedAt: string
  expiresAt: string
  lastUsedAt?: string
  revokedAt?: string
  revokedReason?: string
  issuedBy: string
  /** 会话 id：封禁/改密/解绑按会话即时吊销（auth-identity docs/06）。 */
  sid?: string
  /** 刷新链 id：refresh token 重放时按链吊销全部令牌。 */
  chainId?: string
  /** refresh token 的 SHA-256 哈希（原文不落库，仅签发时返回一次）。 */
  refreshHash?: string
  /** 已被轮转的时间：再次出现即判定重放。 */
  rotatedAt?: string
}

/** OAuth state 记录（防 CSRF，一次性消费）。 */
export interface OAuthStateRecord extends RecordBase {
  provider: string
  /** 多主体：发起授权时指定的连接器配置实例 id（缺省=该 provider 第一个，旧行为）。 */
  configId?: string
  scene: string
  /** 用途隔离：login=三方登录；bind=已登录账号绑定三方身份（防拿绑定 state 换登录）。 */
  purpose?: 'login' | 'bind'
  /** purpose=bind 时锁定的目标平台账号（authorize 时服务端从会话取，前端不可指定）。 */
  userId?: string
  createdAt: string
  consumedAt?: string
}

/** 三方登录未命中的待绑定票据。 */
export interface SsoTicketRecord extends RecordBase {
  provider: string
  profile: Record<string, string>
  createdAt: string
  expiresAt: string
  usedAt?: string
}

export interface VerifiedPrincipal {
  principal: PrincipalRecord
  token: TokenRecord
  scopes: string[]
  actChain: ActEntry[]
}

// ---------------------------------------------------------------------------
// 服务
// ---------------------------------------------------------------------------

/** 令牌生命周期基线（auth-identity docs/06）：access 30min + refresh 7d 轮转。 */
const ACCESS_TTL_MS = 30 * 60_000
const REFRESH_TTL_MS = 7 * 24 * 3600_000
/** 旧签名密钥的验签宽限期：轮换后旧令牌在窗口内仍可验证，宽限期后自然失效（评审 S2）。 */
const SECRET_GRACE_MS = 24 * 3600_000

/** 登录失败锁定策略（评审 S3）：窗口内连续失败达阈值即锁定，时长逐次升级。 */
const LOGIN_MAX_FAILS = 5
const LOGIN_WINDOW_MS = 15 * 60_000
const LOGIN_BASE_LOCK_MS = 15 * 60_000
const LOGIN_MAX_LOCK_MS = 24 * 3600_000

/** 登录尝试计数（持久化：重启不清零，暴力破解者无法借重启绕过锁定）。 */
export interface LoginAttemptRecord extends RecordBase {
  key: string
  fails: number
  /** 窗口起点（ISO）：窗口滑出后计数自然衰减。 */
  windowStart: string
  lockCount: number
  lockedUntil?: string
}

export class AuthnService extends Service {
  static readonly provide = 'authn'

  private signingSecret: string
  /** 已退役但仍在宽限期内的签名密钥（验签兼容旧令牌）。 */
  private retiredSecrets: Array<{ secret: string; retiredAt: number }> = []
  private refreshIndex = new Map<string, string>()
  private cleanupTimer: ReturnType<typeof setInterval> | undefined

  constructor(ctx: Context) {
    super(ctx, 'authn')
    // 认证数据用 durable 集合：吊销/锁定即时落盘（fsync），返回 200 后被杀不丢失
    this.ctx.opsStorage.collection<TokenRecord>('authn:tokens', { durability: 'durable' })
    this.ctx.opsStorage.collection<LoginAttemptRecord>('authn:loginAttempts', { durability: 'durable' })
    this.ctx.opsStorage.collection<PrincipalRecord>('authn:principals', { durability: 'durable' })
    this.signingSecret = this.loadOrCreateSecret()
    this.loadRetiredSecrets()
    // refresh 哈希索引：替代全表扫描（评审 M2）
    for (const token of this.tokens().all()) {
      if (token.kind === 'refresh' && token.refreshHash) this.refreshIndex.set(token.refreshHash, token.id)
    }
    this.tokens().onChange((change) => {
      const hash = change.record.refreshHash
      if (!hash) return
      if (change.kind === 'remove') this.refreshIndex.delete(hash)
      else this.refreshIndex.set(hash, change.record.id)
    })
    // 过期令牌清理（评审 M2 / 测试 DEF-03：撤销/过期记录不无限增长，小时级巡检控制内存与存储膨胀）：
    // 启动即清 + 每小时巡检
    this.cleanupExpiredTokens()
    this.cleanupTimer = setInterval(() => this.cleanupExpiredTokens(), 3600_000)
    ctx.effect(() => {
      if (this.cleanupTimer) clearInterval(this.cleanupTimer)
    })
    // 事件联动：账号冻结 → 吊销全部令牌；Agent 下线 → 吊销机器凭证
    ctx.platformBus.on(PlatformEvents.UserFrozen, (payload) => {
      const { userId, reason } = payload as { userId: string; reason: string }
      const principal = this.humanPrincipal(userId)
      if (principal) this.revokePrincipalTokens(principal.id, `账号冻结联动：${reason}`)
    })
    ctx.platformBus.on(PlatformEvents.AgentOfflined, (payload) => {
      const { id } = payload as { id: string }
      for (const principal of this.principals().find((item) => item.refType === 'agent' && item.refId === id)) {
        this.disablePrincipal(principal.id, 'Agent 下线联动')
      }
    })
    ctx.platformBus.on(PlatformEvents.AppOfflined, (payload) => {
      const { id } = payload as { id: string }
      for (const principal of this.principals().find((item) => item.refType === 'app' && item.refId === id)) {
        this.disablePrincipal(principal.id, '应用下线联动')
      }
    })
  }

  principals(): Collection<PrincipalRecord> {
    return this.ctx.opsStorage.collection<PrincipalRecord>('authn:principals')
  }

  /** OAuth state（防 CSRF，一次性消费，10 分钟有效）。 */
  oauthStates(): Collection<OAuthStateRecord> {
    return this.ctx.opsStorage.collection<OAuthStateRecord>('authn:oauthStates')
  }

  /** 三方登录未命中时的待绑定票据（5 分钟有效，一次性）。 */
  ssoTickets(): Collection<SsoTicketRecord> {
    return this.ctx.opsStorage.collection<SsoTicketRecord>('authn:ssoTickets')
  }

  // -- 会话令牌对（access + refresh 轮转链） --------------------------------

  /** 签发会话令牌对：access（30min）+ refresh（7d，仅存哈希，单次轮转）。 */
  issueSessionPair(principalId: string, options: { sid?: string; chainId?: string; issuedBy: string }): { token: string; refreshToken: string; access: TokenRecord; sid: string } {
    const sid = options.sid ?? newId('sid')
    const chainId = options.chainId ?? newId('chn')
    const access = this.issueToken(principalId, {
      kind: 'access',
      ttlHours: ACCESS_TTL_MS / 3600_000,
      issuedBy: options.issuedBy,
      sid,
      chainId,
    })
    const refreshRaw = 'dstr_' + randomUUID().replace(/-/g, '') + randomUUID().replace(/-/g, '')
    const refreshJti = randomUUID()
    this.tokens().insert({
      id: refreshJti,
      jti: refreshJti,
      principalId,
      kind: 'refresh',
      scopes: [],
      actChain: [],
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + REFRESH_TTL_MS).toISOString(),
      issuedBy: options.issuedBy,
      sid,
      chainId,
      refreshHash: sha256Hex(refreshRaw),
    })
    return { token: access.token, refreshToken: refreshRaw, access: access.record, sid }
  }

  /** 刷新会话：校验 refresh 哈希 → 重放检测（已轮转的 refresh 再现 → 吊销整链）。 */
  refreshSession(refreshToken: string): { token: string; refreshToken: string; sid: string } {
    const hash = sha256Hex(refreshToken)
    const recordId = this.refreshIndex.get(hash)
    const record = recordId ? this.tokens().get(recordId) : undefined
    if (!record || record.kind !== 'refresh') throw new Error('refresh token 无效')
    if (record.revokedAt) throw new Error('refresh token 已吊销：' + (record.revokedReason ?? ''))
    if (new Date(record.expiresAt).getTime() < Date.now()) throw new Error('refresh token 已过期，请重新登录')
    if (record.rotatedAt) {
      this.revokeChain(record.chainId ?? '', 'refresh token 重放检测（原轮转于 ' + record.rotatedAt + '）')
      throw new Error('检测到 refresh token 重放：该会话整链已吊销，请重新登录')
    }
    this.tokens().update(record.id, { rotatedAt: new Date().toISOString() })
    return this.issueSessionPair(record.principalId, {
      sid: record.sid,
      chainId: record.chainId,
      issuedBy: 'refresh-rotation',
    })
  }

  /** 按链吊销全部令牌。 */
  revokeChain(chainId: string, reason: string): number {
    let count = 0
    for (const token of this.tokens().find((item) => item.chainId === chainId && !item.revokedAt)) {
      this.revokeToken(token.jti, reason)
      count++
    }
    return count
  }

  /** 按会话吊销（登出/封禁/改密即时生效）。 */
  revokeSession(sid: string, reason: string): number {
    let count = 0
    for (const token of this.tokens().find((item) => item.sid === sid && !item.revokedAt)) {
      this.revokeToken(token.jti, reason)
      count++
    }
    return count
  }

  // -- 三方登录（IdentityProviderAdapter 链路，融合 auth-identity docs/03/04）--

  /**
   * 发起三方授权：生成一次性 state，返回授权地址。
   * 钉钉等真实 IdP 要求 redirect_uri 为绝对 URL，origin 由调用方从请求头推导后传入；
   * 缺省时回落相对路径（仅本地/mock 链路可用）。
   * options.purpose='bind' 时用于「已登录账号扫码绑定三方身份」：state 锁定目标 userId，
   * 回调由 GET /api/auth/sso/callback 承接（与登录用途隔离，见 completeSso）。
   * options.configId 指定多主体连接器实例：按其适配器发起授权并记入 state，回调按实例解析。
   * options.promptConsent=true 时强制 IdP 弹授权确认页（刷新老用户授权快照，见 providers.ts）。
   */
  async beginSso(provider: string, scene: 'web_qr' | 'h5' | 'in_app', origin?: string, options: { purpose?: 'login' | 'bind'; userId?: string; configId?: string; promptConsent?: boolean } = {}): Promise<{ authorizeUrl: string | null; state: string }> {
    // 多主体：指定 configId 时按配置实例取适配器并校验平台类型一致，否则取该 provider 第一个（旧行为）
    const adapter = options.configId !== undefined
      ? this.ctx.iam.getAuthProviderByConfig(options.configId)
      : this.ctx.iam.getAuthProvider(provider)
    if (options.configId !== undefined && adapter.type !== provider) {
      throw new Error(`连接器实例（${options.configId}）平台类型 ${adapter.type} 与请求 provider ${provider} 不一致`)
    }
    const state = randomUUID().replace(/-/g, '')
    this.oauthStates().insert({
      id: state,
      createdAt: new Date().toISOString(),
      provider,
      ...(options.configId !== undefined ? { configId: options.configId } : {}),
      scene,
      purpose: options.purpose ?? 'login',
      ...(options.userId !== undefined ? { userId: options.userId } : {}),
    })
    // redirect_uri 优先用连接器配置里的 callbackUrl（须与钉钉后台「安全设置」白名单逐字一致）；
    // 未配置时回落 origin 推导的 /api/auth/sso/callback。
    const configured = (options.configId !== undefined
      ? this.ctx.iam.connectorConfigById(options.configId)?.callbackUrl
      : this.ctx.iam.connectorConfig(provider)?.callbackUrl)?.trim()
    const redirectUri = configured || (origin ? `${origin.replace(/\/+$/, '')}/api/auth/sso/callback` : '/api/auth/sso/callback')
    return { authorizeUrl: await adapter.buildAuthorizeUrl(scene, state, redirectUri, { promptConsent: options.promptConsent ?? false }), state }
  }

  /**
   * 完成三方登录：state 一次性消费 → Adapter 链（exchangeCode/getUserInfo/normalizeProfile）
   * → 命中身份链接直接登录；未命中签发待绑定票据（绑定已有账号 / 注册新账号两分支）。
   */
  async completeSso(provider: string, code: string, state: string): Promise<{ kind: 'hit'; session: { token: string; refreshToken: string; access: TokenRecord; sid: string }; userId: string } | { kind: 'pending'; pendingTicket: string; profileName: string }> {
    const stateRecord = this.oauthStates().get(state)
    if (!stateRecord) throw new Error('state 无效（未发起授权或已消费）')
    if (stateRecord.consumedAt) throw new Error('state 已被使用（防重放）')
    if (stateRecord.purpose === 'bind') throw new Error('state 用途为账号绑定，不能用于登录')
    if (Date.now() - new Date(stateRecord.createdAt).getTime() > 10 * 60_000) throw new Error('state 已过期')
    this.oauthStates().update(state, { consumedAt: new Date().toISOString() })

    // 多主体：以 state 记录为准（provider 参数仅兼容旧调用）；configId 命中时按配置实例取适配器
    const ssoProvider = stateRecord.provider
    const adapter = stateRecord.configId
      ? this.ctx.iam.getAuthProviderByConfig(stateRecord.configId)
      : this.ctx.iam.getAuthProvider(ssoProvider)
    const tokenSet = await adapter.exchangeCode(code) // code 一次性，重放抛 ProviderAuthError
    const raw = await adapter.getUserInfo(tokenSet)
    const profile = adapter.normalizeProfile(raw)

    const link = this.ctx.iam.findLinkByProfile(ssoProvider, profile.providerUserId, profile.corpId)
    if (link) {
      const user = this.ctx.iam.users().get(link.userId)
      if (!user) throw new Error('身份链接指向的账号不存在')
      if (user.status !== 'active') throw new Error('账号状态异常，无法登录')
      const principal = this.ensureHumanPrincipal(user.id, user.displayName)
      const session = this.issueSessionPair(principal.id, { issuedBy: 'sso:' + ssoProvider })
      this.ctx.iam.markLogin(user.id)
      this.ctx.platformBus.emit(PlatformEvents.TokenIssued, { jti: session.access.jti, principalId: principal.id, kind: 'access' })
      return { kind: 'hit', session, userId: user.id }
    }
    const ticket = newId('tkt')
    this.ssoTickets().insert({
      id: ticket,
      provider: ssoProvider,
      profile: {
        providerUserId: profile.providerUserId,
        corpId: profile.corpId,
        name: profile.name,
        ...(profile.email !== undefined ? { email: profile.email } : {}),
      },
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    })
    return { kind: 'pending', pendingTicket: ticket, profileName: profile.name }
  }

  /** 读取 state 记录的用途（回调路由分发用；不消费）。 */
  peekOAuthState(state: string): { provider: string; purpose: 'login' | 'bind'; userId?: string; configId?: string } {
    const record = this.oauthStates().get(state)
    if (!record) throw new Error('state 无效（未发起授权或已消费）')
    return {
      provider: record.provider,
      purpose: record.purpose ?? 'login',
      ...(record.userId !== undefined ? { userId: record.userId } : {}),
      ...(record.configId !== undefined ? { configId: record.configId } : {}),
    }
  }

  /**
   * 完成扫码绑定（purpose=bind）：state 一次性消费 → Adapter 链换 unionId
   * → 绑定到 state 锁定的平台账号。全程无需手工输入任何三方 ID。
   * 「一人一号」由 identityLinks 引擎级唯一约束兜底。
   */
  async completeSsoBind(code: string, state: string): Promise<{ userId: string; provider: string; displayName: string; providerUserId: string }> {
    const stateRecord = this.oauthStates().get(state)
    if (!stateRecord) throw new Error('state 无效（未发起授权或已消费）')
    if (stateRecord.consumedAt) throw new Error('state 已被使用（防重放）')
    if ((stateRecord.purpose ?? 'login') !== 'bind') throw new Error('state 用途不是账号绑定')
    if (!stateRecord.userId) throw new Error('绑定目标账号缺失，请重新发起绑定')
    if (Date.now() - new Date(stateRecord.createdAt).getTime() > 10 * 60_000) throw new Error('state 已过期')
    this.oauthStates().update(state, { consumedAt: new Date().toISOString() })

    // 多主体：state 携带 configId 时按配置实例取适配器，否则取该 provider 第一个（旧行为）
    const adapter = stateRecord.configId
      ? this.ctx.iam.getAuthProviderByConfig(stateRecord.configId)
      : this.ctx.iam.getAuthProvider(stateRecord.provider)
    const tokenSet = await adapter.exchangeCode(code) // code 一次性，重放抛 ProviderAuthError
    const raw = await adapter.getUserInfo(tokenSet)
    const profile = adapter.normalizeProfile(raw)

    const user = this.ctx.iam.users().get(stateRecord.userId)
    if (!user) throw new Error('绑定目标账号不存在')
    if (user.status === 'deactivated') throw new Error('绑定目标账号已注销')
    const existing = this.ctx.iam.findLinkByProfile(stateRecord.provider, profile.providerUserId, profile.corpId)
    if (existing && existing.userId !== user.id) {
      throw new Error('该钉钉身份已绑定其他平台账号（一人一号）')
    }
    if (user.bindings.some((item) => item.provider === stateRecord.provider) && !existing) {
      throw new Error('该账号已绑定钉钉身份，请先解绑再重新绑定')
    }
    if (!existing) {
      this.ctx.iam.linkIdentity(user.id, {
        provider: stateRecord.provider as 'dingtalk',
        providerUserId: profile.providerUserId,
        corpId: profile.corpId,
        displayName: profile.name,
      }, 'sso-bind-oauth')
    }
    return { userId: user.id, provider: stateRecord.provider, displayName: profile.name, providerUserId: profile.providerUserId }
  }

  /** 待绑定票据 → 绑定已有平台账号（校验密码）→ 建立身份链接并登录。 */
  ssoBindExisting(pendingTicket: string, username: string, password: string): { session: { token: string; refreshToken: string; access: TokenRecord; sid: string }; userId: string } {
    const ticket = this.peekTicket(pendingTicket)
    const throttleKey = `sso-bind:${username}`
    this.assertNotLocked(throttleKey)
    let user
    try {
      user = this.ctx.iam.verifyPassword(username, password)
    } catch (error) {
      this.recordLoginFailure(throttleKey)
      throw error
    }
    this.recordLoginSuccess(throttleKey)
    this.ctx.iam.linkIdentity(user.id, {
      provider: ticket.provider as 'dingtalk',
      providerUserId: ticket.profile['providerUserId'] ?? '',
      corpId: ticket.profile['corpId'] ?? '',
      displayName: ticket.profile['name'] ?? '',
    }, 'sso-bind:' + username)
    this.consumeTicket(pendingTicket)
    const principal = this.ensureHumanPrincipal(user.id, user.displayName)
    const session = this.issueSessionPair(principal.id, { issuedBy: 'sso-bind:' + ticket.provider })
    this.ctx.iam.markLogin(user.id)
    return { session, userId: user.id }
  }

  /** 待绑定票据 → 注册新账号（默认落入首个组织）→ 建立身份链接并登录。 */
  ssoRegister(pendingTicket: string): { session: { token: string; refreshToken: string; access: TokenRecord; sid: string }; userId: string } {
    const ticket = this.consumeTicket(pendingTicket)
    void ticket
    const defaultOrg = this.ctx.iam.orgs().all()[0]
    if (!defaultOrg) throw new Error('平台尚未初始化组织，无法注册')
    const username = ticket.provider + '_' + (ticket.profile['providerUserId'] ?? '')
    const { user } = this.ctx.iam.createUser({
      username,
      displayName: ticket.profile['name'] ?? username,
      orgId: defaultOrg.id,
      email: ticket.profile['email'],
    })
    this.ctx.iam.activateUser(user.id)
    this.ctx.iam.linkIdentity(user.id, {
      provider: ticket.provider as 'dingtalk',
      providerUserId: ticket.profile['providerUserId'] ?? '',
      corpId: ticket.profile['corpId'] ?? '',
      displayName: ticket.profile['name'] ?? '',
    }, 'sso-register')
    const principal = this.ensureHumanPrincipal(user.id, user.displayName)
    const session = this.issueSessionPair(principal.id, { issuedBy: 'sso-register:' + ticket.provider })
    this.ctx.iam.markLogin(user.id)
    return { session, userId: user.id }
  }

  /** 读取票据（不消费）。 */
  private peekTicket(pendingTicket: string): { provider: string; profile: Record<string, string> } {
    const ticket = this.ssoTickets().get(pendingTicket)
    if (!ticket) throw new Error('待绑定票据无效')
    if (ticket.usedAt) throw new Error('票据已被使用')
    if (new Date(ticket.expiresAt).getTime() < Date.now()) throw new Error('票据已过期，请重新发起授权')
    return { provider: ticket.provider, profile: ticket.profile }
  }

  private consumeTicket(pendingTicket: string): { provider: string; profile: Record<string, string> } {
    const ticket = this.ssoTickets().get(pendingTicket)
    if (!ticket) throw new Error('待绑定票据无效')
    if (ticket.usedAt) throw new Error('票据已被使用')
    if (new Date(ticket.expiresAt).getTime() < Date.now()) throw new Error('票据已过期，请重新发起授权')
    this.ssoTickets().update(pendingTicket, { usedAt: new Date().toISOString() })
    return { provider: ticket.provider, profile: ticket.profile }
  }

  tokens(): Collection<TokenRecord> {
    return this.ctx.opsStorage.collection<TokenRecord>('authn:tokens')
  }

  private loadOrCreateSecret(): string {
    const file = join(this.ctx.opsStorage.dataDirPath, 'authn-signing-secret')
    try {
      if (existsSync(file)) return readFileSync(file, 'utf8').trim()
      mkdirSync(this.ctx.opsStorage.dataDirPath, { recursive: true })
      const secret = generateSecret('sign')
      writeFileSync(file, secret, { encoding: 'utf8', mode: 0o600 })
      return secret
    } catch (error) {
      // 降级为进程内密钥必须显式告警（重启即令牌全部失效，不可静默）
      console.error('[authn] 签名密钥读取/落盘失败，降级为进程内密钥（重启后所有令牌失效）', error)
      return generateSecret('sign')
    }
  }

  private loadRetiredSecrets(): void {
    try {
      const file = join(this.ctx.opsStorage.dataDirPath, 'authn-signing-secret-history.json')
      if (!existsSync(file)) return
      const stored = JSON.parse(readFileSync(file, 'utf8')) as Array<{ secret: string; retiredAt: number }>
      const cutoff = Date.now() - SECRET_GRACE_MS
      this.retiredSecrets = stored.filter((item) => item.retiredAt > cutoff)
    } catch { /* 历史文件缺失/损坏：视为无宽限密钥 */ }
  }

  private saveRetiredSecrets(): void {
    try {
      const file = join(this.ctx.opsStorage.dataDirPath, 'authn-signing-secret-history.json')
      writeFileSync(file, JSON.stringify(this.retiredSecrets, null, 2), 'utf8')
    } catch (error) {
      console.error('[authn] 退役密钥历史落盘失败（仅影响轮换宽限）', error)
    }
  }

  /**
   * 轮换签名密钥（评审 S2 修复）：旧密钥进入宽限期（默认 24h）而非立即作废——
   * 宽限期内旧令牌仍可通过验签（在途请求不掉线），宽限期后自然失效；
   * 会话可随时用 refresh token 换取新密钥签发的访问令牌，全局无感轮换。
   */
  rotateSigningSecret(): { graceMs: number } {
    this.retiredSecrets = [
      ...this.retiredSecrets.filter((item) => Date.now() - item.retiredAt < SECRET_GRACE_MS),
      { secret: this.signingSecret, retiredAt: Date.now() },
    ]
    this.signingSecret = generateSecret('sign')
    const file = join(this.ctx.opsStorage.dataDirPath, 'authn-signing-secret')
    writeFileSync(file, this.signingSecret, 'utf8')
    this.saveRetiredSecrets()
    return { graceMs: SECRET_GRACE_MS }
  }

  /** 校验签名：先当前密钥，再宽限期内的退役密钥（轮换在途兼容）。 */
  private signatureMatches(body: string, signature: string): boolean {
    const candidates = [this.signingSecret, ...this.retiredSecrets.filter((item) => Date.now() - item.retiredAt < SECRET_GRACE_MS).map((item) => item.secret)]
    return candidates.some((secret) => createHmac('sha256', secret).update(body).digest('base64url') === signature)
  }

  /** 清理过期/吊销令牌（评审 M2）：过期 7 天后物理删除（保留一个 refresh 周期用于重放取证），撤销状态不再无限累积。 */
  cleanupExpiredTokens(): number {
    const cutoff = Date.now() - 7 * 24 * 3600_000
    let removed = 0
    for (const token of this.tokens().all()) {
      if (new Date(token.expiresAt).getTime() < cutoff) {
        if (this.tokens().remove(token.id)) removed++
      }
    }
    return removed
  }

  // -- Principal ----------------------------------------------------------

  humanPrincipal(userId: string): PrincipalRecord | undefined {
    return this.principals().findOne((item) => item.type === 'human' && item.refId === userId)
  }

  ensureHumanPrincipal(userId: string, name: string): PrincipalRecord {
    const existing = this.humanPrincipal(userId)
    if (existing) return existing
    return this.principals().insert({
      id: newId('pri'),
      type: 'human',
      refType: 'user',
      refId: userId,
      name,
      status: 'active',
      scopes: [],
    })
  }

  /** 创建机器身份凭证（Client Credentials）。secret 仅返回一次；授权 = 机器角色（roleIds，实时同步）+ 附加权限点（scopes，须命中权限目录）。 */
  createMachineCredential(input: {
    name: string
    refType?: 'agent' | 'app' | 'external'
    refId?: string
    roleIds?: string[]
    scopes: string[]
  }): { principal: PrincipalRecord; clientId: string; clientSecret: string } {
    this.assertMachineScopes(input.scopes)
    this.assertMachineRoles(input.roleIds ?? [])
    if ((input.roleIds ?? []).length === 0 && input.scopes.length === 0) throw new Error('授权不能为空：至少选择机器角色或附加权限点')
    const clientId = `mc-${newId('id').slice(3)}`
    const clientSecret = generateSecret('cs')
    const principal = this.principals().insert({
      id: newId('pri'),
      type: 'machine',
      ...(input.refType !== undefined ? { refType: input.refType } : {}),
      ...(input.refId !== undefined ? { refId: input.refId } : {}),
      name: input.name,
      status: 'active',
      clientId,
      clientSecretHash: sha256Hex(clientSecret),
      ...((input.roleIds ?? []).length > 0 ? { roleIds: input.roleIds } : {}),
      scopes: input.scopes,
    })
    return { principal, clientId, clientSecret }
  }

  disablePrincipal(id: string, reason: string): PrincipalRecord {
    const principal = this.principals().get(id)
    if (!principal) throw new Error(`身份不存在：${id}`)
    this.revokePrincipalTokens(id, reason)
    return this.principals().update(id, { status: 'disabled' })
  }

  /** 校验机器身份附加权限点：恰为 ['*'] 或全部命中权限目录（防拼错，如 usage.wrtie）；可空（授权可全部来自机器角色）。 */
  private assertMachineScopes(scopes: string[]): void {
    if (scopes.length === 0) return
    if (scopes.includes('*')) {
      if (scopes.length !== 1) throw new Error("'*' 不可与其他权限点混用")
      return
    }
    const catalog = new Set(PermissionCatalog.map((item) => item.point))
    const invalid = scopes.filter((scope) => !catalog.has(scope))
    if (invalid.length > 0) throw new Error(`非法权限点：${invalid.join('、')}（须为权限目录中的点，或仅 '*'）`)
  }

  /** 校验机器角色引用：角色必须真实存在（共用 iam:roles 存储）。 */
  private assertMachineRoles(roleIds: string[]): void {
    for (const roleId of roleIds) {
      if (!this.ctx.iam.roles().get(roleId)) throw new Error(`机器角色不存在：${roleId}`)
    }
  }

  /** 机器主体生效权限 = 角色权限（通配符展开，实时同步）∪ 附加直接权限点。 */
  resolveMachineScopes(principal: PrincipalRecord): string[] {
    const fromRoles = this.ctx.iam.resolveRolePermissions(principal.roleIds ?? [])
    if (fromRoles.includes('*') || principal.scopes.includes('*')) return ['*']
    const merged = new Set([...fromRoles, ...principal.scopes])
    return [...merged]
  }

  /** 调整机器身份授权（机器角色 / 附加权限点）；联动吊销全部存量令牌（收权即时生效，下次换牌按新范围签发）。 */
  updateMachineScopes(id: string, patch: { roleIds?: string[]; scopes?: string[] }): PrincipalRecord {
    const principal = this.principals().get(id)
    if (!principal) throw new Error(`身份不存在：${id}`)
    if (principal.type !== 'machine') throw new Error('仅机器身份支持调整权限范围')
    const roleIds = patch.roleIds ?? principal.roleIds ?? []
    const scopes = patch.scopes ?? principal.scopes
    this.assertMachineScopes(scopes)
    this.assertMachineRoles(roleIds)
    if (roleIds.length === 0 && scopes.length === 0) throw new Error('授权不能为空：至少保留机器角色或附加权限点')
    const updated = this.principals().update(id, {
      ...(patch.roleIds !== undefined ? { roleIds } : {}),
      ...(patch.scopes !== undefined ? { scopes } : {}),
    })
    this.revokePrincipalTokens(id, '权限范围调整联动')
    return updated
  }

  /** 轮换机器凭证密钥：clientId 不变，旧 secret 立即失效，存量令牌全部吊销；新 secret 仅此一次返回。 */
  rotateMachineCredential(id: string): { principal: PrincipalRecord; clientSecret: string } {
    const principal = this.principals().get(id)
    if (!principal) throw new Error(`身份不存在：${id}`)
    if (principal.type !== 'machine' || !principal.clientId) throw new Error('仅机器凭证（clientId/clientSecret）支持轮换')
    const clientSecret = generateSecret('cs')
    const updated = this.principals().update(id, { clientSecretHash: sha256Hex(clientSecret) })
    this.revokePrincipalTokens(id, '凭证轮换联动')
    return { principal: updated, clientSecret }
  }

  enablePrincipal(id: string): PrincipalRecord {
    return this.principals().update(id, { status: 'active' })
  }

  // -- 登录 ---------------------------------------------------------------

  /** 登录尝试计数集合（durable：重启不清零）。 */
  loginAttempts(): Collection<LoginAttemptRecord> {
    const collection = this.ctx.opsStorage.collection<LoginAttemptRecord>('authn:loginAttempts')
    collection.uniqueOn('login_attempt_key', (item) => item.key)
    return collection
  }

  /** 锁定校验：命中锁定窗口直接拒绝（评审 S3：暴力破解面收敛；OIDC 授权/换牌端点复用）。 */
  assertNotLocked(key: string): void {
    const record = this.loginAttempts().findOne((item) => item.key === key)
    if (!record?.lockedUntil) return
    const remainMs = new Date(record.lockedUntil).getTime() - Date.now()
    if (remainMs > 0) {
      const minutes = Math.ceil(remainMs / 60_000)
      throw new Error(`失败次数过多已锁定：请约 ${minutes} 分钟后重试（或联系管理员重置）`)
    }
  }

  recordLoginFailure(key: string): void {
    const collection = this.loginAttempts()
    const now = Date.now()
    const existing = collection.findOne((item) => item.key === key)
    if (!existing) {
      collection.insert({ id: newId('lga'), key, fails: 1, windowStart: new Date().toISOString(), lockCount: 0 })
      return
    }
    // 窗口滑出后重新计数
    const inWindow = now - new Date(existing.windowStart).getTime() < LOGIN_WINDOW_MS
    const fails = inWindow ? existing.fails + 1 : 1
    const patch: Partial<LoginAttemptRecord> = {
      fails,
      ...(inWindow ? {} : { windowStart: new Date().toISOString() }),
    }
    if (fails >= LOGIN_MAX_FAILS) {
      const lockCount = existing.lockCount + 1
      const lockMs = Math.min(LOGIN_BASE_LOCK_MS * 2 ** (lockCount - 1), LOGIN_MAX_LOCK_MS)
      patch.lockCount = lockCount
      patch.lockedUntil = new Date(now + lockMs).toISOString()
      patch.fails = 0
      this.ctx.platformBus.emit(PlatformEvents.AlertFired, {
        id: newId('alt'), severity: 'warning', title: '登录失败锁定触发',
        message: `主体 ${key} 在 ${LOGIN_WINDOW_MS / 60_000} 分钟内连续失败 ${LOGIN_MAX_FAILS} 次，锁定 ${Math.round(lockMs / 60_000)} 分钟（暴力破解防护）`,
        resourceType: 'authn', resourceId: key,
      })
    }
    collection.update(existing.id, patch)
  }

  recordLoginSuccess(key: string): void {
    const collection = this.loginAttempts()
    const existing = collection.findOne((item) => item.key === key)
    if (existing) collection.remove(existing.id)
  }

  login(username: string, password: string): { token: string; refreshToken: string; sid: string; record: TokenRecord; principal: PrincipalRecord; userId: string } {
    const throttleKey = `login:${username}`
    this.assertNotLocked(throttleKey)
    let user
    try {
      user = this.ctx.iam.verifyPassword(username, password)
    } catch (error) {
      this.recordLoginFailure(throttleKey)
      throw error
    }
    this.recordLoginSuccess(throttleKey)
    const principal = this.ensureHumanPrincipal(user.id, user.displayName)
    const session = this.issueSessionPair(principal.id, { issuedBy: `password:${username}` })
    this.ctx.iam.markLogin(user.id)
    this.ctx.platformBus.emit(PlatformEvents.TokenIssued, { jti: session.access.jti, principalId: principal.id, kind: 'access' })
    return { token: session.token, refreshToken: session.refreshToken, sid: session.sid, record: session.access, principal, userId: user.id }
  }

  clientCredentialsLogin(clientId: string, clientSecret: string): { token: string; record: TokenRecord; principal: PrincipalRecord } {
    const throttleKey = `cc:${clientId}`
    this.assertNotLocked(throttleKey)
    const principal = this.principals().findOne((item) => item.clientId === clientId)
    if (!principal || principal.clientSecretHash !== sha256Hex(clientSecret)) {
      this.recordLoginFailure(throttleKey)
      throw new Error('client_id 或 client_secret 错误')
    }
    this.recordLoginSuccess(throttleKey)
    if (principal.status !== 'active') throw new Error('机器身份已禁用')
    const { token, record } = this.issueToken(principal.id, {
      kind: 'machine',
      ttlHours: 2,
      scopes: this.resolveMachineScopes(principal),
      issuedBy: 'client_credentials',
    })
    this.ctx.platformBus.emit(PlatformEvents.TokenIssued, { jti: record.jti, principalId: principal.id, kind: 'machine' })
    return { token, record, principal }
  }

  // -- 令牌 ---------------------------------------------------------------

  issueToken(principalId: string, options: {
    kind: TokenRecord['kind']
    ttlHours?: number
    scopes?: string[]
    audience?: string
    actChain?: ActEntry[]
    issuedBy?: string
    sid?: string
    chainId?: string
  }): { token: string; record: TokenRecord } {
    const principal = this.principals().get(principalId)
    if (!principal) throw new Error(`身份不存在：${principalId}`)
    if (principal.status !== 'active') throw new Error('身份已禁用，无法签发令牌')
    // 插件受众收敛面（v1.2 第 1 步）：aud 为 plugin:<id> 时，scope 必须全部落在该插件命名空间内
    if (options.audience?.startsWith('plugin:')) {
      const namespace = `${options.audience}:`
      const offender = (options.scopes ?? []).find((scope) => scope !== '*' && !scope.startsWith(namespace))
      if (offender !== undefined) {
        throw new Error(`插件令牌 scope 越界：${offender} 不在命名空间 ${namespace} 内`)
      }
    }
    const jti = randomUUID()
    const issuedAt = new Date()
    const expiresAt = new Date(issuedAt.getTime() + (options.ttlHours ?? 2) * 3600_000)
    const payload = {
      iss: 'dsh-ops-authn',
      sub: principal.id,
      typ: options.kind,
      jti,
      iat: Math.floor(issuedAt.getTime() / 1000),
      exp: Math.floor(expiresAt.getTime() / 1000),
      scope: options.scopes ?? [],
      act: options.actChain ?? [],
      ...(options.audience !== undefined ? { aud: options.audience } : {}),
      ...(options.sid !== undefined ? { sid: options.sid } : {}),
    }
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
    const sig = createHmac('sha256', this.signingSecret).update(body).digest('base64url')
    const token = `dst1.${body}.${sig}`
    const record = this.tokens().insert({
      id: jti,
      jti,
      principalId,
      kind: options.kind,
      scopes: options.scopes ?? [],
      ...(options.audience !== undefined ? { audience: options.audience } : {}),
      actChain: options.actChain ?? [],
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      issuedBy: options.issuedBy ?? 'api',
      ...(options.sid !== undefined ? { sid: options.sid } : {}),
      ...(options.chainId !== undefined ? { chainId: options.chainId } : {}),
    })
    return { token, record }
  }

  /** on-behalf-of：以当前主体身份为另一主体签发透传令牌（act 链叠加）。 */
  issueOnBehalfOf(parent: VerifiedPrincipal, targetPrincipalId: string): { token: string; record: TokenRecord } {
    const target = this.principals().get(targetPrincipalId)
    if (!target) throw new Error(`目标身份不存在：${targetPrincipalId}`)
    const actChain: ActEntry[] = [
      ...parent.actChain,
      { principalId: parent.principal.id, name: parent.principal.name, type: parent.principal.type },
    ]
    return this.issueToken(targetPrincipalId, {
      kind: 'machine',
      ttlHours: 1,
      scopes: intersectScopes(parent.scopes, target.scopes),
      actChain,
      issuedBy: `obo:${parent.principal.id}`,
    })
  }

  /**
   * 校验令牌。options.audience 指定时执行受众校验：令牌 aud 不匹配即拒绝
   * （v1.2 第 1 步：一个泄漏的插件令牌拿不到平台其它服务）。
   */
  verify(tokenString: string, options: { audience?: string } = {}): VerifiedPrincipal {
    const parts = tokenString.split('.')
    if (parts.length !== 3 || parts[0] !== 'dst1') throw new Error('令牌格式不合法')
    if (!this.signatureMatches(parts[1]!, parts[2]!)) throw new Error('令牌签名校验失败')
    let payload: any
    try {
      payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'))
    } catch {
      throw new Error('令牌载荷解析失败')
    }
    if (payload.iss !== 'dsh-ops-authn') throw new Error('令牌签发方（iss）不匹配')
    if (payload.exp * 1000 < Date.now()) throw new Error('令牌已过期')
    if (options.audience !== undefined) {
      if (payload.aud === undefined) throw new Error('令牌未绑定受众（aud），目标服务要求受众校验')
      if (payload.aud !== options.audience) throw new Error(`令牌受众不匹配：期望 ${options.audience}，实际 ${payload.aud}`)
    }
    const record = this.tokens().get(payload.jti)
    if (!record) throw new Error('令牌不存在或已被清理')
    if (record.revokedAt) throw new Error(`令牌已被吊销：${record.revokedReason ?? '策略吊销'}`)
    const principal = this.principals().get(record.principalId)
    if (!principal) throw new Error('令牌主体不存在')
    if (principal.status !== 'active') throw new Error('令牌主体已禁用')
    // 人机均实时解析：human 按用户角色、machine 按机器角色+附加权限点，角色变更即时同步到存量令牌
    const scopes = principal.type === 'human'
      ? this.ctx.iam.userPermissions(principal.refId ?? '')
      : this.resolveMachineScopes(principal)
    this.tokens().update(record.id, { lastUsedAt: new Date().toISOString() })
    return { principal, token: record, scopes, actChain: record.actChain }
  }

  hasPermission(verified: VerifiedPrincipal, point: string): boolean {
    return verified.scopes.includes('*') || verified.scopes.includes(point)
  }

  revokeToken(jti: string, reason: string): TokenRecord {
    const record = this.tokens().get(jti)
    if (!record) throw new Error(`令牌不存在：${jti}`)
    if (record.revokedAt) return record
    const updated = this.tokens().update(record.id, {
      revokedAt: new Date().toISOString(),
      revokedReason: reason,
    })
    this.ctx.platformBus.emit(PlatformEvents.TokenRevoked, { jti, principalId: record.principalId, reason })
    return updated
  }

  revokePrincipalTokens(principalId: string, reason: string): number {
    let count = 0
    for (const token of this.tokens().find((item) => item.principalId === principalId && !item.revokedAt)) {
      this.revokeToken(token.jti, reason)
      count++
    }
    return count
  }

  /** 令牌是否仍活跃（DEF-03：过期/已轮转的记录不计入「活跃令牌」，避免计数随运行时长失真）。 */
  isTokenActive(token: TokenRecord, now = Date.now()): boolean {
    if (token.revokedAt) return false
    if (new Date(token.expiresAt).getTime() <= now) return false
    // 已轮转的 refresh token（同链已换发新令牌）不再是活跃凭证
    if (token.kind === 'refresh' && token.rotatedAt) return false
    return true
  }

  activeTokenCount(principalId: string): number {
    return this.tokens().find((item) => item.principalId === principalId && this.isTokenActive(item)).length
  }
}

function intersectScopes(a: string[], b: string[]): string[] {
  if (a.includes('*')) return [...b]
  if (b.includes('*')) return [...a]
  const setB = new Set(b)
  return a.filter((scope) => setB.has(scope))
}

// ---------------------------------------------------------------------------
// 插件
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    authn: AuthnService
  }
}

export const name = 'authn'
export const inject = ['opsStorage', 'platformBus', 'iam', 'httpServer']

export function apply(ctx: Context) {
  ctx.plugin(AuthnService)
  ctx.plugin(OidcService)
  ctx.plugin(EntryTicketService)
  ctx.plugin(authnTools)
}
