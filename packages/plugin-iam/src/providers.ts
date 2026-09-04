/**
 * IdentityProviderAdapter —— 统一身份源适配层（融合自 OS-skill/auth-identity 模块设计）。
 *
 * 登录主流程只面向本接口编程，不感知钉钉/飞书/企微差异；
 * 新增身份源 = 新增一个 Adapter 实现 + 连接器配置插一行。
 *
 * 双模式（生态设计 v1.2 第 0 步，M7 消解）：
 *   - real ：配置 appKey/appSecret 后走真实钉钉 OpenAPI（可指定 apiBase 指向代理/专有部署）。
 *   - mock ：未配置凭证时的显式降级——内置演示目录，healthCheck 标注 mock:true，禁止冒充真实。
 */

/** 登录场景：四种形态归一为三类（auth-identity docs/04）。 */
export type LoginScene = 'web_qr' | 'h5' | 'in_app'

/** 归一化后的自然人档案——登录主流程只认这个结构。 */
export interface NormalizedProfile {
  /** 平台侧用户唯一键（优先 unionId：跨应用/跨企业同人标识）。 */
  providerUserId: string
  corpId: string
  name: string
  email?: string
  phone?: string
  avatar?: string
}

/** code 换到的令牌包裹（各家结构差异封在这里）。 */
export interface ProviderTokenSet {
  accessToken: string
  refreshToken?: string
  expiresIn: number
  raw: unknown
}

export class ProviderAuthError extends Error {
  readonly code: string
  constructor(message: string, code = 'PROVIDER_AUTH_FAILED') {
    super(message)
    this.code = code
  }
}

export interface IdentityProviderAdapter {
  readonly type: 'dingtalk' | 'feishu' | 'wecom'
  readonly label: string
  /** 当前是否为降级 mock 模式（IdP 对外卖点禁止使用 mock 数据）。 */
  readonly mock: boolean
  /** 构造授权跳转 URL 或二维码内容（in_app 场景可返回 null，由前端 SDK 取 code）。
   *  options.promptConsent=true 时强制弹授权确认页：应用新增权限点后，
   *  老用户的历史授权快照不含新 scope，需重新授权一次才能刷新。 */
  buildAuthorizeUrl(scene: LoginScene, state: string, redirectUri: string, options?: { promptConsent?: boolean }): Promise<string | null>
  /** code → 平台令牌。code 单次消费，失败/过期抛 ProviderAuthError。 */
  exchangeCode(code: string): Promise<ProviderTokenSet>
  /** 平台令牌 → 原始档案。 */
  getUserInfo(tokenSet: ProviderTokenSet): Promise<unknown>
  /** 原始档案 → 归一化档案（三家差异的最终收敛点）。 */
  normalizeProfile(raw: unknown): NormalizedProfile
}

/** 钉钉连接器凭证（真实模式必需；缺省降级 mock）。 */
export interface DingTalkCredentials {
  corpId: string
  appKey: string
  appSecret: string
  /** OpenAPI 基址（默认 https://api.dingtalk.com；测试/专有部署可指向本地 stub）。 */
  apiBase?: string
  /** 通讯录 topapi 基址（默认 https://oapi.dingtalk.com；测试/专有部署可指向本地 stub）。 */
  oapiBase?: string
}

/** 钉钉演示目录（mock 模式与 OrgConnector 共享同一份远端数据）。 */
export const DINGTALK_DIRECTORY = {
  corpId: 'ding-yuanbingke',
  users: [
    { unionId: 'dd_u001', name: '陈远舟', jobNumber: 'DD0001', email: 'chenyz@yuanbingke.com' },
    { unionId: 'dd_u002', name: '林小满', jobNumber: 'DD0002', email: 'linxm@yuanbingke.com' },
    { unionId: 'dd_u003', name: '周既白', jobNumber: 'DD0003', email: 'zhoujb@yuanbingke.com' },
    { unionId: 'dd_u004', name: '苏砚秋', jobNumber: 'DD0004', email: 'suyq@yuanbingke.com' },
    { unionId: 'dd_u005', name: '何青梧', jobNumber: 'DD0005', email: 'heqw@yuanbingke.com' },
    { unionId: 'dd_u006', name: '顾星阑', jobNumber: 'DD0006', email: 'guxl@yuanbingke.com' },
    { unionId: 'dd_u007', name: '叶栖迟', jobNumber: 'DD0007', email: 'yqz@yuanbingke.com' },
  ],
} as const

/** code 一次性消费窗口：窗口内重放拒绝，窗口外视为新授权码周期（演示友好且语义正确）。 */
const CODE_TTL_MS = 5 * 60_000

/** 钉钉 Auth Adapter：mock 降级实现（演示）。 */
export class DingTalkAuthAdapter implements IdentityProviderAdapter {
  readonly type = 'dingtalk' as const
  readonly label = '钉钉'
  readonly mock = true
  private consumedCodes = new Map<string, number>()

  async buildAuthorizeUrl(scene: LoginScene, state: string, redirectUri: string, _options?: { promptConsent?: boolean }): Promise<string | null> {
    if (scene === 'in_app') return null
    // 不带 prompt=consent：已授权过的用户（浏览器持有钉钉会话）可静默通过，缩短回跳链路
    // （mock 无真实授权页，promptConsent 仅作签名兼容，不产生行为差异）
    const params = new URLSearchParams({
      client_id: 'demo-app-key',
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid corpid',
      state,
    })
    return `https://login.dingtalk.com/oauth2/auth?${params}`
  }

  async exchangeCode(code: string): Promise<ProviderTokenSet> {
    const consumedAt = this.consumedCodes.get(code)
    const now = Date.now()
    if (consumedAt !== undefined && now - consumedAt < CODE_TTL_MS) {
      throw new ProviderAuthError('授权码已被使用（code 仅可消费一次）', 'CODE_REPLAY')
    }
    const user = DINGTALK_DIRECTORY.users.find((item) => item.jobNumber === code || item.unionId === code)
    if (!user) throw new ProviderAuthError('授权码无效或已过期', 'INVALID_CODE')
    this.consumedCodes.set(code, now)
    return {
      accessToken: `mock-user-token-${user.unionId}-${now}`,
      expiresIn: 7200,
      raw: { unionId: user.unionId, code },
    }
  }

  async getUserInfo(tokenSet: ProviderTokenSet): Promise<unknown> {
    const raw = tokenSet.raw as { unionId: string }
    const user = DINGTALK_DIRECTORY.users.find((item) => item.unionId === raw.unionId)
    if (!user) throw new ProviderAuthError('用户档案不存在', 'PROFILE_NOT_FOUND')
    return { ...user, corpId: DINGTALK_DIRECTORY.corpId }
  }

  normalizeProfile(raw: unknown): NormalizedProfile {
    const record = raw as { unionId: string; name: string; email?: string; corpId: string }
    return {
      providerUserId: record.unionId,
      corpId: record.corpId,
      name: record.name,
      ...(record.email !== undefined ? { email: record.email } : {}),
    }
  }
}

/**
 * 钉钉 Auth Adapter：真实 OpenAPI 实现。
 * 链路（与钉钉官方文档对齐）：
 *   扫码授权 → POST /v1.0/oauth2/userAccessToken（clientId/clientSecret/code → accessToken）
 *   → GET /v1.0/contact/users/me（Bearer accessToken → unionId/name/email）
 */
export class RealDingTalkAuthAdapter implements IdentityProviderAdapter {
  readonly type = 'dingtalk' as const
  readonly label = '钉钉'
  readonly mock = false
  private consumedCodes = new Map<string, number>()
  private readonly credentials: DingTalkCredentials

  constructor(credentials: DingTalkCredentials) {
    this.credentials = credentials
  }

  private get apiBase(): string {
    return this.credentials.apiBase ?? 'https://api.dingtalk.com'
  }

  async buildAuthorizeUrl(scene: LoginScene, state: string, redirectUri: string, options?: { promptConsent?: boolean }): Promise<string | null> {
    if (scene === 'in_app') return null
    // 默认不带 prompt=consent：已授权过的用户（浏览器持有钉钉会话）可静默通过，缩短回跳链路；
    // 组织归属由用户在钉钉「选择你加入的组织」页一次性选定，平台侧不再要求预选主体。
    // promptConsent=true 时强制弹授权确认页：应用新增权限点后老用户的历史授权快照不含新 scope，
    // 静默换到的 userAccessToken 调 users/me 会 403（AccessTokenPermissionDenied），需重授权一次刷新。
    const params = new URLSearchParams({
      client_id: this.credentials.appKey,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: 'openid corpid',
      state,
    })
    if (options?.promptConsent) params.set('prompt', 'consent')
    return `https://login.dingtalk.com/oauth2/auth?${params}`
  }

  async exchangeCode(code: string): Promise<ProviderTokenSet> {
    const consumedAt = this.consumedCodes.get(code)
    const now = Date.now()
    if (consumedAt !== undefined && now - consumedAt < CODE_TTL_MS) {
      throw new ProviderAuthError('授权码已被使用（code 仅可消费一次）', 'CODE_REPLAY')
    }
    const response = await fetch(`${this.apiBase}/v1.0/oauth2/userAccessToken`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        clientId: this.credentials.appKey,
        clientSecret: this.credentials.appSecret,
        code,
        grantType: 'authorization_code',
      }),
    })
    const payload = (await response.json().catch(() => ({}))) as {
      accessToken?: string
      refreshToken?: string
      expireIn?: number
      corpId?: string
    }
    if (!response.ok || !payload.accessToken) {
      throw new ProviderAuthError(`钉钉 userAccessToken 换取失败（HTTP ${response.status}）`, 'INVALID_CODE')
    }
    this.consumedCodes.set(code, now)
    return {
      accessToken: payload.accessToken,
      ...(payload.refreshToken !== undefined ? { refreshToken: payload.refreshToken } : {}),
      expiresIn: payload.expireIn ?? 7200,
      raw: { accessToken: payload.accessToken, corpId: payload.corpId ?? this.credentials.corpId },
    }
  }

  async getUserInfo(tokenSet: ProviderTokenSet): Promise<unknown> {
    const response = await fetch(`${this.apiBase}/v1.0/contact/users/me`, {
      headers: { 'x-acs-dingtalk-access-token': tokenSet.accessToken },
    })
    const bodyText = await response.text().catch(() => '')
    let payload: Record<string, unknown> = {}
    try {
      payload = JSON.parse(bodyText) as Record<string, unknown>
    } catch {
      payload = {}
    }
    if (!response.ok) {
      // 诊断透出：钉钉返回体含 errcode/message/requiredScopes，token 企业用于识别「选错组织」场景
      const tokenCorpId = (tokenSet.raw as { corpId?: string }).corpId ?? '未知'
      // AccessTokenPermissionDenied（requiredScopes 未覆盖）：多为应用新增权限点后老用户授权快照未刷新，
      // 单独错误码供回调层识别并自动发起一次 prompt=consent 重授权
      const scopeDenied = bodyText.includes('AccessTokenPermissionDenied')
      throw new ProviderAuthError(
        `钉钉用户档案获取失败（HTTP ${response.status}，token企业=${tokenCorpId}）：${bodyText.slice(0, 500)}`,
        scopeDenied ? 'PROVIDER_SCOPE_DENIED' : 'PROFILE_NOT_FOUND',
      )
    }
    // 优先采用用户在钉钉组织选择页实际选中的企业（userAccessToken 响应回传的 corpId），
    // 使「选定哪个组织就以哪个组织的身份命中身份链接」；无回传时按连接器归属兜底
    const rawCorpId = (tokenSet.raw as { corpId?: string }).corpId
    return { ...payload, corpId: rawCorpId || this.credentials.corpId }
  }

  normalizeProfile(raw: unknown): NormalizedProfile {
    const record = raw as { unionId?: string; userId?: string; nick?: string; name?: string; email?: string; corpId?: string }
    const providerUserId = record.unionId ?? record.userId
    if (!providerUserId) throw new ProviderAuthError('钉钉档案缺少 unionId/userId', 'PROFILE_NOT_FOUND')
    return {
      providerUserId,
      corpId: record.corpId ?? this.credentials.corpId,
      name: record.name ?? record.nick ?? providerUserId,
      ...(record.email !== undefined && record.email !== '' ? { email: record.email } : {}),
    }
  }
}
