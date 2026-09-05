/**
 * NasAuthzService —— NAS 数据权限决策服务（PDP，dev-plan-nas-authz §2.1/§2.3）。
 *
 * 分层约束（O8）：判定逻辑全部在纯函数模块 ./authz/engine.ts（不依赖容器、无 IO），
 * 本 Service 只做 IO 装配：取数（IAM 组织树/身份映射 + NAS 资产 + 规则快照）→ 调引擎 → 落留痕。
 *
 * 硬性约束：
 * - 身份一律经 X-On-Behalf-User 请求头/入参 userId 解析（支持平台 userId 与钉钉 userId 反查
 *   identityLinks），绝不进网关工具参数（P0-2 教训）；
 * - rules 单例带 version 字段，PUT 必须携带 ifVersion 乐观锁，冲突抛 RulesVersionConflictError（409）；
 * - fail-closed：无法解析用户/NAS/作用域一律 deny；判定留痕异步化（fire-and-forget 进 bus），
 *   普通记录 90 天滚动清理，delete/share/admin 高危留痕永久保留。
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { newId, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import {
  AUTHZ_OPS, HIGH_RISK_OPS,
  buildOrgIndex, check as engineCheck, deriveRole, deriveScope, effectiveMatrix,
  findVacantLeaderOrgs, nearestLeaderOrg, reconcileOrgDirs,
  type AuthzException, type AuthzOp, type AuthzRole, type EngineDecision,
  type EngineNas, type EngineUser, type OrgIndex,
} from './authz/engine.ts'

// ---------------------------------------------------------------------------
// 数据模型
// ---------------------------------------------------------------------------

/** 规则配置单例（nas:authzRules；version 乐观锁，PUT 携带 ifVersion）。 */
export interface AuthzRulesRecord extends RecordBase {
  id: 'singleton'
  version: number
  /** 多租户预留：本期固定 t_default。 */
  tenantId: string
  matrixOverrides?: Partial<Record<AuthzRole, Partial<Record<AuthzOp, boolean>>>>
  exceptions: AuthzException[]
  /** C 角色关联的动态用户组 id（导入支持按组名解析）。 */
  cGroups: string[]
  externalReadPaths: Array<{ nasId: string; path: string }>
  observeOnly: boolean
  degradeAllToReadonly: boolean
  updatedBy?: string
}

/** 判定留痕（nas:authzDecisions）：高危 op 与全部 deny 落痕；异步写入。 */
export interface AuthzDecisionRecord extends RecordBase {
  nasId: string
  userId: string
  userName?: string
  op: AuthzOp
  paths: string[]
  decision: 'allow' | 'deny'
  role?: AuthzRole
  scope: string[]
  reasons: string[]
  ruleId?: string
  caller: string
  override: boolean
  observeOnly: boolean
  highRisk: boolean
}

/** 版本乐观锁冲突（REST 层映射 409）。 */
export class RulesVersionConflictError extends Error {
  readonly currentVersion: number
  constructor(currentVersion: number, expected: number) {
    super(`规则版本冲突：当前 version=${currentVersion}，请求 ifVersion=${expected}（请重新读取后重试）`)
    this.name = 'RulesVersionConflictError'
    this.currentVersion = currentVersion
  }
}

const DENIED_ALERT_WINDOW_MS = 10 * 60_000
const DENIED_ALERT_THRESHOLD = 10
const DECISION_RETENTION_DAYS = 90

// ---------------------------------------------------------------------------
// 服务
// ---------------------------------------------------------------------------

export class NasAuthzService extends Service {
  static readonly provide = 'nasAuthz'

  /**
   * Service 级依赖（cordis 惰性解析）：iam=组织树/身份映射/动态组（外部插件依赖），
   * nasRegistry=同插件文件网关客户端（对账 job 枚举目录用）。插件级 inject 不自引用，
   * 同插件服务经 Service.inject 声明，避免插件装载期自依赖死锁。
   */
  static readonly inject = ['iam', 'nasRegistry']

  private denyWindows = new Map<string, number[]>()
  private lastDecisionPruneAt = 0

  constructor(ctx: Context) {
    super(ctx, 'nasAuthz')
    // 判定留痕异步化（R2）：check 只发事件不落库，订阅侧兜住全部存储异常
    ctx.platformBus.on('nas.authz.decision', (payload) => {
      try {
        const record = payload as Omit<AuthzDecisionRecord, 'id' | 'createdAt' | 'updatedAt'>
        this.decisions().insert({ ...record, id: newId('adz') })
      } catch (error) {
        this.ctx.logger('nasAuthz').warn('判定留痕落库失败', error)
      }
    })
    // C 组漂移告警（R5）：IAM 动态组重算漂移 → 平台告警中心
    ctx.platformBus.on('nas.authz.cGroupDrift', (payload) => {
      const p = payload as { groupId: string; groupName: string; addedCount: number; removedCount: number; threshold: number }
      this.ctx.audit.fire({
        severity: 'warning',
        title: `动态用户组「${p.groupName}」成员漂移`,
        message: `+${p.addedCount}/-${p.removedCount} 人（阈值 ${p.threshold}）。该组被 NAS 数据权限 C 角色引用，跨域只读范围可能静默变化，请复核。`,
        resourceType: 'iam_group',
        resourceId: p.groupId,
      })
    })
    // 每日组织↔目录对账 job（R1）+ 留痕滚动清理；unref 不阻断进程退出
    const daily = setInterval(() => {
      void this.dailyReconcile().catch((error) => this.ctx.logger('nasAuthz').warn('对账 job 失败', error))
    }, 24 * 60 * 60_000)
    daily.unref?.()
    // share 审批执行器：审批通过自动写入 7 天 share 例外（§2.7 闭环）
    this.registerShareExecutor()
  }

  // -- 集合 ---------------------------------------------------------------

  rulesCollection(): Collection<AuthzRulesRecord> {
    return this.ctx.opsStorage.collection<AuthzRulesRecord>('nas:authzRules')
  }

  decisions(): Collection<AuthzDecisionRecord> {
    return this.ctx.opsStorage.collection<AuthzDecisionRecord>('nas:authzDecisions')
  }

  // -- 规则 -----------------------------------------------------------------

  getRules(): AuthzRulesRecord {
    const existing = this.rulesCollection().get('singleton')
    if (existing) return existing
    return this.rulesCollection().insert({
      id: 'singleton',
      version: 1,
      tenantId: 't_default',
      exceptions: [],
      cGroups: [],
      externalReadPaths: [],
      observeOnly: true,
      degradeAllToReadonly: false,
    })
  }

  /**
   * 更新规则（乐观锁）：ifVersion 必须等于当前 version，否则抛 RulesVersionConflictError。
   * cGroups 支持按动态组名引用（与导入一致，消除部署间 ID 耦合；解析不到的名称直接报错）。
   * 变更落审计（调用方 changeLog 由 REST 层补记）；C 组引用变化回写 iam 组标记（drift 联动）。
   */
  updateRules(patch: {
    matrixOverrides?: Partial<Record<AuthzRole, Partial<Record<AuthzOp, boolean>>>>
    exceptions?: AuthzException[]
    cGroups?: string[]
    externalReadPaths?: Array<{ nasId: string; path: string }>
    observeOnly?: boolean
    degradeAllToReadonly?: boolean
  }, ifVersion: number, actor: string): AuthzRulesRecord {
    const current = this.getRules()
    if (typeof ifVersion !== 'number' || ifVersion !== current.version) {
      throw new RulesVersionConflictError(current.version, ifVersion)
    }
    let cGroups = current.cGroups
    if (patch.cGroups !== undefined) {
      const { ids, unresolved } = this.resolveCGroupNames(patch.cGroups)
      if (unresolved.length > 0) throw new Error(`C 关联动态用户组不存在：${unresolved.join('、')}（请先在组织账号创建同名动态组）`)
      cGroups = ids
    }
    const next: AuthzRulesRecord = {
      ...current,
      ...(patch.matrixOverrides !== undefined ? { matrixOverrides: patch.matrixOverrides } : {}),
      ...(patch.exceptions !== undefined ? { exceptions: this.normalizeExceptions(patch.exceptions, current, actor) } : {}),
      cGroups,
      ...(patch.externalReadPaths !== undefined ? { externalReadPaths: patch.externalReadPaths } : {}),
      ...(patch.observeOnly !== undefined ? { observeOnly: patch.observeOnly } : {}),
      ...(patch.degradeAllToReadonly !== undefined ? { degradeAllToReadonly: patch.degradeAllToReadonly } : {}),
      updatedBy: actor,
    }
    next.version = current.version + 1
    this.syncCGroupFlags(next.cGroups)
    const saved = this.rulesCollection().update('singleton', next)
    this.ctx.platformBus.emit('nas.authz.rulesChanged', { version: saved.version, actor })
    return saved
  }

  /**
   * 种子导入（幂等）：与 hermes_nas_rbac_rules.json 等价的规则快照。
   * cGroups 支持按动态组名解析；内容与现规则一致时不升版本（幂等）。
   */
  importRules(seed: {
    matrixOverrides?: Partial<Record<AuthzRole, Partial<Record<AuthzOp, boolean>>>>
    exceptions?: Array<Partial<AuthzException> & { effect: 'allow' | 'deny'; nasId: string; path: string; ops: AuthzOp[] }>
    cGroups?: string[]
    externalReadPaths?: Array<{ nasId: string; path: string }>
    observeOnly?: boolean
    degradeAllToReadonly?: boolean
  }, actor: string): { changed: boolean; version: number; unresolvedGroups: string[] } {
    const current = this.getRules()
    const { ids: groupIds, unresolved } = this.resolveCGroupNames(seed.cGroups ?? [])
    const mergedExceptions = seed.exceptions !== undefined
      ? this.normalizeExceptions(seed.exceptions.map((exception) => ({
          ...exception,
          id: exception.id ?? `exc_${newId('e').slice(4)}`,
        } as AuthzException)), current, actor)
      : current.exceptions
    const candidate = {
      matrixOverrides: seed.matrixOverrides ?? current.matrixOverrides ?? {},
      exceptions: mergedExceptions,
      cGroups: seed.cGroups !== undefined ? groupIds : current.cGroups,
      externalReadPaths: seed.externalReadPaths ?? current.externalReadPaths,
      observeOnly: seed.observeOnly ?? current.observeOnly,
      degradeAllToReadonly: seed.degradeAllToReadonly ?? current.degradeAllToReadonly,
    }
    const unchanged = JSON.stringify(candidate.matrixOverrides ?? {}) === JSON.stringify(current.matrixOverrides ?? {})
      && JSON.stringify(candidate.exceptions) === JSON.stringify(current.exceptions)
      && JSON.stringify(candidate.cGroups) === JSON.stringify(current.cGroups)
      && JSON.stringify(candidate.externalReadPaths) === JSON.stringify(current.externalReadPaths)
      && candidate.observeOnly === current.observeOnly
      && candidate.degradeAllToReadonly === current.degradeAllToReadonly
    if (unchanged) return { changed: false, version: current.version, unresolvedGroups: unresolved }
    const saved = this.updateRules(candidate, current.version, actor)
    return { changed: true, version: saved.version, unresolvedGroups: unresolved }
  }

  /** 追加例外（share 审批产物 / 运维手工授权），自动升版本。 */
  addException(exception: Omit<AuthzException, 'id' | 'createdAt'> & { id?: string }, actor: string): AuthzException {
    const current = this.getRules()
    const record: AuthzException = {
      ...exception,
      id: exception.id ?? `exc_${newId('e').slice(4)}`,
      createdAt: new Date().toISOString(),
    }
    this.updateRules({ exceptions: [...current.exceptions, record] }, current.version, actor)
    return record
  }

  listExceptions(): AuthzException[] {
    return this.getRules().exceptions
  }

  // -- 判定 -----------------------------------------------------------------

  /**
   * 五步判定（入口）：身份解析（平台 userId / 钉钉 userId 反查）→ 取数装配 → 纯函数引擎 → 留痕。
   * fail-closed：任何取数失败（用户不存在/NAS 不存在/作用域未命中）都产出带理由的 deny。
   */
  check(input: { nasId: string; userId: string; paths: string[]; op: AuthzOp; override?: boolean; caller?: string }): EngineDecision & { userName?: string; nasName?: string } {
    const caller = input.caller ?? 'unknown'
    const op = AUTHZ_OPS.includes(input.op) ? input.op : undefined
    const rules = this.getRules()
    const paths = (Array.isArray(input.paths) ? input.paths : [input.paths]).map(String).filter(Boolean)
    const base = {
      observeOnly: rules.observeOnly,
      override: input.override === true,
      cTag: false,
      scope: [] as string[],
      reasons: [] as string[],
      perPath: [],
      decision: 'deny' as const,
    }
    if (!op) return { ...base, reasons: [`op.unsupported：未知操作 ${input.op}`], perPath: paths.map((path) => ({ path, decision: 'deny' as const, reasons: [`op.unsupported：未知操作 ${input.op}`] })) }
    const user = this.resolveUser(input.userId)
    const nas = this.nasDescriptor(input.nasId)
    // 网关回调以 NAS IP 充当 nasId（其天然只知 IP）：统一收敛到平台资产 ID，
    // 保证例外/规则的 nasId 按键一致命中（否则 IP 字面量 ≠ 资产 ID，显式授权永不生效）。
    const canonicalNasId = nas?.id ?? input.nasId
    const orgIndex = this.orgIndex()
    const engineUser: EngineUser | undefined = user
      ? { id: user.id, displayName: user.displayName, orgId: user.orgId, ...(user.primaryOrgId !== undefined ? { primaryOrgId: user.primaryOrgId } : {}), ...(user.accountType !== undefined ? { accountType: user.accountType } : {}), status: user.status }
      : undefined
    const decision = engineCheck(
      { userId: input.userId, nasId: canonicalNasId, paths, op, ...(input.override !== undefined ? { override: input.override } : {}) },
      {
        orgIndex,
        ...(engineUser !== undefined ? { user: engineUser } : {}),
        ...(nas !== undefined ? { nas } : {}),
        rules,
        cGroupHits: this.cGroupHits(user?.id ?? input.userId, rules.cGroups),
      },
    )
    const enriched = { ...decision, ...(user ? { userName: user.displayName } : {}), ...(nas?.name ? { nasName: nas.name } : {}) }
    // 留痕与告警（fire-and-forget；deny 全量、高危 op 全量留痕）
    const highRisk = HIGH_RISK_OPS.has(op)
    if (decision.decision === 'deny' || highRisk) {
      this.ctx.platformBus.emit('nas.authz.decision', {
        nasId: canonicalNasId, userId: user?.id ?? input.userId, ...(user ? { userName: user.displayName } : {}),
        op, paths, decision: decision.decision, ...(decision.role !== undefined ? { role: decision.role } : {}),
        scope: decision.scope, reasons: decision.reasons, ...(decision.ruleId !== undefined ? { ruleId: decision.ruleId } : {}),
        caller, override: input.override === true, observeOnly: rules.observeOnly, highRisk,
      } satisfies Omit<AuthzDecisionRecord, 'id' | 'createdAt' | 'updatedAt'>)
    }
    if (decision.decision === 'deny' && rules.observeOnly === false) {
      this.trackDeniedBurst(user?.id ?? input.userId, { nasId: canonicalNasId, op, paths })
      this.ctx.platformBus.emit('nas.authz.denied', {
        userId: user?.id ?? input.userId, userName: user?.displayName ?? input.userId,
        nasId: input.nasId, op, paths, reasons: decision.reasons, caller,
      })
    }
    this.pruneDecisionsIfNeeded()
    return enriched
  }

  /** scope 查询（hermes/控制台收敛 list/search 枚举范围；亦是网关降级快照的数据源）。 */
  scopeOf(nasId: string, userId: string): { role?: AuthzRole; special?: string; cTag: boolean; scope: string[]; matrix: Record<AuthzRole, Record<AuthzOp, boolean>>; observeOnly: boolean; degradeAllToReadonly: boolean; reasons: string[]; nasName?: string; userName?: string } {
    const rules = this.getRules()
    const user = this.resolveUser(userId)
    const nas = this.nasDescriptor(nasId)
    if (!user || !nas) {
      return {
        cTag: false, scope: [], matrix: effectiveMatrix(rules), observeOnly: rules.observeOnly,
        degradeAllToReadonly: rules.degradeAllToReadonly,
        reasons: [!user ? 'user-not-found：账号不存在或未同步' : 'nas-not-found：NAS 资产不存在'],
      }
    }
    const orgIndex = this.orgIndex()
    const engineUser: EngineUser = { id: user.id, displayName: user.displayName, orgId: user.orgId, ...(user.primaryOrgId !== undefined ? { primaryOrgId: user.primaryOrgId } : {}), ...(user.accountType !== undefined ? { accountType: user.accountType } : {}), status: user.status }
    const derived = deriveRole(engineUser, orgIndex)
    const scope = deriveScope(engineUser, nas, orgIndex)
    const reasons: string[] = []
    if (scope.via === 'none') reasons.push(`nas.no-scope：未命中该 NAS 的接入组织锚点（${scope.reason}）`)
    if (derived.special) reasons.push(`account.special：特殊账号态 ${derived.special}`)
    return {
      ...(derived.role !== undefined ? { role: derived.role } : {}),
      ...(derived.special !== undefined ? { special: derived.special } : {}),
      cTag: this.cGroupHits(user.id, rules.cGroups).length > 0,
      scope: scope.prefixes,
      matrix: effectiveMatrix(rules),
      observeOnly: rules.observeOnly,
      degradeAllToReadonly: rules.degradeAllToReadonly,
      reasons,
      ...(nas.name ? { nasName: nas.name } : {}),
      userName: user.displayName,
    }
  }

  // -- 治理：负责人悬空 / 组织目录对账 / share 审批 ------------------------------

  /** 负责人悬空扫描：leaderUserIds 为空（限挂了账号的组织）→ leaderVacant 事件 + 告警。 */
  scanLeaderVacancy(): Array<{ orgId: string; orgName: string }> {
    const iam = this.ctx.iam
    const withUsers = new Set(iam.users().all().map((user) => user.orgId))
    const orgIndex = this.orgIndex()
    const vacant = findVacantLeaderOrgs(orgIndex, { withUserOrgIds: withUsers })
    for (const org of vacant) {
      this.ctx.platformBus.emit('nas.authz.leaderVacant', { orgId: org.id, orgName: org.name })
      this.ctx.audit.fire({
        severity: 'info',
        title: `组织「${org.name}」负责人悬空`,
        message: `leaderUserIds 为空：该部门 delete/share 按矩阵无人可执行。可在控制台「组织与账号」选中该组织 →「设置负责人」手动绑定（锁定后不被连接器同步覆盖，清空即恢复跟随同步），或在钉钉侧配置部门负责人后触发同步。`,
        resourceType: 'org',
        resourceId: org.id,
      })
    }
    return vacant.map((org) => ({ orgId: org.id, orgName: org.name }))
  }

  /** 组织↔目录对账（每日 job；亦由 REST 手动触发）：对在线 NAS 比对一级目录与组织树。 */
  async dailyReconcile(): Promise<Array<{ nasId: string; nasName: string; findings: ReturnType<typeof reconcileOrgDirs>; error?: string }>> {
    const report: Array<{ nasId: string; nasName: string; findings: ReturnType<typeof reconcileOrgDirs>; error?: string }> = []
    const orgIndex = this.orgIndex()
    for (const nasEntity of this.ctx.resourceCore.list('nas', { status: 'online' })) {
      const nas = this.nasDescriptor(nasEntity.id)
      if (!nas) continue
      let dirNames: string[] = []
      try {
        const shares = await this.ctx.nasRegistry.listShares(nasEntity.id) as unknown
        dirNames = this.extractDirNames(shares)
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        this.ctx.logger('nasAuthz').warn(`对账：NAS ${nasEntity.name} 目录枚举失败`, error)
        report.push({ nasId: nasEntity.id, nasName: nasEntity.name, findings: [], error: message })
        continue
      }
      const findings = reconcileOrgDirs(dirNames, nas, orgIndex)
      if (findings.length > 0) {
        this.ctx.platformBus.emit('nas.authz.dirOrphan', { nasId: nasEntity.id, nasName: nasEntity.name, findings })
        this.ctx.audit.fire({
          severity: 'info',
          title: `NAS「${nasEntity.name}」组织目录对账发现 ${findings.length} 处不匹配`,
          message: findings.map((finding) => finding.detail).join('；'),
          resourceType: 'nas',
          resourceId: nasEntity.id,
        })
      }
      report.push({ nasId: nasEntity.id, nasName: nasEntity.name, findings })
    }
    this.pruneDecisionsIfNeeded()
    return report
  }

  /**
   * share 申请（dev-plan-nas-authz §2.7）：成员 T/M share 被拒后经 hermes/控制台发起，
   * 审批人自动路由 = 沿申请者组织链向上找最近非空负责人，找不到升级 resource_admin 兜底。
   */
  async requestShareApproval(input: { nasId: string; userId: string; path: string; reason?: string; requesterName?: string }): Promise<{ approvalId: string; approverSuggestion: { orgId?: string; orgName?: string; leaderUserIds: string[] }; escalated: boolean }> {
    const iam = this.ctx.iam
    const user = this.resolveUser(input.userId)
    if (!user) throw new Error(`申请账号不存在：${input.userId}`)
    const orgIndex = this.orgIndex()
    const nearest = nearestLeaderOrg(orgIndex, user.primaryOrgId ?? user.orgId)
    let approverSuggestion: { orgId?: string; orgName?: string; leaderUserIds: string[] } = { leaderUserIds: [] }
    let escalated = false
    let approverNameHint: string
    if (nearest) {
      approverSuggestion = { orgId: nearest.orgId, orgName: nearest.orgName, leaderUserIds: nearest.leaderUserIds }
      approverNameHint = `自动路由：${nearest.orgName} 负责人`
    } else {
      escalated = true
      const admins = iam.users().all().filter((candidate) => candidate.status === 'active' && candidate.roleIds.some((roleId) => iam.roles().get(roleId)?.code === 'resource_admin'))
      approverSuggestion = { leaderUserIds: admins.map((admin) => admin.id) }
      approverNameHint = `未找到组织链负责人，升级 resource_admin 兜底（${admins.map((admin) => admin.displayName).join('、') || '暂无'}）`
    }
    const nas = this.ctx.resourceCore.get('nas', input.nasId)
    const approval = this.ctx.audit.createApproval({
      kind: 'nas.share',
      title: `NAS 分享申请：${user.displayName} → ${nas?.name ?? input.nasId} ${input.path}`,
      payload: {
        nasId: input.nasId, path: input.path, userId: user.id, userName: user.displayName,
        ...(input.reason ? { reason: input.reason } : {}),
        approverSuggestion, escalated, approverNameHint,
      },
      requesterId: user.id,
      requesterName: input.requesterName ?? user.displayName,
    })
    return { approvalId: approval.id, approverSuggestion, escalated }
  }

  /** 注册 share 审批执行器：审批通过 → 写入 7 天有效 share allow 例外（事由留痕）。 */
  registerShareExecutor(): () => void {
    return this.ctx.audit.registerExecutor('nas.share', async (payload) => {
      const { nasId, path, userId, userName, reason } = payload as { nasId: string; path: string; userId: string; userName?: string; reason?: string }
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60_000).toISOString()
      const exception = this.addException({
        effect: 'allow', nasId, path, ops: ['share'], userIds: [userId],
        ...(expiresAt ? { expiresAt } : {}), note: `share 审批通过${reason ? `：${reason}` : ''}`, createdBy: 'approval:nas.share',
      }, 'approval:nas.share')
      this.ctx.audit.record({
        type: 'authz', actorType: 'system', actorId: 'nasAuthz', actorName: 'NAS 数据权限',
        action: 'nas.authz.share_granted', resourceType: 'nas', resourceId: nasId,
        resourceName: this.ctx.resourceCore.get('nas', nasId)?.name ?? nasId,
        result: 'ok', detail: `${userName ?? userId} 获得 ${path} 分享授权（例外 ${exception.id}，${expiresAt} 到期）`,
      })
      return { exceptionId: exception.id, expiresAt }
    })
  }

  // -- 内部装配 -------------------------------------------------------------

  /** 身份解析：平台 userId 优先，其次钉钉等三方 userId 反查 identityLinks（事实源）。 */
  private resolveUser(userId: string): { id: string; displayName: string; orgId: string; primaryOrgId?: string; accountType?: string; status: string } | undefined {
    const iam = this.ctx.iam
    const direct = iam.users().get(userId)
    if (direct) return { id: direct.id, displayName: direct.displayName, orgId: direct.orgId, ...(direct.primaryOrgId !== undefined ? { primaryOrgId: direct.primaryOrgId } : {}), ...(direct.accountType !== undefined ? { accountType: direct.accountType } : {}), status: direct.status }
    const link = iam.identityLinks().findOne((item) => item.providerUserId === userId)
    if (!link) return undefined
    const user = iam.users().get(link.userId)
    if (!user) return undefined
    return { id: user.id, displayName: user.displayName, orgId: user.orgId, ...(user.primaryOrgId !== undefined ? { primaryOrgId: user.primaryOrgId } : {}), ...(user.accountType !== undefined ? { accountType: user.accountType } : {}), status: user.status }
  }

  private orgIndex(): OrgIndex {
    const iam = this.ctx.iam
    return buildOrgIndex(iam.orgs().all().map((org) => ({ id: org.id, name: org.name, parentId: org.parentId, leaderUserIds: iam.leadersOf(org.id) })))
  }

  /** NAS 引擎描述符：rootPath/orgRoot/orgPathOverrides（access 组属性；映射表为 JSON 文本或对象）。
   *  nasId 兼容两种形态：平台资产 ID，或网关侧天然持有的 NAS IP（按 attrs.nasIp 反查）。 */
  private nasDescriptor(nasId: string): EngineNas | undefined {
    let entity = this.ctx.resourceCore.get('nas', nasId)
    if (!entity && /\d+(\.\d+){3}$/.test(nasId.trim())) {
      entity = this.ctx.resourceCore.list('nas').find((candidate) => String(candidate.attrs['nasIp'] ?? '') === nasId.trim())
    }
    if (!entity) return undefined
    const rawOverrides = entity.attrs['orgPathOverrides']
    let overrides: Record<string, string> | undefined
    if (typeof rawOverrides === 'string' && rawOverrides.trim()) {
      try {
        const parsed = JSON.parse(rawOverrides)
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) overrides = Object.fromEntries(Object.entries(parsed).map(([key, value]) => [key, String(value)]))
      } catch {
        throw new Error(`NAS「${entity.name}」orgPathOverrides 不是合法 JSON`)
      }
    } else if (rawOverrides && typeof rawOverrides === 'object' && !Array.isArray(rawOverrides)) {
      overrides = Object.fromEntries(Object.entries(rawOverrides as Record<string, unknown>).map(([key, value]) => [key, String(value)]))
    }
    return {
      id: entity.id,
      name: entity.name,
      rootPath: String(entity.attrs['rootPath'] ?? '/'),
      ...(entity.attrs['orgRoot'] !== undefined && String(entity.attrs['orgRoot']).trim() !== '' ? { orgRoot: String(entity.attrs['orgRoot']).trim() } : {}),
      ...(overrides !== undefined ? { orgPathOverrides: overrides } : {}),
    }
  }

  private cGroupHits(userId: string, cGroups: string[]): string[] {
    if (cGroups.length === 0) return []
    const iam = this.ctx.iam
    return cGroups.filter((groupId) => {
      try {
        return iam.resolveGroupMembers(groupId).some((member) => member.id === userId)
      } catch {
        return false
      }
    })
  }

  private trackDeniedBurst(userId: string, context: { nasId: string; op: AuthzOp; paths: string[] }): void {
    const now = Date.now()
    const times = (this.denyWindows.get(userId) ?? []).filter((time) => now - time < DENIED_ALERT_WINDOW_MS)
    times.push(now)
    this.denyWindows.set(userId, times)
    if (times.length > DENIED_ALERT_THRESHOLD) {
      // evaluateAlerts 对自定义 metric 统一读 context.value（count 同步提供便于告警文案）
      this.ctx.audit.evaluateAlerts('nas_authz_denied', { value: times.length, count: times.length, userId, ...context, resourceType: 'nas', resourceId: context.nasId })
    }
  }

  /** 留痕保留策略：普通记录 90 天滚动清理；delete/share/admin 高危永久保留。节流每小时一次。 */
  private pruneDecisionsIfNeeded(): void {
    const now = Date.now()
    if (now - this.lastDecisionPruneAt < 60 * 60_000) return
    this.lastDecisionPruneAt = now
    try {
      const cutoff = new Date(now - DECISION_RETENTION_DAYS * 24 * 60 * 60_000).toISOString()
      for (const record of this.decisions().find((item) => !item.highRisk && item.createdAt < cutoff)) {
        this.decisions().remove(record.id)
      }
    } catch (error) {
      this.ctx.logger('nasAuthz').warn('判定留痕清理失败', error)
    }
  }

  private normalizeExceptions(exceptions: AuthzException[], current: AuthzRulesRecord, actor: string): AuthzException[] {
    for (const exception of exceptions) {
      if (!exception.effect || !['allow', 'deny'].includes(exception.effect)) throw new Error(`例外 effect 非法：${exception.effect}`)
      if (!exception.nasId) throw new Error('例外必须指定 nasId')
      if (!exception.path) throw new Error('例外必须指定 path')
      if (!Array.isArray(exception.ops) || exception.ops.length === 0 || exception.ops.some((op) => !AUTHZ_OPS.includes(op))) {
        throw new Error(`例外 ops 非法：${JSON.stringify(exception.ops)}`)
      }
      if (exception.expiresAt !== undefined && Number.isNaN(Date.parse(exception.expiresAt))) throw new Error(`例外 expiresAt 非法：${exception.expiresAt}`)
    }
    // 合并语义：同 id 覆盖、新增追加、未出现在补丁中的既有例外保留（幂等导入靠内容比对）
    const byId = new Map(current.exceptions.map((exception) => [exception.id, exception]))
    for (const exception of exceptions) {
      byId.set(exception.id, { ...byId.get(exception.id), ...exception, createdBy: byId.get(exception.id)?.createdBy ?? actor })
    }
    return [...byId.values()]
  }

  /** C 组名 → 组 id 解析（导入/更新按名引用，消除部署间 ID 耦合）。 */
  private resolveCGroupNames(names: string[]): { ids: string[]; unresolved: string[] } {
    const iam = this.ctx.iam
    const ids: string[] = []
    const unresolved: string[] = []
    for (const nameOrId of names) {
      const byId = iam.groups().get(nameOrId)
      if (byId) {
        ids.push(byId.id)
        continue
      }
      const byName = iam.groups().findOne((group) => group.name === nameOrId)
      if (byName) {
        ids.push(byName.id)
        continue
      }
      unresolved.push(nameOrId)
    }
    return { ids, unresolved }
  }

  /** 回写动态组 authzRoleC 标记（drift 告警联动：C 关联组任何漂移都告警）。 */
  private syncCGroupFlags(cGroups: string[]): void {
    const iam = this.ctx.iam
    const referenced = new Set(cGroups)
    for (const group of iam.groups().all()) {
      const shouldBeMarked = referenced.has(group.id)
      if (shouldBeMarked && group.authzRoleC !== true) iam.groups().update(group.id, { authzRoleC: true })
      if (!shouldBeMarked && group.authzRoleC === true) iam.groups().update(group.id, { authzRoleC: false })
    }
  }

  /** 从网关 fs_list_shares 响应提取一级目录名（容错：content 块数组 / JSON 文本 / 对象）。 */
  private extractDirNames(payload: unknown): string[] {
    const collect = (input: unknown): Array<{ name?: string; path?: string }> => {
      if (typeof input === 'string') {
        try { return collect(JSON.parse(input)) } catch { return [] }
      }
      if (Array.isArray(input)) return input.flatMap((item) => collect(item))
      if (input && typeof input === 'object') {
        const record = input as Record<string, unknown>
        if (Array.isArray(record['shares'])) return record['shares'] as Array<{ name?: string }>
        if (Array.isArray(record['files'])) return record['files'] as Array<{ name?: string }>
        return [record]
      }
      return []
    }
    return collect(payload)
      .map((item) => String(item?.name ?? item?.path ?? '').replace(/^.*\//, '').trim())
      .filter(Boolean)
  }
}

// ---------------------------------------------------------------------------
// 插件
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    nasAuthz: NasAuthzService
  }
}

export { WRITE_OPS, HIGH_RISK_OPS } from './authz/engine.ts'
export type { AuthzOp, AuthzRole, EngineDecision } from './authz/engine.ts'
