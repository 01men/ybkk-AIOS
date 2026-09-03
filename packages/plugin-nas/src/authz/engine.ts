/**
 * NAS 数据权限判定引擎（纯函数模块，dev-plan-nas-authz §2.1 分层约束）。
 *
 * - 不依赖 Service 容器、不做任何 IO：入参为已取数的组织树快照 / 用户 / NAS 资产 / 规则快照，
 *   出参为判定结果（含 reasons）。Service 层（../authz.ts）只做取数装配与留痕落盘。
 * - 判定序移植自 saas-permission-service（服务 B）语义，只移植语义不部署本体：
 *   ① 账号特殊规则（外部/可疑/挂根/未落班组/兼任只读）
 *   ② 资源级显式 deny（nasId+path 尾通配，可带 userIds）
 *   ③ 资源级显式 allow（C 跨域白名单、临时授权，可设 expiresAt）
 *   ④ 角色矩阵 MATRIX[role][op] × 作用域边界
 *   ⑤ 默认 deny
 * - selftest 直接单测本模块（引擎分层约束 O8）。
 */

// ---------------------------------------------------------------------------
// 类型
// ---------------------------------------------------------------------------

/** 七类操作（附件第四章操作矩阵维度；share/admin 在网关工具面不存在，网关侧恒 deny）。 */
export type AuthzOp = 'read' | 'download' | 'write' | 'modify' | 'delete' | 'share' | 'admin'

export const AUTHZ_OPS: AuthzOp[] = ['read', 'download', 'write', 'modify', 'delete', 'share', 'admin']

/** 写类操作（readonly 语义 = read/download 放行、写类拒绝）。 */
export const WRITE_OPS: ReadonlySet<AuthzOp> = new Set<AuthzOp>(['write', 'modify', 'delete', 'share', 'admin'])

/** 高危操作（判定留痕永久保留；普通记录 90 天滚动清理）。 */
export const HIGH_RISK_OPS: ReadonlySet<AuthzOp> = new Set<AuthzOp>(['delete', 'share', 'admin'])

/** 主角色（C 为叠加标签，不参与主角色序）。 */
export type AuthzRole = 'P' | 'D' | 'T' | 'M'

export interface EngineOrgNode {
  id: string
  name: string
  parentId: string | null
  /** 组织树深度：根=1（平台级），2=部门级，≥3=职能组/班组级。 */
  depth: number
  leaderUserIds: string[]
}

/** 组织树快照索引：orgId → 节点（含 depth，由 buildOrgIndex 预计算）。 */
export type OrgIndex = Map<string, EngineOrgNode>

export interface EngineUser {
  id: string
  displayName: string
  /** 挂靠组织；与 primaryOrgId 不同时，orgId 子树按兼任只读处理。 */
  orgId: string
  /** 主归属组织（兼任语义）；缺省取组织链最深者（单人单挂时即 orgId）。 */
  primaryOrgId?: string
  accountType?: 'internal' | 'external' | 'suspended-review'
  status?: string
}

export interface EngineNas {
  id: string
  name?: string
  /** 资产级授权根路径（现有 rootPath 属性）。 */
  rootPath: string
  /** 接入组织锚点：平台级组织名或 orgId（数据权限作用域推导锚点）。 */
  orgRoot?: string
  /** 组织 → 目录前缀显式映射（优先于名字推导，组织改名/合并不漂移）。 */
  orgPathOverrides?: Record<string, string>
}

/** 资源级例外：显式 allow/deny，可按人收敛、可过期（服务 B 语义）。 */
export interface AuthzException {
  id: string
  effect: 'allow' | 'deny'
  nasId: string
  /** 路径前缀；尾部 `/*` 通配该子树，`*` 通配全部。 */
  path: string
  ops: AuthzOp[]
  /** 缺省 = 对全部用户生效（按路径的资源级例外）。 */
  userIds?: string[]
  /** ISO 时间；过期即失效（判定序仍在原位，只是不再命中）。 */
  expiresAt?: string
  note?: string
  createdBy?: string
  createdAt?: string
}

/** 规则配置快照（nas:authzRules 单例的引擎可见投影）。 */
export interface AuthzRulesSnapshot {
  version: number
  /** 矩阵覆盖项：true=放宽为 allow，false=收紧为 deny（在内置矩阵之上打补丁）。 */
  matrixOverrides?: Partial<Record<AuthzRole, Partial<Record<AuthzOp, boolean>>>>
  exceptions: AuthzException[]
  /** C 角色关联的动态用户组 id 集合（不建第二份人员名单）。 */
  cGroups: string[]
  /** 外部账号白名单目录（external 只读范围）。 */
  externalReadPaths: Array<{ nasId: string; path: string }>
  /** 观察模式：判定结果不变，仅标注（网关 deny 只告警不拦截）。 */
  observeOnly: boolean
  /** 全量降级只读：所有 allow 视作 readonly（灰度 G3）。 */
  degradeAllToReadonly: boolean
}

export interface EngineCheckInput {
  userId: string
  nasId: string
  paths: string[]
  op: AuthzOp
  /** 破窗：走 P 判定并强制留痕（须持 nas.authz.write，Service 层校验后透传）。 */
  override?: boolean
  now?: string
}

export interface EnginePathVerdict {
  path: string
  decision: 'allow' | 'deny'
  reasons: string[]
}

export interface EngineDecision {
  decision: 'allow' | 'deny'
  /** 主角色（P/D/T/M）；特殊账号无主角色时缺省。 */
  role?: AuthzRole
  /** 是否叠加 C 标签（动态用户组成员）。 */
  cTag: boolean
  /** 判定时的作用域前缀列表（平台口径，供 scope 查询与降级快照复用）。 */
  scope: string[]
  reasons: string[]
  /** 命中的显式例外 id（allow/deny 皆回填，便于审计归因）。 */
  ruleId?: string
  perPath: EnginePathVerdict[]
  observeOnly: boolean
  override: boolean
}

// ---------------------------------------------------------------------------
// 内置矩阵与工具函数
// ---------------------------------------------------------------------------

/**
 * 内置操作矩阵（附件第四章默认值）：
 * - P 平台负责人：全部放行；
 * - D 部门负责人：本部门子树全权（admin 为平台规则管理权限点，矩阵恒 deny，走权限点而非目录）；
 * - T 班组负责人：可写不可删（delete/share 需走审批例外）；
 * - M 普通成员：可读写文件，不可改结构（rename/copy/compress）、不可删；
 * - C 叠加标签：跨域只读（在 check 中作为 read/download 范围扩展实现）。
 */
export const MATRIX_DEFAULT: Record<AuthzRole, Record<AuthzOp, boolean>> = {
  P: { read: true, download: true, write: true, modify: true, delete: true, share: true, admin: true },
  D: { read: true, download: true, write: true, modify: true, delete: true, share: true, admin: false },
  T: { read: true, download: true, write: true, modify: true, delete: false, share: false, admin: false },
  M: { read: true, download: true, write: true, modify: false, delete: false, share: false, admin: false },
}

/** 合并矩阵覆盖项（规则可收紧/放宽单格；admin 恒需平台权限点，覆盖其矩阵无网关侧效果）。 */
export function effectiveMatrix(rules: Pick<AuthzRulesSnapshot, 'matrixOverrides'>): Record<AuthzRole, Record<AuthzOp, boolean>> {
  const matrix = structuredClone(MATRIX_DEFAULT)
  const overrides = rules.matrixOverrides ?? {}
  for (const role of Object.keys(overrides) as AuthzRole[]) {
    for (const op of Object.keys(overrides[role] ?? {}) as AuthzOp[]) {
      const value = overrides[role]?.[op]
      if (typeof value === 'boolean') matrix[role][op] = value
    }
  }
  return matrix
}

/** 路径归一化：绝对化、去尾斜杠、禁 `..`；根返回 ''（内部比较口径，展示层再补 `/`）。 */
export function normalizePath(path: string): string {
  const normalized = `/${path}`.replace(/\\/g, '/').replace(/\/+$/, '')
  const segments = normalized.split('/').filter(Boolean)
  if (segments.some((segment) => segment === '..')) throw new Error('路径不允许包含 ..')
  return `/${segments.join('/')}`
}

/** scope 前缀命中：path === prefix 或 path 位于 prefix 子树内。 */
export function pathWithin(path: string, prefix: string): boolean {
  const p = normalizePath(path)
  const f = normalizePath(prefix)
  if (f === '/') return true
  return p === f || p.startsWith(`${f}/`)
}

/** 例外路径通配命中：`*` 全部；尾 `/*` 子树；其余精确前缀（子树语义）。 */
export function matchExceptionPath(exceptionPath: string, path: string): boolean {
  const trimmed = exceptionPath.trim()
  if (trimmed === '*') return true
  if (trimmed.endsWith('/*')) return pathWithin(path, trimmed.slice(0, -2))
  return pathWithin(path, trimmed)
}

/** 组织树快照构建：由扁平 OrgRecord 数组计算 depth（孤儿节点挂深度按 1 兜底）。 */
export function buildOrgIndex(records: Array<{ id: string; name: string; parentId: string | null; leaderUserIds?: string[] }>): OrgIndex {
  const index: OrgIndex = new Map()
  for (const record of records) {
    index.set(record.id, { id: record.id, name: record.name, parentId: record.parentId, depth: 0, leaderUserIds: record.leaderUserIds ?? [] })
  }
  for (const node of index.values()) {
    let cursor: string | null = node.id
    let depth = 0
    const guard = new Set<string>()
    while (cursor && index.has(cursor) && !guard.has(cursor)) {
      guard.add(cursor)
      depth++
      cursor = index.get(cursor)!.parentId
    }
    node.depth = depth || 1
  }
  return index
}

/** 组织祖先链（自身 → 根，平台口径）。 */
export function orgChain(orgIndex: OrgIndex, orgId: string): EngineOrgNode[] {
  const chain: EngineOrgNode[] = []
  let cursor: string | null = orgId
  const guard = new Set<string>()
  while (cursor && orgIndex.has(cursor) && !guard.has(cursor)) {
    guard.add(cursor)
    const node = orgIndex.get(cursor)!
    chain.push(node)
    cursor = node.parentId
  }
  return chain
}

// ---------------------------------------------------------------------------
// 角色推导（附件第三章，纯函数，无人员名单配置）
// ---------------------------------------------------------------------------

export interface DerivedRole {
  role?: AuthzRole
  /** 主归属链上的负责人身份（多负责人 co-leader 语义：一人可同时是 D + 子树 T，取最高为主角色）。 */
  leaderOf: Array<{ orgId: string; depth: number; role: AuthzRole; coLeader: boolean }>
  /** 跨分支负责人身份（一人多角色）：主归属链之外的部门负责人，作用域与矩阵按所领导部门子树独立生效（leaderScopes）。 */
  leaderOfElsewhere: Array<{ orgId: string; orgName: string; depth: number; role: AuthzRole; coLeader: boolean }>
  /** 主归属组织（兼任语义锚点）。 */
  primaryOrg?: EngineOrgNode
  /** 挂靠组织（orgId；与主归属不同即为兼任）。 */
  attachedOrg?: EngineOrgNode
  secondaryAffiliation: boolean
  special?: 'external' | 'suspended-review' | 'root-no-role' | 'dept-root-readonly'
}

/**
 * 角色推导：
 * - P/D/T = 主归属组织链上的负责人（深度 1/2/≥3）；多负责人全部推导（reasons 标 co-leader）；
 * - M = 挂在深度≥3 组织下的非负责人成员；
 * - 挂根组织（深度=1 非负责人）→ special 'root-no-role'（deny 全部）；
 * - 未落班组（挂在深度=2 部门根且非负责人）→ special 'dept-root-readonly'（部门根只读）；
 * - external / suspended-review 见 special；
 * - 主归属缺省取组织链最深者（orgId 与 primaryOrgId 不一致即为兼任）。
 */
export function deriveRole(user: EngineUser, orgIndex: OrgIndex): DerivedRole {
  const result: DerivedRole = { leaderOf: [], leaderOfElsewhere: [], secondaryAffiliation: false }
  if (user.accountType === 'external') result.special = 'external'
  if (user.accountType === 'suspended-review') result.special = 'suspended-review'
  const attached = orgIndex.get(user.orgId)
  const primary = user.primaryOrgId ? orgIndex.get(user.primaryOrgId) : attached
  if (!attached || !primary) return result
  result.attachedOrg = attached
  result.primaryOrg = primary
  result.secondaryAffiliation = attached.id !== primary.id

  const primaryChain = orgChain(orgIndex, primary.id)
  // 主归属链上的负责人身份（含链上所有层级，多负责人全部推导）
  for (const node of primaryChain) {
    const coLeader = node.leaderUserIds.length > 1 && node.leaderUserIds.includes(user.id)
    if (node.leaderUserIds.includes(user.id)) {
      const role: AuthzRole = node.depth === 1 ? 'P' : node.depth === 2 ? 'D' : 'T'
      result.leaderOf.push({ orgId: node.id, depth: node.depth, role, coLeader })
    }
  }
  // 跨分支负责人身份（一人多角色，多主体兼任管理）：不并入主角色推导（避免抬高主归属矩阵档位），
  // 由 check 的 leaderScopes 按所领导部门子树独立套用矩阵——多身份权限并存不冲突。
  for (const node of orgIndex.values()) {
    if (!node.leaderUserIds.includes(user.id)) continue
    if (primaryChain.some((onChain) => onChain.id === node.id)) continue
    const role: AuthzRole = node.depth === 1 ? 'P' : node.depth === 2 ? 'D' : 'T'
    result.leaderOfElsewhere.push({ orgId: node.id, orgName: node.name, depth: node.depth, role, coLeader: node.leaderUserIds.length > 1 })
  }
  // 主角色取链上最高负责人角色；无负责人身份按挂载深度推导
  if (result.leaderOf.length > 0) {
    result.role = result.leaderOf.reduce((best, item) => (item.role === 'P' || (best !== 'P' && item.role === 'D') ? item.role : best), result.leaderOf[0]!.role)
  } else if (primary.depth >= 3) {
    result.role = 'M'
  } else if (primary.depth === 1) {
    result.special = 'root-no-role'
  } else {
    result.special = 'dept-root-readonly'
  }
  return result
}

// ---------------------------------------------------------------------------
// 作用域推导（映射表优先、名字推导为默认，消除"路径即权限"单点脆性）
// ---------------------------------------------------------------------------

export interface DerivedScope {
  /** 命中的锚点组织（orgRoot 对应节点）。 */
  anchor?: EngineOrgNode
  /** 作用域前缀列表（平台口径绝对路径，含 NAS rootPath 收敛）。 */
  prefixes: string[]
  /** 解析方式：override=映射表命中；name=名字推导；none=未命中（对该 NAS 全 deny）。 */
  via: 'override' | 'name' | 'none'
  reason?: string
}

/**
 * 作用域推导（dev-plan-nas-authz §2.1 修订）：
 * 1. 组织祖先链（锚点 → 根）命中 `orgPathOverrides[orgId]` → 用映射前缀（组织改名/合并不漂移）；
 * 2. 否则名字推导：链上命中 `orgRoot`（orgId 或组织名）→ 目录子树 = rootPath + 自锚点起的名字拼接；
 * 3. 未命中 → none（对该 NAS 全 deny）。
 */
export function deriveScope(user: EngineUser, nas: EngineNas, orgIndex: OrgIndex): DerivedScope {
  const root = normalizePath(nas.rootPath || '/')
  const primary = orgIndex.get(user.primaryOrgId ?? user.orgId) ?? orgIndex.get(user.orgId)
  if (!primary) return { prefixes: [], via: 'none', reason: 'user-org-not-found' }
  // 角色与作用域对齐：主归属链上若领导某个（更浅层的）部门——负责人主部门挂在下属班组是常态
  // （钉钉 dept_id_list[0] 为主部门，管理职务在上级部门）——作用域锚提升到所领导的最高部门，
  // 否则 D/P 角色会落进更窄的下属作用域，矩阵放行形同虚设。
  const primaryChain = orgChain(orgIndex, primary.id)
  const ledAnchor = primaryChain
    .filter((node) => node.leaderUserIds.includes(user.id))
    .reduce<EngineOrgNode | undefined>((best, node) => (!best || node.depth < best.depth ? node : best), undefined)
  const anchor = ledAnchor ?? primary
  const chain = orgChain(orgIndex, anchor.id)
  const overrides = nas.orgPathOverrides ?? {}
  // ① 映射表优先：从锚点向根找第一个显式映射（锚点自身映射优先级最高）
  for (const node of chain) {
    const mapped = overrides[node.id]
    if (mapped) {
      const below = chain.slice(0, chain.indexOf(node)).reverse().map((item) => item.name)
      const prefix = joinPaths(root, [mapped.trim(), ...below].filter(Boolean).join('/'))
      return { anchor: node, prefixes: [prefix], via: 'override' }
    }
  }
  // ② 名字推导：链上找 orgRoot（orgId 精确匹配优先，组织名次之；取最浅命中=最接近平台级）
  if (nas.orgRoot) {
    const byId = chain.find((node) => node.id === nas.orgRoot)
    const byName = chain.find((node) => node.name === nas.orgRoot)
    const hit = byId ?? byName
    if (hit) {
      // 锚点组织自身（平台负责人 P 直属锚点）：作用域即 NAS 授权根整体
      const below = chain.slice(0, chain.indexOf(hit)).reverse().map((item) => item.name)
      const prefix = hit.id === anchor.id ? root : joinPaths(root, [hit.name, ...below].join('/'))
      return { anchor: hit, prefixes: [prefix], via: 'name' }
    }
  }
  // ③ 未命中任何锚点 → 对该 NAS 全 deny
  return { prefixes: [], via: 'none', reason: nas.orgRoot ? 'org-root-not-on-chain' : 'nas-org-root-not-configured' }
}

function joinPaths(root: string, suffix: string): string {
  const normalizedSuffix = `/${suffix}`.replace(/\\/g, '/').replace(/\/+$/, '')
  const segments = normalizedSuffix.split('/').filter(Boolean)
  if (root === '/' || root === '') return `/${segments.join('/')}`
  return `${root.replace(/\/+$/, '')}/${segments.join('/')}`
}

// ---------------------------------------------------------------------------
// 判定序（服务 B 语义移植，每步产出 reasons）
// ---------------------------------------------------------------------------

export interface EngineCheckContext {
  orgIndex: OrgIndex
  user?: EngineUser
  nas?: EngineNas
  rules: Pick<AuthzRulesSnapshot, 'version' | 'matrixOverrides' | 'exceptions' | 'cGroups' | 'externalReadPaths' | 'observeOnly' | 'degradeAllToReadonly'>
  /** 命中的 C 关联动态用户组 id（Service 层按规则解析后传入，引擎不做 IO）。 */
  cGroupHits: string[]
}

const OP_LABEL: Record<AuthzOp, string> = {
  read: '读取', download: '下载', write: '写入', modify: '改动', delete: '删除', share: '分享', admin: '管理',
}

/** 五步判定序（纯函数）。多路径取最严决策（任一 deny 即 deny），逐路径产出 reasons。 */
export function check(input: EngineCheckInput, ctx: EngineCheckContext): EngineDecision {
  const now = input.now ?? new Date().toISOString()
  const base: EngineDecision = { decision: 'deny', cTag: false, scope: [], reasons: [], perPath: [], observeOnly: ctx.rules.observeOnly, override: input.override === true }
  const denyAll = (reasons: string[]): EngineDecision => {
    base.decision = 'deny'
    base.reasons = reasons
    base.perPath = input.paths.map((path) => ({ path, decision: 'deny' as const, reasons }))
    return base
  }

  const user = ctx.user
  if (!user) return denyAll(['user-not-found：账号不存在或未同步'])
  if (ctx.nas === undefined) return denyAll(['nas-not-found：NAS 资产不存在'])

  // C 叠加标签（判定序④的范围扩展依据）
  const cTag = ctx.rules.cGroups.some((groupId) => ctx.cGroupHits.includes(groupId))
  base.cTag = cTag
  base.scope = deriveScope(user, ctx.nas, ctx.orgIndex).prefixes

  // ① 账号特殊规则
  const derived = deriveRole(user, ctx.orgIndex)
  base.role = derived.role
  if (derived.special === 'suspended-review') {
    return denyAll(['account.suspended-review：账号带可疑标记已冻结判定，转人工复核（审计已留痕）'])
  }
  if (derived.special === 'external') {
    const verdicts = input.paths.map((path) => {
      const whitelisted = ctx.rules.externalReadPaths.some((entry) => entry.nasId === input.nasId && matchExceptionPath(entry.path, path))
      if (!whitelisted) return { path, decision: 'deny' as const, reasons: ['account.external：外部账号仅白名单目录可读'] }
      if (WRITE_OPS.has(input.op)) return { path, decision: 'deny' as const, reasons: ['account.external：外部账号只读（白名单目录）'] }
      return { path, decision: 'allow' as const, reasons: ['account.external：白名单目录只读放行'] }
    })
    base.decision = verdicts.every((verdict) => verdict.decision === 'allow') ? 'allow' : 'deny'
    base.reasons = [...new Set(verdicts.flatMap((verdict) => verdict.reasons))]
    base.perPath = verdicts
    return finalize(base, ctx.rules, input)
  }
  if (derived.special === 'root-no-role') {
    return denyAll(['org.root-no-role：挂根组织且非负责人，无数据权限（请落入部门/班组）'])
  }

  const scope = deriveScope(user, ctx.nas, ctx.orgIndex)
  // 未落班组：部门根只读（read/download 放行于部门子树，写类拒绝）
  const deptRootReadonly = derived.special === 'dept-root-readonly'

  const matrix = effectiveMatrix(ctx.rules)
  const primaryRole = derived.role
  const coLeaderMarks = derived.leaderOf.filter((item) => item.coLeader).map((item) => `co-leader@${item.orgId}`)
  // 跨分支领导作用域（一人多角色）：所领导部门子树按该部门角色独立套用矩阵（全权限，非只读层），
  // 与主归属权限并存；所领导部门未命中该 NAS 锚点时不产生作用域（跨 NAS 隔离不变）。
  const leaderScopes = derived.leaderOfElsewhere.map((led) => ({
    ...led,
    prefixes: deriveScope({ ...user, primaryOrgId: led.orgId }, ctx.nas, ctx.orgIndex).prefixes,
  })).filter((led) => led.prefixes.length > 0)
  // 主作用域未命中锚点不提前拒绝：跨分支领导作用域仍可能命中（反之才全 deny）
  if (scope.via === 'none' && leaderScopes.length === 0) {
    return denyAll([`nas.no-scope：未命中该 NAS 的接入组织锚点（${scope.reason}）`])
  }
  base.scope = scope.via === 'none' ? [] : [...scope.prefixes]
  for (const led of leaderScopes) {
    if (!base.scope.some((prefix) => led.prefixes.includes(prefix))) base.scope = [...base.scope, ...led.prefixes]
  }
  // 兼任归属作用域（仅只读层）：锚点切到挂靠组织再推导一次
  const secondaryScope = derived.secondaryAffiliation
    ? deriveScope({ ...user, primaryOrgId: user.orgId }, ctx.nas, ctx.orgIndex)
    : undefined
  const secondaryPrefixes = secondaryScope && secondaryScope.via !== 'none' ? secondaryScope.prefixes : []
  if (secondaryPrefixes.length > 0) base.scope = [...base.scope, ...secondaryPrefixes]

  // 根目录只读列举（B 语义，2026-09-03 拍板）：在本 NAS 有任一作用域（主/跨分支领导/兼任挂靠）的用户，
  // 放行对 NAS 根路径本身的只读操作（列目录/查元信息）——否则子树作用域用户浏览文件第一步列根即被拒。
  // 显式 deny 例外仍优先（判定序②不变）；写类与根下越界路径不受影响；无任何作用域用户照常全拒。
  const nasRoot = normalizePath(ctx.nas!.rootPath || '/')
  const rootListingAllowed = scope.via !== 'none' || leaderScopes.length > 0 || secondaryPrefixes.length > 0

  const verdicts: EnginePathVerdict[] = input.paths.map((rawPath) => {
    const path = normalizePath(rawPath)
    // ② 资源级显式 deny（尾通配，可按人收敛）
    const denyHit = ctx.rules.exceptions.find((exception) => exception.effect === 'deny'
      && exception.nasId === input.nasId
      && exception.ops.includes(input.op)
      && !expired(exception, now)
      && (!exception.userIds || exception.userIds.includes(user.id))
      && matchExceptionPath(exception.path, path))
    if (denyHit) {
      return { path, decision: 'deny', reasons: [`exception.deny：命中显式拒绝规则 ${denyHit.id}${denyHit.note ? `（${denyHit.note}）` : ''}`], ruleId: denyHit.id }
    }
    // ③ 资源级显式 allow（C 跨域白名单、临时授权；可过期）
    const allowHit = ctx.rules.exceptions.find((exception) => exception.effect === 'allow'
      && exception.nasId === input.nasId
      && exception.ops.includes(input.op)
      && !expired(exception, now)
      && (!exception.userIds || exception.userIds.includes(user.id))
      && matchExceptionPath(exception.path, path))
    if (allowHit) {
      return { path, decision: 'allow', reasons: [`exception.allow：命中显式授权规则 ${allowHit.id}${allowHit.expiresAt ? `（${allowHit.expiresAt} 到期）` : ''}${allowHit.note ? `（${allowHit.note}）` : ''}`], ruleId: allowHit.id }
    }
    // 根目录只读列举（B 语义）：判定序在显式例外之后、作用域边界之前
    if (rootListingAllowed && !WRITE_OPS.has(input.op) && path === nasRoot) {
      return { path, decision: 'allow', reasons: ['org.root-listing：本 NAS 作用域内用户的根目录只读列举放行'] }
    }

    // ④ 角色矩阵 × 作用域边界（主作用域 / 跨分支领导层 / 兼任只读层 / C 跨域只读层）
    if (input.override === true) {
      return { path, decision: 'allow', reasons: ['override：破窗放行（P 判定，强制留痕）'] }
    }
    const inPrimary = scope.prefixes.some((prefix) => pathWithin(path, prefix))
    const ledHits = leaderScopes.filter((led) => led.prefixes.some((prefix) => pathWithin(path, prefix)))
    const inSecondary = !inPrimary && ledHits.length === 0 && secondaryPrefixes.some((prefix) => pathWithin(path, prefix))
    const inCScope = cTag && pathWithin(path, ctx.nas!.rootPath)
    if (!inPrimary && ledHits.length === 0 && !inSecondary && !inCScope) {
      return { path, decision: 'deny', reasons: [`path.out-of-scope：超出作用域 ${[...scope.prefixes, ...leaderScopes.flatMap((led) => led.prefixes)].join('、')}`] }
    }
    // 有效角色 = 主作用域角色与跨分支所领导部门角色的最高档（多身份作用域重叠时取高不叠加）
    const roleRank: Record<AuthzRole, number> = { P: 0, D: 1, T: 2 }
    let effRole: AuthzRole | undefined = inPrimary ? primaryRole : undefined
    let effFrom: string | undefined
    for (const led of ledHits) {
      if (!effRole || roleRank[led.role] < roleRank[effRole]) {
        effRole = led.role
        effFrom = led.orgName
      }
    }
    if (effRole) {
      const allowed = matrix[effRole][input.op]
      const sourceTag = effFrom ? `（跨分支所领导部门「${effFrom}」）` : ''
      const shareHint = input.op === 'share' && (effRole === 'T' || effRole === 'M') ? '（需走审批申请例外）' : ''
      return allowed
        ? { path, decision: 'allow', reasons: [`matrix.allow：角色 ${roleLabel(effRole)}${sourceTag} 在作用域内放行「${OP_LABEL[input.op]}」${!effFrom && coLeaderMarks.length > 0 ? `（${coLeaderMarks.join('、')}）` : ''}`] }
        : { path, decision: 'deny', reasons: [`matrix.deny：角色 ${roleLabel(effRole)}${sourceTag} 对「${OP_LABEL[input.op]}」无权限${shareHint}`] }
    }
    if (deptRootReadonly) {
      return WRITE_OPS.has(input.op)
        ? { path, decision: 'deny', reasons: ['org.dept-root-readonly：未落班组，部门根目录只读'] }
        : { path, decision: 'allow', reasons: ['org.dept-root-readonly：部门根目录只读放行'] }
    }
    if (inSecondary) {
      return WRITE_OPS.has(input.op)
        ? { path, decision: 'deny', reasons: ['org.secondary-readonly：兼任归属子树仅授只读（避免双写冲突）'] }
        : { path, decision: 'allow', reasons: ['org.secondary-readonly：兼任归属子树只读放行'] }
    }
    if (inCScope) {
      return WRITE_OPS.has(input.op)
        ? { path, decision: 'deny', reasons: ['role.c-readonly：C 跨域叠加仅只读，白名单目录写需显式授权'] }
        : { path, decision: 'allow', reasons: ['role.c-readonly：C 动态用户组跨域只读放行'] }
    }
    return { path, decision: 'deny', reasons: ['role.none：无法推导主角色（组织挂载异常）'] }
  })

  base.perPath = verdicts
  base.decision = verdicts.every((verdict) => verdict.decision === 'allow') ? 'allow' : 'deny'
  base.reasons = [...new Set(verdicts.flatMap((verdict) => verdict.reasons))]
  const hitRule = verdicts.find((verdict) => 'ruleId' in verdict && verdict.ruleId)
  if (hitRule) base.ruleId = (hitRule as EnginePathVerdict & { ruleId: string }).ruleId
  return finalize(base, ctx.rules, input)
}

/** 收尾：全量降级只读（G3）与观察模式标注。 */
function finalize(decision: EngineDecision, rules: Pick<AuthzRulesSnapshot, 'observeOnly' | 'degradeAllToReadonly'>, input: EngineCheckInput): EngineDecision {
  decision.observeOnly = rules.observeOnly
  if (decision.decision === 'allow' && rules.degradeAllToReadonly && WRITE_OPS.has(input.op) && input.override !== true) {
    decision.decision = 'deny'
    decision.reasons = [...decision.reasons, 'degrade.readonly：全量降级观察期，写类操作统一拒绝（G3）']
    decision.perPath = decision.perPath.map((verdict) => verdict.decision === 'allow'
      ? { ...verdict, decision: 'deny' as const, reasons: [...verdict.reasons, 'degrade.readonly：全量降级观察期'] }
      : verdict)
  }
  return decision
}

function expired(exception: AuthzException, now: string): boolean {
  return exception.expiresAt !== undefined && exception.expiresAt <= now
}

function roleLabel(role: AuthzRole): string {
  return role === 'P' ? 'P(平台负责人)' : role === 'D' ? 'D(部门负责人)' : role === 'T' ? 'T(班组负责人)' : 'M(成员)'
}

// ---------------------------------------------------------------------------
// 治理纯函数：负责人悬空 / 组织目录对账 / 审批人路由
// ---------------------------------------------------------------------------

/** 负责人悬空检测：leaderUserIds 为空的组织（可选限定挂了账号的组织）。 */
export function findVacantLeaderOrgs(orgIndex: OrgIndex, opts?: { withUserOrgIds?: Set<string> }): EngineOrgNode[] {
  return [...orgIndex.values()].filter((node) => {
    if (node.leaderUserIds.length > 0) return false
    if (opts?.withUserOrgIds && !opts.withUserOrgIds.has(node.id)) return false
    return true
  })
}

export interface DirOrphanFinding {
  kind: 'dir-without-org' | 'org-without-dir'
  name: string
  detail: string
}

/**
 * 组织 ↔ 目录对账（每日 job 的纯函数核心，dev-plan-nas-authz §2.1）：
 * - NAS 一级目录名在组织树（orgRoot 锚点子树直接子级）无同名组织 → dir-without-org；
 * - 锚点组织直接子级组织在 NAS 一级目录无同名目录 → org-without-dir。
 * 命中即发 dirOrphan 告警；组织 rename 时提示管理员确认登记 orgPathOverrides。
 */
export function reconcileOrgDirs(dirNames: string[], nas: EngineNas, orgIndex: OrgIndex): DirOrphanFinding[] {
  const findings: DirOrphanFinding[] = []
  const anchor = nas.orgRoot ? ([...orgIndex.values()].find((node) => node.id === nas.orgRoot || node.name === nas.orgRoot)) : undefined
  if (!anchor) return [{ kind: 'dir-without-org', name: '*', detail: `NAS 未配置有效 orgRoot（${nas.orgRoot ?? '空'}），作用域推导处于全 deny 态` }]
  const overrides = nas.orgPathOverrides ?? {}
  const childOrgs = [...orgIndex.values()].filter((node) => node.parentId === anchor.id)
  const dirSet = new Set(dirNames)
  for (const dir of dirNames) {
    const hasOrg = childOrgs.some((node) => node.name === dir)
    const hasOverride = Object.values(overrides).some((prefix) => normalizePath(prefix) === normalizePath(`/${dir}`) || normalizePath(prefix).startsWith(normalizePath(`/${dir}`)))
    if (!hasOrg && !hasOverride) findings.push({ kind: 'dir-without-org', name: dir, detail: `目录「/${dir}」在组织树（${anchor.name} 子级）无归属` })
  }
  for (const org of childOrgs) {
    if (!dirSet.has(org.name)) findings.push({ kind: 'org-without-dir', name: org.name, detail: `组织「${org.name}」在 NAS 上无同名目录（改名请登记 orgPathOverrides）` })
  }
  return findings
}

/**
 * share 审批人自动路由（dev-plan-nas-authz §2.7）：沿申请路径所属子树向上找最近
 * leaderUserIds 非空的负责人（从申请者组织链找；返回链上最近有负责人的组织与人员）。
 * 找不到返回 undefined（调用方升级 resource_admin 兜底审批）。
 */
export function nearestLeaderOrg(orgIndex: OrgIndex, userOrgId: string): { orgId: string; orgName: string; leaderUserIds: string[] } | undefined {
  for (const node of orgChain(orgIndex, userOrgId)) {
    if (node.leaderUserIds.length > 0) return { orgId: node.id, orgName: node.name, leaderUserIds: node.leaderUserIds }
  }
  return undefined
}
