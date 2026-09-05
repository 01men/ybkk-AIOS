/**
 * @dsh-ops/plugin-skillhub —— Skill 市场（方案 §四）。
 *
 * 提交流水线（事件驱动）：submitted → scanned(静态扫描) → approved(两级审批)
 *                        → published(版本化上架)。
 * - 提交前置校验：格式/元数据完整性、恶意代码静态扫描、敏感信息检测。
 * - 两级审批：领域负责人（业务适用性）→ 平台管理员（安全合规）；
 *   高风险 Skill（外联/写文件）需安全团队加签。
 * - 版本不可变：新版本上架不覆盖旧版，支持弃用标记与强制下架。
 * - 下载/安装即登记依赖关系（接入 Agent 时自动回填关联 Skill 列表）。
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { PlatformEvents, createZip, newId, slugify, type Collection, type RecordBase } from '../../platform-core/src/index.ts'
import * as skillhubTools from './tools.ts'

// ---------------------------------------------------------------------------
// 数据模型
// ---------------------------------------------------------------------------

export type SkillStatus = 'draft' | 'scanning' | 'pending_approval' | 'rejected' | 'published' | 'deprecated' | 'offline'

export interface ScanFinding {
  level: 'block' | 'warn' | 'info'
  rule: string
  message: string
}

export interface VersionApproval {
  level: 'domain' | 'security'
  approverId: string
  approverName: string
  opinion: string
  at: string
}

/** 上架产物：Skill 包（skill.zip）的位置与体积（storage=nas 时由上架钩子写入）。 */
export interface SkillPackageInfo {
  storage: 'nas' | 'local'
  nasId?: string
  path?: string
  sizeBytes?: number
  uploadedAt?: string
}

export interface SkillVersion {
  version: string
  changelog: string
  content: string
  status: 'scanning' | 'pending_domain' | 'pending_security' | 'approved' | 'rejected' | 'published' | 'deprecated'
  submittedAt: string
  findings: ScanFinding[]
  approvals: VersionApproval[]
  publishedAt?: string
  rejectedReason?: string
  /** 提交时可选携带的 skill.zip 包内容（base64；上架时原样上传 NAS）。 */
  packageBase64?: string
  /** 上架时写入的包位置（storage=nas 为 NAS 绝对路径；local 为平台内联）。 */
  package?: SkillPackageInfo
}

export interface SkillRecord extends RecordBase {
  name: string
  slug: string
  category: string
  tags: string[]
  summary: string
  description: string
  authorId: string
  authorName: string
  orgId: string
  visibility: 'all' | 'orgs' | 'groups'
  targetOrgs: string[]
  applicableModels: string[]
  deps: string[]
  riskLevel: 'low' | 'medium' | 'high'
  status: SkillStatus
  currentVersion: string
  versions: SkillVersion[]
  /** 弃用/强制下架原因（下架分析口径：随记录持久化，详情与看板可见）。 */
  deprecatedReason?: string
  deprecatedAt?: string
  stats: { downloads: number; installs: number; rating: number; ratingCount: number }
  ratings: Array<{ userId: string; stars: number; at: string }>
  cover: string
}

export interface SkillDownloadRecord extends RecordBase {
  skillId: string
  version: string
  userId: string
  userName: string
}

// ---------------------------------------------------------------------------
// 静态扫描器
// ---------------------------------------------------------------------------

const BLOCK_RULES: Array<{ rule: string; pattern: RegExp; message: string }> = [
  { rule: 'destructive', pattern: /rm\s+-rf|del\s+\/[sq]/i, message: '检测到破坏性删除命令' },
  { rule: 'shell-injection', pattern: /eval\s*\(|exec\s*\(|system\s*\(/i, message: '检测到动态代码执行调用' },
  { rule: 'pipe-download', pattern: /(curl|wget)[^\n]*\|\s*(sh|bash|zsh)/i, message: '检测到下载并直接执行脚本' },
  { rule: 'secret', pattern: /(sk-[a-zA-Z0-9]{16,}|AKID[A-Za-z0-9]{12,}|api[_-]?key\s*[:=]\s*['"][^'"]{8,})/i, message: '检测到疑似密钥/凭证泄露' },
]

const WARN_RULES: Array<{ rule: string; pattern: RegExp; message: string }> = [
  { rule: 'network', pattern: /https?:\/\/(?!127\.0\.0\.1|localhost)/i, message: '包含外部网络访问，需评估数据出域风险' },
  { rule: 'fs-write', pattern: /writeFile|open\s*\(.['"]w|>\s*\/[a-z]/i, message: '包含文件写入操作' },
  { rule: 'subprocess', pattern: /child_process|subprocess|spawn/i, message: '包含子进程调用' },
]

export function scanContent(content: string): ScanFinding[] {
  const findings: ScanFinding[] = []
  for (const rule of BLOCK_RULES) {
    if (rule.pattern.test(content)) findings.push({ level: 'block', rule: rule.rule, message: rule.message })
  }
  for (const rule of WARN_RULES) {
    if (rule.pattern.test(content)) findings.push({ level: 'warn', rule: rule.rule, message: rule.message })
  }
  if (content.length < 40) findings.push({ level: 'warn', rule: 'too-short', message: 'SKILL.md 内容过短，请补充使用说明' })
  return findings
}

// ---------------------------------------------------------------------------
// 服务
// ---------------------------------------------------------------------------

export class SkillHubService extends Service {
  static readonly provide = 'skillHub'

  constructor(ctx: Context) {
    super(ctx, 'skillHub')
  }

  skills(): Collection<SkillRecord> {
    return this.ctx.opsStorage.collection<SkillRecord>('skill:skills')
  }

  downloads(): Collection<SkillDownloadRecord> {
    return this.ctx.opsStorage.collection<SkillDownloadRecord>('skill:downloads')
  }

  categories(): string[] {
    return [...new Set(this.skills().all().map((skill) => skill.category))].filter(Boolean)
  }

  // -- 提交与扫描 ---------------------------------------------------------

  submit(input: {
    name: string
    category?: string
    tags?: string[]
    summary?: string
    description?: string
    content: string
    version?: string
    changelog?: string
    authorId: string
    authorName: string
    orgId: string
    visibility?: SkillRecord['visibility']
    targetOrgs?: string[]
    applicableModels?: string[]
    deps?: string[]
    cover?: string
    /** 可选：skill.zip 包内容（base64）。上架时经存储后端（可配 NAS）原样上传。 */
    packageBase64?: string
  }): SkillRecord {
    if (!input.name?.trim()) throw new Error('Skill 名称不能为空')
    if (!input.content?.trim()) throw new Error('SKILL.md 内容不能为空')
    if (input.packageBase64 !== undefined) validatePackageBase64(input.packageBase64)
    const slug = slugify(input.name)
    const existing = this.skills().findOne((skill) => skill.slug === slug)
    const version: SkillVersion = {
      version: input.version ?? (existing ? bumpMinor(existing.currentVersion) : '1.0.0'),
      changelog: input.changelog ?? '首次提交',
      content: input.content,
      status: 'scanning',
      submittedAt: now(),
      findings: [],
      approvals: [],
      ...(input.packageBase64 !== undefined ? { packageBase64: input.packageBase64 } : {}),
    }
    if (existing) {
      if (existing.versions.some((item) => item.version === version.version)) {
        throw new Error(`版本 ${version.version} 已存在（版本不可变原则），请递增版本号`)
      }
      const updated = this.skills().update(existing.id, {
        versions: [...existing.versions, version],
        currentVersion: version.version,
        status: 'scanning',
        ...(input.summary !== undefined ? { summary: input.summary } : {}),
        ...(input.description !== undefined ? { description: input.description } : {}),
      })
      this.runScan(updated.id, version.version)
      return this.skills().get(updated.id)!
    }
    const created = this.skills().insert({
      id: newId('skl'),
      name: input.name,
      slug,
      category: input.category ?? '通用',
      tags: input.tags ?? [],
      summary: input.summary ?? input.content.split('\n')[0]?.slice(0, 80) ?? '',
      description: input.description ?? '',
      authorId: input.authorId,
      authorName: input.authorName,
      orgId: input.orgId,
      visibility: input.visibility ?? 'all',
      targetOrgs: input.targetOrgs ?? [],
      applicableModels: input.applicableModels ?? ['deepseek-chat'],
      deps: input.deps ?? [],
      riskLevel: 'low',
      status: 'scanning',
      currentVersion: version.version,
      versions: [version],
      stats: { downloads: 0, installs: 0, rating: 0, ratingCount: 0 },
      ratings: [],
      cover: input.cover ?? 'spark',
    })
    this.ctx.platformBus.emit(PlatformEvents.SkillSubmitted, { skillId: created.id, name: created.name, version: version.version, author: input.authorName })
    this.runScan(created.id, version.version)
    return this.skills().get(created.id)!
  }

  /** 静态扫描：blocking 发现 → 自动驳回；警告 → 高风险需安全加签。 */
  runScan(skillId: string, version: string): ScanFinding[] {
    const skill = this.requireSkill(skillId)
    const target = skill.versions.find((item) => item.version === version)
    if (!target) throw new Error(`版本不存在：${version}`)
    const findings = scanContent(target.content)
    const hasBlock = findings.some((finding) => finding.level === 'block')
    const hasWarn = findings.some((finding) => finding.level === 'warn')
    const versions = skill.versions.map((item) =>
      item.version === version
        ? { ...item, findings, status: hasBlock ? ('rejected' as const) : ('pending_domain' as const), rejectedReason: hasBlock ? '静态扫描发现阻断级问题' : undefined }
        : item)
    const nextStatus: SkillStatus = hasBlock ? 'rejected' : 'pending_approval'
    this.skills().update(skillId, {
      versions: versions as SkillVersion[],
      status: nextStatus,
      riskLevel: hasWarn ? 'high' : findings.some((f) => f.level === 'info') ? 'medium' : 'low',
    })
    if (hasBlock) {
      this.ctx.audit.record({
        type: 'change', actorType: 'system', actorId: 'scanner', actorName: '静态扫描',
        action: 'skill.scan.rejected', resourceType: 'skill', resourceId: skillId, resourceName: skill.name,
        result: 'denied', detail: findings.filter((f) => f.level === 'block').map((f) => f.message).join('；'),
      })
    }
    return findings
  }

  // -- 审批与上架 ---------------------------------------------------------

  approve(skillId: string, version: string, level: 'domain' | 'security', approver: { id: string; name: string }, opinion: string): SkillRecord {
    const skill = this.requireSkill(skillId)
    const target = skill.versions.find((item) => item.version === version)
    if (!target) throw new Error(`版本不存在：${version}`)
    if (target.status !== 'pending_domain' && target.status !== 'pending_security') {
      throw new Error(`该版本当前状态 ${target.status} 不可审批`)
    }
    if (level === 'domain' && target.status !== 'pending_domain') throw new Error('领域审批已完成，当前等待安全审批')
    if (level === 'security' && target.status !== 'pending_security') throw new Error('高风险 Skill 才需要安全加签，当前等待领域审批')
    if (target.approvals.some((item) => item.level === level && item.approverId === approver.id)) {
      throw new Error('同一审批人不可重复审批')
    }
    const approvals = [...target.approvals, { level, approverId: approver.id, approverName: approver.name, opinion, at: now() }]
    const needSecurity = skill.riskLevel === 'high'
    const nextVersionStatus: SkillVersion['status'] = level === 'domain' && needSecurity ? 'pending_security' : 'approved'
    const versions = skill.versions.map((item) => item.version === version ? { ...item, approvals, status: nextVersionStatus } : item)
    return this.skills().update(skillId, { versions: versions as SkillVersion[] })
  }

  reject(skillId: string, version: string, approver: { id: string; name: string }, opinion: string): SkillRecord {
    const skill = this.requireSkill(skillId)
    const versions = skill.versions.map((item) =>
      item.version === version
        ? { ...item, status: 'rejected' as const, rejectedReason: opinion, approvals: [...item.approvals, { level: item.status === 'pending_domain' ? 'domain' : 'security', approverId: approver.id, approverName: approver.name, opinion, at: now() }] }
        : item)
    return this.skills().update(skillId, { versions: versions as SkillVersion[], status: 'rejected' })
  }

  /**
   * 上架：审批通过 →（可选）skill.zip 上传 NAS 存储后端 → 版本标记 published。
   * 存储后端为 nas 时 fail-closed：包上传失败即上架失败（错误信息含网关/中转目录排查指引）。
   * NAS 上传走平台服务身份（onBehalf=false）：存储区写入是平台自身能力，不随操作人个人
   * NAS 数据权限起伏（操作人仍留在平台审计/事件里；网关侧以令牌绑定账号判定，需有
   * skill 存储目录的显式 allow 例外——数据权限页可配）。
   */
  async publish(skillId: string, version: string, actor: { id: string; name: string }): Promise<SkillRecord> {
    const skill = this.requireSkill(skillId)
    const target = skill.versions.find((item) => item.version === version)
    if (!target) throw new Error(`版本不存在：${version}`)
    if (target.status !== 'approved') throw new Error(`版本状态 ${target.status} 不可上架（需完成审批）`)
    let packageInfo: SkillPackageInfo | undefined
    const storage = this.ctx.nasRegistry.getSkillStorage()
    if (storage.mode === 'nas') {
      const nasId = storage.nasId!
      const nas = this.ctx.nasRegistry.get(nasId)
      if (!nas) throw new Error(`Skill 包存储后端指向的 NAS 资产不存在：${nasId}（请在 Skill 存储配置中修正）`)
      if (nas.status !== 'online') throw new Error(`Skill 包存储后端 NAS「${nas.name}」当前状态 ${nas.status}，上架中止（fail-closed）`)
      const buffer = this.packageBufferOf(skill, target)
      const basePath = (storage.basePath ?? '/skillhub').replace(/\/+$/, '')
      const destPath = `${basePath}/${skill.slug}/${skill.slug}-${version}.zip`
      try {
        const uploaded = await this.ctx.nasRegistry.uploadFile(nasId, {
          buffer,
          destPath,
          actor,
          onBehalf: false,
        })
        packageInfo = { storage: 'nas', nasId, path: uploaded.path, sizeBytes: uploaded.sizeBytes, uploadedAt: new Date().toISOString() }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        throw new Error(`skill.zip 上传 NAS 失败，上架中止：${message}（排查：网关服务与令牌；若为数据权限拒绝，请在数据权限页为网关令牌绑定账号授予存储目录 ${basePath} 的 allow 例外；或先把 Skill 存储切回 local）`)
      }
    }
    const versions = skill.versions.map((item) =>
      item.version === version
        ? { ...item, status: 'published' as const, publishedAt: now(), ...(packageInfo !== undefined ? { package: packageInfo } : {}) }
        : item)
    const updated = this.skills().update(skillId, { versions: versions as SkillVersion[], status: 'published' })
    this.ctx.platformBus.emit(PlatformEvents.SkillPublished, {
      skillId, name: updated.name, version, actor: actor.name, type: 'skill', slug: updated.slug,
      ...(packageInfo !== undefined ? { package: { storage: packageInfo.storage, path: packageInfo.path, sizeBytes: packageInfo.sizeBytes } } : {}),
    })
    return updated
  }

  /** 上架/下载用的 skill.zip 字节：优先提交时携带的原始包；否则由 SKILL.md + manifest 现场打包。 */
  packageBufferOf(skill: SkillRecord, target: SkillVersion): Buffer {
    if (target.packageBase64) return Buffer.from(target.packageBase64, 'base64')
    return createZip([
      { path: 'SKILL.md', content: target.content },
      { path: 'manifest.json', content: JSON.stringify({ name: skill.name, slug: skill.slug, version: target.version, category: skill.category, tags: skill.tags, summary: skill.summary }, null, 2) },
    ])
  }

  /** 取某已发布版本的 skill.zip（本地字节与 NAS 上架产物同源）。 */
  packageOf(skillId: string, version: string): { buffer: Buffer; filename: string; info: SkillPackageInfo } {
    const skill = this.requireSkill(skillId)
    const target = skill.versions.find((item) => item.version === version && item.status === 'published')
    if (!target) throw new Error(`已发布版本不存在：${version}`)
    return {
      buffer: this.packageBufferOf(skill, target),
      filename: `${skill.slug}-${target.version}.zip`,
      info: target.package ?? { storage: 'local' },
    }
  }

  // -- 编辑与资源重传 -------------------------------------------------------

  /**
   * 编辑已上架（及其他状态）Skill 的市场信息：分类/标签/简介/描述/可见性/适用模型/依赖/封面。
   * 仅作者本人或管理员（skill.publish，路由层判定后传 asAdmin）可编辑；slug 保持稳定
   * （Agent 按 slug 回填关联 Skill，改名不打断引用）；SKILL.md 内容不走此口——内容变更
   * 属新版本，仍须走提交 → 扫描 → 审批流水线（版本不可变原则）。
   */
  update(skillId: string, patch: {
    name?: string
    category?: string
    tags?: string[]
    summary?: string
    description?: string
    visibility?: SkillRecord['visibility']
    targetOrgs?: string[]
    applicableModels?: string[]
    deps?: string[]
    cover?: string
    /** 作者/开发者展示名：仅改展示（列表与详情署名），authorId 归属锚点不变。 */
    authorName?: string
  }, actor: { id: string; name: string }, opts?: { asAdmin?: boolean }): SkillRecord {
    const skill = this.requireSkill(skillId)
    if (skill.authorId !== actor.id && opts?.asAdmin !== true) {
      throw new Error('仅 Skill 作者或平台管理员可编辑该 Skill 信息')
    }
    if (patch.name !== undefined && !patch.name.trim()) throw new Error('Skill 名称不能为空')
    if (patch.authorName !== undefined && !patch.authorName.trim()) throw new Error('作者名称不能为空')
    if (patch.tags !== undefined && (!Array.isArray(patch.tags) || patch.tags.some((tag) => typeof tag !== 'string'))) {
      throw new Error('标签格式不正确')
    }
    if (patch.visibility !== undefined && !['all', 'orgs', 'groups'].includes(patch.visibility)) {
      throw new Error(`可见性取值不合法：${patch.visibility}`)
    }
    if (patch.visibility === 'orgs' && patch.targetOrgs !== undefined && patch.targetOrgs.length === 0 && skill.targetOrgs.length === 0) {
      throw new Error('可见性为「指定组织」时须至少选择一个目标组织')
    }
    const allowed = ['name', 'category', 'tags', 'summary', 'description', 'visibility', 'targetOrgs', 'applicableModels', 'deps', 'cover', 'authorName'] as const
    const changes = Object.fromEntries(allowed.map((key) => [key, patch[key]]).filter(([, value]) => value !== undefined))
    if (Object.keys(changes).length === 0) return skill
    // 名称可改、slug 不变：slug 是安装依赖回填（agent.attrs.skills）的引用键
    const updated = this.skills().update(skillId, {
      ...changes,
      ...(patch.name !== undefined ? { name: patch.name.trim() } : {}),
      ...(patch.authorName !== undefined ? { authorName: patch.authorName.trim() } : {}),
    })
    this.ctx.platformBus.emit(PlatformEvents.SkillUpdated, {
      skillId, name: updated.name, actor: actor.name, actorId: actor.id, asAdmin: opts?.asAdmin === true,
      fields: Object.keys(changes), type: 'skill', slug: updated.slug,
    })
    return updated
  }

  /**
   * 重新手动上传当前已发布版本的 skill.zip 资源包：原地替换（版本号不变），
   * storage=nas 时按上架同链路重传 NAS（fail-closed），local 时仅更新内联包与登记。
   * 仅作者本人或管理员可操作；替换后下载/安装取到的即是新包（packageBufferOf 优先 packageBase64）。
   */
  async replacePackage(skillId: string, packageBase64: string, actor: { id: string; name: string }, opts?: { asAdmin?: boolean }): Promise<SkillRecord> {
    const skill = this.requireSkill(skillId)
    if (skill.authorId !== actor.id && opts?.asAdmin !== true) {
      throw new Error('仅 Skill 作者或平台管理员可更新该 Skill 资源包')
    }
    validatePackageBase64(packageBase64)
    const target = skill.versions.find((item) => item.version === skill.currentVersion && item.status === 'published')
    if (!target) throw new Error(`当前版本 ${skill.currentVersion} 不存在已发布产物，无法替换资源包`)
    const sizeBytes = Buffer.from(packageBase64, 'base64').length
    let packageInfo: SkillPackageInfo = { ...(target.package ?? { storage: 'local' as const }), sizeBytes, uploadedAt: new Date().toISOString() }
    const storage = this.ctx.nasRegistry.getSkillStorage()
    if (storage.mode === 'nas') {
      const nasId = storage.nasId!
      const nas = this.ctx.nasRegistry.get(nasId)
      if (!nas) throw new Error(`Skill 包存储后端指向的 NAS 资产不存在：${nasId}（请在 Skill 存储配置中修正）`)
      if (nas.status !== 'online') throw new Error(`Skill 包存储后端 NAS「${nas.name}」当前状态 ${nas.status}，更新中止（fail-closed）`)
      const buffer = Buffer.from(packageBase64, 'base64')
      const basePath = (storage.basePath ?? '/skillhub').replace(/\/+$/, '')
      const destPath = `${basePath}/${skill.slug}/${skill.slug}-${target.version}.zip`
      try {
        const uploaded = await this.ctx.nasRegistry.uploadFile(nasId, { buffer, destPath, actor, onBehalf: false })
        packageInfo = { storage: 'nas', nasId, path: uploaded.path, sizeBytes: uploaded.sizeBytes, uploadedAt: new Date().toISOString() }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        throw new Error(`skill.zip 上传 NAS 失败，资源包未更新：${message}（排查：网关服务与令牌；若为数据权限拒绝，请在数据权限页为网关令牌绑定账号授予存储目录 ${basePath} 的 allow 例外；或先把 Skill 存储切回 local）`)
      }
    }
    const versions = skill.versions.map((item) =>
      item.version === target.version ? { ...item, packageBase64, package: packageInfo } : item)
    const updated = this.skills().update(skillId, { versions: versions as SkillVersion[] })
    this.ctx.platformBus.emit(PlatformEvents.SkillPackageReplaced, {
      skillId, name: updated.name, version: target.version, actor: actor.name, actorId: actor.id,
      asAdmin: opts?.asAdmin === true, storage: packageInfo.storage, sizeBytes: packageInfo.sizeBytes,
      type: 'skill', slug: updated.slug,
    })
    return updated
  }

  deprecate(skillId: string, actor: string, note: string, force?: boolean): { skill: SkillRecord; referencingAgents: Array<{ id: string; name: string; owner: string }> } {
    const skill = this.requireSkill(skillId)
    if (!note?.trim()) throw new Error('弃用必须填写原因（护栏要求）')
    if (skill.status !== 'published') throw new Error('仅已上架 Skill 可弃用')
    const versions = skill.versions.map((item) => item.status === 'published' ? { ...item, status: 'deprecated' as const } : item)
    const updated = this.skills().update(skillId, {
      versions: versions as SkillVersion[],
      status: force ? 'offline' : 'deprecated',
      deprecatedReason: note,
      deprecatedAt: new Date().toISOString(),
    })
    // 扫描引用该 Skill 的 Agent，产出存量引用告警
    const referencingAgents = this.referencingAgents(skillId)
    this.ctx.platformBus.emit(PlatformEvents.SkillDeprecated, {
      skillId, name: updated.name, actor, note, force,
      referencingAgents: referencingAgents.map((agent) => agent.id),
      type: 'skill', slug: updated.slug,
    })
    if (referencingAgents.length > 0) {
      this.ctx.audit.fire({
        severity: 'warning',
        title: `Skill「${updated.name}」已${force ? '强制下架' : '弃用'}，存在存量引用`,
        message: `${referencingAgents.length} 个 Agent 仍在使用该 Skill：${referencingAgents.map((agent) => agent.name).join('、')}。请通知负责人灰度迁移。`,
        resourceType: 'skill',
        resourceId: skillId,
      })
    }
    return { skill: updated, referencingAgents }
  }

  /** 依赖图反查：哪些 Agent 安装了该 Skill。 */
  referencingAgents(skillId: string): Array<{ id: string; name: string; owner: string }> {
    return this.ctx.resourceCore.dependencies()
      .find((record) => record.kind === 'skill' && record.toId === skillId)
      .map((record) => {
        const agent = this.ctx.resourceCore.collection('agent').get(record.fromId)
        return agent ? { id: agent.id, name: agent.name, owner: agent.attrs['ownerName'] ?? agent.ownerId } : null
      })
      .filter((item): item is { id: string; name: string; owner: string } => item !== null)
  }

  /** 删除后的关联清理：安装依赖边、下载登记与技能记录；审计数据保留。 */
  purge(skillId: string): void {
    for (const record of this.ctx.resourceCore.dependencies().find((item) => item.kind === 'skill' && item.toId === skillId)) {
      this.ctx.resourceCore.dependencies().remove(record.id)
    }
    for (const record of this.downloads().find((item) => item.skillId === skillId)) this.downloads().remove(record.id)
    this.skills().remove(skillId)
  }

  // -- 下载 / 安装 --------------------------------------------------------

  download(skillId: string, version: string, user: { id: string; name: string }): { content: string } {
    const skill = this.requireSkill(skillId)
    const target = skill.versions.find((item) => item.version === version && item.status === 'published')
    if (!target) throw new Error(`已发布版本不存在：${version}`)
    const record = this.downloads().insert({ id: newId('dwl'), skillId, version, userId: user.id, userName: user.name })
    this.skills().update(skillId, { stats: { ...skill.stats, downloads: skill.stats.downloads + 1 } })
    this.meterSkillUsage(skill, 'downloads', `skill:dl:${record.id}`, `user:${user.id}`)
    return { content: target.content }
  }

  /** 安装到 Agent：登记依赖关系（资源依赖图自动回填）。 */
  install(skillId: string, version: string, agentId: string, actor: string): SkillRecord {
    const skill = this.requireSkill(skillId)
    const agent = this.ctx.resourceCore.collection('agent').get(agentId)
    if (!agent) throw new Error(`Agent 不存在：${agentId}`)
    const target = skill.versions.find((item) => item.version === version && item.status === 'published')
    if (!target) throw new Error(`已发布版本不存在：${version}`)
    this.ctx.resourceCore.addDependency({ fromType: 'agent', fromId: agentId, toType: 'skill', toId: skillId, kind: 'skill' })
    // 回填 Agent 属性中的关联 Skill 列表
    const skillsAttr = Array.isArray(agent.attrs['skills']) ? [...agent.attrs['skills'] as string[]] : []
    if (!skillsAttr.includes(skill.slug)) {
      skillsAttr.push(skill.slug)
      this.ctx.resourceCore.collection('agent').update(agentId, { attrs: { ...agent.attrs, skills: skillsAttr } })
    }
    const updated = this.skills().update(skillId, { stats: { ...skill.stats, installs: skill.stats.installs + 1 } })
    this.meterSkillUsage(skill, 'installs', `skill:inst:${newId('uis')}`, `agent:${agentId}`)
    this.ctx.platformBus.emit(PlatformEvents.SkillInstalled, { skillId, version, agentId, agentName: agent.name, actor })
    return updated
  }

  /** 计量管道（观测补齐）：skill 下载/安装进 usage 事件（skill:<ID>，中文名 slug 含非 ASCII 故用 ID；
   *  skill:* 默认零费率，失败只告警不阻断主流程。calls 为价格簿计价键（usage.record 硬校验要求
   *  事件必含计价键），downloads/installs 为观测维度保留。 */
  private meterSkillUsage(skill: SkillRecord, meterKey: 'downloads' | 'installs', idempotencyKey: string, subject: string): void {
    try {
      this.ctx.usage.record({
        org: skill.orgId,
        subject,
        principal: `org:${skill.orgId}`,
        resource: `skill:${skill.id}`,
        meters: [
          { key: 'calls', value: 1, unit: '次' },
          { key: meterKey, value: 1, unit: '次' },
        ],
        idempotency_key: idempotencyKey,
      })
    } catch (error) {
      this.ctx.logger('skillhub').warn('usage 计量登记失败', error)
    }
  }

  uninstall(skillId: string, agentId: string): void {
    this.ctx.resourceCore.removeDependency({ fromType: 'agent', fromId: agentId, toType: 'skill', toId: skillId })
    const agent = this.ctx.resourceCore.collection('agent').get(agentId)
    if (agent && Array.isArray(agent.attrs['skills'])) {
      const skills = (agent.attrs['skills'] as string[]).filter((slug) => slug !== this.requireSkill(skillId).slug)
      this.ctx.resourceCore.collection('agent').update(agentId, { attrs: { ...agent.attrs, skills } })
    }
  }

  rate(skillId: string, userId: string, stars: number): SkillRecord {
    const skill = this.requireSkill(skillId)
    if (stars < 1 || stars > 5 || !Number.isInteger(stars)) throw new Error('评分须为 1-5 的整数')
    const ratings = [...skill.ratings.filter((item) => item.userId !== userId), { userId, stars, at: now() }]
    const rating = ratings.length === 0 ? 0 : Math.round((ratings.reduce((sum, item) => sum + item.stars, 0) / ratings.length) * 10) / 10
    return this.skills().update(skillId, { ratings, stats: { ...skill.stats, rating, ratingCount: ratings.length } })
  }

  // -- 搜索 ---------------------------------------------------------------

  /**
   * 搜索：默认仅已上架/已弃用；includePending 时把在途项（待审批/扫描中）一并呈现
   * （排最前、按更新时间排序，带状态徽标）——让审批人直接在市场里看到待办。
   */
  search(options: { q?: string; category?: string; tag?: string; sort?: 'downloads' | 'rating' | 'updated'; viewerOrgId?: string; includePending?: boolean }): SkillRecord[] {
    let list = this.skills().find((skill) => {
      const inFlight = options.includePending === true && ['pending_approval', 'scanning'].includes(skill.status)
      if (!['published', 'deprecated'].includes(skill.status) && !inFlight) return false
      if (options.category && skill.category !== options.category) return false
      if (options.tag && !skill.tags.includes(options.tag)) return false
      if (skill.visibility === 'orgs' && options.viewerOrgId && !skill.targetOrgs.includes(options.viewerOrgId)) return false
      if (options.q) {
        const haystack = `${skill.name} ${skill.summary} ${skill.tags.join(' ')} ${skill.category}`.toLowerCase()
        if (!haystack.includes(options.q.toLowerCase())) return false
      }
      return true
    })
    const published = list.filter((skill) => ['published', 'deprecated'].includes(skill.status))
    const sort = options.sort ?? 'downloads'
    const sorted = published.sort((a, b) => {
      if (sort === 'rating') return b.stats.rating - a.stats.rating
      if (sort === 'updated') return b.updatedAt.localeCompare(a.updatedAt)
      return b.stats.downloads - a.stats.downloads
    })
    if (options.includePending !== true) return sorted
    const pending = list.filter((skill) => !['published', 'deprecated'].includes(skill.status))
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
    return [...pending, ...sorted]
  }

  detail(skillId: string): SkillRecord {
    return this.requireSkill(skillId)
  }

  private requireSkill(skillId: string): SkillRecord {
    const skill = this.skills().get(skillId)
    if (!skill) throw new Error(`Skill 不存在：${skillId}`)
    return skill
  }
}

function bumpMinor(version: string): string {
  const parts = version.split('.').map(Number)
  parts[1] = (parts[1] ?? 0) + 1
  parts[2] = 0
  return parts.join('.')
}

/** 提交包校验：base64 可解码、ZIP 魔数（PK\u0003\u0004）、体积 ≤ 32MB。 */
function validatePackageBase64(value: string): void {
  if (typeof value !== 'string' || value.length === 0) throw new Error('packageBase64 不能为空字符串')
  if (value.length > 44_000_000) throw new Error('skill.zip 过大（base64 后上限 32MB）')
  const buffer = Buffer.from(value, 'base64')
  if (buffer.length < 4 || buffer[0] !== 0x50 || buffer[1] !== 0x4b) {
    throw new Error('packageBase64 不是合法的 ZIP 内容（缺少 PK 魔数）')
  }
}

function now(): string {
  return new Date().toISOString()
}

// ---------------------------------------------------------------------------
// 插件
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    skillHub: SkillHubService
  }
}

export const name = 'skillhub'
export const inject = ['opsStorage', 'platformBus', 'resourceCore', 'audit', 'nasRegistry', 'usage']

export function apply(ctx: Context) {
  ctx.plugin(SkillHubService)
  ctx.plugin(skillhubTools)
}
