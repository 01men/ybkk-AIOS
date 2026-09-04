/**
 * 门户契约映射层（api.md v1.0「AI 数字化门户 · 数据接口对接文档」）：
 * 平台资源 → 门户只读 JSON 的唯一映射点。
 *
 * 设计约束（门户与推送方式可能变化，本能力为外部对接、非平台核心）：
 *   - 门户字段契约变化时只改本文件（换来源/加字段），端点与事件留痕不受影响；
 *   - 全部为纯函数，空值一律回退空串（契约约定：不返回 null / 缺省字段）。
 */
import type { ResourceEntity } from '../../platform-core/src/index.ts'

// ---- 门户字段契约（api.md §4） ------------------------------------------------

export interface PortalApp {
  id: string
  tag: string
  name: string
  desc: string
  dept: string
  version: string
  accent: string
  link: string
  launchDate: string
}

export interface PortalEmployee {
  id: string
  name: string
  role: string
  avatar: string
  skills: string
  dept: string
  link: string
  launchDate: string
}

export interface PortalSolution {
  id: string
  icon: string
  title: string
  desc: string
  cases: string
  link: string
  launchDate: string
}

export interface PortalTool {
  id: string
  name: string
  desc: string
  category: string
  link: string
  icon: string
  dept: string
  pinned: boolean
}

export interface PortalSkill {
  id: string
  name: string
  tag: string
  desc: string
  dept: string
  version: string
  downloadUrl: string
  launchDate: string
}

export interface PortalStat {
  value: string
  unit: string
  label: string
}

/** Skill 上架记录的映射所需最小结构（结构化类型，避免跨插件类型耦合）。 */
export interface PortalSkillSource {
  id: string
  name: string
  category: string
  tags: string[]
  summary: string
  description: string
  orgId: string
  authorName: string
  status: string
  currentVersion: string
  versions: Array<{ status: string; publishedAt?: string }>
}

/** 映射上下文：跨域服务（组织名/Skill 名/下载地址）经回调注入，映射函数保持无依赖可测。 */
export interface PortalMappingContext {
  deptName: (orgId: string) => string
  skillName: (skillId: string) => string
  /** 技能包公开下载地址（门户免鉴权下载端点）。 */
  skillDownloadUrl: (skillId: string) => string
  /** 机密应用不出门户（PORTAL_HIDE_CONFIDENTIAL=1 开启，默认关闭）。 */
  hideConfidential: boolean
}

// ---- 映射辅助 ----------------------------------------------------------------

const s = (value: unknown): string => (value === undefined || value === null ? '' : String(value))

const tags = (value: unknown): unknown[] => (Array.isArray(value) ? value : [])

/** 应用形态 → 门户分类标签（门户按 tag 筛选；未登记发布渠道时兜底为形态标签）。 */
const APP_TYPE_LABELS: Record<string, string> = {
  web: 'Web',
  h5: 'H5',
  miniapp: '小程序',
  desktop: '桌面端',
  api: 'API',
}

/** 卡片主题色调板（契约要求 #RRGGBB；平台无该属性，按 id 稳定散列取色，同应用恒定）。 */
const ACCENTS = ['#00AECC', '#7C3AED', '#059669', '#D97706', '#DB2777', '#0891B2', '#6366F1', '#F97316']

export function accentFor(id: string): string {
  let hash = 0
  for (const ch of id) hash = (hash * 31 + (ch.codePointAt(0) ?? 0)) >>> 0
  return ACCENTS[hash % ACCENTS.length]!
}

/** 生命周期历史中最近一次进入 online 的日期（YYYY-MM-DD）；从未上线返回空串（契约：「未上线」）。 */
export function lastOnlineDate(entity: Pick<ResourceEntity, 'lifecycleHistory'>): string {
  const at = (entity.lifecycleHistory ?? []).filter((entry) => entry.to === 'online').at(-1)?.at ?? ''
  return /^\d{4}-\d{2}-\d{2}/.test(at) ? at.slice(0, 10) : ''
}

// ---- 端点映射 ----------------------------------------------------------------

/**
 * 已上线 AI 应用 → 门户 /apps。
 * 「上线」即门户可见：应用经 L4 审批上线后，status=online 才进入清单（未上线不出门户）。
 */
export function mapApps(entities: ResourceEntity[], mctx: PortalMappingContext): PortalApp[] {
  return entities
    .filter((app) => app.status === 'online')
    .filter((app) => !mctx.hideConfidential || app.attrs['dataClass'] !== 'confidential')
    .map((app) => ({
      id: app.id,
      tag: s(tags(app.attrs['channels'])[0]) || APP_TYPE_LABELS[s(app.attrs['appType'])] || s(app.attrs['appType']),
      name: app.name,
      desc: s(app.attrs['description']),
      dept: mctx.deptName(app.orgId),
      version: s(app.attrs['publishVersion']),
      accent: accentFor(app.id),
      link: s(app.attrs['url']),
      launchDate: lastOnlineDate(app),
    }))
}

/** 已上线 Agent → 门户 /employees（数字员工）。 */
export function mapEmployees(entities: ResourceEntity[], mctx: PortalMappingContext): PortalEmployee[] {
  return entities
    .filter((agent) => agent.status === 'online')
    .map((agent) => {
      const skillNames = tags(agent.attrs['skills']).map((id) => mctx.skillName(s(id))).filter(Boolean)
      return {
        id: agent.id,
        name: agent.name,
        role: s(agent.attrs['description']),
        avatar: s(agent.attrs['avatar']) || '🤖',
        skills: (skillNames.length > 0 ? skillNames : tags(agent.attrs['tags']).map(s)).join(','),
        dept: mctx.deptName(agent.orgId),
        link: s(agent.attrs['entryUrl']),
        launchDate: lastOnlineDate(agent),
      }
    })
}

/** 已上架 Skill → 门户 /skills（launchDate 取最近一次版本上架时间）。 */
export function mapSkills(skills: PortalSkillSource[], mctx: PortalMappingContext): PortalSkill[] {
  return skills
    .filter((skill) => skill.status === 'published')
    .map((skill) => {
      const publishedAt = skill.versions
        .filter((version) => version.status === 'published' && version.publishedAt)
        .map((version) => String(version.publishedAt))
        .sort()
        .at(-1) ?? ''
      return {
        id: skill.id,
        name: skill.name,
        tag: s(skill.category) || s(skill.tags[0]),
        desc: s(skill.summary) || s(skill.description),
        dept: mctx.deptName(skill.orgId) || s(skill.authorName),
        version: s(skill.currentVersion),
        // 已上架技能包的公开下载端点（门户免鉴权可下载，平台侧登记下载计量）
        downloadUrl: mctx.skillDownloadUrl(s(skill.id)),
        launchDate: /^\d{4}-\d{2}-\d{2}/.test(publishedAt) ? publishedAt.slice(0, 10) : '',
      }
    })
}

/** 首页统计 4 卡（契约：value 必须为字符串，门户按数组顺序渲染 4 个指标卡）。 */
export function mapStats(counts: { apps: number; employees: number; skills: number; mcp: number }): PortalStat[] {
  return [
    { value: String(counts.apps), unit: '+', label: '已上线AI应用' },
    { value: String(counts.employees), unit: '+', label: '数字员工' },
    { value: String(counts.skills), unit: '+', label: '上架技能' },
    { value: String(counts.mcp), unit: '+', label: '在线MCP服务' },
  ]
}

/** /solutions：平台暂无对应数据源，返回空数组（契约 §5：门户自动降级展示内置样板）。 */
export function emptySolutions(): PortalSolution[] {
  return []
}

/** /tools：同上（数据源明确后再在 mapping.ts 补一个 map 函数即可）。 */
export function emptyTools(): PortalTool[] {
  return []
}
