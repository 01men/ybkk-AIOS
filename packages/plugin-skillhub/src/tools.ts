/**
 * skillhub 插件对模型暴露的工具。
 */
import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '../../platform-core/src/index.ts'

export const name = 'skillhub-tools'
export const inject = ['tools', 'skillHub']

export function apply(ctx: Context) {
  const t = ctx.tools

  t.register(defineTool({
    name: 'skill_search',
    description: '搜索 Skill 市场（关键字/分类/标签，按下载量/评分/更新时间排序）。',
    parameters: {
      q: { type: 'string', description: '关键字' },
      category: { type: 'string', description: '分类' },
      sort: { type: 'string', enum: ['downloads', 'rating', 'updated'], description: '排序' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const skills = ctx.skillHub.search(args)
      return {
        total: skills.length,
        skills: skills.map((skill) => ({
          id: skill.id, name: skill.name, slug: skill.slug, category: skill.category,
          summary: skill.summary, version: skill.currentVersion, status: skill.status,
          author: skill.authorName, riskLevel: skill.riskLevel, stats: skill.stats, tags: skill.tags,
        })),
      }
    },
  }))

  t.register(defineTool({
    name: 'skill_submit',
    description: '提交 Skill 到市场（自动进入静态扫描 → 两级审批流水线）。可选携带 skill.zip 包内容（base64，上架时经存储后端上传 NAS）。',
    parameters: {
      name: { type: 'string', required: true, description: 'Skill 名称' },
      content: { type: 'string', required: true, description: 'SKILL.md 全文' },
      category: { type: 'string', description: '分类' },
      summary: { type: 'string', description: '一句话简介' },
      authorId: { type: 'string', required: true, description: '提交人用户 ID' },
      authorName: { type: 'string', required: true, description: '提交人姓名' },
      orgId: { type: 'string', required: true, description: '归属组织 ID' },
      version: { type: 'string', description: '版本号（默认 1.0.0）' },
      packageBase64: { type: 'string', description: 'skill.zip 包内容（base64，可选）' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const skill = ctx.skillHub.submit(args)
      return {
        id: skill.id, status: skill.status, version: skill.currentVersion,
        findings: skill.versions.at(-1)?.findings ?? [],
      }
    },
  }))

  t.register(defineTool({
    name: 'skill_approve',
    description: '审批 Skill 版本（domain 领域审批 / security 安全加签，高风险必须两級都过）。',
    permission: 'skill.approve',
    parameters: {
      skillId: { type: 'string', required: true, description: 'Skill ID' },
      version: { type: 'string', required: true, description: '版本号' },
      decision: { type: 'string', enum: ['approve', 'reject'], required: true, description: '审批结论' },
      level: { type: 'string', enum: ['domain', 'security'], required: true, description: '审批级别' },
      approverId: { type: 'string', required: true, description: '审批人用户 ID' },
      approverName: { type: 'string', required: true, description: '审批人姓名' },
      opinion: { type: 'string', required: true, description: '审批意见' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const skill = args.decision === 'approve'
        ? ctx.skillHub.approve(args.skillId, args.version, args.level, { id: args.approverId, name: args.approverName }, args.opinion)
        : ctx.skillHub.reject(args.skillId, args.version, { id: args.approverId, name: args.approverName }, args.opinion)
      return { id: skill.id, status: skill.status, versionStatus: skill.versions.find((item) => item.version === args.version)?.status }
    },
  }))

  t.register(defineTool({
    name: 'skill_publish',
    description: '上架已审批通过的 Skill 版本（版本不可变，旧版保留）。存储后端为 NAS 时自动打包上传 skill.zip（fail-closed）。',
    permission: 'skill.publish',
    parameters: {
      skillId: { type: 'string', required: true, description: 'Skill ID' },
      version: { type: 'string', required: true, description: '版本号' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const skill = await ctx.skillHub.publish(args.skillId, args.version, { id: 'platform', name: 'agent-tool' })
      const target = skill.versions.find((item) => item.version === args.version)
      return { id: skill.id, status: skill.status, package: target?.package ?? null }
    },
  }))

  t.register(defineTool({
    name: 'skill_install',
    description: '将市场 Skill 安装到指定 Agent（自动登记依赖关系并回填关联列表）。',
    permission: 'skill.install',
    parameters: {
      skillId: { type: 'string', required: true, description: 'Skill ID' },
      version: { type: 'string', required: true, description: '版本号' },
      agentId: { type: 'string', required: true, description: '目标 Agent ID' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const skill = ctx.skillHub.install(args.skillId, args.version, args.agentId, 'agent-tool')
      return { id: skill.id, installs: skill.stats.installs, note: '依赖已登记到资源依赖图' }
    },
  }))

  t.register(defineTool({
    name: 'skill_deprecate',
    description: '弃用/强制下架 Skill（触发存量引用告警与迁移建议）。必须给出 reason。',
    permission: 'skill.publish',
    parameters: {
      skillId: { type: 'string', required: true, description: 'Skill ID' },
      reason: { type: 'string', required: true, description: '弃用原因' },
      force: { type: 'boolean', description: 'true 为强制下架（L4，建议走审批）' },
    },
    output: { type: 'object', additionalProperties: true },
    async execute(args) {
      const result = ctx.skillHub.deprecate(args.skillId, 'agent-tool', args.reason, args.force)
      return {
        id: result.skill.id, status: result.skill.status,
        referencingAgents: result.referencingAgents,
        note: '已发布 skill.deprecated 事件并触发存量引用告警',
      }
    },
  }))
}
