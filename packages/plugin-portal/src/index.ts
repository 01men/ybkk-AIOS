/**
 * @dsh-ops/plugin-portal —— 门户数据通道（外部系统对接，非平台核心功能）。
 *
 * 企业门户（http://192.168.0.4:8092，纯前端静态站点）按「拉取（Pull）」策略主动来宿主平台
 * 获取已发布的 AI 应用 / 数字员工等数据（接口契约：docs/portal-integration.md，对接文档
 * api.md v1.0）。本插件只实现 6 个公开只读 GET 端点 + CORS 放行 + 可见性审计留痕，
 * 不向门户发起任何推送/回调请求。
 *
 * 边界（刻意保持，门户对接方式可能随门户方演进）：
 *   - 可整体停用：PORTAL_SYNC=off；摘除 = 删除本目录 + boot-all/cordis.yml 各一行，
 *     不影响平台任何业务链路；
 *   - 只读直读：端点实时读取 resourceCore/skillHub/mcpRegistry，无本地副本、无缓存，
 *     「上线/下架 → 门户刷新页面即可见」（契约的更新即时性要求）；
 *   - 契约可变：字段映射集中在 src/mapping.ts；端点前缀、放行来源均可环境变量覆盖。
 */
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { PlatformEvents, type HttpExchange } from '../../platform-core/src/index.ts'
import {
  emptySolutions, emptyTools, mapApps, mapEmployees, mapSkills, mapStats,
  type PortalMappingContext, type PortalSolution, type PortalTool,
} from './mapping.ts'

/** 端点前缀：门户 VITE_API_BASE 指向「<平台对外地址><前缀>」（默认 /api/portal）。 */
export function portalPrefix(): string {
  const raw = (process.env.PORTAL_API_PREFIX ?? '/api/portal').trim().replace(/\/+$/, '')
  return raw === '' ? '/api/portal' : (raw.startsWith('/') ? raw : `/${raw}`)
}

/** 数据通道总开关（默认开；PORTAL_SYNC=off 停用端点与留痕，门户侧降级展示内置样板）。 */
export function portalEnabled(): boolean {
  return String(process.env.PORTAL_SYNC ?? 'on').trim().toLowerCase() !== 'off'
}

/** 平台对外基址：拼进 downloadUrl 等需要绝对地址的字段（反代/换址时环境变量覆盖）。 */
export function portalPublicBase(): string {
  return (process.env.PORTAL_PUBLIC_BASE ?? 'http://192.168.0.7:7300').trim().replace(/\/+$/, '')
}

const ENDPOINTS = ['apps', 'employees', 'solutions', 'tools', 'skills', 'stats'] as const

export class PortalFeedService extends Service {
  static readonly provide = 'portalFeed'

  /** 单端点契约快照（端点应答唯一出口；CLI/自测亦可复用）。 */
  feed(endpoint: string): unknown[] | undefined {
    const mctx = this.mappingCtx()
    switch (endpoint) {
      case 'apps': return mapApps(this.ctx.resourceCore.list('app'), mctx)
      case 'employees': return mapEmployees(this.ctx.resourceCore.list('agent'), mctx)
      case 'solutions': return emptySolutions() satisfies PortalSolution[]
      case 'tools': return emptyTools() satisfies PortalTool[]
      case 'skills': return mapSkills(this.ctx.skillHub.skills().all(), mctx)
      case 'stats': return mapStats({
        apps: mapApps(this.ctx.resourceCore.list('app'), mctx).length,
        employees: mapEmployees(this.ctx.resourceCore.list('agent'), mctx).length,
        skills: mapSkills(this.ctx.skillHub.skills().all(), mctx).length,
        mcp: this.ctx.mcpRegistry.services().all()
          .filter((service) => service.status === 'online' || service.status === 'gray').length,
      })
      default: return undefined
    }
  }

  /**
   * 已上架技能包字节（门户公开下载，downloadUrl 的应答端）。
   * 仅 status=published 的当前已发布版本可取；经 skillHub.download 登记下载计量
   * （内部自带容错），再取与 NAS 上架产物同源的 zip 字节。
   */
  skillPackage(skillId: string): { buffer: Buffer; filename: string } | undefined {
    try {
      const skill = this.ctx.skillHub.skills().get(skillId)
      if (!skill || skill.status !== 'published') return undefined
      const version = skill.currentVersion
      const published = skill.versions.find((item) => item.version === version && item.status === 'published')
      if (!published) return undefined
      const pkg = this.ctx.skillHub.packageOf(skillId, version)
      try {
        this.ctx.skillHub.download(skillId, version, { id: 'portal', name: '企业门户（匿名拉取）' })
      } catch {
        // 下载计量失败不阻断取包
      }
      try {
        this.ctx.audit.record({
          type: 'invoke', actorType: 'system', actorId: 'portal-feed', actorName: '门户数据通道',
          action: 'portal.skill.download', resourceType: 'skill', resourceId: skillId, resourceName: skill.name,
          result: 'ok', detail: `门户公开下载：version=${version} bytes=${pkg.buffer.length}（免鉴权内网通道）`,
        })
      } catch {
        // 留痕失败不阻断下载
      }
      return { buffer: pkg.buffer, filename: pkg.filename }
    } catch {
      return undefined
    }
  }

  private mappingCtx(): PortalMappingContext {
    const prefix = portalPrefix()
    return {
      deptName: (orgId) => {
        try { return this.ctx.iam.orgs().get(orgId)?.name ?? '' } catch { return '' }
      },
      skillName: (skillId) => {
        try { return this.ctx.skillHub.skills().get(skillId)?.name ?? skillId } catch { return skillId }
      },
      skillDownloadUrl: (skillId) => `${portalPublicBase()}${prefix}/skills/${skillId}/download`,
      hideConfidential: String(process.env.PORTAL_HIDE_CONFIDENTIAL ?? '') === '1',
    }
  }
}

// ---- CORS（契约 §6：门户为浏览器跨域直连，必须放行，否则门户无法访问） --------------

/** 生产门户来源。 */
const PRODUCTION_PORTAL_ORIGINS = ['http://192.168.0.4:8092']

/** 门户侧显式追加来源（逗号分隔，如 http://192.168.0.4:8092,http://portal.example:8092）。 */
function extraOrigins(): Set<string> {
  return new Set(String(process.env.PORTAL_CORS_ORIGINS ?? '')
    .split(',').map((item) => item.trim()).filter(Boolean))
}

/** 门户开发服务器监听 0.0.0.0:8443（本地开发为 localhost，内网同事为各自 IP）。 */
function isPortalDevOrigin(origin: string): boolean {
  try {
    const url = new URL(origin)
    const host = url.hostname.toLowerCase()
    const intranet = host === 'localhost' || host === '127.0.0.1' || host === '::1'
      || /^10\.\d+\.\d+\.\d+$/.test(host)
      || /^192\.168\.\d+\.\d+$/.test(host)
      || /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/.test(host)
    return intranet && (url.port === '8443' || url.port === '8092')
  } catch {
    return false
  }
}

/** 允许则回显来源（无凭证，契约不需要 credentials），否则仅回 Vary。 */
function corsHeaders(origin: unknown): Record<string, string> {
  const value = typeof origin === 'string' ? origin : ''
  const allowed = value !== ''
    && (PRODUCTION_PORTAL_ORIGINS.includes(value) || isPortalDevOrigin(value) || extraOrigins().has(value))
  return allowed
    ? { vary: 'Origin', 'access-control-allow-origin': value }
    : { vary: 'Origin' }
}

/** 契约包装应答（{code, message, data}，code 0/200 门户视为成功；no-cache 保证刷新即可见）。 */
function respond(exchange: HttpExchange, status: number, payload: unknown, headers: Record<string, string>): void {
  if (exchange.res.headersSent) return
  exchange.res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-cache',
    ...headers,
  })
  exchange.res.end(JSON.stringify(payload))
}

export const name = 'portal'
export const inject = ['httpServer', 'platformBus', 'resourceCore', 'iam', 'skillHub', 'mcpRegistry', 'audit']

export function apply(ctx: Context) {
  const service = new PortalFeedService(ctx)

  if (portalEnabled()) {
    const prefix = portalPrefix()
    // 门户端点为公开只读（契约 §3：无鉴权）——在 console 鉴权中间件之前截获本前缀请求，
    // 自带 CORS 与契约应答，其余路径原样放行。注册顺序要求本插件先于 console 装配
    // （boot-all / cordis.yml 已按此声明）。
    ctx.effect(() => ctx.httpServer.use((exchange) => {
      if (exchange.path !== prefix && !exchange.path.startsWith(`${prefix}/`)) return
      const headers = corsHeaders(exchange.headers.origin)
      if (exchange.method === 'OPTIONS') {
        if (!exchange.res.headersSent) {
          exchange.res.writeHead(204, {
            ...headers,
            'access-control-allow-methods': 'GET, OPTIONS',
            'access-control-allow-headers': 'content-type',
            'access-control-max-age': '600',
          })
          exchange.res.end()
        }
        return true
      }
      if (exchange.method !== 'GET' && exchange.method !== 'HEAD') {
        respond(exchange, 405, { code: 40500, message: '门户契约为只读 GET，不支持该方式', data: null }, headers)
        return true
      }
      // 技能包公开下载（downloadUrl 的应答端）：zip 字节直出，非 JSON 契约
      const downloadMatch = exchange.path.slice(prefix.length).match(/^\/skills\/([^/]+)\/download$/)
      if (downloadMatch) {
        const pkg = service.skillPackage(decodeURIComponent(downloadMatch[1]!))
        if (!pkg) {
          respond(exchange, 404, { code: 40400, message: '技能不存在或未上架，无可下载包', data: null }, headers)
          return true
        }
        try {
          if (!exchange.res.headersSent) {
            // HTTP 头仅允许 ISO-8859-1：ASCII 兜底名（非 ASCII 字符替换为 _）+ RFC 5987 UTF-8 扩展名
            const asciiName = pkg.filename.replace(/[^\x20-\x7E]/g, '_').replace(/"/g, "'")
            exchange.res.writeHead(200, {
              'content-type': 'application/zip',
              'content-length': pkg.buffer.length,
              'content-disposition': `attachment; filename="${asciiName}"; filename*=UTF-8''${encodeURIComponent(pkg.filename)}`,
              'cache-control': 'no-cache',
              ...headers,
            })
            exchange.res.end(pkg.buffer)
          }
        } catch (error) {
          console.error('[portal] 技能包下载应答失败', error)
          respond(exchange, 500, { code: 50000, message: '技能包读取失败，请稍后重试', data: null }, headers)
        }
        return true
      }
      const tail = exchange.path.slice(prefix.length).replace(/^\/+|\/+$/g, '')
      if (tail === '') {
        // 端点发现：联调自检入口（curl <BASE>/ 应看到端点清单）
        respond(exchange, 200, {
          code: 0,
          message: 'ok',
          data: {
            service: 'portal-feed',
            contract: 'api.md v1.0',
            endpoints: ENDPOINTS,
            subResources: ['skills/:id/download（技能包公开下载，即 skills[].downloadUrl）'],
            generatedAt: new Date().toISOString(),
          },
        }, headers)
        return true
      }
      if (!(ENDPOINTS as readonly string[]).includes(tail)) {
        respond(exchange, 404, { code: 40400, message: `门户端点不存在：${tail}`, data: null }, headers)
        return true
      }
      respond(exchange, 200, { code: 0, message: 'ok', data: service.feed(tail) }, headers)
      return true
    }))
  } else {
    ctx.logger('portal').info('门户数据通道已停用（PORTAL_SYNC=off），门户将降级展示内置样板数据')
  }

  // 可见性留痕：应用/数字员工上下线 → 审计记录。门户为拉取模式，留痕仅为运营可观测
  // （「何时对门户可见/不可见」），无任何外呼动作。
  const visibilityTrail: Array<[string, string, string]> = [
    [PlatformEvents.AppOnlined, 'app', 'portal.feed.app.visible'],
    [PlatformEvents.AppOfflined, 'app', 'portal.feed.app.hidden'],
    [PlatformEvents.AgentOnlined, 'agent', 'portal.feed.employee.visible'],
    [PlatformEvents.AgentOfflined, 'agent', 'portal.feed.employee.hidden'],
  ]
  for (const [event, resourceType, action] of visibilityTrail) {
    ctx.platformBus.on(event, (payload) => {
      const record = payload as { id?: string; name?: string } | undefined
      try {
        ctx.audit.record({
          type: 'change', actorType: 'system', actorId: 'portal-feed', actorName: '门户数据通道',
          action, resourceType, resourceId: record?.id ?? '', resourceName: record?.name ?? '',
          result: 'ok', detail: '门户拉取模式：资源对门户可见性已变化，门户刷新页面即可见',
        })
      } catch {
        // 留痕失败不阻断业务事件链
      }
    })
  }
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    portalFeed: PortalFeedService
  }
}
