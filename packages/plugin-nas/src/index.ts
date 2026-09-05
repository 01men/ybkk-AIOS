/**
 * @dsh-ops/plugin-nas —— NAS（FS 文件存储类）资产纳管。
 *
 * 访问模型：每台 NAS 经「MCP 文件网关」（参考 synology-filestation-mcp）访问——
 * 网关地址 + Bearer 令牌 + X-NAS-IP 设备路由头；全部文件操作（列表/检索/建删/
 * 上传/下载/改名/移动复制）经网关 tools/call 完成，平台不直连 DSM 私有 API。
 *
 * 基于 resource-core 底座（Pattern A）：属性表 + 生命周期状态机 + 依赖图复用，
 * 本插件补充：网关客户端、健康探活、工具发现、文件操作面与 Skill 包存储配置。
 * 全部写类文件操作审计留痕；读类操作仅在线资产可调；全部文件操作进 usage 计量
 * （nas:* 资源、calls/bytes 口径，默认零费率——观测先行，计费由价格簿调价决定）。
 */
import { mkdir, writeFile, readFile } from 'node:fs/promises'
import { join, normalize, sep } from 'node:path'
import { tmpdir } from 'node:os'
import type { Context } from '@deepseek-ai/cordis'
import { Service } from '@deepseek-ai/cordis'
import { PlatformEvents, newId, type RecordBase } from '../../platform-core/src/index.ts'
import type { ResourceEntity } from '../../plugin-resource-core/src/index.ts'
import { NasMcpClient, type McpToolInfo } from './client.ts'
import { NAS_TYPE_SPEC } from './schema.ts'
import { NasAuthzService } from './authz.ts'
import * as nasTools from './tools.ts'

// ---------------------------------------------------------------------------
// 数据模型
// ---------------------------------------------------------------------------

export interface NasHealthRecord extends RecordBase {
  nasId: string
  status: 'healthy' | 'degraded' | 'down' | 'unknown'
  latencyMs: number
  lastProbeAt: string
  consecutiveFails: number
  serverName?: string
}

export interface NasToolCacheRecord extends RecordBase {
  nasId: string
  tools: McpToolInfo[]
  syncedAt: string
}

/** Skill 包存储后端配置（单例）：local = 平台内联存储；nas = 上架时上传到指定 NAS 资产。 */
export interface SkillStorageConfigRecord extends RecordBase {
  mode: 'local' | 'nas'
  nasId?: string
  basePath?: string
  updatedAt: string
  updatedBy: string
}

// ---------------------------------------------------------------------------
// 服务
// ---------------------------------------------------------------------------

export class NasRegistryService extends Service {
  static readonly provide = 'nasRegistry'

  private clients = new Map<string, { client: NasMcpClient; signature: string }>()

  constructor(ctx: Context) {
    super(ctx, 'nasRegistry')
    ctx.resourceCore.registerType(NAS_TYPE_SPEC)
  }

  health(): CollectionLike<NasHealthRecord> {
    return this.ctx.opsStorage.collection<NasHealthRecord>('nas:health')
  }

  toolCache(): CollectionLike<NasToolCacheRecord> {
    return this.ctx.opsStorage.collection<NasToolCacheRecord>('nas:tools')
  }

  skillStorage(): CollectionLike<SkillStorageConfigRecord> {
    return this.ctx.opsStorage.collection<SkillStorageConfigRecord>('skill:storage')
  }

  // -- 注册与生命周期 -------------------------------------------------------

  register(input: { name: string; slug?: string; attrs?: Record<string, unknown>; ownerId: string; orgId: string }): ResourceEntity {
    const entity = this.ctx.resourceCore.create('nas', input)
    this.health().insert({ id: `hlt_${entity.id}`, nasId: entity.id, status: 'unknown', latencyMs: 0, lastProbeAt: '', consecutiveFails: 0 })
    this.ctx.platformBus.emit(PlatformEvents.NasRegistered, { id: entity.id, name: entity.name, slug: entity.slug, actor: input.ownerId, type: 'nas' })
    return entity
  }

  update(id: string, patch: { name?: string; attrs?: Record<string, unknown> }): ResourceEntity {
    const entity = this.ctx.resourceCore.update('nas', id, patch)
    // 接入属性变更后作废缓存的网关客户端（令牌轮换/换网关即时生效）
    this.clients.delete(id)
    return entity
  }

  get(id: string): ResourceEntity | undefined {
    return this.ctx.resourceCore.get('nas', id)
  }

  list(filter?: { status?: string; orgId?: string; q?: string }): ResourceEntity[] {
    return this.ctx.resourceCore.list('nas', filter)
  }

  /** 上线：先做网关 initialize 探活（不可达拒绝上线），再走状态机迁移与工具发现。 */
  async online(id: string, actor: string): Promise<ResourceEntity> {
    const nas = this.requireNas(id)
    const probe = await this.probe(id)
    if (probe.status === 'down') {
      throw new Error(`网关不可达，暂不能上线（${nas.attrs['gatewayUrl']}）`)
    }
    const result = this.ctx.resourceCore.transition('nas', id, 'online', actor)
    this.ctx.platformBus.emit(PlatformEvents.NasOnlined, { id, name: result.entity.name, slug: result.entity.slug, actor, type: 'nas' })
    void this.discoverTools(id).catch(() => undefined)
    return result.entity
  }

  offline(id: string, actor: string, reason: string): ResourceEntity {
    const result = this.ctx.resourceCore.transition('nas', id, 'offline', actor, reason)
    this.ctx.platformBus.emit(PlatformEvents.NasOfflined, { id, name: result.entity.name, slug: result.entity.slug, actor, reason, type: 'nas' })
    this.clients.delete(id)
    return result.entity
  }

  archive(id: string, actor: string): ResourceEntity {
    this.clients.delete(id)
    return this.ctx.resourceCore.transition('nas', id, 'archive', actor).entity
  }

  /** 删除后的关联清理：健康档案、工具发现缓存与网关客户端句柄。 */
  purge(id: string): void {
    this.clients.delete(id)
    for (const record of this.health().find((item) => item.nasId === id)) this.health().remove(record.id)
    for (const record of this.toolCache().find((item) => item.nasId === id)) this.toolCache().remove(record.id)
  }

  // -- 健康与工具发现 -------------------------------------------------------

  /** initialize 探活：延迟 > 800ms 记 degraded；连续失败 3 次记 down 并告警。 */
  async probe(id: string): Promise<NasHealthRecord> {
    const nas = this.requireNas(id)
    const existing = this.health().findOne((item) => item.nasId === id)
    const started = Date.now()
    let status: NasHealthRecord['status'] = 'healthy'
    let serverName: string | undefined
    try {
      const info = await this.clientFor(nas).probe()
      serverName = info.serverInfo?.name
      if (Date.now() - started > 800) status = 'degraded'
    } catch {
      status = 'down'
    }
    const fails = status === 'down' ? (existing?.consecutiveFails ?? 0) + 1 : 0
    const record: NasHealthRecord = {
      id: existing?.id ?? `hlt_${id}`,
      nasId: id,
      status,
      latencyMs: status === 'down' ? -1 : Date.now() - started,
      lastProbeAt: new Date().toISOString(),
      consecutiveFails: fails,
      ...(serverName !== undefined ? { serverName } : {}),
    }
    this.health().update(record.id, record)
    if (fails === 3) {
      this.ctx.audit.fire({
        severity: 'warning',
        title: `NAS「${nas.name}」网关连续探活失败`,
        message: `${nas.attrs['gatewayUrl']} 连续 3 次 initialize 探活失败，资产已标记 down，请检查网关服务与网络。`,
        resourceType: 'nas',
        resourceId: id,
      })
    }
    return record
  }

  healthOf(id: string): NasHealthRecord {
    return this.health().findOne((item) => item.nasId === id)
      ?? { id: `hlt_${id}`, nasId: id, status: 'unknown', latencyMs: 0, lastProbeAt: '', consecutiveFails: 0 }
  }

  /** 工具发现：网关 tools/list 结果落缓存（展示网关提供的 fs_* 能力面）。 */
  async discoverTools(id: string): Promise<McpToolInfo[]> {
    const nas = this.requireNas(id)
    const tools = await this.clientFor(nas).listTools()
    const existing = this.toolCache().findOne((item) => item.nasId === id)
    const record: NasToolCacheRecord = { id: existing?.id ?? `tls_${id}`, nasId: id, tools, syncedAt: new Date().toISOString() }
    if (existing) this.toolCache().update(existing.id, record)
    else this.toolCache().insert(record)
    return tools
  }

  toolsOf(id: string): McpToolInfo[] {
    return this.toolCache().findOne((item) => item.nasId === id)?.tools ?? []
  }

  // -- 文件操作面（全部经网关 tools/call） -----------------------------------

  async listShares(id: string, actor?: { id: string; name: string }): Promise<unknown> {
    return await this.fsCall(id, 'fs_list_shares', { additional: ['name', 'path', 'isdir'] }, { actor })
  }

  async listFiles(id: string, path = '/', actor?: { id: string; name: string }): Promise<unknown> {
    const fullPath = this.toFullPath(id, path)
    return await this.fsCall(id, 'fs_list', { folder_path: fullPath, additional: ['size', 'time', 'type', 'owner', 'perm'] }, { actor })
  }

  async getInfo(id: string, path: string, actor?: { id: string; name: string }): Promise<unknown> {
    const fullPath = this.toFullPath(id, path)
    return await this.fsCall(id, 'fs_get_info', { path: [fullPath], additional: ['size', 'time', 'type', 'owner', 'perm', 'real_path'] }, { actor })
  }

  async search(id: string, pattern: string, path = '/', actor?: { id: string; name: string }): Promise<unknown> {
    const fullPath = this.toFullPath(id, path)
    return await this.fsCall(id, 'fs_search', { folder_path: fullPath, pattern, recursive: true, limit: 200 }, { actor })
  }

  async mkdir(id: string, path: string, actor: { id: string; name: string }): Promise<unknown> {
    const { parent, name } = this.parentAndName(id, path)
    const result = await this.fsCall(id, 'fs_create_folder', { folder_path: [parent], name: [name], force_parent: true }, { actor })
    this.fsAudit(actor, 'nas.fs.mkdir', id, path)
    return result
  }

  async rename(id: string, path: string, newName: string, actor: { id: string; name: string }): Promise<unknown> {
    const fullPath = this.toFullPath(id, path)
    const result = await this.fsCall(id, 'fs_rename', { path: [fullPath], name: [newName] }, { actor })
    this.fsAudit(actor, 'nas.fs.rename', id, `${path} → ${newName}`)
    return result
  }

  async copyMove(id: string, paths: string[], destination: string, mode: 'copy' | 'move', actor: { id: string; name: string }): Promise<unknown> {
    const destFolder = this.toFullPath(id, destination)
    const srcFull = paths.map((p) => this.toFullPath(id, p))
    const result = await this.fsCall(id, 'fs_copy_move', { path: srcFull, dest_folder_path: destFolder, overwrite: true, remove_src: mode === 'move' }, { actor, timeoutMs: 120_000 })
    this.fsAudit(actor, `nas.fs.${mode}`, id, `${paths.join(',')} → ${destination}`)
    return result
  }

  async delete(id: string, paths: string[], actor: { id: string; name: string }): Promise<unknown> {
    const fullPaths = paths.map((p) => this.toFullPath(id, p))
    const result = await this.fsCall(id, 'fs_delete', { path: fullPaths, accurate_progress: false }, { actor, timeoutMs: 120_000 })
    this.fsAudit(actor, 'nas.fs.delete', id, paths.join(','))
    return result
  }

  /**
   * 上传文件到 NAS：buffer/本地文件 → 平台 staging 目录 → 网关 fs_upload（网关读本地 staging）。
   * 超时随字节数放宽（基线 30s + 每 MB 1s，上限 10 分钟）。跨机部署需共享 staging 卷。
   * onBehalf=false（默认 true）为平台服务身份直连：不透传 X-On-Behalf-User 头（网关以令牌
   * 绑定账号做数据权限判定，须有目标目录的显式 allow 例外），actor 仅进平台审计/计量——
   * 用于平台自有存储区写入（如 Skill 包上架），不应随操作人个人数据权限起伏。
   */
  async uploadFile(id: string, input: { buffer?: Buffer; localFile?: string; destPath: string; actor: { id: string; name: string }; onBehalf?: boolean }): Promise<{ path: string; sizeBytes: number }> {
    const nas = this.requireNas(id)
    let stagingFile: string
    let sizeBytes: number
    if (input.buffer !== undefined) {
      stagingFile = join(this.stagingDir(nas), input.destPath.split('/').filter(Boolean).pop() ?? `upload-${Date.now()}`)
      await mkdir(this.stagingDir(nas), { recursive: true })
      await writeFile(stagingFile, input.buffer)
      sizeBytes = input.buffer.length
    } else if (input.localFile) {
      stagingFile = input.localFile
      sizeBytes = (await readFile(stagingFile)).length
    } else {
      throw new Error('uploadFile 需要 buffer 或 localFile 之一')
    }
    const fullPath = this.toFullPath(id, input.destPath)
    const destDir = `/${fullPath.split('/').filter(Boolean).slice(0, -1).join('/')}`
    const timeoutMs = Math.min(600_000, 30_000 + Math.ceil(sizeBytes / (1024 * 1024)) * 1000)
    await this.fsCall(id, 'fs_upload', { local_file: stagingFile, dest_path: destDir || '/', create_parents: true, overwrite: true }, { actor: input.actor, bytes: sizeBytes, timeoutMs, onBehalf: input.onBehalf })
    this.fsAudit(input.actor, 'nas.fs.upload', id, `${input.destPath}（${sizeBytes}B，staging=${stagingFile}）`)
    return { path: input.destPath, sizeBytes }
  }

  /** 从 NAS 下载到平台 staging（网关 fs_download 在网关侧落盘到 dest_dir）。返回本地绝对路径 + 字节数。 */
  async downloadFile(id: string, path: string, actor: { id: string; name: string }): Promise<{ localFile: string; bytes: number; savedTo?: string }> {
    const nas = this.requireNas(id)
    const dir = join(this.stagingDir(nas), 'downloads')
    await mkdir(dir, { recursive: true })
    const fullPath = this.toFullPath(id, path)
    const result = await this.fsCall(id, 'fs_download', { path: [fullPath], mode: 'download', local_dir: dir }, { actor, timeoutMs: 600_000 })
    const parsed = extractFirstJson(result)
    const baseName = fullPath.split('/').filter(Boolean).pop() ?? 'file'
    const declared = typeof parsed?.saved_to === 'string' ? parsed.saved_to : undefined
    const candidate = declared ?? join(dir, baseName)
    let bytes = Number(parsed?.bytes ?? 0)
    try {
      const stat = await import('node:fs/promises').then((m) => m.stat(candidate))
      if (stat.isFile() && stat.size > 0) bytes = stat.size
      this.fsAudit(actor, 'nas.fs.download', id, `${path} → ${candidate}（${bytes}B）`)
      return { localFile: candidate, bytes, ...(declared ? { savedTo: declared } : {}) }
    } catch {
      this.fsAudit(actor, 'nas.fs.download', id, `${path} → ${candidate}（文件未落盘）`)
      return { localFile: candidate, bytes }
    }
  }

  async taskStatus(id: string, taskId: string, actor?: { id: string; name: string }): Promise<unknown> {
    return await this.fsCall(id, 'fs_task_status', { taskid: taskId }, { actor })
  }

  /**
   * 批量上传（保留目录结构）：files = [{ relativePath, contentBase64 | localPath }]
   * 顺序调用 fs_upload（NAS 端 create_parents 即可建链），返回每项的最终路径/字节数。
   */
  async uploadMany(id: string, items: Array<{ relativePath: string; contentBase64?: string; localPath?: string }>, destDir: string, actor: { id: string; name: string }): Promise<{ uploaded: Array<{ path: string; sizeBytes: number }>; failed: Array<{ relativePath: string; error: string }> }> {
    const uploaded: Array<{ path: string; sizeBytes: number }> = []
    const failed: Array<{ relativePath: string; error: string }> = []
    for (const item of items) {
      const destPath = `/${destDir}/${item.relativePath}`.replace(/\\/g, '/').replace(/\/+/g, '/')
      try {
        if (item.contentBase64 !== undefined) {
          const buf = Buffer.from(item.contentBase64, 'base64')
          const result = await this.uploadFile(id, { buffer: buf, destPath, actor })
          uploaded.push(result)
        } else if (item.localPath) {
          const result = await this.uploadFile(id, { localFile: item.localPath, destPath, actor })
          uploaded.push(result)
        } else {
          failed.push({ relativePath: item.relativePath, error: '缺少 contentBase64/localPath' })
        }
      } catch (error) {
        failed.push({ relativePath: item.relativePath, error: error instanceof Error ? error.message : String(error) })
      }
    }
    return { uploaded, failed }
  }

  /** 解析网关 fs_download 落盘的本地文件绝对路径（不重新调用网关），给 HTTP 层 streamReadFile 使用。 */
  async resolveDownloadedFile(id: string, path: string): Promise<{ localFile: string; bytes: number }> {
    const nas = this.requireNas(id)
    const dir = join(this.stagingDir(nas), 'downloads')
    const fullPath = this.toFullPath(id, path)
    const baseName = fullPath.split('/').filter(Boolean).pop() ?? 'file'
    const candidate = join(dir, baseName)
    let bytes = 0
    try {
      const stat = await import('node:fs/promises').then((m) => m.stat(candidate))
      bytes = stat.size
    } catch {
      throw new Error(`网关落盘文件不存在：${candidate}（请先调用 downloadFile 让网关写入）`)
    }
    return { localFile: candidate, bytes }
  }

  // -- Skill 包存储配置 -----------------------------------------------------

  getSkillStorage(): SkillStorageConfigRecord {
    return this.skillStorage().get('singleton')
      ?? { id: 'singleton', mode: 'local', updatedAt: '', updatedBy: '' }
  }

  setSkillStorage(patch: { mode?: 'local' | 'nas'; nasId?: string; basePath?: string }, actor: string): SkillStorageConfigRecord {
    const current = this.getSkillStorage()
    const next: SkillStorageConfigRecord = {
      ...current,
      ...(patch.mode !== undefined ? { mode: patch.mode } : {}),
      ...(patch.nasId !== undefined ? { nasId: patch.nasId } : {}),
      ...(patch.basePath !== undefined ? { basePath: patch.basePath } : {}),
      updatedAt: new Date().toISOString(),
      updatedBy: actor,
    }
    if (next.mode === 'nas') {
      if (!next.nasId) throw new Error('NAS 存储模式必须指定 nasId（先在 NAS 存储页纳管资产）')
      const nas = this.get(next.nasId)
      if (!nas) throw new Error(`NAS 资产不存在：${next.nasId}`)
      if (!next.basePath || !next.basePath.startsWith('/')) throw new Error('basePath 必须是以 / 开头的绝对路径')
    }
    if (this.skillStorage().get('singleton')) return this.skillStorage().update('singleton', next)
    return this.skillStorage().insert(next)
  }

  // -- 内部 -----------------------------------------------------------------

  private requireNas(id: string): ResourceEntity {
    const nas = this.ctx.resourceCore.get('nas', id)
    if (!nas) throw new Error(`NAS 资产不存在：${id}`)
    return nas
  }

  private requireOnline(id: string): ResourceEntity {
    const nas = this.requireNas(id)
    if (nas.status !== 'online') throw new Error(`NAS「${nas.name}」当前状态 ${nas.status}，仅已上线资产可执行文件操作`)
    return nas
  }

  private clientFor(nas: ResourceEntity): NasMcpClient {
    const endpoint = String(nas.attrs['gatewayUrl'] ?? '')
    const token = String(nas.attrs['accessToken'] ?? '')
    const nasIp = String(nas.attrs['nasIp'] ?? '')
    if (!endpoint || !token || !nasIp) throw new Error(`NAS「${nas.name}」接入属性未配全（gatewayUrl/accessToken/nasIp）`)
    const signature = `${endpoint}|${token}|${nasIp}`
    const cached = this.clients.get(nas.id)
    if (cached && cached.signature === signature) return cached.client
    const client = new NasMcpClient(endpoint, {
      Authorization: `Bearer ${token}`,
      'X-NAS-IP': nasIp,
    })
    this.clients.set(nas.id, { client, signature })
    return client
  }

  private async fsCall(id: string, tool: string, args: Record<string, unknown>, meter?: { actor?: { id: string; name: string }; bytes?: number; timeoutMs?: number; onBehalf?: boolean }): Promise<unknown> {
    const nas = this.requireOnline(id)
    const onBehalf = meter?.onBehalf === false ? {} : this.onBehalfHeaders(meter?.actor)
    const raw = await this.clientFor(nas).call(tool, args, {
      ...(meter?.timeoutMs ? { timeoutMs: meter.timeoutMs } : {}),
      ...(Object.keys(onBehalf).length > 0 ? { headers: onBehalf } : {}),
    })
    this.meterFsUsage(nas, meter)
    return typeof raw === 'string' ? parseMaybeJson(raw) : raw
  }

  /**
   * X-On-Behalf-User 解析（dev-plan-nas-authz §2.4 / P0-2 教训）：真实用户身份只经请求头
   * 透传给网关，绝不进网关工具参数。优先钉钉 userId（identityLinks 事实源反查），否则平台 userId。
   * 机器/工具自身调用（无真实用户或 actor 非账号标识，如内部系统中文名）不带该头——
   * 网关以令牌绑定身份为准（防伪造），且 HTTP 头仅收 ByteString。
   */
  private onBehalfHeaders(actor?: { id: string; name: string }): Record<string, string> {
    if (!actor?.id) return {}
    const rawId = actor.id.startsWith('user:') ? actor.id.slice('user:'.length) : actor.id
    if (rawId.startsWith('tool:') || rawId === 'platform' || rawId.includes(':')) return {}
    try {
      const user = this.ctx.iam?.users().get(rawId)
      if (user) {
        const link = this.ctx.iam.identityLinks().findOne((item) => item.userId === user.id && item.provider === 'dingtalk')
        return { 'X-On-Behalf-User': link ? link.providerUserId : user.id }
      }
    } catch { /* IAM 不可用时不带身份头（fail-closed 由网关侧兜底） */ }
    // 未落库的裸标识：仅 ASCII 可打印字符才可作头值（中文姓名等非账号标识一律不透传）
    if (!/^[\x21-\x7e]+$/.test(rawId)) return {}
    return { 'X-On-Behalf-User': rawId }
  }

  /** 计量管道（观测补齐）：全部文件操作进 usage 事件（nas:* 默认零费率，失败只告警不阻断）。 */
  private meterFsUsage(nas: ResourceEntity, meter?: { actor?: { id: string; name: string }; bytes?: number }): void {
    try {
      this.ctx.usage.record({
        org: nas.orgId,
        subject: meter?.actor ? (meter.actor.id.includes(':') ? meter.actor.id : `user:${meter.actor.id}`) : 'user:platform',
        principal: `org:${nas.orgId}`,
        resource: `nas:${nas.id}`,
        meters: [
          { key: 'calls', value: 1, unit: '次' },
          ...(meter?.bytes && meter.bytes > 0 ? [{ key: 'bytes', value: meter.bytes, unit: '字节' }] : []),
        ],
        idempotency_key: `nas:fs:${newId('nfs')}`,
      })
    } catch (error) {
      this.ctx.logger('nas').warn('usage 计量登记失败', error)
    }
  }

  /** 平台路径 → 真实网关契约的"绝对路径"（dsm 完整路径，如 /video/folder），并收敛到授权根路径内。
   *  真实 synology-filestation 网关以 `/volume1/<share>/<sub>` 形态传递，本平台取"平台路径"
   *  直接作为 DSM 路径（rootPath 默认 "/" 与网关 share 列表根等价）。 */
  private toFullPath(id: string, path: string): string {
    const nas = this.requireNas(id)
    const normalized = normalize(`/${path}`).replace(/\\/g, '/').replace(/\/+$/, '') || '/'
    const root = normalize(String(nas.attrs['rootPath'] ?? '/')).replace(/\\/g, '/').replace(/\/+$/, '') || '/'
    const compareRoot = root === '/' ? '/' : root
    if (compareRoot !== '/' && !normalized.startsWith(compareRoot === '/' ? '/' : compareRoot.endsWith('/') ? compareRoot : `${compareRoot}/`) && normalized !== compareRoot) {
      throw new Error(`路径 ${normalized} 超出授权根路径 ${root}`)
    }
    const segments = normalized.split('/').filter(Boolean)
    if (segments.some((s) => s === '..')) throw new Error('路径不允许包含 ..')
    if (segments.length === 0) return root
    return root === '/' ? `/${segments.join('/')}` : normalized
  }

  /** 解析创建目录所需的「父目录绝对路径 + 文件名」并保证在 rootPath 内。 */
  private parentAndName(id: string, path: string): { parent: string; name: string } {
    const full = this.toFullPath(id, path)
    const segments = full.split('/').filter(Boolean)
    if (segments.length < 1) throw new Error('新建目录必须形如 /<share>/name')
    const name = segments.pop()!
    const parent = `/${segments.join('/')}`
    return { parent, name }
  }

  private stagingDir(nas: ResourceEntity): string {
    const configured = String(nas.attrs['stagingDir'] ?? '').trim()
    if (configured) return configured
    return join(this.ctx.opsStorage.dataDirPath, 'nas-staging')
  }

  private fsAudit(actor: { id: string; name: string }, action: string, nasId: string, detail: string): void {
    this.ctx.audit.record({
      type: 'change',
      actorType: 'human',
      actorId: actor.id,
      actorName: actor.name,
      action,
      resourceType: 'nas',
      resourceId: nasId,
      resourceName: this.get(nasId)?.name ?? nasId,
      result: 'ok',
      detail,
    })
  }
}

// opsStorage 集合类型的本地别名（避免与服务名冲突的轻量声明）
interface CollectionLike<T extends RecordBase> {
  get(id: string): T | undefined
  findOne(predicate: (item: T) => boolean): T | undefined
  insert(record: T): T
  update(id: string, patch: Partial<T>): T
}

function parseMaybeJson(text: string): unknown {
  const trimmed = text.trim()
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return text
  try {
    return JSON.parse(trimmed)
  } catch {
    return text
  }
}

/** 兼容网关返回：单字符串块 / 数组块 / 嵌套 JSON；从数组/对象中提取首个 JSON 文本。 */
function extractFirstJson(result: unknown): Record<string, unknown> | undefined {
  if (!result) return undefined
  if (typeof result === 'object' && !Array.isArray(result)) return result as Record<string, unknown>
  const text = Array.isArray(result) ? (result as Array<Record<string, unknown>>).map((b) => typeof b?.text === 'string' ? b.text : '').join('') : typeof result === 'string' ? result : ''
  const trimmed = text.trim()
  if (!trimmed.startsWith('{')) return undefined
  try { return JSON.parse(trimmed) } catch { return undefined }
}

// ---------------------------------------------------------------------------
// 插件
// ---------------------------------------------------------------------------

declare module '@deepseek-ai/cordis' {
  interface Context {
    nasRegistry: NasRegistryService
  }
}

export const name = 'nas'
export const inject = ['opsStorage', 'platformBus', 'resourceCore', 'audit', 'usage', 'iam']

export function apply(ctx: Context) {
  ctx.plugin(NasRegistryService)
  ctx.plugin(NasAuthzService)
  ctx.plugin(nasTools)
}
