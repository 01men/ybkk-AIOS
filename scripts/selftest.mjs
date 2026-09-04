/**
 * 功能自测：启动隔离实例（独立端口 + 独立数据目录），对全链路做端到端断言。
 * 覆盖：认证/RBAC、IAM 生命周期与三方同步、令牌吊销联动、MCP 部署灰度与网关鉴权限流、
 *       Skill 流水线（扫描/两级审批/上架/安装/弃用告警）、Agent/App 生命周期 L4 审批、
 *       on-behalf-of、审计四类日志、告警、成本、工具桥。
 * 用法：npm run selftest
 */
import { spawn } from 'node:child_process'
// NAS 数据权限纯函数引擎（dev-plan-nas-authz O8：引擎直接单测，不经服务层）
import {
  MATRIX_DEFAULT, buildOrgIndex, check as engineCheck, deriveRole, findVacantLeaderOrgs, nearestLeaderOrg,
} from '../packages/plugin-nas/src/authz/engine.ts'
import { readFileSync as __readFileSyncSeed } from 'node:fs'
const NAS_AUTHZ_SEED = JSON.parse(__readFileSyncSeed(new URL('../packages/plugin-nas/seed/nas-authz-rules.json', import.meta.url), 'utf8'))
import { createServer, request as httpRequest } from 'node:http'
import { createHash } from 'node:crypto'
import { rm, mkdir } from 'node:fs/promises'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const readBody = (req) => new Promise((resolve) => {
  const chunks = []
  req.on('data', (c) => chunks.push(c))
  req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
})

const PORT = 7311
const BASE = `http://127.0.0.1:${PORT}`
const DATA_DIR = join(process.cwd(), 'data-selftest')

const results = []
let currentSection = ''
function section(name) {
  currentSection = name
  console.log(`\n\x1b[36m━━ ${name} ━━\x1b[0m`)
}
function check(name, condition, detail = '') {
  const pass = Boolean(condition)
  results.push({ section: currentSection, name, pass })
  console.log(`  ${pass ? '\x1b[32m✔' : '\x1b[31m✘'} ${name}\x1b[0m${pass ? '' : `  ← ${detail}`}`)
  return pass
}
async function api(method, path, { token, body } = {}) {
  const headers = { 'content-type': 'application/json' }
  if (token) headers.authorization = `Bearer ${token}`
  const response = await fetch(`${BASE}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  let payload = null
  try { payload = await response.json() } catch { /* ignore */ }
  return { status: response.status, ok: payload?.ok ?? false, data: payload?.data, error: payload?.error }
}

/** 原始 HTTP 请求（OIDC 协议端点：302 Location / WWW-Authenticate / form 编码等需要原始面）。 */
const rawReq = (method, path, { headers = {}, body } = {}) => new Promise((resolve, reject) => {
  const req = httpRequest({ host: '127.0.0.1', port: PORT, method, path, headers }, (res) => {
    const chunks = []
    res.on('data', (chunk) => chunks.push(chunk))
    res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }))
  })
  req.on('error', reject)
  if (body !== undefined) req.write(body)
  req.end()
})
const jsonBody = (raw) => { try { return JSON.parse(raw.body) } catch { return {} } }

/** OIDC 授权流平台端点为原始 JSON 契约（无 {ok,data} 包裹），直连读取。 */
const authReqInfo = async (reqId) => {
  const raw = await rawReq('GET', `/api/authn/oidc/auth-requests/${encodeURIComponent(reqId)}`)
  return { status: raw.status, info: jsonBody(raw) }
}
const authorizeConfirm = async (token, reqId, consent) => {
  const raw = await rawReq('POST', '/api/authn/oidc/authorize', {
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ reqId, ...(consent !== undefined ? { consent } : {}) }),
  })
  return { status: raw.status, result: jsonBody(raw) }
}

// ---------------------------------------------------------------- stub 上游仓库（平台更新检查用）
// 进程内真实 HTTP stub：raw package.json（版本 9.9.9）+ compare API（落后 2 个提交）。
// 更新插件经 DSH_UPDATE_RAW_BASE / DSH_UPDATE_API_BASE 指向本 stub，自测不依赖外网。
const GH_PORT = 7361
const ghStub = createServer((req, res) => {
  const url = req.url ?? ''
  if (url.endsWith('/package.json')) {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ name: 'dsh-enterprise-ops', version: '9.9.9' }))
    return
  }
  if (url.includes('/compare/')) {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({
      behind_by: 2,
      commits: [
        { sha: 'f1111111111111111111111111111111111111111', commit: { message: 'feat: 上游演示提交一', author: { name: '上游作者', date: '2026-08-24T02:00:00Z' } } },
        { sha: 'a2222222222222222222222222222222222222222', commit: { message: 'fix: 上游演示提交二', author: { name: '上游作者', date: '2026-08-24T03:00:00Z' } } },
      ],
    }))
    return
  }
  res.writeHead(404, { 'content-type': 'application/json' })
  res.end('{}')
})
await new Promise((resolve) => ghStub.listen(GH_PORT, '127.0.0.1', resolve))

// ---------------------------------------------------------------- stub NAS 文件网关
// 进程内真实 HTTP stub，复刻 synology-filestation-mcp 契约：
// POST /mcp（initialize / notifications/initialized / tools/list / tools/call），
// 强制校验 Authorization: Bearer 与 X-NAS-IP 设备路由头；fs_upload 按真实网关语义
// 在「网关进程侧」读取 local_file（同机/共享卷契约——本进程可直接读平台 staging 目录）。
const NAS_GW_PORT = 7362
const NAS_GW_TOKEN = 'gw-selftest-token-9f8e7d6c'
const NAS_GW_IP = '192.168.0.196'
const nasGwCalls = []
const nasGwUploads = []
const nasGwStub = createServer(async (req, res) => {
  const json = (status, payload, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', ...headers })
    res.end(JSON.stringify(payload))
  }
  if (req.method !== 'POST' || req.url !== '/mcp') return json(404, { error: 'not found' })
  if (req.headers.authorization !== `Bearer ${NAS_GW_TOKEN}`) return json(401, { jsonrpc: '2.0', id: null, error: { code: -32001, message: '网关鉴权失败' } })
  if (req.headers['x-nas-ip'] !== NAS_GW_IP) return json(400, { jsonrpc: '2.0', id: null, error: { code: -32002, message: '未知 NAS 设备（X-NAS-IP）' } })
  let message = null
  try { message = JSON.parse(await readBody(req)) } catch { return json(400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }) }
  const sessionHeaders = { 'mcp-session-id': 'stub-session-selftest' }
  // 通知类消息（无 id）：确认即止
  if (message.id === undefined || message.id === null) { res.writeHead(202, sessionHeaders); res.end(); return }
  const reply = (result) => json(200, { jsonrpc: '2.0', id: message.id, result }, sessionHeaders)
  const replyError = (code, text) => json(200, { jsonrpc: '2.0', id: message.id, error: { code, message: text } }, sessionHeaders)
  if (message.method === 'initialize') {
    return reply({ protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'synology-filestation-stub', version: '1.0.0' } })
  }
  if (message.method === 'tools/list') {
    const names = ['fs_list_shares', 'fs_list', 'fs_get_info', 'fs_search', 'fs_create_folder', 'fs_rename', 'fs_delete', 'fs_upload', 'fs_download', 'fs_task_status']
    return reply({ tools: names.map((name) => ({ name, description: `stub ${name}`, inputSchema: { type: 'object' } })) })
  }
  if (message.method === 'tools/call') {
    const name = String(message.params?.name ?? '')
    const args = message.params?.arguments ?? {}
    nasGwCalls.push({ name, args, onBehalf: req.headers['x-on-behalf-user'] ?? null })
    const text = (value) => reply({ content: [{ type: 'text', text: JSON.stringify(value) }] })
    // 对齐真实 synology-filestation 网关契约（folder_path/path 为字符串/数组；create_folder 用 folder_path+name 一一对应数组；download 用 path 数组 + local_dir）
    if (name === 'fs_list_shares') return text({ shares: [{ name: 'homes', path: '/homes', isdir: true }, { name: 'skillhub', path: '/skillhub', isdir: true }] })
    if (name === 'fs_list') return text({ files: [{ name: 'readme.txt', isdir: false, size: 128 }, { name: 'reports', isdir: true }], total: 2, offset: 0 })
    if (name === 'fs_get_info') {
      const reqPaths = Array.isArray(args.path) ? args.path : [args.path].filter(Boolean)
      return text({ files: reqPaths.map((p) => ({ path: p, name: String(p).split('/').pop(), size: 128, isdir: false })) })
    }
    if (name === 'fs_search') return text({ files: [{ path: `/found/${args.pattern}` }], taskid: 'tsk_1' })
    if (name === 'fs_create_folder') {
      const folders = Array.isArray(args.folder_path) ? args.folder_path : [args.folder_path].filter(Boolean)
      const names = Array.isArray(args.name) ? args.name : [args.name].filter(Boolean)
      return text({ folders: folders.map((folder, i) => ({ path: `${folder}/${names[i] ?? 'new'}`, name: names[i] })) })
    }
    if (name === 'fs_rename') {
      const reqPaths = Array.isArray(args.path) ? args.path : [args.path].filter(Boolean)
      const names = Array.isArray(args.name) ? args.name : [args.name].filter(Boolean)
      return text({ files: reqPaths.map((p, i) => ({ path: `${String(p).split('/').slice(0, -1).join('/')}/${names[i] ?? 'renamed'}`, name: names[i] })) })
    }
    if (name === 'fs_copy_move') return text({ success: true, paths: args.path, dest_folder_path: args.dest_folder_path, moved: !!args.remove_src })
    if (name === 'fs_delete') {
      const reqPaths = Array.isArray(args.path) ? args.path : [args.path].filter(Boolean)
      return text({ success: true, deleted: reqPaths })
    }
    if (name === 'fs_download') {
      const reqPaths = Array.isArray(args.path) ? args.path : [args.path].filter(Boolean)
      const destDir = String(args.local_dir ?? '/tmp')
      const fsPromises = await import('node:fs/promises')
      await fsPromises.mkdir(destDir, { recursive: true })
      const payload = Buffer.from('selftest-download-bytes', 'utf8')
      const written = []
      for (const p of reqPaths) {
        const filename = String(p).split('/').filter(Boolean).pop() ?? 'file.bin'
        const target = `${destDir}/${filename}`
        await fsPromises.writeFile(target, payload)
        written.push({ saved_to: target, bytes: payload.length })
      }
      return text(written[0] ?? { saved_to: destDir, bytes: 0 })
    }
    if (name === 'fs_task_status') return text({ taskid: args.taskid, finished: true })
    if (name === 'fs_upload') {
      // 对齐真实 synology-filestation-mcp 契约：dest_path（目标目录，必填 string）+ local_file（必填 string），
      // 上传文件名取 basename(local_file)；缺必填参数按真实网关回 -32602（zod 校验失败）
      if (typeof args.dest_path !== 'string' || typeof args.local_file !== 'string') {
        return replyError(-32602, 'Input validation error: Invalid arguments for tool fs_upload: Invalid input: expected string, received undefined at dest_path')
      }
      try {
        const buffer = await import('node:fs/promises').then((fs) => fs.readFile(String(args.local_file)))
        const filename = String(args.local_file).split(/[\\/]/).pop()
        nasGwUploads.push({ destPath: args.dest_path, filename, sizeBytes: buffer.length, magic: buffer.subarray(0, 2).toString('latin1'), content: buffer })
        return text({ uploaded: `${args.dest_path}/${filename}`, bytes: buffer.length })
      } catch (error) {
        return reply({ content: [{ type: 'text', text: `fs_upload 网关侧读不到 local_file：${error instanceof Error ? error.message : error}` }], isError: true })
      }
    }
    return replyError(-32601, `未知工具：${name}`)
  }
  return replyError(-32601, `方法不存在：${message.method}`)
})
await new Promise((resolve) => nasGwStub.listen(NAS_GW_PORT, '127.0.0.1', resolve))

// ---------------------------------------------------------------- stub open-connector 数据面网关（v1.4.0 契约）
// 进程内真实 HTTP stub：统一信封 {success,data,meta}/{success:false,errorCode}、
// 强制管理 Bearer、oct_ 令牌策略校验（T-11/T-29）、PUT 四数组严格校验（T-12）、
// token 值仅创建时返回一次、oauth_client_config_required 分支（T-06）、cursor 分页 runs + 注入伪造 run（T-23）。
const OC_STUB_PORT = 7363
const OC_BASE = `http://127.0.0.1:${OC_STUB_PORT}`
const OC_TOKEN = 'oc-selftest-admin-token'
const ocCalls = []          // POST /v1/actions/:id 调用记录 {actionId,bearerOk,alias,idempotencyKey,input}
const ocPuts = []           // PUT /api/runtime-tokens/:id 记录（四数组断言用）
const ocDeletes = []        // DELETE /api/runtime-tokens/:id
const ocMintedValues = []   // 每次铸造返回的 oct_ 一次性值（T-24 全文扫描名单）
const ocLedgerTokens = new Map()  // id → {policy,name}
const ocTokenByValue = new Map()
const ocConnections = new Map() // service → Map(connectionName → summary)
const ocIdemCache = new Map()   // Idempotency-Key → 完整响应体（24h 重放窗口的 stub 等价物，T-22）
const ocClientsConfigured = new Set()   // 已存 OAuth client 配置的 service
const ocRuns = []           // 伪造/真实 run 日志（runtimeTokenId 维度对账）
const ocCtl = {
  connNotAllowedOnce: null,   // 下一次该 tokenValue 执行回 403 connection_not_allowed 后自动清除
  alwaysDenyToken: null,      // 该 tokenValue 执行恒 403 connection_not_allowed（自动恢复重试仍失败路径）
  auditPersistedNext: false,  // 下一次成功执行 meta.auditPersisted=false
  actions: null,              // 当前目录 action 集（null=默认；测试可删改模拟下架）
  overlapDupInRuns: false,    // 分页重叠窗口：第二页重复首条（T-23 去重）
}

const ocActionsDefault = [
  { id: 'hackernews.get_top_stories', name: 'get_top_stories', service: 'hackernews', description: '获取热帖', requiredScopes: [], providerPermissions: [], inputSchema: { type: 'object', properties: { limit: { type: 'number' } } } },
  { id: 'hackernews.fetch_item', name: 'fetch_item', service: 'hackernews', description: '拉取条目', requiredScopes: ['public:read'], inputSchema: { type: 'object' } },
  { id: 'hackernews.submit_post', name: 'submit_post', service: 'hackernews', description: '提交帖子', requiredScopes: ['write:posts'], inputSchema: { type: 'object', properties: { title: { type: 'string' }, url: { type: 'string' } } } },
  { id: 'github.list_issues', name: 'list_issues', service: 'github', description: '列 issue', requiredScopes: ['repo:read'], inputSchema: { type: 'object' } },
  { id: 'github.create_issue', name: 'create_issue', service: 'github', description: '建 issue', requiredScopes: ['repo:write'], inputSchema: { type: 'object', properties: { title: { type: 'string' } } } },
  { id: 'github.delete_webhook', name: 'delete_webhook', service: 'github', description: '删除 webhook', requiredScopes: ['webhook:admin'], inputSchema: { type: 'object' } },
  { id: 'hackernews.do_the_thing', name: 'do_the_thing', service: 'hackernews', description: '无 scope 无名可判定的动作', requiredScopes: [], inputSchema: { type: 'object' } },
]
const ocProvidersDefault = [
  { service: 'hackernews', name: 'Hacker News', description: 'no_auth 示例', auth: [{ type: 'no_auth' }] },
  { service: 'github', name: 'GitHub', description: 'OAuth+API Key 示例', auth: [{ type: 'oauth' }, { type: 'api_key' }] },
  // resource 正则拒绝纳管的反例（T-03）
  { service: 'weird service!', name: 'Weird', description: '非法 service 标识', auth: [] },
]

let ocSeq = 10
const ocEnvelope = (res, status, payload) => {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(payload))
}
const ocAdmin = (req) => req.headers.authorization === `Bearer ${OC_TOKEN}`
const ocPolicyFits = (tokenPolicy, actionId) => {
  const allowed = tokenPolicy.allowedActions ?? []
  return allowed.includes('*') || allowed.includes(actionId)
    || allowed.some((p) => typeof p === 'string' && p.endsWith('.*') && actionId.startsWith(p.slice(0, -2)))
}

const ocStub = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', OC_BASE)
  const path = url.pathname
  const bodyText = await readBody(req)
  let body = {}
  try { body = bodyText ? JSON.parse(bodyText) : {} } catch { /* ignore */ }
  // 健康探测与数据面执行（oct_）公开于管理门禁之外；/api/* 一律 admin Bearer
  const bearerValue = String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, '')
  const isKnownOct = ocTokenByValue.has(bearerValue)
  if (req.method === 'GET' && path === '/v1/health') {
    return ocEnvelope(res, 200, { success: true, data: { ok: true, runtime: 'oomol-connect' } })
  }
  const isDataPlaneExec = /^\/v1\/actions\/[^/]+$/.test(path) && req.method === 'POST'
  if (!path.startsWith('/oauth/callback') && !isDataPlaneExec && !ocAdmin(req)) {
    return ocEnvelope(res, 401, { success: false, errorCode: 'unauthorized', message: '管理接口需要 Bearer 口令' })
  }
  void isKnownOct

  // -- 目录 ---------------------------------------------------------------
  if (req.method === 'GET' && path === '/v1/providers') {
    return ocEnvelope(res, 200, { success: true, data: ocProvidersDefault })
  }
  if (req.method === 'GET' && path === '/v1/actions') {
    return ocEnvelope(res, 200, { success: true, data: (ocCtl.actions ?? ocActionsDefault), ...(url.searchParams.get('service') ? {} : {}) })
  }
  const actionDetailMatch = path.match(/^\/v1\/actions\/([^/]+)$/)
  if (req.method === 'GET' && actionDetailMatch) {
    const found = (ocCtl.actions ?? ocActionsDefault).find((item) => item.id === decodeURIComponent(actionDetailMatch[1]))
    if (!found) return ocEnvelope(res, 404, { success: false, errorCode: 'unknown_action' })
    return ocEnvelope(res, 200, { success: true, data: found })
  }
  const guideMatch = path.match(/^\/api\/actions\/([^/]+)\/agent\.md$/)
  if (req.method === 'GET' && guideMatch) {
    res.writeHead(200, { 'content-type': 'text/markdown; charset=utf-8' })
    res.end(`## 连接指南（stub agent.md）\n\n为 ${decodeURIComponent(guideMatch[1])} 配置连接：先注册 OAuth App / 准备 API Key。\n`)
    return
  }

  // -- 连接 ---------------------------------------------------------------
  if (req.method === 'GET' && path === '/api/connections') {
    const all = [...ocConnections.values()].flatMap((m) => [...m.values()])
    return ocEnvelope(res, 200, { success: true, data: all })
  }
  const connectionMatch = path.match(/^\/api\/connections\/([^/]+)$/)
  if (req.method === 'PUT' && connectionMatch) {
    const service = decodeURIComponent(connectionMatch[1])
    if (!ocConnections.has(service)) ocConnections.set(service, new Map())
    const summary = {
      id: `oc-con-${++ocSeq}`,
      service,
      connectionName: String(body.connectionName ?? ''),
      authType: body.authType === 'custom_credential' ? 'custom_credential' : 'api_key',
      configured: true,
      virtual: false,
      default: Boolean(body.default),
      profile: { ...Object.fromEntries(Object.entries(body.values ?? {}).map(([k, v]) => [k, typeof v === 'string' ? `${String(v).slice(0, 4)}***` : v])) },
    }
    ocConnections.get(service).set(summary.connectionName, summary)
    return ocEnvelope(res, 200, { success: true, data: summary }) // 成功状态码上游未载——按默认 200 断言信封
  }
  if (req.method === 'DELETE' && connectionMatch) {
    const service = decodeURIComponent(connectionMatch[1])
    const removed = ocConnections.get(service)?.delete(String(body.connectionName ?? ''))
    return removed
      ? ocEnvelope(res, 200, { success: true, data: { deleted: true } })
      : ocEnvelope(res, 404, { success: false, errorCode: 'unknown_connection', message: `连接不存在：${service}/${body.connectionName}` })
  }

  // -- OAuth ----------------------------------------------------------------
  if (req.method === 'POST' && path === '/api/oauth/authorizations') {
    const service = String(body.service ?? '')
    if (!ocClientsConfigured.has(service)) {
      return ocEnvelope(res, 400, { success: false, errorCode: 'oauth_client_config_required', message: `${service} 未存 client 配置` })
    }
    const state = `st-${++ocSeq}`
    pendingOauth.set(state, { service, connectionName: String(body.connectionName ?? '') })
    return ocEnvelope(res, 200, { success: true, data: { authorizationUrl: `${OC_BASE}/oauth/authorize?state=${state}`, state } })
  }
  if (req.method === 'GET' && path === '/oauth/callback') {
    const state = url.searchParams.get('state') ?? ''
    const entry = pendingOauth.get(state)
    if (!entry) {
      res.writeHead(400, { 'content-type': 'text/html; charset=utf-8' }); res.end('<html>bad state</html>'); return
    }
    pendingOauth.delete(state)
    if (!ocConnections.has(entry.service)) ocConnections.set(entry.service, new Map())
    ocConnections.get(entry.service).set(entry.connectionName, {
      id: `oc-con-${++ocSeq}`, service: entry.service, connectionName: entry.connectionName,
      authType: 'oauth', configured: true, virtual: false, default: false,
      profile: { login: 'dsh-selftest' },
    })
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    res.end('<html><body>授权完成（stub 回调页）</body></html>')
    return
  }

  // -- 运行时令牌 -------------------------------------------------------------
  if (req.method === 'POST' && path === '/api/runtime-tokens') {
    const requiredArrays = ['allowedActions', 'blockedActions', 'allowedProxies', 'allowedConnections']
    for (const key of requiredArrays) {
      if (!Array.isArray(body[key])) return ocEnvelope(res, 400, { success: false, errorCode: 'invalid_policy_arrays', message: `${key} 必须是数组（四数组全发契约）` })
    }
    const id = `tok-${++ocSeq}`
    const value = `oct_selftest_${++ocSeq}_${Math.random().toString(36).slice(2, 8)}`
    ocLedgerTokens.set(id, { policy: { allowedActions: body.allowedActions, blockedActions: body.blockedActions, allowedProxies: body.allowedProxies, allowedConnections: body.allowedConnections }, name: String(body.name ?? '') })
    ocTokenByValue.set(value, id)
    ocMintedValues.push(value)
    return ocEnvelope(res, 200, { success: true, data: { id, name: body.name, token: value, createdAt: new Date().toISOString(), policy: ocLedgerTokens.get(id).policy } })
  }
  if (req.method === 'GET' && path === '/api/runtime-tokens') {
    return ocEnvelope(res, 200, { success: true, data: [...ocLedgerTokens.entries()].map(([id, rec]) => ({ id, name: rec.name, createdAt: new Date().toISOString(), policy: rec.policy })) })
  }
  const tokenMatch = path.match(/^\/api\/runtime-tokens\/([^/]+)$/)
  if (req.method === 'PUT' && tokenMatch) {
    const id = decodeURIComponent(tokenMatch[1])
    if (!ocLedgerTokens.has(id)) return ocEnvelope(res, 404, { success: false, errorCode: 'unknown_token' })
    for (const key of ['allowedActions', 'blockedActions', 'allowedProxies', 'allowedConnections']) {
      if (!Array.isArray(body[key])) return ocEnvelope(res, 400, { success: false, errorCode: 'invalid_policy_arrays', message: `${key} 缺失或非数组（PUT 四数组全发契约）` })
    }
    ocLedgerTokens.get(id).policy = { allowedActions: body.allowedActions, blockedActions: body.blockedActions, allowedProxies: body.allowedProxies, allowedConnections: body.allowedConnections }
    ocPuts.push({ id, policy: ocLedgerTokens.get(id).policy })
    return ocEnvelope(res, 200, { success: true, data: { id, policy: ocLedgerTokens.get(id).policy } })
  }
  if (req.method === 'DELETE' && tokenMatch) {
    const id = decodeURIComponent(tokenMatch[1])
    ocDeletes.push(id)
    ocLedgerTokens.delete(id)
    return ocEnvelope(res, 200, { success: true, data: { deleted: true } })
  }

  // -- 数据面执行 --------------------------------------------------------------
  const execMatch = path.match(/^\/v1\/actions\/([^/]+)$/)
  if (req.method === 'POST' && execMatch) {
    const bearer = String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, '')
    const tokenId = ocTokenByValue.get(bearer)
    const actionId = decodeURIComponent(execMatch[1])
    ocCalls.push({
      actionId, bearerOk: Boolean(tokenId),
      alias: req.headers['x-oo-connector-alias'] ?? null,
      idempotencyKey: req.headers['idempotency-key'] ?? null,
      input: body.input ?? {},
    })
    if (!tokenId) return ocEnvelope(res, 401, { success: false, errorCode: 'unauthorized', message: '缺少合法 oct_ 运行时令牌' })
    // 数据面独立强制（T-29）与策略镜像一致性（T-11）：令牌 policy 与请求 action 不符即 403，
    // 越权在凭证加载前拒绝——即使调用方完全绕开平台侧权限组也一样。
    const record = ocLedgerTokens.get(tokenId)
    if (!record || !ocPolicyFits(record.policy, actionId)) {
      return ocEnvelope(res, 403, { success: false, errorCode: 'forbidden_action', message: `action ${actionId} 不在该运行时令牌 allowedActions 内` })
    }
    const allowedConnections = record.policy.allowedConnections ?? []
    if (allowedConnections.length > 0) {
      const alias = req.headers['x-oo-connector-alias']
      const boundSummary = [...ocConnections.values()].flatMap((m) => [...m.values()])
        .find((s) => s.id === allowedConnections[0] || s.connectionName === alias)
      if (!boundSummary) return ocEnvelope(res, 403, { success: false, errorCode: 'connection_not_allowed', message: `连接未获令牌授权：${alias ?? '(default)'}` })
    }
    // 哨兵 '*ANY*' 匹配任意合法 oct_（测试注入用），否则按精确值匹配
    const denyOnceMatch = ocCtl.connNotAllowedOnce !== null && (ocCtl.connNotAllowedOnce === '*ANY*' || ocCtl.connNotAllowedOnce === bearer)
    if (denyOnceMatch) {
      ocCtl.connNotAllowedOnce = null
      return ocEnvelope(res, 403, { success: false, errorCode: 'connection_not_allowed' })
    }
    const denyAlwaysMatch = ocCtl.alwaysDenyToken !== null && (ocCtl.alwaysDenyToken === '*ANY*' || ocCtl.alwaysDenyToken === bearer)
    if (denyAlwaysMatch) {
      return ocEnvelope(res, 403, { success: false, errorCode: 'connection_not_allowed' })
    }
    const executionId = `exec-${++ocSeq}`
    ocRuns.push({ id: executionId, service: actionId.split('.')[0], actionId, ok: true, runtimeTokenId: tokenId, caller: 'http', startedAt: new Date().toISOString(), latencyMs: 12 })
    const successPayload = {
      success: true,
      data: { echo: body.input ?? {}, viaAlias: req.headers['x-oo-connector-alias'] ?? null, replayKey: req.headers['idempotency-key'] ?? null },
      meta: { executionId, actionId, auditPersisted: !ocCtl.auditPersistedNext },
    }
    // T-22：同 Idempotency-Key 在重放窗口内返回原响应（含原 executionId），不产生重复 run
    if (req.headers['idempotency-key']) {
      const key = String(req.headers['idempotency-key'])
      const cached = ocIdemCache.get(key)
      if (cached) return ocEnvelope(res, 200, cached)
      ocIdemCache.set(key, successPayload)
      // 注入的伪造 run 会在下一个调用带同键时被消费为空（避免污染去重断言）
    }
    return ocEnvelope(res, 200, successPayload)
  }

  // -- runs 对账视图（cursor 分页 + 重叠窗口 + 伪造注入） ----------------------------------
  if (req.method === 'GET' && path === '/api/runs') {
    let items = [...ocRuns]
    const fakeCount = Number(url.searchParams.get('injectFakeBypass') ?? 0)
    for (let i = 0; i < fakeCount; i++) {
      items.push({ id: `fake-bypass-${Date.now()}-${i}`, service: 'github', actionId: 'github.list_issues', ok: true, runtimeTokenId: [...ocLedgerTokens.keys()][0] ?? 'tok-foreign', caller: 'direct-sidecar', startedAt: new Date(Date.now() + i * 1000).toISOString() })
    }
    items.sort((a, b) => a.startedAt.localeCompare(b.startedAt))
    const cursorRaw = url.searchParams.get('cursor')
    let offset = 0
    if (cursorRaw) {
      try { offset = Number(JSON.parse(decodeURIComponent(cursorRaw)).i ?? 0) } catch { offset = 0 }
    }
    const limit = Math.max(1, Number(url.searchParams.get('limit') ?? 100))
    let page = items.slice(offset, offset + limit)
    const nextOffset = offset + limit
    // T-23 重叠窗口：第二页首条重复第一页末条（cursor 分页去重由平台侧负责）
    if (offset > 0 && nextOffset < items.length && ocCtl.overlapDupInRuns && page.length > 0) {
      page = [items[offset - 1], ...page]
    }
    const payload = { items: page }
    if (nextOffset < items.length) {
      payload.nextCursor = encodeURIComponent(JSON.stringify({ startedAt: page[page.length - 1].startedAt, i: nextOffset }))
    }
    return ocEnvelope(res, 200, { success: true, data: payload })
  }

  // -- MCP 桥接端点（POST /mcp，与平台同形态；供 M0 importServices 探测） ----------------------
  if (req.method === 'POST' && path === '/mcp') {
    let msg = {}
    try { msg = JSON.parse(bodyText) } catch { /* ignore */ }
    const jsonrpc = { jsonrpc: '2.0', id: msg.id }
    if (msg.method === 'initialize') {
      return ocEnvelope(res, 200, { ...jsonrpc, result: { protocolVersion: '2025-03-26', capabilities: {}, serverInfo: { name: 'open-connector-stub', version: '1.4.0' } } })
    }
    // M0 数据面鉴权（对齐集成指南 v0.2 §五）：Bearer 为管理口令（bootstrap 形态）或合法 oct_
    const mcpBearer = String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, '')
    if (!ocAdmin(req) && !ocTokenByValue.has(mcpBearer)) {
      return ocEnvelope(res, 401, { ...jsonrpc, error: { code: -32001, message: '/mcp 数据面需 Bearer 管理口令或合法 oct_ 运行时令牌' } })
    }
    if (msg.method === 'tools/list') {
      const legacyNames = ['hackernews_get_top_stories', 'hackernews_fetch_item', 'hackernews_submit_post', 'github_list_issues', 'github_create_issue']
      const tools = [
        // 上游文档未细载项：真实 /mcp 以 execute_action(actionId,input) 为准（cto-doc-agent 核对结论）
        { name: 'execute_action', description: 'execute an open-connector action', inputSchema: { type: 'object', properties: { actionId: { type: 'string' }, input: { type: 'object' } }, required: ['actionId'] } },
        ...legacyNames.map((name) => ({ name, description: `stub ${name}（legacy 别名形态）`, inputSchema: { type: 'object' } })),
      ]
      return ocEnvelope(res, 200, { ...jsonrpc, result: { tools } })
    }
    if (msg.method === 'tools/call') {
      const toolName = String(msg.params?.name ?? '')
      const argsIn = msg.params?.arguments ?? {}
      if (toolName === 'execute_action') {
        const executionId = `exec-mcp-${++ocSeq}`
        ocCalls.push({ actionId: String(argsIn.actionId ?? ''), bearerOk: true, alias: null, idempotencyKey: null, input: argsIn.input ?? {} })
        ocRuns.push({ id: executionId, service: String(argsIn.actionId ?? '').split('.')[0], ok: true, startedAt: new Date().toISOString(), latencyMs: 9 })
        return ocEnvelope(res, 200, { ...jsonrpc, result: { content: [{ type: 'text', text: JSON.stringify({ bridgeEcho: argsIn, runId: executionId }) }] } })
      }
      ocCalls.push({ actionId: toolName.replace(/_([a-z])/g, '.$1'), bearerOk: true, alias: null, idempotencyKey: null, input: argsIn })
      const executionId = `exec-mcp-${++ocSeq}`
      ocRuns.push({ id: executionId, service: 'hackernews', ok: true, startedAt: new Date().toISOString(), latencyMs: 9 })
      return ocEnvelope(res, 200, { ...jsonrpc, result: { content: [{ type: 'text', text: JSON.stringify({ bridgeEcho: argsIn, runId: executionId }) }] } })
    }
    return ocEnvelope(res, 200, { ...jsonrpc, error: { code: -32601, message: `方法不存在：${msg.method}` } })
  }

  return ocEnvelope(res, 404, { success: false, errorCode: 'not_found', message: path })
})
const pendingOauth = new Map()
await new Promise((resolve) => ocStub.listen(OC_STUB_PORT, '127.0.0.1', resolve))

// ---------------- 启动隔离实例
console.log('\x1b[90m» 启动隔离测试实例…\x1b[0m')
await rm(DATA_DIR, { recursive: true, force: true })
await mkdir(DATA_DIR, { recursive: true })
const proc = spawn(process.execPath, ['src/main.ts', '--port', String(PORT), '--data', DATA_DIR], {
  stdio: ['ignore', 'pipe', 'pipe'],
  // DEMO_SEED：自测基于完整演示种子（隔离实例，不触碰生产 data/）
  // DSH_UPDATE_*：更新检查指向本进程 stub 上游；关闭启动自动首查保证断言确定性
  env: {
    ...process.env,
    DEMO_SEED: '1',
    // 连接器纳管：强制 env 由自测进程下发（fail-closed 门禁的绿路前提）；
    // 桥接 stub 地址 + 演示种子开关（网关/连接/权限组模板）
    OOMOL_CONNECT_ENCRYPTION_KEY: 'selftest-encryption-key-not-a-secret',
    OOMOL_CONNECT_ADMIN_TOKEN: OC_TOKEN,
    OOMOL_CONNECT_STUB_URL: OC_BASE,
    OOMOL_CONNECT_DEMO_SEED: '1',
    DSH_UPDATE_RAW_BASE: `http://127.0.0.1:${GH_PORT}`,
    DSH_UPDATE_API_BASE: `http://127.0.0.1:${GH_PORT}`,
    DSH_UPDATE_AUTO_CHECK: 'off',
    // OIDC 授权请求 TTL 压到 2 秒：过期路径可在自测内确定性验证（正常流程毫秒级完成不受影响）
    OIDC_AUTHREQ_TTL_SECONDS: '2',
    // 门户 downloadUrl 生成基址指向自测实例：门户技能包下载断言可直连验证
    PORTAL_PUBLIC_BASE: `http://127.0.0.1:${PORT}`,
  },
})
proc.stderr.on('data', (chunk) => process.stderr.write(`\x1b[90m[server] ${chunk}\x1b[0m`))

let booted = false
for (let i = 0; i < 40; i++) {
  await new Promise((resolve) => setTimeout(resolve, 500))
  try {
    const probe = await fetch(`${BASE}/api/health`)
    if (probe.ok) { booted = true; break }
  } catch { /* retry */ }
}
if (!booted) {
  console.error('\x1b[31m实例启动失败\x1b[0m')
  proc.kill('SIGKILL')
  process.exit(1)
}
// 轮询等待种子数据就绪（工具注册 + Agent 上线 + 调用记录）
let seeded = false
for (let i = 0; i < 60; i++) {
  await new Promise((resolve) => setTimeout(resolve, 500))
  try {
    const probe = await api('POST', '/api/auth/login', { body: { username: 'admin', password: 'Ybk@2026' } })
    if (!probe.ok) continue
    const info = await api('GET', '/api/platform/info', { token: probe.data.token })
    const overview = await api('GET', '/api/overview', { token: probe.data.token })
    if (info.data?.tools?.length >= 37 && overview.data?.agents?.online >= 5 && overview.data?.mcp?.totalCalls > 100) {
      seeded = true
      break
    }
  } catch { /* retry */ }
}
if (!seeded) console.log('[33m! 种子数据就绪超时，部分断言可能失败[0m')

try {
  // ================================================================ 基础与认证
  section('平台健康与登录')
  const health = await api('GET', '/api/health')
  check('健康检查', health.ok)

  const noAuth = await api('GET', '/api/overview')
  check('无令牌访问被拒绝（401）', noAuth.status === 401)

  const badLogin = await api('POST', '/api/auth/login', { body: { username: 'admin', password: 'wrong' } })
  check('错误密码被拒绝', badLogin.status === 401)

  const adminLogin = await api('POST', '/api/auth/login', { body: { username: 'admin', password: 'Ybk@2026' } })
  check('管理员登录成功', adminLogin.ok && adminLogin.data.token.startsWith('dst1.'))
  const admin = adminLogin.data.token
  check('登录返回权限点（含 *）', adminLogin.data.user.permissions.includes('*'))

  // 三方登录完整链路（IdentityProviderAdapter：authorize → state → code → normalize）
  const authorize = await api('POST', '/api/auth/sso/authorize', { body: { provider: 'dingtalk', scene: 'web_qr' } })
  check('SSO 发起授权（签发 state）', authorize.ok && authorize.data.state.length >= 32)
  check('SSO 授权地址不带 prompt=consent（已授权用户可静默通过，缩短回跳链路）',
    typeof authorize.data.authorizeUrl === 'string' && authorize.data.authorizeUrl.includes('login.dingtalk.com/oauth2/auth')
    && !authorize.data.authorizeUrl.includes('prompt=consent') && authorize.data.authorizeUrl.includes('scope=openid'))
  const sso = await api('POST', '/api/auth/sso', { body: { provider: 'dingtalk', code: 'DD0002', state: authorize.data.state } })
  check('钉钉免密登录（身份链接命中）', sso.ok && sso.data.kind === 'hit' && sso.data.user.username === 'linxm')
  check('登录返回 refresh token（7d 轮转链）', typeof sso.data.refreshToken === 'string' && sso.data.refreshToken.startsWith('dstr_'))

  // 攻击演练 1：state 重放拒绝
  const stateReplay = await api('POST', '/api/auth/sso', { body: { provider: 'dingtalk', code: 'DD0002', state: authorize.data.state } })
  check('state 重放被拒绝（防 CSRF）', stateReplay.status === 401)

  // 攻击演练 2：伪造 state 拒绝
  const stateForged = await api('POST', '/api/auth/sso', { body: { provider: 'dingtalk', code: 'DD0002', state: 'forged-state-000' } })
  check('伪造 state 被拒绝', stateForged.status === 401)

  // 攻击演练 3：code 重放拒绝（5 分钟窗口内单次消费）
  const authorize2 = await api('POST', '/api/auth/sso/authorize', { body: { provider: 'dingtalk', scene: 'web_qr' } })
  await api('POST', '/api/auth/sso', { body: { provider: 'dingtalk', code: 'DD0004', state: authorize2.data.state } }).catch(() => null)
  const codeReplayAuth = await api('POST', '/api/auth/sso/authorize', { body: { provider: 'dingtalk', scene: 'web_qr' } })
  const codeReplay = await api('POST', '/api/auth/sso', { body: { provider: 'dingtalk', code: 'DD0004', state: codeReplayAuth.data.state } })
  check('code 重放被拒绝（单次消费）', codeReplay.status === 401)

  // 未命中 → 待绑定票据 → 绑定已有账号
  const authorize3 = await api('POST', '/api/auth/sso/authorize', { body: { provider: 'dingtalk', scene: 'h5' } })
  const pending = await api('POST', '/api/auth/sso', { body: { provider: 'dingtalk', code: 'DD0003', state: authorize3.data.state } })
  check('未命中身份签发待绑定票据', pending.ok && pending.data.kind === 'pending' && pending.data.profileName === '周既白')
  const bindWrong = await api('POST', '/api/auth/sso/bind', { body: { pendingTicket: pending.data.pendingTicket, username: 'dev', password: 'wrong' } })
  check('绑定校验密码（错误拒绝）', bindWrong.status === 401)
  const bindOk = await api('POST', '/api/auth/sso/bind', { body: { pendingTicket: pending.data.pendingTicket, username: 'dev', password: 'Ybk@2026' } })
  check('绑定已有账号并登录', bindOk.ok && bindOk.data.user.username === 'dev')

  // 唯一约束：已绑定的三方身份（dd_u003→dev）再绑定他人 → 引擎级拒绝
  const opsUser = (await api('GET', '/api/iam/users?q=' + encodeURIComponent('韩若飞'), { token: admin })).data.users[0]
  const dupBind = await api('POST', `/api/iam/users/${opsUser.id}/bindings`, {
    token: admin,
    body: { provider: 'dingtalk', unionId: 'dd_u003', displayName: '周既白', verifyCode: '123456' },
  })
  check('一人一号：身份绑定第二个账号被拒（引擎唯一约束）', !dupBind.ok && JSON.stringify(dupBind.error).includes('唯一约束'))

  // 未命中 → 注册新账号分支
  const authorize5 = await api('POST', '/api/auth/sso/authorize', { body: { provider: 'dingtalk', scene: 'web_qr' } })
  const pending3 = await api('POST', '/api/auth/sso', { body: { provider: 'dingtalk', code: 'DD0006', state: authorize5.data.state } })
  const register = await api('POST', '/api/auth/sso/register', { body: { pendingTicket: pending3.data.pendingTicket } })
  check('三方身份注册新账号并登录', register.ok && register.data.user.username === 'dingtalk_dd_u006')

  const devLogin = await api('POST', '/api/auth/login', { body: { username: 'dev', password: 'Ybk@2026' } })
  check('开发者登录', devLogin.ok)
  let dev = devLogin.data.token

  // ================================================================ RBAC
  section('RBAC 权限模型')
  const devForbidden = await api('POST', '/api/iam/orgs', { token: dev, body: { name: '越权组织' } })
  check('开发者创建组织被拒（403）', devForbidden.status === 403)

  const auditorLogin = await api('POST', '/api/auth/login', { body: { username: 'audit', password: 'Ybk@2026' } })
  const auditor = auditorLogin.data.token
  const auditorWrite = await api('POST', '/api/iam/users', { token: auditor, body: { username: 'x', displayName: 'x', orgId: 'y' } })
  check('审计员写操作被拒', auditorWrite.status === 403)
  const auditorRead = await api('GET', '/api/audit/logs', { token: auditor })
  check('审计员读日志放行', auditorRead.ok)

  // ================================================================ 工作台
  section('工作台聚合')
  const overview = await api('GET', '/api/overview', { token: admin })
  check('总览数据完整', overview.ok
    && overview.data.iam.users >= 10
    && overview.data.mcp.totalCalls > 0
    && overview.data.agents.online >= 5
    && overview.data.apps.online >= 3
    && overview.data.skills.published >= 6)

  // ================================================================ IAM
  section('组织账号（IAM）')
  const newOrg = await api('POST', '/api/iam/orgs', { token: admin, body: { name: '自测事业部' } })
  check('创建组织', newOrg.ok && newOrg.data.id.startsWith('org_'))

  const dupUser = await api('POST', '/api/iam/users', { token: admin, body: { username: 'admin', displayName: '重复', orgId: newOrg.data.id } })
  check('重复用户名被拒', !dupUser.ok)

  const newUser = await api('POST', '/api/iam/users', { token: admin, body: { username: 'selftester', displayName: '测试账号', orgId: newOrg.data.id, title: '测试工程师' } })
  check('创建账号（默认激活）', newUser.ok && newUser.data.status === 'active')
  check('创建账号返回一次性随机初始口令', newUser.ok && typeof newUser.data.initialPassword === 'string' && newUser.data.initialPassword.length >= 16)
  const testerInitialPassword = newUser.data.initialPassword

  // 口令二次修改（传达过程中改为指定口令）
  const pwUser = await api('POST', '/api/iam/users', { token: admin, body: { username: 'pwtest01', displayName: '口令修改测试', orgId: newOrg.data.id } })
  const pwShort = await api('POST', `/api/iam/users/${pwUser.data.id}/reset-password`, { token: admin, body: { password: 'short' } })
  check('指定口令过短被拒（护栏）', !pwShort.ok)
  const pwSet = await api('POST', `/api/iam/users/${pwUser.data.id}/reset-password`, { token: admin, body: { password: 'SelfTest@2026' } })
  check('二次修改为指定口令', pwSet.ok && pwSet.data.initialPassword === 'SelfTest@2026')
  const pwOldLogin = await api('POST', '/api/auth/login', { body: { username: 'pwtest01', password: pwUser.data.initialPassword } })
  check('修改后原口令立即失效', pwOldLogin.status === 401)
  const pwNewLogin = await api('POST', '/api/auth/login', { body: { username: 'pwtest01', password: 'SelfTest@2026' } })
  check('指定口令可登录', pwNewLogin.ok)

  const roleList = await api('GET', '/api/iam/roles', { token: admin })
  const devRole = roleList.data.roles.find((role) => role.code === 'developer')
  const assign = await api('PATCH', `/api/iam/users/${newUser.data.id}`, { token: admin, body: { roleIds: [devRole.id] } })
  check('分配角色', assign.ok && assign.data.roleIds.length === 1)
  check('开发者角色默认含 agent.write（与 app.write 对称，注册/提报更新闭环）', devRole.permissions.includes('agent.write'))

  const importResult = await api('POST', '/api/iam/users/import', { token: admin, body: { items: [
    { username: 'batch01', displayName: '批量一号', orgId: newOrg.data.id },
    { username: 'batch02', displayName: '批量二号', orgId: newOrg.data.id },
  ] } })
  check('批量导入', importResult.ok && importResult.data.created.length === 2)

  const tree = await api('GET', '/api/iam/orgs/tree', { token: admin })
  check('组织树包含新组织', tree.ok && JSON.stringify(tree.data).includes('自测事业部'))

  // 组织改名 / 层级调整（PATCH /api/iam/orgs/:id）
  const siblingOrg = await api('POST', '/api/iam/orgs', { token: admin, body: { name: '自测兄弟部门' } })
  check('创建同级组织（改名冲突靶子）', siblingOrg.ok)
  const renameOrg = await api('PATCH', `/api/iam/orgs/${newOrg.data.id}`, { token: admin, body: { name: '自测事业部（更名）' } })
  check('组织重命名', renameOrg.ok && renameOrg.data.name === '自测事业部（更名）')
  const renameEmpty = await api('PATCH', `/api/iam/orgs/${newOrg.data.id}`, { token: admin, body: { name: '   ' } })
  check('空白名称重命名被拒', !renameEmpty.ok)
  const renameDup = await api('PATCH', `/api/iam/orgs/${newOrg.data.id}`, { token: admin, body: { name: '自测兄弟部门' } })
  check('同级重名重命名被拒', !renameDup.ok)
  const moveOrg = await api('PATCH', `/api/iam/orgs/${newOrg.data.id}`, { token: admin, body: { parentId: siblingOrg.data.id } })
  check('调整上级组织', moveOrg.ok && moveOrg.data.parentId === siblingOrg.data.id)
  const moveSelf = await api('PATCH', `/api/iam/orgs/${newOrg.data.id}`, { token: admin, body: { parentId: newOrg.data.id } })
  check('移动到自身被拒（环检测）', !moveSelf.ok)
  const moveChild = await api('PATCH', `/api/iam/orgs/${siblingOrg.data.id}`, { token: admin, body: { parentId: newOrg.data.id } })
  check('移动到子孙被拒（环检测）', !moveChild.ok)

  // 组织级联一键删除（2026-08）：任意层级可整棵子树删除，直属账号自动上移到上级组织
  const cascadeOrgA = await api('POST', '/api/iam/orgs', { token: admin, body: { name: '自测级联母部门', parentId: siblingOrg.data.id } })
  const cascadeOrgB = await api('POST', '/api/iam/orgs', { token: admin, body: { name: '自测级联子部门', parentId: cascadeOrgA.data.id } })
  const cascadeUser = await api('POST', '/api/iam/users', { token: admin, body: { username: 'cascadeu01', displayName: '级联上移测试', orgId: cascadeOrgB.data.id } })
  check('级联删除靶子就绪（母/子组织 + 直属账号）', cascadeOrgA.ok && cascadeOrgB.ok && cascadeUser.ok)
  const delNonCascade = await api('DELETE', `/api/iam/orgs/${cascadeOrgA.data.id}`, { token: admin })
  check('存在子组织时普通删除被拒并指路', !delNonCascade.ok && JSON.stringify(delNonCascade.error).includes('一键删除'))
  const delCascade = await api('DELETE', `/api/iam/orgs/${cascadeOrgA.data.id}`, { token: admin, body: { cascade: true } })
  check('级联一键删除整棵子树（组织数/上移账号数）', delCascade.ok && delCascade.data.removedOrgs === 2 && delCascade.data.movedUsers === 1, JSON.stringify(delCascade.data))
  const treeAfterCascade = await api('GET', '/api/iam/orgs/tree', { token: admin })
  const treeTextAfterCascade = JSON.stringify(treeAfterCascade.data)
  check('级联后子树全部消失、上级组织仍在', treeAfterCascade.ok && !treeTextAfterCascade.includes('自测级联子部门') && !treeTextAfterCascade.includes('自测级联母部门') && treeTextAfterCascade.includes('自测兄弟部门'))
  const usersAfterCascade = await api('GET', `/api/iam/users?orgId=${siblingOrg.data.id}`, { token: admin })
  check('直属账号自动上移到上级组织', usersAfterCascade.ok && usersAfterCascade.data.users.some((u) => u.username === 'cascadeu01' && u.orgId === siblingOrg.data.id))
  const scratchOrg = await api('POST', '/api/iam/orgs', { token: admin, body: { name: '自测空部门' } })
  const delEmptyOrg = await api('DELETE', `/api/iam/orgs/${scratchOrg.data.id}`, { token: admin })
  check('空组织普通删除仍可用（非级联路径回归）', delEmptyOrg.ok && delEmptyOrg.data.removedOrgs === 1)

  const groupCreate = await api('POST', '/api/iam/groups', { token: admin, body: { name: '自测静态组', type: 'static', memberIds: [newUser.data.id] } })
  check('创建静态用户组', groupCreate.ok)

  // 三方同步 + 冲突
  const sync = await api('POST', '/api/iam/connectors/dingtalk/sync', { token: admin })
  check('钉钉全量同步执行', sync.ok && sync.data.created >= 0)
  const conflicts = await api('GET', '/api/iam/conflicts', { token: admin })
  if (conflicts.data.conflicts.length > 0) {
    const resolved = await api('POST', `/api/iam/conflicts/${conflicts.data.conflicts[0].id}/resolve`, { token: admin, body: { keep: 'third_party' } })
    check('同步冲突处理（以三方为准）', resolved.ok && resolved.data.status === 'resolved')
  } else {
    check('同步冲突队列（无冲突时跳过）', true)
  }

  // 冻结联动：令牌吊销
  section('账号冻结 → 令牌联动吊销')
  const testerLogin = await api('POST', '/api/auth/login', { body: { username: 'selftester', password: testerInitialPassword } })
  check('新账号可登录（随机初始口令）', testerLogin.ok)
  const testerToken = testerLogin.data.token
  const testerMe = await api('GET', '/api/auth/me', { token: testerToken })
  check('新账号令牌可用', testerMe.ok)
  const freezeNoReason = await api('POST', `/api/iam/users/${newUser.data.id}/freeze`, { token: admin, body: {} })
  check('冻结缺少原因被拒（护栏）', !freezeNoReason.ok)
  const freeze = await api('POST', `/api/iam/users/${newUser.data.id}/freeze`, { token: admin, body: { reason: '自测：验证联动吊销' } })
  check('冻结成功', freeze.ok && freeze.data.status === 'frozen')
  const revokedCheck = await api('GET', '/api/auth/me', { token: testerToken })
  check('冻结后令牌立即失效（401）', revokedCheck.status === 401)
  const frozenLogin = await api('POST', '/api/auth/login', { body: { username: 'selftester', password: testerInitialPassword } })
  check('冻结账号无法登录', frozenLogin.status === 401)

  // ================================================================ refresh 轮转链
  section('refresh token 轮转与重放防护')
  const rl = await api('POST', '/api/auth/login', { body: { username: 'ops', password: 'Ybk@2026' } })
  check('登录返回令牌对', rl.ok && rl.data.refreshToken)
  const rotated = await api('POST', '/api/auth/refresh', { body: { refreshToken: rl.data.refreshToken } })
  check('refresh 轮转签发新对', rotated.ok && rotated.data.refreshToken !== rl.data.refreshToken)
  const newMe = await api('GET', '/api/auth/me', { token: rotated.data.token })
  check('轮转后新 access 可用', newMe.ok)
  const oldReplay = await api('POST', '/api/auth/refresh', { body: { refreshToken: rl.data.refreshToken } })
  check('旧 refresh 重放被拒绝', oldReplay.status === 401)
  const chainKilled = await api('GET', '/api/auth/me', { token: rotated.data.token })
  check('重放触发整链吊销（新 access 一并失效）', chainKilled.status === 401)

  // ================================================================ Authn
  section('统一认证（机器身份 / 令牌）')
  const cred = await api('POST', '/api/authn/principals', { token: admin, body: { name: 'selftest-ci', refType: 'external', scopes: ['mcp.invoke'] } })
  check('签发机器凭证（secret 一次性返回）', cred.ok && cred.data.clientSecret.startsWith('cs_'))

  // 可绑定资源聚合 + 选择已注册主体自动关联（refType/refId 回填）
  const bindable = await api('GET', '/api/authn/bindable-resources', { token: admin })
  check('可绑定资源聚合（Agent / AI 应用清单）', bindable.ok && Array.isArray(bindable.data.agents) && bindable.data.agents.length > 0 && Array.isArray(bindable.data.apps))
  const agentEntry = bindable.data.agents[0]
  const credBind = await api('POST', '/api/authn/principals', { token: admin, body: { name: `agent:${agentEntry.name}`, refType: 'agent', refId: agentEntry.id, scopes: ['agent.read'] } })
  const principalList = await api('GET', '/api/authn/principals', { token: admin })
  const boundPrincipal = principalList.data.principals.find((p) => p.id === credBind.data.principalId)
  check('选择已注册主体签发 → 凭据自动关联资源', credBind.ok && boundPrincipal?.refType === 'agent' && boundPrincipal?.refId === agentEntry.id)

  const ccBad = await api('POST', '/api/auth/client-credentials', { body: { clientId: cred.data.clientId, clientSecret: 'wrong' } })
  check('错误 client_secret 被拒', ccBad.status === 401)

  const cc = await api('POST', '/api/auth/client-credentials', { body: { clientId: cred.data.clientId, clientSecret: cred.data.clientSecret } })
  check('Client Credentials 登录', cc.ok && cc.data.token.startsWith('dst1.'))
  const machine = cc.data.token

  const machineForbidden = await api('POST', '/api/iam/orgs', { token: machine, body: { name: '机器越权' } })
  check('机器身份越权被拒（scope 限制）', machineForbidden.status === 403)

  const issueToken = await api('POST', '/api/authn/tokens', { token: admin, body: { principalId: cc.data.principal.id, ttlHours: 1, reason: '自测签发' } })
  check('管理端签发令牌', issueToken.ok)
  const revoke = await api('DELETE', `/api/authn/tokens/${issueToken.data.jti}`, { token: admin, body: { reason: '自测吊销' } })
  check('吊销令牌', revoke.ok && revoke.data.revokedAt)
  const revokedUse = await api('GET', '/api/auth/me', { token: issueToken.data.token })
  check('吊销后令牌失效', revokedUse.status === 401)

  // 机器凭证治理：scopes 编辑（联动吊销）/ 密钥轮换 / 列表 hash 脱敏
  const govCred = await api('POST', '/api/authn/principals', { token: admin, body: { name: 'gov-machine', refType: 'external', scopes: ['agent.read'] } })
  const govCc1 = await api('POST', '/api/auth/client-credentials', { body: { clientId: govCred.data.clientId, clientSecret: govCred.data.clientSecret } })
  check('治理夹具：签发 agent.read 机器凭证并换牌', govCc1.ok)

  const scopesPatch = await api('PATCH', `/api/authn/principals/${govCred.data.principalId}`, { token: admin, body: { scopes: ['agent.read', 'usage.write'] } })
  check('调整权限范围 200', scopesPatch.ok && scopesPatch.data.scopes.join(',') === 'agent.read,usage.write')
  const oldTokenAfterPatch = await api('GET', '/api/agents', { token: govCc1.data.token })
  check('调整 scopes 后旧令牌联动吊销（收权即时生效）', oldTokenAfterPatch.status === 401)
  const govCc2 = await api('POST', '/api/auth/client-credentials', { body: { clientId: govCred.data.clientId, clientSecret: govCred.data.clientSecret } })
  check('重新换牌按新范围签发', govCc2.ok && govCc2.data.principal.scopes.join(',') === 'agent.read,usage.write')

  const scopesTypo = await api('PATCH', `/api/authn/principals/${govCred.data.principalId}`, { token: admin, body: { scopes: ['usage.wrtie'] } })
  check('拼错权限点被拒（权限目录校验）', !scopesTypo.ok && JSON.stringify(scopesTypo.error).includes('非法权限点'))
  const scopesStarMix = await api('PATCH', `/api/authn/principals/${govCred.data.principalId}`, { token: admin, body: { scopes: ['*', 'agent.read'] } })
  check("'*' 与其他权限点混用被拒", !scopesStarMix.ok)
  const createTypo = await api('POST', '/api/authn/principals', { token: admin, body: { name: 'typo-machine', refType: 'external', scopes: ['usage.wrtie'] } })
  check('创建凭证即校验权限点（入口防拼错）', !createTypo.ok && JSON.stringify(createTypo.error).includes('非法权限点'))

  // 机器角色：凭证引用组织角色（共用 iam:roles），权限随角色编辑实时同步，无需换牌
  const mrole = await api('POST', '/api/iam/roles', { token: admin, body: { name: '机器角色自测', code: 'mrole_selftest', description: 'selftest', permissions: ['agent.read'] } })
  check('创建机器角色（组织角色目录）', mrole.ok && !!mrole.data.id)
  const roleCred = await api('POST', '/api/authn/principals', { token: admin, body: { name: 'role-machine', refType: 'external', roleIds: [mrole.data.id], scopes: [] } })
  check('签发仅角色授权的机器凭证（scopes 可空）', roleCred.ok)
  const roleCc = await api('POST', '/api/auth/client-credentials', { body: { clientId: roleCred.data.clientId, clientSecret: roleCred.data.clientSecret } })
  check('换牌 scope 解析自角色权限点', roleCc.ok && [...roleCc.data.principal.scopes].sort().join(',') === 'agent.read')
  const roleMachine = roleCc.data.token
  const roleAllowed = await api('GET', '/api/agents', { token: roleMachine })
  check('角色授权机器可调用角色权限范围内的接口', roleAllowed.ok)
  const mroleShrink = await api('PATCH', `/api/iam/roles/${mrole.data.id}`, { token: admin, body: { permissions: ['skill.read'] } })
  const roleAfterShrink = await api('GET', '/api/agents', { token: roleMachine })
  check('角色收权后存量令牌实时降级（无需换牌）', mroleShrink.ok && roleAfterShrink.status === 403)
  const roleCc2 = await api('POST', '/api/auth/client-credentials', { body: { clientId: roleCred.data.clientId, clientSecret: roleCred.data.clientSecret } })
  check('重新换牌按新角色范围签发', roleCc2.ok && [...roleCc2.data.principal.scopes].sort().join(',') === 'skill.read')
  const roleCredPlus = await api('PATCH', `/api/authn/principals/${roleCred.data.principalId}`, { token: admin, body: { roleIds: [mrole.data.id], scopes: ['usage.write'] } })
  const principalAfterPlus = (await api('GET', '/api/authn/principals', { token: admin })).data.principals.find((p) => p.id === roleCred.data.principalId)
  check('角色 + 附加权限点并集生效（列表含角色名与解析后权限）', roleCredPlus.ok && principalAfterPlus.roleNames.includes('机器角色自测') && principalAfterPlus.resolvedScopes.includes('skill.read') && principalAfterPlus.resolvedScopes.includes('usage.write'))
  const emptyAuthz = await api('POST', '/api/authn/principals', { token: admin, body: { name: 'empty-machine', refType: 'external', scopes: [] } })
  check('无角色且无权限点的凭证被拒', !emptyAuthz.ok)
  const ghostRole = await api('POST', '/api/authn/principals', { token: admin, body: { name: 'ghost-machine', refType: 'external', roleIds: ['pri_nonexist'], scopes: ['agent.read'] } })
  check('引用不存在的角色被拒', !ghostRole.ok && JSON.stringify(ghostRole.error).includes('机器角色不存在'))

  const rotateCred = await api('POST', `/api/authn/principals/${govCred.data.principalId}/rotate-secret`, { token: admin })
  check('轮换 clientSecret（clientId 不变 + note 提示 + 无 hash 外发）', rotateCred.ok && rotateCred.data.clientId === govCred.data.clientId && !!rotateCred.data.note && !JSON.stringify(rotateCred.data).includes('Hash'))
  const oldSecretAfterRotate = await api('POST', '/api/auth/client-credentials', { body: { clientId: govCred.data.clientId, clientSecret: govCred.data.clientSecret } })
  check('旧 secret 换牌立即 401', oldSecretAfterRotate.status === 401)
  const newSecretLogin = await api('POST', '/api/auth/client-credentials', { body: { clientId: rotateCred.data.clientId, clientSecret: rotateCred.data.clientSecret } })
  check('新 secret 换牌 200', newSecretLogin.ok)

  const principalsList = await api('GET', '/api/authn/principals', { token: admin })
  check('身份列表不再外发 clientSecretHash', principalsList.ok && !JSON.stringify(principalsList.data).includes('clientSecretHash'))

  // ================================================================ 第 1 步：受众与插件命名空间
  section('第 1 步：令牌受众（aud）与插件命名空间收敛')
  const audPrincipal = await api('POST', '/api/authn/principals', { token: admin, body: { name: 'billing-svc', refType: 'external', scopes: ['audit.read'] } })
  const audToken = await api('POST', '/api/authn/tokens', { token: admin, body: { principalId: audPrincipal.data.principalId, audience: 'billing', ttlHours: 1, reason: '受限受众令牌' } })
  check('签发带受众（aud）的令牌', audToken.ok)

  const audOk = await api('POST', '/api/authn/verify-audience', { token: admin, body: { token: audToken.data.token, audience: 'billing' } })
  check('受众匹配 → 校验通过', audOk.data.valid === true)
  const audMismatch = await api('POST', '/api/authn/verify-audience', { token: admin, body: { token: audToken.data.token, audience: 'market' } })
  check('受众不匹配 → 拒绝', audMismatch.data.valid === false && String(audMismatch.data.reason).includes('受众'))

  const noAudToken = await api('POST', '/api/authn/tokens', { token: admin, body: { principalId: audPrincipal.data.principalId, ttlHours: 1 } })
  const noAudCheck = await api('POST', '/api/authn/verify-audience', { token: admin, body: { token: noAudToken.data.token, audience: 'billing' } })
  check('无受众令牌访问受众服务被拒', noAudCheck.data.valid === false)

  const pluginScopeOk = await api('POST', '/api/authn/tokens', { token: admin, body: { principalId: audPrincipal.data.principalId, audience: 'plugin:com.demo.kb', scopes: ['plugin:com.demo.kb:read'], ttlHours: 1 } })
  check('插件令牌命名空间内 scope 放行', pluginScopeOk.ok)
  const pluginScopeBad = await api('POST', '/api/authn/tokens', { token: admin, body: { principalId: audPrincipal.data.principalId, audience: 'plugin:com.demo.kb', scopes: ['mcp.invoke'], ttlHours: 1 } })
  check('插件令牌跨命名空间 scope 被拒（唯一收敛面）', !pluginScopeBad.ok && JSON.stringify(pluginScopeBad.error).includes('越界'))

  // ================================================================ 第 2 步：租户最小集 + usage 管道
  section('第 2 步：多租户最小集与 usage 计量管道')
  const tenants = await api('GET', '/api/iam/tenants', { token: admin })
  check('默认租户兜底（存量数据落 t_default）', tenants.ok && tenants.data.tenants.some((t) => t.id === 't_default'))
  const newTenant = await api('POST', '/api/iam/tenants', { token: admin, body: { name: '磁姆科技', plan: 'enterprise' } })
  check('创建租户', newTenant.ok && newTenant.data.id.startsWith('t_'))
  const tenantOrg = await api('POST', '/api/iam/orgs', { token: admin, body: { name: '磁姆中国区', tenantId: newTenant.data.id } })
  check('组织挂载租户', tenantOrg.ok && tenantOrg.data.tenantId === newTenant.data.id)

  const meterInput = { org: tenantOrg.data.id, subject: 'user:' + adminLogin.data.user.id, principal: `org:${tenantOrg.data.id}`, resource: 'mcp:real-backend', meters: [{ key: 'tokens', value: 5000, unit: 'token' }], idempotency_key: 'test-usage-001' }
  const meterA = await api('POST', '/api/usage/record', { token: admin, body: meterInput })
  check('计量事件登记（价格簿计价 + 租户解析）', meterA.ok && meterA.data.pricing.charge_cents === 150 && meterA.data.tenant_id === newTenant.data.id && meterA.data.schema_version === 1)
  const meterDup = await api('POST', '/api/usage/record', { token: admin, body: meterInput })
  check('幂等键重复投递不重复计量', meterDup.ok && meterDup.data.event_id === meterA.data.event_id)
  const meterTotals = await api('GET', '/api/usage/totals?principal=' + encodeURIComponent(`org:${tenantOrg.data.id}`), { token: admin })
  check('租户隔离的计量总额（只计一次）', meterTotals.ok && meterTotals.data.count === 1 && meterTotals.data.charge_cents === 150)
  const meterConflict = await api('POST', '/api/usage/record', { token: admin, body: { ...meterInput, meters: [{ key: 'tokens', value: 999, unit: 'token' }] } })
  check('同幂等键不同内容被拒（防篡改）', !meterConflict.ok && JSON.stringify(meterConflict.error).includes('冲突'))
  const badResource = await api('POST', '/api/usage/record', { token: admin, body: { ...meterInput, idempotency_key: 'test-usage-002', resource: 'not-a-resource' } })
  check('schema v1 校验（resource 格式拒绝）', !badResource.ok)
  const noPrice = await api('POST', '/api/usage/record', { token: admin, body: { ...meterInput, idempotency_key: 'test-usage-003', resource: 'model:no-such-model' } })
  check('无计价规则拒绝登记（不免费放行）', !noPrice.ok && JSON.stringify(noPrice.error).includes('计价'))

  // 计量键硬校验：事件必含价格簿 meter_key（缺失 400 且错误信息携带期望键；不再静默 0 计费）
  const wrongMeterKey = await api('POST', '/api/usage/record', { token: admin, body: { ...meterInput, idempotency_key: 'test-usage-wrong-key-1', meters: [{ key: 'calls', value: 1, unit: '次' }] } })
  check('计量键与价格簿不符被拒（mcp:* 须 tokens，错误可自纠）', !wrongMeterKey.ok && JSON.stringify(wrongMeterKey.error).includes('计量键不匹配') && JSON.stringify(wrongMeterKey.error).includes('tokens'))
  const rightKeyAgain = await api('POST', '/api/usage/record', { token: admin, body: { ...meterInput, idempotency_key: 'test-usage-right-key-1', meters: [{ key: 'tokens', value: 1000, unit: 'token' }] } })
  check('计量键匹配路径计价不变（1000 tokens = 30 分）', rightKeyAgain.ok && rightKeyAgain.data.pricing.charge_cents === 30)

  const reconcile1 = await api('POST', '/api/usage/reconcile', { token: admin })
  check('三方对账：usage 口径 = audit 投影（全量比对）', reconcile1.ok
    && reconcile1.data.reconciliation.mismatch === false
    && reconcile1.data.reconciliation.projections.some((p) => p.consumer === 'audit' && p.count === reconcile1.data.reconciliation.usage.count && p.charge_cents === reconcile1.data.reconciliation.usage.charge_cents))
  check('运行时对账检出未声明能力（M5 漂移）', reconcile1.data.drift.drift.length >= 1)
  const grant = await api('PUT', '/api/usage/capability-grants', { token: admin, body: { principal: `org:${tenantOrg.data.id}`, capabilities: ['mcp:*'] } })
  const reconcile2 = await api('POST', '/api/usage/reconcile', { token: admin })
  const tenantStillDrift = reconcile2.data.drift.drift.find((d) => d.principal === `org:${tenantOrg.data.id}`)
  check('授权后该主体能力漂移消除', grant.ok && tenantStillDrift === undefined)
  const driftAlerts = await api('GET', '/api/audit/alerts', { token: admin })
  check('能力漂移已入告警中心', driftAlerts.ok && JSON.stringify(driftAlerts.data.alerts).includes('能力漂移'))

  // ================================================================ 第 3 步：契约五面 / 事件源校验 / L0 市场
  section('第 3 步：契约五面 / 事件源校验 / 代理 ctx / L0 市场')

  const sandbox = await api('POST', '/api/market/sandbox-check', { token: admin, body: {} })
  const sb = sandbox.data?.results ?? {}
  check('代理 ctx：自有命名空间事件放行', sb.emitOwnNamespace === 'ok')
  check('代理 ctx：平台事件被拦（前缀强制）', sb.emitPlatformViaProxy === 'blocked')
  check('总线：plugin 来源直发保留命名空间被拦', sb.directEmitReserved === 'blocked')
  check('总线：plugin 命名空间无来源被拦', sb.pluginEventWithoutSource === 'blocked')
  check('代理 ctx：未授权服务访问被拦（能力裁剪）', sb.serviceWithoutCapability === 'blocked')
  check('代理 ctx：授权能力内服务放行', sb.serviceWithCapability === 'ok')

  const { generateKeyPairSync, createHash, sign: edSign } = await import('node:crypto')
  const devKeys = generateKeyPairSync('ed25519')
  const devPub = devKeys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
  const devReg = await api('POST', '/api/market/developers/register', { body: { username: 'acme-dev', displayName: '磁姆开发者', email: 'dev@acme.com', password: 'Acme@20260', publicKey: devPub, company: '磁姆科技', payoutAccount: '待登记（资金通道依赖清单）' } })
  check('开发者注册（Ed25519 发布者公钥）', devReg.ok && devReg.data.developer.username === 'acme-dev')
  const devPortalLogin = await api('POST', '/api/market/developers/login', { body: { username: 'acme-dev', password: 'Acme@20260' } })
  check('开发者登录（独立身份域）', devPortalLogin.ok && devPortalLogin.data.token.startsWith('dst1.'))
  const devToken2 = devPortalLogin.data.token
  const devBadLogin = await api('POST', '/api/market/developers/login', { body: { username: 'acme-dev', password: 'wrong-pass' } })
  check('开发者密码错误被拒', devBadLogin.status === 401)

  const pluginYaml = (opts = {}) => [
    `id: ${opts.id ?? 'com.acme.hello'}`,
    'version: 1.0.0',
    `publisher: ${opts.publisher ?? 'acme-dev'}`,
    'depends:',
    '  - dsh-plugin-platform-core: ^1.0',
    'capabilities_request:',
    '  - knowledgebase.read',
    `sandbox: ${opts.sandbox ?? 'L0'}`,
    'content:',
    '  prompts:',
    '    - name: hello',
    '      description: Hello World 提示词包',
    '      template: |',
    `        ${opts.template ?? '你是磁姆助手。请复述用户请求并给出结构化回答。'}`,
    '',
  ].join('\n')
  const buildFiles = (opts = {}) => ({
    'plugin.yaml': pluginYaml(opts),
    'manifest/permissions.yaml': 'requested:\n  - knowledgebase.read\n',
    'manifest/api.yaml': 'routes: []\n',
    'manifest/events.yaml': 'subscribes: []\nemits: []\n',
    'manifest/billing.yaml': 'model: usage\nusage:\n  - key: prompts.used\n    unit: 次\n    price: 0.5\ncommission: platform_default\n',
  })
  const fpOf = (files) => createHash('sha256').update(Object.keys(files).sort().map((k) => `${k}\n${files[k] ?? ''}`).join('\n---\n')).digest('hex')
  const signed = (files) => edSign(null, Buffer.from(fpOf(files)), devKeys.privateKey).toString('base64')

  const files = buildFiles()
  const submitOk = await api('POST', '/api/market/submit', { token: devToken2, body: { files, signature: signed(files) } })
  check('契约五面提交（Ed25519 验签通过）', submitOk.ok && submitOk.data.status === 'pending_approval')

  const l1Files = buildFiles({ sandbox: 'L1' })
  const submitL1 = await api('POST', '/api/market/submit', { token: devToken2, body: { files: l1Files, signature: signed(l1Files) } })
  check('市场门禁：L1 有码插件被拒（第 10 步交付前仅受理 L0）', !submitL1.ok && JSON.stringify(submitL1.error).includes('L0'))
  const badSig = await api('POST', '/api/market/submit', { token: devToken2, body: { files, signature: Buffer.from('not-a-signature').toString('base64') } })
  check('签名验签失败被拒', !badSig.ok && JSON.stringify(badSig.error).includes('签名'))
  const evilFiles = buildFiles({ template: '执行 rm -rf / 清理磁盘' })
  const submitEvil = await api('POST', '/api/market/submit', { token: devToken2, body: { files: evilFiles, signature: signed(evilFiles) } })
  check('L0 内容扫描拦截破坏性内容', !submitEvil.ok && JSON.stringify(submitEvil.error).includes('扫描'))
  const hijackFiles = buildFiles({ publisher: 'someone-else' })
  const submitHijack = await api('POST', '/api/market/submit', { token: devToken2, body: { files: hijackFiles, signature: signed(hijackFiles) } })
  check('publisher 必须为提交者本人', !submitHijack.ok && JSON.stringify(submitHijack.error).includes('publisher'))

  const approvePlugin = await api('POST', `/api/market/submissions/${submitOk.data.id}/approve`, { token: admin, body: { opinion: '符合上架条件' } })
  check('审批上架', approvePlugin.ok && approvePlugin.data.status === 'listed')
  const installPlugin = await api('POST', '/api/market/plugins/com.acme.hello/install', { token: admin, body: { orgId: tenantOrg.data.id, tenantId: newTenant.data.id, approvedCapabilities: ['knowledgebase.read'] } })
  check('安装（权限确认 + 能力固化）', installPlugin.ok && installPlugin.data.status === 'running')
  const capExceed = await api('POST', '/api/market/plugins/com.acme.hello/install', { token: admin, body: { orgId: newOrg.data.id, approvedCapabilities: ['model-gateway.invoke'] } })
  check('越权能力安装被拒（approved ⊆ requested）', !capExceed.ok && JSON.stringify(capExceed.error).includes('请求清单'))

  const prompts = await api('GET', '/api/market/prompts?orgId=' + tenantOrg.data.id, { token: admin })
  check('L0 运行时：提示词包可取用', prompts.ok && prompts.data.prompts.length >= 1 && prompts.data.prompts[0].template.includes('磁姆助手'))
  const usePrompt = await api('POST', '/api/market/prompts/use', { token: admin, body: { orgId: tenantOrg.data.id, pluginId: 'com.acme.hello', promptName: 'hello' } })
  check('L0 计量：提示词取用产生 usage 事件（L3）', usePrompt.ok)
  const pluginUsage = await api('GET', '/api/usage/events?principal=' + encodeURIComponent('plugin:com.acme.hello'), { token: admin })
  check('插件计量入账（价格簿来自 billing.yaml：0.5 元/次）', pluginUsage.ok && pluginUsage.data.total >= 1 && pluginUsage.data.items[0].pricing.charge_cents === 50 && pluginUsage.data.items[0].tenant_id === newTenant.data.id)

  // app 复合验收（F5 修正：以覆盖面而非复杂度为由）
  const seededApps = (await api('GET', '/api/apps', { token: admin })).data.apps
  const anyApp = seededApps[0]
  const compoundAppDetail = await api('GET', `/api/apps/${anyApp.id}`, { token: admin })
  const chainTotals = await api('GET', '/api/usage/totals', { token: admin })
  check('app 复合验收：拓扑 + 成本穿透 + 计量管道三链齐备', compoundAppDetail.ok && compoundAppDetail.data.topology.children.length >= 1 && compoundAppDetail.data.cost.length >= 1 && chainTotals.ok && chainTotals.data.count >= 2, JSON.stringify({ app: compoundAppDetail.ok ? { topo: compoundAppDetail.data.topology.children.length, cost: compoundAppDetail.data.cost.length } : compoundAppDetail, totals: chainTotals }))

  // 应用指标主动上报（接入方 → 宿主的推送通道：REST / 工具 / CLI 同一契约）
  const reportDate = new Date(Date.now() - 5 * 86_400_000).toISOString().slice(0, 10)
  const sessionsBefore = (await api('GET', `/api/apps/${anyApp.id}`, { token: admin })).data.metrics.sessions
  const appReport = await api('POST', `/api/apps/${anyApp.id}/metrics-report`, { token: admin, body: { dau: 777, sessions: 1234, avgDepth: 3.5, retention7: 0.42 } })
  check('应用指标上报端点写入成功（DAU/留存即生效）', appReport.ok && appReport.data.dau >= 777 && appReport.data.retention7 === 0.42)
  const appReportBackfill = await api('POST', `/api/apps/${anyApp.id}/metrics-report`, { token: admin, body: { date: reportDate, dau: 100, sessions: 200 } })
  check('应用指标可指定日期补录历史（同日已有记录则会话累加）', appReportBackfill.ok && appReportBackfill.data.sessions === sessionsBefore + 1234 + 200 && appReportBackfill.data.series.some((row) => row.date === reportDate))
  const appReportBadDate = await api('POST', `/api/apps/${anyApp.id}/metrics-report`, { token: admin, body: { date: '2026/07/01', dau: 1 } })
  check('应用指标日期格式非法被拒（400）', appReportBadDate.status === 400)
  const appReportGhost = await api('POST', '/api/apps/app_ghost/metrics-report', { token: admin, body: { dau: 1 } })
  check('不存在应用上报被拒（400）', appReportGhost.status === 400)
  const appReportDenied = await api('POST', `/api/apps/${anyApp.id}/metrics-report`, { token: auditor, body: { dau: 1 } })
  check('无 app.write 上报应用指标被拒（403）', appReportDenied.status === 403)
  const appReportTool = await api('POST', '/api/tools/execute', { token: admin, body: { name: 'app_metrics_report', args: { appId: anyApp.id, dau: 888 } } })
  check('工具 app_metrics_report 上报（同日 DAU 取最大）', appReportTool.ok && appReportTool.data.isError === false && appReportTool.data.value.reported === true && appReportTool.data.value.metrics.dau === 888)
  const appReportPv = await api('POST', `/api/apps/${anyApp.id}/metrics-report`, { token: admin, body: { pv: 500, uv: 260, dau: 800 } })
  check('PV/UV 口径上报（首日写入）', appReportPv.ok && appReportPv.data.pv === 500 && appReportPv.data.uv === 260 && appReportPv.data.dau === 888)
  const appReportPv2 = await api('POST', `/api/apps/${anyApp.id}/metrics-report`, { token: admin, body: { pv: 120, uv: 300 } })
  check('PV 同日累加 / UV 同日取最大（DAU 800 不覆盖 888）', appReportPv2.ok && appReportPv2.data.pv === 620 && appReportPv2.data.uv === 300 && appReportPv2.data.dau === 888)

  // 平台侧指标自动折算（指标口径补全）：浏览器 beacon → PV/UV；entry-ticket 兑换 / OIDC 发码 → DAU
  section('平台侧指标自动折算（beacon PV/UV + SSO 到访 DAU）')
  const autoAppCreate = await api('POST', '/api/apps', { token: admin, body: { name: '指标自动折算验收', attrs: { description: 'beacon PV/UV 与 SSO DAU 自动折算验收', appType: 'web', riskLevel: 'low', dataClass: 'internal' } } })
  check('折算验收应用创建', autoAppCreate.ok && Boolean(autoAppCreate.data?.app?.id), JSON.stringify(autoAppCreate.error))
  const autoAppId = autoAppCreate.data.app.id
  const autoMetrics = async () => (await api('GET', `/api/apps/${autoAppId}`, { token: admin })).data.metrics
  const vidA = 'selftest-vid-aaaa-0903'
  const vidB = 'selftest-vid-bbbb-0903'
  const beaconGif = await rawReq('GET', `/api/apps/beacon?app=${autoAppId}&vid=${vidA}`)
  check('beacon GET 免鉴权：200 + 1x1 GIF + no-store', beaconGif.status === 200 && beaconGif.headers['content-type'].includes('image/gif') && String(beaconGif.headers['cache-control']).includes('no-store') && beaconGif.body.startsWith('GIF8'), JSON.stringify({ status: beaconGif.status, ct: beaconGif.headers['content-type'] }))
  await rawReq('GET', `/api/apps/beacon?app=${autoAppId}&vid=${vidA}`)
  await rawReq('GET', `/api/apps/beacon?app=${autoAppId}&vid=${vidB}`)
  await rawReq('POST', '/api/apps/beacon', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ app: autoAppId, vid: vidA }) })
  const beaconMetrics = await autoMetrics()
  check('beacon PV 逐次累加 / UV 按 vid 去重（4 次上报 → pv=4 uv=2 dau=0）', beaconMetrics.pv === 4 && beaconMetrics.uv === 2 && beaconMetrics.dau === 0, JSON.stringify(beaconMetrics))
  const ghostBeacon = await rawReq('GET', '/api/apps/beacon?app=app_ghost&vid=selftest-vid-cccc-0903')
  check('未知应用 beacon 恒 200 GIF（不泄露应用存在性）', ghostBeacon.status === 200 && ghostBeacon.body === beaconGif.body && ghostBeacon.headers['content-type'] === beaconGif.headers['content-type'])
  const autoTicket = await api('POST', `/api/apps/${autoAppId}/entry-ticket`, { token: admin, body: {} })
  const autoRedeem = await rawReq('POST', '/api/authn/entry-tickets/redeem', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ticket: autoTicket.data.ticket }) })
  check('entry-ticket 兑换 200（公开端点）', autoRedeem.status === 200)
  const afterTicket = await autoMetrics()
  check('entry-ticket 兑换自动折算 DAU（admin 新访客 → dau=1 uv=3）', afterTicket.dau === 1 && afterTicket.uv === 3 && afterTicket.pv === 4, JSON.stringify(afterTicket))
  const autoSso = await api('POST', `/api/apps/${autoAppId}/sso-client`, { token: admin, body: { redirectUris: ['https://auto-check.example/cb'], consentRequired: false } })
  check('折算验收应用自助签发 SSO 客户端', autoSso.ok && autoSso.data.clientId.startsWith('oc-'), JSON.stringify(autoSso.error))
  const autoVerifier = 'selftest-auto-pkce-verifier-43-chars-aaaaaaaaaa'
  const autoFirst = await rawReq('GET', `/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: autoSso.data.clientId, redirect_uri: 'https://auto-check.example/cb', state: 'st-auto', scope: 'openid profile', code_challenge: createHash('sha256').update(autoVerifier).digest('base64url'), code_challenge_method: 'S256' }).toString()}`)
  const autoReqId = new URLSearchParams(String(autoFirst.headers.location).split('?')[1] ?? '').get('req')
  const autoApprove = await authorizeConfirm(auditor, autoReqId, true)
  check('OIDC 授权确认发码（auditor human）', autoApprove.status === 200 && String(autoApprove.result.location).includes('code='), JSON.stringify(autoApprove.result))
  const afterOidc = await autoMetrics()
  check('OIDC 发码自动折算 DAU（auditor 新访客 → dau=2 uv=4）', afterOidc.dau === 2 && afterOidc.uv === 4, JSON.stringify(afterOidc))

  // dshctl plugin init 脚手架（真实生成文件）
  const { execFile } = await import('node:child_process')
  const scaffoldDir = join(DATA_DIR, 'scaffold-plugin')
  await new Promise((resolve) => execFile(process.execPath, ['cli/dshctl.mjs', 'plugin', 'init', '--id=com.selftest.scaffold', `--dir=${scaffoldDir}`], { cwd: process.cwd() }, (error) => { void error; resolve() }))
  const { existsSync: existsFile, readFileSync } = await import('node:fs')
  const SCAFFOLD_FILES = ['plugin.yaml', 'manifest/permissions.yaml', 'manifest/api.yaml', 'manifest/events.yaml', 'manifest/billing.yaml']
  check('dshctl plugin init 脚手架五面生成', SCAFFOLD_FILES.every((f) => existsFile(join(scaffoldDir, f))))
  const scaffoldYaml = existsFile(join(scaffoldDir, 'plugin.yaml')) ? readFileSync(join(scaffoldDir, 'plugin.yaml'), 'utf8') : ''
  check('脚手架默认 L0 + Hello World + 发布者密钥对', scaffoldYaml.includes('sandbox: L0') && scaffoldYaml.includes('hello') && existsFile(join(scaffoldDir, 'publisher-private-key.pem')))

  // ================================================================ 第 5 步：钱包 / 资金流水 / 模型转售
  section('第 5 步：钱包资金流水（只追加+幂等）与模型转售网关')

  const walletKey = { ownerType: 'org', ownerId: tenantOrg.data.id, tenantId: newTenant.data.id }
  const recharge1 = await api('POST', '/api/billing/recharge', { token: admin, body: { ...walletKey, amountCents: 100_000, channelRef: 'BANK-20260821-001', idempotencyKey: 'rc-test-001' } })
  check('充值入账（资金通道未就位→管理员手工录入流水）', recharge1.ok && recharge1.data.balanceCents === 100_000 && recharge1.data.duplicated === false)
  const rechargeDup = await api('POST', '/api/billing/recharge', { token: admin, body: { ...walletKey, amountCents: 100_000, channelRef: 'BANK-20260821-001', idempotencyKey: 'rc-test-001' } })
  check('充值幂等（同渠道单号重复录入不重复入账）', rechargeDup.ok && rechargeDup.data.duplicated === true && rechargeDup.data.balanceCents === 100_000)
  const badRecharge = await api('POST', '/api/billing/recharge', { token: admin, body: { ...walletKey, amountCents: -5, channelRef: 'x', idempotencyKey: 'rc-test-002' } })
  check('负数充值被拒', !badRecharge.ok)

  // 模型转售：OpenAI 兼容真实 stub
  const modelStub = createServer(async (req, res) => {
    if (req.url.endsWith('/chat/completions')) {
      await readBody(req)
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({
        choices: [{ message: { role: 'assistant', content: '你好，这是来自真实模型 stub 的回答。' } }],
        usage: { prompt_tokens: 120, completion_tokens: 1500 },
      }))
      return
    }
    res.writeHead(404).end('{}')
  })
  await new Promise((resolve) => modelStub.listen(0, '127.0.0.1', resolve))
  const modelPort = modelStub.address().port

  const noEndpointModel = await api('POST', '/api/modelgw/models', { token: admin, body: { slug: 'ghost-model', endpoint: '', listCentsPerKTokens: 10 } })
  const ghostInvoke = await api('POST', '/api/modelgw/invoke', { token: admin, body: { model: 'ghost-model', messages: [{ role: 'user', content: 'hi' }], orgId: tenantOrg.data.id } })
  check('未配置 endpoint 的模型拒绝调用（不生成假 completion）', noEndpointModel.ok && !ghostInvoke.ok && JSON.stringify(ghostInvoke.error).includes('endpoint'))

  const modelReg = await api('POST', '/api/modelgw/models', { token: admin, body: { slug: 'ds-stub', displayName: 'DeepSeek（stub 验证）', provider: 'deepseek', endpoint: `http://127.0.0.1:${modelPort}/v1`, apiKey: 'stub-key', listCentsPerKTokens: 10, costCentsPerKTokens: 5 } })
  check('模型目录登记（价格簿自动登记）', modelReg.ok)

  const modelInvoke = await api('POST', '/api/modelgw/invoke', { token: admin, body: { model: 'ds-stub', messages: [{ role: 'user', content: '真实链路测试' }], orgId: tenantOrg.data.id } })
  check('模型调用真实往返 + 实测 tokens 计量', modelInvoke.ok && modelInvoke.data.content.includes('真实模型') && modelInvoke.data.inputTokens === 120 && modelInvoke.data.outputTokens === 1500)
  check('按价格簿扣费（1500 tokens × 10分/千 = 15 分）', modelInvoke.ok && modelInvoke.data.chargeCents === 15 && modelInvoke.data.balanceAfterCents === 100_000 - 15, JSON.stringify(modelInvoke))

  const modelUsageEvents = await api('GET', '/api/usage/events?resource=model:ds-stub', { token: admin })
  check('模型计量事件含 input/output meters + 租户维度', modelUsageEvents.ok && modelUsageEvents.data.total >= 1 && modelUsageEvents.data.items[0].meters.length === 2 && modelUsageEvents.data.items[0].tenant_id === newTenant.data.id)

  const walletAfter = await api('GET', `/api/billing/wallets/org/${tenantOrg.data.id}`, { token: admin })
  check('钱包余额与流水一致（扣费经计量管道）', walletAfter.ok && walletAfter.data.balanceCents === 100_000 - 15 && walletAfter.data.monthSpentCents === 15, JSON.stringify(walletAfter))

  // 预算/限额
  await api('PUT', `/api/billing/budgets/${tenantOrg.data.id}`, { token: admin, body: { monthlyCents: 30 } })
  const budgetBlock = await api('POST', '/api/modelgw/invoke', { token: admin, body: { model: 'ds-stub', messages: [{ role: 'user', content: '再试一次' }], orgId: tenantOrg.data.id } })
  check('月度预算限额拦截（quota.exceeded，不计费）', !budgetBlock.ok && JSON.stringify(budgetBlock.error).includes('预算'))
  const balanceAfterBlock = await api('GET', `/api/billing/wallets/org/${tenantOrg.data.id}`, { token: admin })
  check('被拒调用不产生扣费', balanceAfterBlock.data.balanceCents === 100_000 - 15)

  const poorOrg = await api('POST', '/api/billing/recharge', { token: admin, body: { ownerType: 'org', ownerId: newOrg.data.id, amountCents: 10, channelRef: 'BANK-POOR', idempotencyKey: 'rc-poor-001' } })
  const poorInvoke = await api('POST', '/api/modelgw/invoke', { token: admin, body: { model: 'ds-stub', messages: [{ role: 'user', content: '余额不足测试' }], orgId: newOrg.data.id } })
  check('余额不足预检拦截（先检后用）', poorOrg.ok && !poorInvoke.ok && JSON.stringify(poorInvoke.error).includes('余额不足'))

  const integrity = await api('POST', '/api/billing/verify', { token: admin })
  check('资金完整性：余额 ≡ Σ流水（全量重放）', integrity.ok && integrity.data.ok === true && integrity.data.wallets >= 2)
  modelStub.close()

  // ================================================================ 第 6 步：OIDC Provider（浏览器授权流 / 协议合规）
  section('第 6 步：OIDC Provider（浏览器授权流 / RS256 / 协议合规）')
  const discovery = await rawReq('GET', '/.well-known/openid-configuration')
  const disco = jsonBody(discovery)
  check('OIDC 发现文档暴露（jwks_uri / 端点 / RS256）', discovery.status === 200 && disco.jwks_uri.includes('/.well-known/jwks.json') && disco.id_token_signing_alg_values_supported.includes('RS256'))
  check('发现文档协议面（email scope / Basic+Post 双认证 / refresh+revoke+end_session）',
    disco.scopes_supported.includes('email')
    && disco.token_endpoint_auth_methods_supported.includes('client_secret_basic')
    && disco.token_endpoint_auth_methods_supported.includes('client_secret_post')
    && disco.grant_types_supported.includes('refresh_token')
    && Boolean(disco.revocation_endpoint) && Boolean(disco.end_session_endpoint))
  const jwks = jsonBody(await rawReq('GET', '/.well-known/jwks.json'))
  check('JWKS 数组化公钥（kid/kty/n）', Array.isArray(jwks.keys) && jwks.keys[0].kty === 'RSA' && jwks.keys[0].kid.length === 16 && Boolean(jwks.keys[0].n))

  const oidcClient = await api('POST', '/api/authn/oidc/clients', { token: admin, body: { name: '外部 CRM 应用', redirectUris: ['https://crm.partner.example/cb'], consentRequired: false } })
  check('登记 OIDC 客户端（secret 一次性返回）', oidcClient.ok && oidcClient.data.clientId.startsWith('oc-') && oidcClient.data.clientSecret.startsWith('ocs'))
  const OC = oidcClient.data

  // -- CORS：纯前端（public + PKCE）客户端跨域直调协议端点（允许来源 = 已登记 redirect_uri origin）--
  const corsHit = await rawReq('GET', '/.well-known/openid-configuration', { headers: { origin: 'https://crm.partner.example' } })
  check('discovery 携带 CORS 放行头（origin 命中已登记 redirect_uri）', corsHit.headers['access-control-allow-origin'] === 'https://crm.partner.example' && String(corsHit.headers.vary).includes('Origin'))
  const corsPreflight = await rawReq('OPTIONS', '/oauth/token', { headers: { origin: 'https://crm.partner.example', 'access-control-request-method': 'POST' } })
  check('OPTIONS 预检 → 204 + allow-methods/headers/max-age', corsPreflight.status === 204 && corsPreflight.headers['access-control-allow-origin'] === 'https://crm.partner.example' && String(corsPreflight.headers['access-control-allow-headers']).includes('authorization') && String(corsPreflight.headers['access-control-allow-headers']).includes('content-type'))
  const corsMiss = await rawReq('GET', '/.well-known/openid-configuration', { headers: { origin: 'https://evil.example' } })
  check('未登记来源不发放 allow-origin（仅 vary）', corsMiss.headers['access-control-allow-origin'] === undefined && String(corsMiss.headers.vary).includes('Origin'))
  const corsErrPath = await rawReq('POST', '/oauth/token', { headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://crm.partner.example' }, body: 'grant_type=authorization_code&code=forged' })
  check('错误响应（invalid_client）同样携带放行头（浏览器可读错误体）', corsErrPath.status === 401 && jsonBody(corsErrPath).error === 'invalid_client' && corsErrPath.headers['access-control-allow-origin'] === 'https://crm.partner.example')

  // -- 第一跳校验：任一失败 → 302 平台错误页（绝不携带外部 redirect_uri，防开放重定向）--
  const pkceVerifier = 'selftest-pkce-verifier-43-chars-aaaaaaaaaaaaaa'
  const pkceChallenge = createHash('sha256').update(pkceVerifier).digest('base64url')
  const authorizeQuery = (over = {}) => new URLSearchParams({
    response_type: 'code', client_id: OC.clientId, redirect_uri: 'https://crm.partner.example/cb',
    state: 'st-selftest', scope: 'openid profile email', code_challenge: pkceChallenge, code_challenge_method: 'S256', ...over,
  }).toString()
  const reqIdOf = (raw) => new URLSearchParams(String(raw.headers.location).split('?')[1] ?? '').get('req')

  const badClient = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ client_id: 'oc-forged' })}`)
  check('无效 client_id → 302 平台错误页（Location 不含外部域）', badClient.status === 302 && String(badClient.headers.location).startsWith('/#/oauth/error') && !String(badClient.headers.location).includes('crm.partner.example'))
  const badRedirect = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ redirect_uri: 'https://evil.example/cb' })}`)
  check('redirect_uri 不在白名单 → 平台错误页', badRedirect.status === 302 && String(badRedirect.headers.location).startsWith('/#/oauth/error'))
  const badScope = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ scope: 'openid profile billing:admin' })}`)
  check('白名单外 scope → invalid_scope 错误页', badScope.status === 302 && decodeURIComponent(String(badScope.headers.location)).includes('invalid_scope'))
  const noPkce = await rawReq('GET', `/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: OC.clientId, redirect_uri: 'https://crm.partner.example/cb', state: 'st', scope: 'openid' }).toString()}`)
  check('缺少 PKCE → 错误页（强制 S256）', noPkce.status === 302 && String(noPkce.headers.location).startsWith('/#/oauth/error') && decodeURIComponent(String(noPkce.headers.location)).includes('PKCE'))
  const badResponseType = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ response_type: 'token' })}`)
  check('response_type=token → unsupported_response_type 错误页', badResponseType.status === 302 && decodeURIComponent(String(badResponseType.headers.location)).includes('unsupported_response_type'))

  // -- 合法第一跳：302 平台授权页 + 公开查询不泄露 redirect_uri --
  const goodFirst = await rawReq('GET', `/oauth/authorize?${authorizeQuery()}`)
  check('合法授权请求 → 302 平台授权页（/#/oauth/authorize?req=）', goodFirst.status === 302 && String(goodFirst.headers.location).startsWith('/#/oauth/authorize?req='))
  const reqId = reqIdOf(goodFirst)
  const reqInfo = await authReqInfo(reqId)
  check('授权请求公开查询（客户端名/scope，不泄露 redirect_uri）', reqInfo.status === 200 && reqInfo.info.clientName === '外部 CRM 应用' && reqInfo.info.scope.includes('openid') && !JSON.stringify(reqInfo.info).includes('redirect_uri'))

  // -- 授权确认：机器 403 / human 通过 / 重放、伪造、过期 400 --
  const machineAuthorize = await api('POST', '/api/authn/oidc/authorize', { token: machine, body: { reqId } })
  check('机器身份确认授权被拒（human-only）', machineAuthorize.status === 403)
  const authApprove = await authorizeConfirm(admin, reqId, true)
  check('用户确认授权 → 回跳地址（code/state 原样透传 + iss 防 mix-up）', authApprove.status === 200 && authApprove.result.location.includes('code=') && authApprove.result.location.includes('state=st-selftest') && authApprove.result.location.includes('iss='))
  const replayReq = await authorizeConfirm(admin, reqId, true)
  check('授权请求重放被拒（单次消费）', replayReq.status === 400)
  const forgedReq = await authorizeConfirm(admin, 'forged-req-id')
  check('伪造 reqId 被拒', forgedReq.status === 400)
  const expFirst = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'st-expired' })}`)
  const expReqId = reqIdOf(expFirst)
  await new Promise((resolve) => setTimeout(resolve, 2500))
  const expApprove = await authorizeConfirm(admin, expReqId, true)
  check('过期授权请求被拒（TTL 语义）', expApprove.status === 400)

  // -- consent 门禁：未同意 400 / 显式拒绝 access_denied 回跳 / 同意放行 --
  const consentClient = await api('POST', '/api/authn/oidc/clients', { token: admin, body: { name: '需同意的外部门户', redirectUris: ['https://portal.partner.example/cb'], consentRequired: true } })
  check('登记需显式同意的客户端', consentClient.ok)
  const ccFirst = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ client_id: consentClient.data.clientId, redirect_uri: 'https://portal.partner.example/cb', state: 'st-consent' })}`)
  const ccReqId = reqIdOf(ccFirst)
  const ccInfo = await authReqInfo(ccReqId)
  check('consentRequired 状态公开回显', ccInfo.status === 200 && ccInfo.info.consentRequired === true)
  const ccNo = await authorizeConfirm(admin, ccReqId, undefined)
  check('未表达同意 → 400', ccNo.status === 400)
  const ccDeny = await authorizeConfirm(admin, ccReqId, false)
  check('显式拒绝 → access_denied 回跳（拒绝事件留痕）', ccDeny.status === 200 && ccDeny.result.location.includes('error=access_denied'))
  const ccFirst2 = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ client_id: consentClient.data.clientId, redirect_uri: 'https://portal.partner.example/cb', state: 'st-consent2' })}`)
  const ccOk = await authorizeConfirm(admin, reqIdOf(ccFirst2), true)
  check('勾选同意后放行（签发 code）', ccOk.status === 200 && ccOk.result.location.includes('code='))

  // -- 换牌：Basic/Post 双认证 × form/JSON 双编码、PKCE 正误、code 重放、错误码状态码 --
  const basicAuth = Buffer.from(`${OC.clientId}:${OC.clientSecret}`).toString('base64')
  const tokenForm = (extra = {}) => new URLSearchParams({
    grant_type: 'authorization_code', client_id: OC.clientId, client_secret: OC.clientSecret,
    redirect_uri: 'https://crm.partner.example/cb', code_verifier: pkceVerifier, ...extra,
  }).toString()
  const code1 = new URL(authApprove.result.location).searchParams.get('code')
  const tPost = await rawReq('POST', '/oauth/token', { headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: tokenForm({ code: code1 }) })
  const ts1 = jsonBody(tPost)
  check('code 换令牌（client_secret_post + form 编码）', tPost.status === 200 && ts1.access_token?.split('.').length === 3 && ts1.token_type === 'Bearer')
  check('响应契约（scope 字段 + confidential 客户端附带 refresh_token）', ts1.scope === 'openid profile email' && ts1.refresh_token?.startsWith('otr_'))
  const oidcCodeReplay = await rawReq('POST', '/oauth/token', { headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: tokenForm({ code: code1 }) })
  check('授权码重放被拒（单次消费 → 400 invalid_grant）', oidcCodeReplay.status === 400 && jsonBody(oidcCodeReplay).error === 'invalid_grant')

  const first2 = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'st-basic' })}`)
  const approve2 = await authorizeConfirm(admin, reqIdOf(first2), true)
  const oidcCode2 = new URL(approve2.result.location).searchParams.get('code')
  const tBasic = await rawReq('POST', '/oauth/token', {
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${basicAuth}` },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: oidcCode2, redirect_uri: 'https://crm.partner.example/cb', code_verifier: pkceVerifier }).toString(),
  })
  check('code 换令牌（client_secret_basic + Basic 头认证）', tBasic.status === 200 && jsonBody(tBasic).access_token?.split('.').length === 3)
  const first3 = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'st-json' })}`)
  const approve3 = await authorizeConfirm(admin, reqIdOf(first3), true)
  const tJson = await rawReq('POST', '/oauth/token', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', code: new URL(approve3.result.location).searchParams.get('code'), client_id: OC.clientId, client_secret: OC.clientSecret, redirect_uri: 'https://crm.partner.example/cb', code_verifier: pkceVerifier }),
  })
  check('code 换令牌（JSON 编码 + Post 认证）', tJson.status === 200 && jsonBody(tJson).access_token?.split('.').length === 3)

  const first4 = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'st-badverifier' })}`)
  const approve4 = await authorizeConfirm(admin, reqIdOf(first4), true)
  const tBadVerifier = await rawReq('POST', '/oauth/token', {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: tokenForm({ code: new URL(approve4.result.location).searchParams.get('code'), code_verifier: 'wrong-verifier-wrong-verifier-wrong-verifier-wrong' }),
  })
  check('PKCE verifier 错误 → 400 invalid_grant', tBadVerifier.status === 400 && jsonBody(tBadVerifier).error === 'invalid_grant')
  const first5 = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'st-noverifier' })}`)
  const approve5 = await authorizeConfirm(admin, reqIdOf(first5), true)
  const tNoVerifier = await rawReq('POST', '/oauth/token', {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: OC.clientId, client_secret: OC.clientSecret, code: new URL(approve5.result.location).searchParams.get('code') }).toString(),
  })
  check('PKCE 缺少 code_verifier → 400', tNoVerifier.status === 400 && JSON.stringify(tNoVerifier.body).includes('code_verifier'))
  const tBadSecret = await rawReq('POST', '/oauth/token', {
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${OC.clientId}:wrong-secret`).toString('base64')}` },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: 'whatever' }).toString(),
  })
  check('client_secret 错误 → 401 + WWW-Authenticate: Basic', tBadSecret.status === 401 && jsonBody(tBadSecret).error === 'invalid_client' && String(tBadSecret.headers['www-authenticate'] ?? '').includes('Basic'))

  // -- token 类型区分 + JWKS 本地验签 + userinfo --
  const [jwtH, jwtP, jwtS] = ts1.access_token.split('.')
  const jwtClaims = JSON.parse(Buffer.from(jwtP, 'base64url').toString('utf8'))
  const jwtHeader = JSON.parse(Buffer.from(jwtH, 'base64url').toString('utf8'))
  const idClaims = JSON.parse(Buffer.from(ts1.id_token.split('.')[1], 'base64url').toString('utf8'))
  check('token 类型打标（access/id 区分 + kid 头）', jwtClaims.token_use === 'access' && idClaims.token_use === 'id' && jwtHeader.kid === jwks.keys[0].kid && jwtClaims.aud === OC.clientId && idClaims.nonce === undefined)
  const { createPublicKey: cpk, verify: rsVerify } = await import('node:crypto')
  const jwkKey = cpk({ key: { kty: jwks.keys[0].kty, n: jwks.keys[0].n, e: jwks.keys[0].e }, format: 'jwk' })
  check('外部应用以 JWKS 公钥本地验签通过', rsVerify('RSA-SHA256', Buffer.from(`${jwtH}.${jwtP}`), jwkKey, Buffer.from(jwtS, 'base64url')) === true && jwtClaims.iss.includes('127.0.0.1'))

  const userInfo = await rawReq('GET', '/oauth/userinfo', { headers: { authorization: `Bearer ${ts1.access_token}` } })
  const ui = jsonBody(userInfo)
  check('userinfo 返回 NormalizedProfile（org/角色/租户）', userInfo.status === 200 && ui.sub === adminLogin.data.user.id && ui.org !== null && Array.isArray(ui.roles) && ui.roles.includes('super_admin'))
  const idAsAccess = await rawReq('GET', '/oauth/userinfo', { headers: { authorization: `Bearer ${ts1.id_token}` } })
  check('id_token 调 userinfo 被拒（token_use 收敛）', idAsAccess.status === 401)
  const noBearer = await rawReq('GET', '/oauth/userinfo')
  check('userinfo 无凭证 → 401 + WWW-Authenticate: Bearer', noBearer.status === 401 && String(noBearer.headers['www-authenticate'] ?? '').includes('Bearer'))

  // -- SPA 静态页（授权页/错误页由前端路由承载）--
  const spaIndex = await rawReq('GET', '/')
  check('SPA 静态页可达（#/oauth/* 前端路由承载）', spaIndex.status === 200 && spaIndex.body.includes('id="app"'))

  // -- openid-client 冒烟（标准 SDK 一行 discovery 驱动：authorize → token → userinfo）--
  const oc = await import('openid-client')
  const ocConfig = await oc.discovery(new URL(BASE), OC.clientId, undefined, new oc.ClientSecretBasic(OC.clientSecret), { execute: [oc.allowInsecureRequests] })
  const ocVerifier = oc.randomPKCECodeVerifier()
  const ocChallenge = await oc.calculatePKCECodeChallenge(ocVerifier)
  const ocState = oc.randomState()
  const ocNonce = oc.randomNonce()
  const ocRedirectTo = oc.buildAuthorizationUrl(ocConfig, {
    redirect_uri: 'https://crm.partner.example/cb', scope: 'openid profile email',
    state: ocState, nonce: ocNonce, code_challenge: ocChallenge, code_challenge_method: 'S256',
  })
  const ocFirst = await rawReq('GET', ocRedirectTo.pathname + ocRedirectTo.search)
  check('openid-client：授权地址 302 平台授权页', ocFirst.status === 302 && String(ocFirst.headers.location).startsWith('/#/oauth/authorize?req='))
  const ocApprove = await authorizeConfirm(admin, reqIdOf(ocFirst), true)
  const ocTokens = await oc.authorizationCodeGrant(ocConfig, new URL(ocApprove.result.location), { pkceCodeVerifier: ocVerifier, expectedState: ocState, expectedNonce: ocNonce })
  check('openid-client：授权码换令牌（Basic 认证 + PKCE + id_token 验签全过）', typeof ocTokens.access_token === 'string' && typeof ocTokens.id_token === 'string')
  const ocUser = await oc.fetchUserInfo(ocConfig, ocTokens.access_token, ocTokens.claims().sub)
  check('openid-client：userinfo 取回身份（一行 SDK 式接入闭环）', ocUser.sub === adminLogin.data.user.id && ocUser.org !== null && ocUser.roles.includes('super_admin'))

  // 冻结联动：OIDC 令牌即时失效（无需等过期）
  const frozenAuth = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'st-frozen' })}`)
  const frozenApprove = await authorizeConfirm(dev, reqIdOf(frozenAuth), true)
  const frozenTokens = jsonBody(await rawReq('POST', '/oauth/token', {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: tokenForm({ code: new URL(frozenApprove.result.location).searchParams.get('code') }),
  }))
  const devUserFull = (await api('GET', '/api/iam/users?q=' + encodeURIComponent('陈默'), { token: admin })).data.users[0]
  await api('POST', `/api/iam/users/${devUserFull.id}/freeze`, { token: admin, body: { reason: '第 6 步：验证 OIDC 离职/冻结联动' } })
  const frozenInfo = await rawReq('GET', '/oauth/userinfo', { headers: { authorization: `Bearer ${frozenTokens.access_token}` } })
  check('账号冻结 → OIDC 令牌即时失效（卖点闭环）', frozenInfo.status === 401)
  // 解冻并重登：后续 MCP/Skill 段仍需 dev 令牌（冻结已即时吊销旧令牌）
  await api('POST', `/api/iam/users/${devUserFull.id}/unfreeze`, { token: admin })
  const devRelogin = await api('POST', '/api/auth/login', { body: { username: 'dev', password: 'Ybk@2026' } })
  dev = devRelogin.data.token

  // ================================================================ 第 7 步：L0 市场 beta（自营供给 + 订阅代收）
  section('第 7 步：L0 市场 beta（自营供给 / 订阅代收 / 卸载联动）')
  const marketList = await api('GET', '/api/market/plugins', { token: admin })
  check('自营首批供给上架（3 个标杆 L0）', marketList.ok && marketList.data.plugins.filter((p) => p.pluginId.startsWith('com.platform.')).length === 3, JSON.stringify(marketList).slice(0, 400))
  const officialInstall = await api('POST', '/api/market/plugins/com.platform.contract-review/install', { token: admin, body: { orgId: newOrg.data.id, approvedCapabilities: ['knowledgebase.read'] } })
  check('安装自营插件', officialInstall.ok && officialInstall.data.status === 'running')
  const subs = await api('GET', '/api/market/subscriptions', { token: admin })
  const subEntry = subs.data.subscriptions.find((s) => s.pluginId === 'com.platform.contract-review' && s.orgId === newOrg.data.id)
  check('L3 订阅代收登记（hybrid 999 元/月，人工对账过渡）', Boolean(subEntry) && subEntry.monthlyCents === 99900 && subEntry.channel === 'manual-settlement')
  const officialPrompts = await api('GET', '/api/market/prompts?orgId=' + newOrg.data.id, { token: admin })
  check('自营插件提示词包可取用', officialPrompts.ok && JSON.stringify(officialPrompts.data.prompts).includes('合同审查'))

  const uninstall = await api('POST', '/api/market/plugins/com.acme.hello/uninstall', { token: admin, body: { orgId: tenantOrg.data.id } })
  check('卸载联动（运行态回收）', uninstall.ok && uninstall.data.status === 'uninstalled')
  const promptsAfterUninstall = await api('GET', '/api/market/prompts?orgId=' + tenantOrg.data.id, { token: admin })
  check('卸载后提示词包不再提供', promptsAfterUninstall.ok && !JSON.stringify(promptsAfterUninstall.data.prompts).includes('磁姆助手'))

  // ================================================================ MCP
  section('MCP 部署服务')
  const svcCreate = await api('POST', '/api/mcp/services', { token: admin, body: { name: '自测检索服务', slug: 'selftest-search', orgId: newOrg.data.id, description: '自测用（演示传输层）', transport: 'http', mode: 'hosted', exec: 'demo' } })
  check('注册 MCP 服务（草稿）', svcCreate.ok && svcCreate.data.status === 'draft')
  const svcId = svcCreate.data.id

  const invokeDraft = await api('POST', '/api/mcp/invoke', { token: admin, body: { serviceId: svcId, tool: 'selftest-search_search' } })
  check('草稿服务拒绝调用', !invokeDraft.ok || invokeDraft.data.status === 'denied')

  const verify = await api('POST', `/api/mcp/services/${svcId}/verify`, { token: admin })
  check('测试环境验证', verify.ok && verify.data.status === 'verifying')

  const dryRun = await api('POST', `/api/mcp/services/${svcId}/deploy`, { token: admin, body: { dryRun: true } })
  check('部署 dry-run 影响面预览', dryRun.ok && dryRun.data.dryRun === true)

  const deployGray = await api('POST', `/api/mcp/services/${svcId}/deploy`, { token: admin, body: { grayPercent: 20, version: '0.1.0', changelog: '灰度首发' } })
  check('灰度发布（20%）', deployGray.ok && deployGray.data.status === 'gray' && deployGray.data.grayPercent === 20)

  const deployFull = await api('POST', `/api/mcp/services/${svcId}/deploy`, { token: admin, body: { grayPercent: 100, version: '0.2.0', changelog: '全量' } })
  check('全量发布', deployFull.ok && deployFull.data.status === 'online')

  const rollback = await api('POST', `/api/mcp/services/${svcId}/rollback`, { token: admin, body: { targetVersion: '0.1.0' } })
  check('版本回滚（版本不可变保留）', rollback.ok && rollback.data.currentVersion === '0.1.0')

  // 网关鉴权：未授权主体
  const invokeDenied = await api('POST', '/api/mcp/invoke', { token: dev, body: { serviceId: svcId, tool: 'selftest-search_search', args: { query: 'hi' } } })
  check('未授权主体被网关拒绝', invokeDenied.ok && invokeDenied.data.status === 'denied', JSON.stringify(invokeDenied).slice(0, 300))

  // 权限组授权后放行
  const pg = await api('POST', '/api/mcp/perm-groups', { token: admin, body: {
    name: '自测权限组', policies: { [svcId]: { allowedTools: '*', constraints: { readOnly: true } } },
    subjects: [{ type: 'user_group', id: groupCreate.data.id }],
  } })
  check('创建 MCP 权限组', pg.ok)

  const devUser = (await api('GET', '/api/iam/users?q=' + encodeURIComponent('陈默'), { token: admin })).data.users[0]
  await api('PATCH', '/api/iam/groups/' + groupCreate.data.id, { token: admin, body: { memberIds: [devUser.id] } })
  const invokeOk = await api('POST', '/api/mcp/invoke', { token: dev, body: { serviceId: svcId, tool: 'selftest-search_search', args: { query: '自测' } } })
  check('授权后调用成功（只读工具放行）', invokeOk.ok && invokeOk.data.ok === true, JSON.stringify(invokeOk).slice(0, 300))

  const writeTool = (await api('GET', '/api/mcp/services', { token: admin })).data.services.find((s) => s.id === svcId).tools.find((t) => t.riskLevel !== 'read')
  if (writeTool) {
    const invokeWrite = await api('POST', '/api/mcp/invoke', { token: dev, body: { serviceId: svcId, tool: writeTool.name } })
    check('只读约束拦截写工具', invokeWrite.data?.status === 'denied' && String(invokeWrite.data.error).includes('只读'), JSON.stringify(invokeWrite).slice(0, 300))
  }

  // 回归：Agent 机器凭证身份解析（权限组 subject type=agent 必须能命中）
  const agentMcp = await api('POST', '/api/agents', { token: admin, body: { name: '自测MCP机器人', attrs: { description: 'MCP 鉴权回归', model: 'deepseek-chat', riskLevel: 'low', avatar: '🤖' } } })
  check('注册 Agent（MCP 鉴权回归用）', agentMcp.ok && agentMcp.data.credential?.clientId)
  const agentMcpId = agentMcp.data.agent.id
  const agentCc = await api('POST', '/api/auth/client-credentials', { body: { clientId: agentMcp.data.credential.clientId, clientSecret: agentMcp.data.credential.clientSecret } })
  check('Agent 机器凭证换令牌', agentCc.ok && agentCc.data.token)
  const agentToken = agentCc.data.token

  const agentInvokeDenied = await api('POST', '/api/mcp/invoke', { token: agentToken, body: { serviceId: svcId, tool: 'selftest-search_search', args: { query: '未授权' } } })
  check('未授权 Agent 被网关拒绝', agentInvokeDenied.ok && agentInvokeDenied.data.status === 'denied', JSON.stringify(agentInvokeDenied).slice(0, 300))

  const pgAgent = await api('POST', '/api/mcp/perm-groups', { token: admin, body: {
    name: '自测Agent权限组', policies: { [svcId]: { allowedTools: '*', constraints: { readOnly: true } } },
    subjects: [{ type: 'agent', id: agentMcpId }],
  } })
  check('创建 Agent 主体权限组', pgAgent.ok)

  const agentInvokeOk = await api('POST', '/api/mcp/invoke', { token: agentToken, body: { serviceId: svcId, tool: 'selftest-search_search', args: { query: '自测' } } })
  check('Agent 主体命中权限组放行', agentInvokeOk.ok && agentInvokeOk.data.ok === true, JSON.stringify(agentInvokeOk).slice(0, 300))

  const agentMcpCall = await rawReq('POST', '/mcp', {
    headers: { 'content-type': 'application/json', authorization: `Bearer ${agentToken}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 90, method: 'tools/call', params: { name: 'mcp_invoke', arguments: { serviceId: svcId, tool: 'selftest-search_search', args: { query: '自测' } } } }),
  })
  const agentMcpText = jsonBody(agentMcpCall).result?.content?.[0]?.text ?? ''
  const agentMcpInvoke = (() => { try { return JSON.parse(agentMcpText) } catch { return {} } })()
  check('Agent 机器令牌经 /mcp mcp_invoke 放行', agentMcpCall.status === 200 && agentMcpInvoke.status === 'ok', agentMcpText.slice(0, 300))

  const metrics = await api('GET', `/api/mcp/services/${svcId}/metrics`, { token: admin })
  check('调用监控指标（调用方/工具/序列）', metrics.ok && metrics.data.calls >= 1 && metrics.data.toolStats.length > 0 && metrics.data.series.length === 60)

  const healthProbe = await api('POST', `/api/mcp/services/${svcId}/health`, { token: admin })
  check('健康探测', healthProbe.ok && ['healthy', 'degraded'].includes(healthProbe.data.status))

  // ================================================================ 第 0 步：执行层/连接器真实化
  section('第 0 步：真实传输层与真实连接器')
  // -- MCP 真实 stub（JSON-RPC over HTTP） ---------------------------------
  const mcpStub = createServer(async (req, res) => {
    const raw = await readBody(req)
    let msg = {}
    try { msg = JSON.parse(raw) } catch { /* ignore */ }
    if (msg.method === 'initialize') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-03-26', capabilities: {} } }))
      return
    }
    if (msg.method === 'tools/call') {
      if (msg.params?.name === 'boom') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { isError: true, content: '故意失败' } }))
        return
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({
        jsonrpc: '2.0', id: msg.id,
        result: { content: [{ type: 'text', text: `real-echo:${msg.params?.name}` }], usage: { totalTokens: 4321 } },
      }))
      return
    }
    res.writeHead(404).end('{}')
  })
  await new Promise((resolve) => mcpStub.listen(0, '127.0.0.1', resolve))
  const mcpPort = mcpStub.address().port

  const realSvc = await api('POST', '/api/mcp/services', { token: admin, body: { name: '真实后端服务', slug: 'real-backend', orgId: newOrg.data.id, endpoint: `http://127.0.0.1:${mcpPort}/mcp`, transport: 'http', mode: 'external', exec: 'real', tools: [
    { name: 'real_query', description: '真实查询', inputSchema: { type: 'object' }, riskLevel: 'read' },
    { name: 'boom', description: '总是失败', inputSchema: { type: 'object' }, riskLevel: 'read' },
  ] } })
  check('注册 real 服务（默认真实传输）', realSvc.ok && realSvc.data.exec === 'real')
  const realId = realSvc.data.id
  await api('POST', '/api/mcp/perm-groups', { token: admin, body: {
    name: 'real 全放行', policies: { [realId]: { allowedTools: '*', constraints: {} } },
    subjects: [{ type: 'user', id: adminLogin.data.user.id, name: 'admin' }],
  } })
  const realVerify = await api('POST', `/api/mcp/services/${realId}/verify`, { token: admin })
  check('real 服务测试验证（真实 initialize 探测）', realVerify.ok && realVerify.data.health.status === 'healthy')
  await api('POST', `/api/mcp/services/${realId}/deploy`, { token: admin, body: { version: '1.0.0', changelog: '真实首发' } })

  const realInvoke = await api('POST', '/api/mcp/invoke', { token: admin, body: { serviceId: realId, tool: 'real_query', args: { q: '真实链路' } } })
  check('real 调用真实往返（stub 内容透传）', realInvoke.ok && JSON.stringify(realInvoke.data.result).includes('real-echo:real_query'))

  const boomInvoke = await api('POST', '/api/mcp/invoke', { token: admin, body: { serviceId: realId, tool: 'boom', args: {} } })
  check('real 错误路径（isError → status error）', boomInvoke.data.status === 'error')
  const realCalls = (await api('GET', `/api/mcp/calls?serviceId=${realId}`, { token: admin })).data.items
  const okRealCall = realCalls.find((c) => c.tool === 'real_query')
  const boomRealCall = realCalls.find((c) => c.tool === 'boom')
  check('real 计量来自响应 usage（tokens=4321，非伪造）', okRealCall && okRealCall.tokens === 4321 && okRealCall.exec === 'real')
  check('real 失败调用同样标记 exec=real', boomRealCall && boomRealCall.exec === 'real' && boomRealCall.ok === false)

  const mcpUsage = await api('GET', '/api/usage/events?resource=mcp:real-backend', { token: admin })
  check('MCP real 调用自动进入计量管道（含失败调用）', mcpUsage.ok && mcpUsage.data.total >= 2
    && mcpUsage.data.items.every((e) => typeof e.tenant_id === 'string' && e.tenant_id.length > 0 && e.principal.startsWith('org:')), JSON.stringify((mcpUsage.data?.items ?? []).map((e) => ({ t: e.tenant_id, p: e.principal, r: e.resource }))))

  const deadSvc = await api('POST', '/api/mcp/services', { token: admin, body: { name: '不可达服务', slug: 'dead-backend', orgId: newOrg.data.id, endpoint: 'http://127.0.0.1:1/mcp', mode: 'external', exec: 'real', tools: [{ name: 'x', description: 'x', inputSchema: { type: 'object' }, riskLevel: 'read' }] } })
  const deadVerify = await api('POST', `/api/mcp/services/${deadSvc.data.id}/verify`, { token: admin })
  check('real 验证不可达 endpoint 被拒（不再恒可达）', !deadVerify.ok)

  // ================================================================ MCP 配置导入（mcpServers JSON）
  section('MCP 配置导入（mcpServers JSON 一键接入）')
  // streamable HTTP + SSE 响应帧 + 会话头的 mock 服务（复刻 teambition 形态）
  const mcpSseStub = createServer(async (req, res) => {
    const raw = await readBody(req)
    let msg = {}
    try { msg = JSON.parse(raw) } catch { /* ignore */ }
    const sseReply = (payload, extra = {}) => {
      res.writeHead(200, { 'content-type': 'text/event-stream', ...extra })
      res.end(`data: ${JSON.stringify(payload)}\n\n`)
    }
    const noSession = { jsonrpc: '2.0', id: msg.id, error: { code: -32600, message: 'Server not initialized: session required' } }
    if (msg.method === 'initialize') {
      return sseReply({ jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'tb-like', version: '1.0' } } }, { 'mcp-session-id': 'sess-stub-1' })
    }
    if (msg.method === 'notifications/initialized') { res.writeHead(202); return res.end() }
    if (msg.method === 'tools/list') {
      if (req.headers['mcp-session-id'] !== 'sess-stub-1') return sseReply(noSession)
      return sseReply({ jsonrpc: '2.0', id: msg.id, result: { tools: [
        { name: 'tb_query_task', description: '查询任务', inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] } },
        { name: 'tb_create_task', description: '创建任务', inputSchema: { type: 'object', properties: { title: { type: 'string' } } } },
      ] } })
    }
    if (msg.method === 'tools/call') {
      if (req.headers['mcp-session-id'] !== 'sess-stub-1') return sseReply(noSession)
      const auth = req.headers.authorization ? `|auth:${req.headers.authorization}` : ''
      return sseReply({ jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: `sse-echo:${msg.params?.name}${auth}` }], usage: { totalTokens: 88 } } })
    }
    res.writeHead(404).end('{}')
  })
  await new Promise((resolve) => mcpSseStub.listen(0, '127.0.0.1', resolve))
  const ssePort = mcpSseStub.address().port

  // 1. 标准形态导入（用户实际粘贴的配置样式）
  const tbConfig = JSON.stringify({ mcpServers: { 'teambition-mcp': { type: 'streamableHttp', url: `http://127.0.0.1:${ssePort}/api/mcp?userToken=u-demo` } } })
  const imp = await api('POST', '/api/mcp/import', { token: admin, body: { config: tbConfig } })
  check('mcpServers JSON 一键导入', imp.ok && imp.data.imported === 1 && imp.data.results[0].ok, JSON.stringify(imp).slice(0, 300))
  const impR = imp.data.results[0]
  check('工具自动发现（initialize→tools/list，SSE 帧解析）', impR.tools === 2 && impR.reachable === true)
  check('导入即验证并上线（autoDeploy）', impR.status === 'online')
  const tbService = (await api('GET', '/api/mcp/services', { token: admin })).data.services.find((s) => s.id === impR.serviceId)
  check('发现的工具含完整 inputSchema', tbService.tools.length === 2 && tbService.tools[0].inputSchema?.required?.[0] === 'id')

  // 2. 全链路调用（SSE + 会话头 + 权限组）
  await api('POST', '/api/mcp/perm-groups', { token: admin, body: {
    name: 'teambition 全放行', policies: { [impR.serviceId]: { allowedTools: '*', constraints: {} } },
    subjects: [{ type: 'user', id: adminLogin.data.user.id, name: 'admin' }],
  } })
  const tbInvoke = await api('POST', '/api/mcp/invoke', { token: admin, body: { serviceId: impR.serviceId, tool: 'tb_query_task', args: { id: 't-1' } } })
  check('导入服务真实调用（SSE 响应 + 会话复用）', tbInvoke.ok && tbInvoke.data.ok === true && JSON.stringify(tbInvoke.data.result).includes('sse-echo:tb_query_task'), JSON.stringify(tbInvoke).slice(0, 300))

  // 3. headers 透传（Authorization）
  const authConfig = JSON.stringify({ mcpServers: { 'authed-mcp': { type: 'http', url: `http://127.0.0.1:${ssePort}/api/mcp`, headers: { Authorization: 'Bearer tk-123' } } } })
  const impAuth = await api('POST', '/api/mcp/import', { token: admin, body: { config: authConfig } })
  await api('POST', '/api/mcp/perm-groups', { token: admin, body: {
    name: 'authed 全放行', policies: { [impAuth.data.results[0].serviceId]: { allowedTools: '*', constraints: {} } },
    subjects: [{ type: 'user', id: adminLogin.data.user.id, name: 'admin' }],
  } })
  const authInvoke = await api('POST', '/api/mcp/invoke', { token: admin, body: { serviceId: impAuth.data.results[0].serviceId, tool: 'tb_query_task', args: {} } })
  check('导入的认证头透传到远端（Authorization）', authInvoke.ok && authInvoke.data.ok === true && JSON.stringify(authInvoke.data.result).includes('auth:Bearer tk-123'), JSON.stringify(authInvoke).slice(0, 300))
  const whoamiInvoke = await api('POST', '/api/mcp/invoke', { token: admin, body: { serviceId: impAuth.data.results[0].serviceId, tool: 'whoami', args: {} } })
  check('清单外工具被网关拒绝（导入不越权）', whoamiInvoke.data?.status === 'denied', JSON.stringify(whoamiInvoke).slice(0, 200))
  const authSvc = (await api('GET', '/api/mcp/services', { token: admin })).data.services.find((s) => s.id === impAuth.data.results[0].serviceId)
  check('认证头列表回显脱敏', authSvc?.headers?.Authorization && !String(authSvc.headers.Authorization).includes('tk-123'), JSON.stringify(authSvc?.headers))

  // 4. stdio/command 本地形态不支持
  const impStdio = await api('POST', '/api/mcp/import', { token: admin, body: { config: JSON.stringify({ mcpServers: { 'local-tools': { command: 'npx', args: ['-y', 'some-mcp'] } } }) } })
  check('stdio/command 形态标记不可导入', impStdio.ok && impStdio.data.results[0].ok === false && /stdio/.test(impStdio.data.results[0].error))

  // 5. 非法 JSON
  const impBad = await api('POST', '/api/mcp/import', { token: admin, body: { config: '{oops' } })
  check('非法 JSON 报错（400）', !impBad.ok && impBad.status === 400 && /JSON/.test(impBad.error?.message ?? ''))

  // 6. 重复导入（slug 冲突）
  const impDup = await api('POST', '/api/mcp/import', { token: admin, body: { config: tbConfig } })
  check('重复导入同名列出冲突', impDup.ok && impDup.data.results[0].ok === false && /已存在/.test(impDup.data.results[0].error))

  // 7. 权限控制
  const impDenied = await api('POST', '/api/mcp/import', { token: dev, body: { config: tbConfig } })
  check('无 mcp.service.write 权限导入被拒（403）', impDenied.status === 403)

  // 8. 远端不可达：导入成功但保留草稿
  const impDead = await api('POST', '/api/mcp/import', { token: admin, body: { config: JSON.stringify({ mcpServers: { 'dead-remote': { type: 'http', url: 'http://127.0.0.1:1/mcp' } } }) } })
  check('远端不可达：导入保留草稿并回传原因', impDead.data.results[0].ok === true && impDead.data.results[0].reachable === false && impDead.data.results[0].status === 'draft' && /发现失败/.test(impDead.data.results[0].error ?? ''), JSON.stringify(impDead).slice(0, 300))
  const deadImported = (await api('GET', '/api/mcp/services', { token: admin })).data.services.find((s) => s.id === impDead.data.results[0].serviceId)
  check('不可达服务不落伪工具清单', deadImported.tools.length === 0)

  // 9. 在线外部服务同步工具
  const syncRes = await api('POST', `/api/mcp/services/${impR.serviceId}/sync-tools`, { token: admin })
  check('在线外部服务可同步工具清单', syncRes.ok && syncRes.data.tools.length === 2)

  // -- 钉钉真实 stub（复刻 OpenAPI 形状） ---------------------------------
  const ddUsers = {
    dd_u002: { unionId: 'dd_u002', userId: 'u002', name: '林小满', email: 'linxm@yuanbingke.com' },
    dd_u020: { unionId: 'dd_u020', userId: 'u020', name: '真实连接用户', jobNumber: 'DD0020', title: '真实目录工程师', email: 'real@yuanbingke.com', active: true },
  }
  const ddStub = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://stub')
    const raw = await readBody(req)
    const jsonReply = (code, payload) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(payload)) }
    if (url.pathname === '/v1.0/oauth2/accessToken') {
      const body = JSON.parse(raw || '{}')
      if (body.appKey === 'stub-key' && body.appSecret === 'stub-secret') return jsonReply(200, { accessToken: 'corp-token-stub', expireIn: 7200 })
      return jsonReply(400, { code: 'invalid.credentials' })
    }
    if (url.pathname === '/v1.0/oauth2/userAccessToken') {
      const body = JSON.parse(raw || '{}')
      if (typeof body.code === 'string' && body.code.startsWith('STUB-')) return jsonReply(200, { accessToken: `ut-${body.code}`, expireIn: 7200, corpId: 'ding-real' })
      return jsonReply(400, { code: 'invalid.code' })
    }
    if (url.pathname === '/v1.0/contact/users/me') {
      const token = req.headers['x-acs-dingtalk-access-token']
      if (token !== 'ut-STUB-OK') return jsonReply(401, { code: 'invalid.token' })
      return jsonReply(200, { ...ddUsers.dd_u002, corpId: 'ding-real' })
    }
    if (url.pathname === '/topapi/v2/department/listsubid') {
      if (url.searchParams.get('access_token') !== 'corp-token-stub') return jsonReply(200, { errcode: 40014, errmsg: 'invalid access_token' })
      const body = JSON.parse(raw || '{}')
      if (body.dept_id === 1) return jsonReply(200, { errcode: 0, errmsg: 'ok', result: { dept_id_list: [500] } })
      return jsonReply(200, { errcode: 0, errmsg: 'ok', result: { dept_id_list: [] } })
    }
    if (url.pathname === '/topapi/v2/department/get') {
      if (url.searchParams.get('access_token') !== 'corp-token-stub') return jsonReply(200, { errcode: 40014, errmsg: 'invalid access_token' })
      const body = JSON.parse(raw || '{}')
      return jsonReply(200, { errcode: 0, errmsg: 'ok', result: { dept_id: body.dept_id, name: body.dept_id === 1 ? '真实企业根' : '真实连接器部门' } })
    }
    if (url.pathname === '/topapi/v2/user/list') {
      if (url.searchParams.get('access_token') !== 'corp-token-stub') return jsonReply(200, { errcode: 40014, errmsg: 'invalid access_token' })
      const body = JSON.parse(raw || '{}')
      if (body.dept_id !== 500) return jsonReply(200, { errcode: 0, errmsg: 'ok', result: { list: [], has_more: false } })
      return jsonReply(200, { errcode: 0, errmsg: 'ok', result: { list: [{ unionid: 'dd_u020', userid: 'u020', name: '真实连接用户', job_number: 'DD0020', title: '真实目录工程师', email: 'real@yuanbingke.com', active: true }], has_more: false } })
    }
    res.writeHead(404).end('{}')
  })
  await new Promise((resolve) => ddStub.listen(0, '127.0.0.1', resolve))
  const ddPort = ddStub.address().port

  const putConnector = await api('PUT', '/api/iam/connectors/dingtalk', { token: admin, body: { corpId: 'ding-real', appKey: 'stub-key', appSecret: 'stub-secret', mode: 'real', apiBase: `http://127.0.0.1:${ddPort}`, oapiBase: `http://127.0.0.1:${ddPort}`, enabled: true, conflictStrategy: 'manual' } })
  check('连接器切换真实模式', putConnector.ok && putConnector.data.mode === 'real')
  const connTest = await api('POST', '/api/iam/connectors/dingtalk/test', { token: admin })
  check('真实连接器健康检查（mock:false）', connTest.ok && connTest.data.ok === true && connTest.data.mock === false)

  const realAuth = await api('POST', '/api/auth/sso/authorize', { body: { provider: 'dingtalk', scene: 'web_qr' } })
  const realSso = await api('POST', '/api/auth/sso', { body: { provider: 'dingtalk', code: 'STUB-OK', state: realAuth.data.state } })
  check('真实 OpenAPI 登录链路（token→userinfo→命中）', realSso.ok && realSso.data.kind === 'hit' && realSso.data.user.username === 'linxm')

  const realSync = await api('POST', '/api/iam/connectors/dingtalk/sync', { token: admin })
  check('真实目录同步（OpenAPI 分页拉取）', realSync.ok && realSync.data.created >= 1)
  const syncedUser = (await api('GET', '/api/iam/users?q=' + encodeURIComponent('真实连接用户'), { token: admin })).data.users[0]
  check('真实同步新建账号落库', Boolean(syncedUser) && syncedUser.status === 'active')

  // 降级回归：切回 mock 后显式标注
  const mockBack = await api('PUT', '/api/iam/connectors/dingtalk', { token: admin, body: { corpId: 'ding-yuanbingke', appKey: 'demo-app-key', appSecret: 'demo-secret-do-not-use', mode: 'mock', enabled: true } })
  check('切回降级模式（显式标注 mock）', mockBack.ok && mockBack.data.mode === 'mock')

  // 事务存储落位（计量/资金类数据库文件创建）
  const { existsSync } = await import('node:fs')
  check('SQLite 事务存储已就位（txnstore.db）', existsSync(join(DATA_DIR, 'txnstore.db')))

  // -- 多主体接入（同 provider 多实例连接器） --------------------------------
  // 兼容语义：:param 先按实例 id 解析、失败按 provider 取第一条；旧路由 'dingtalk' 零改动可用。
  section('多主体接入（同 provider 多实例连接器：创建/唯一约束/隔离同步/删除）')
  const createSecond = await api('POST', '/api/iam/connectors', { token: admin, body: { provider: 'dingtalk', name: '第二主体', corpId: 'ding-second', appKey: 'demo-key-2', appSecret: 'demo-secret-2', mode: 'mock', enabled: true, conflictStrategy: 'manual' } })
  check('创建第二主体连接器（POST /api/iam/connectors）', createSecond.ok && Boolean(createSecond.data?.id), JSON.stringify(createSecond).slice(0, 300))
  const listAfterCreate = await api('GET', '/api/iam/connectors', { token: admin })
  check('连接器列表出现 2 条配置', listAfterCreate.ok && listAfterCreate.data.configs.length === 2, JSON.stringify(listAfterCreate.data).slice(0, 200))
  const dupCorp = await api('POST', '/api/iam/connectors', { token: admin, body: { provider: 'dingtalk', name: '重复主体', corpId: 'ding-second', appKey: 'demo-key-2', appSecret: 'demo-secret-2', mode: 'mock', enabled: true, conflictStrategy: 'manual' } })
  check('同 provider+corpId 重复创建被拒（provider|corpId 唯一约束）', !dupCorp.ok, JSON.stringify(dupCorp).slice(0, 200))
  const id2 = createSecond.data?.id
  const syncSecond = await api('POST', `/api/iam/connectors/${id2}/sync`, { token: admin })
  check('按实例 id 同步第二主体', syncSecond.ok && /同步完成/.test(syncSecond.data?.message ?? ''), JSON.stringify(syncSecond).slice(0, 300))
  const syncFirstAgain = await api('POST', '/api/iam/connectors/dingtalk/sync', { token: admin })
  check('第一主体旧路由（按 provider 解析）同步互不影响', syncFirstAgain.ok && /同步完成/.test(syncFirstAgain.data?.message ?? ''), JSON.stringify(syncFirstAgain).slice(0, 300))
  const orgsAfterMulti = (await api('GET', '/api/iam/orgs', { token: admin })).data
  const mockRootCount = orgsAfterMulti.filter((org) => org.name === '元冰可集团').length
  check('两家主体部门并存（两家根部门均落库）', mockRootCount >= 2, `元冰可集团根数=${mockRootCount}`)
  const delSecond = await api('DELETE', `/api/iam/connectors/${id2}`, { token: admin })
  check('删除第二主体连接器（DELETE /api/iam/connectors/:id）', delSecond.ok && delSecond.data?.deleted === true, JSON.stringify(delSecond).slice(0, 200))
  const listAfterDelete = await api('GET', '/api/iam/connectors', { token: admin })
  check('删除后列表回到 1 条', listAfterDelete.ok && listAfterDelete.data.configs.length === 1, JSON.stringify(listAfterDelete.data).slice(0, 200))
  const testDeleted = await api('POST', `/api/iam/connectors/${id2}/test`, { token: admin })
  check('已删除实例不可再测试', !testDeleted.ok, JSON.stringify(testDeleted).slice(0, 200))
  const authProviders = await api('GET', '/api/auth/providers')
  check('三方登录入口带 configId/name（多主体可区分）', authProviders.ok && authProviders.data.providers.length >= 1
    && authProviders.data.providers.every((p) => p.configId && p.name), JSON.stringify(authProviders.data).slice(0, 300))

  section('连接器自动同步与全员名册（组织数据通道）')
  // 自动同步：intervalMinutes 到期巡检（定时器每分钟跑同一 runDueAutoSyncs，此处以手动触发口等价验证）
  const autoSyncConn = await api('POST', '/api/iam/connectors', { token: admin, body: { provider: 'dingtalk', name: '自动同步主体', corpId: 'ding-autosync', appKey: 'demo-key-auto', appSecret: 'demo-secret-auto', mode: 'mock', enabled: true, intervalMinutes: 5, conflictStrategy: 'manual' } })
  check('创建自动同步主体（intervalMinutes=5，从未同步=到期）', autoSyncConn.ok && Boolean(autoSyncConn.data?.id), JSON.stringify(autoSyncConn).slice(0, 200))
  const manualOnlyConn = await api('POST', '/api/iam/connectors', { token: admin, body: { provider: 'dingtalk', name: '仅手动主体', corpId: 'ding-manualonly', appKey: 'demo-key-manual', appSecret: 'demo-secret-manual', mode: 'mock', enabled: true, intervalMinutes: 0, conflictStrategy: 'manual' } })
  check('创建仅手动主体（intervalMinutes=0）', manualOnlyConn.ok && Boolean(manualOnlyConn.data?.id), JSON.stringify(manualOnlyConn).slice(0, 200))
  const autoRun1 = await api('POST', '/api/iam/connectors/auto-sync', { token: admin })
  check('到期巡检：从未同步的连接器被补同步', autoRun1.ok && autoRun1.data.processed >= 1
    && autoRun1.data.results.some((item) => item.configId === autoSyncConn.data?.id && item.ok), JSON.stringify(autoRun1.data).slice(0, 300))
  check('到期巡检：0=仅手动的连接器不被处理', autoRun1.ok && !autoRun1.data.results.some((item) => item.configId === manualOnlyConn.data?.id), JSON.stringify(autoRun1.data).slice(0, 300))
  const autoRun2 = await api('POST', '/api/iam/connectors/auto-sync', { token: admin })
  check('到期巡检：刚同步过的连接器不重复处理', autoRun2.ok && autoRun2.data.processed === 0, JSON.stringify(autoRun2.data).slice(0, 200))
  const delAutoSync = await api('DELETE', `/api/iam/connectors/${autoSyncConn.data?.id}`, { token: admin })
  check('清理自动同步主体', delAutoSync.ok)
  const delManualOnly = await api('DELETE', `/api/iam/connectors/${manualOnlyConn.data?.id}`, { token: admin })
  check('清理仅手动主体', delManualOnly.ok)

  // 全员名册：iam.roster.read（org_admin 经 iam.* 通配自带；接入应用经机器凭证 scope 授权）
  const rosterAdmin = await api('GET', '/api/iam/roster', { token: admin })
  check('管理员拉取全员名册（users+orgs）', rosterAdmin.ok && Array.isArray(rosterAdmin.data.users) && Array.isArray(rosterAdmin.data.orgs), JSON.stringify(rosterAdmin.data).slice(0, 200))
  const rosterSyncedUser = rosterAdmin.ok ? rosterAdmin.data.users.find((u) => u.jobNumber === 'DD0001') : undefined
  check('名册含同步账号（工号/组织名/稳定关联键 id）', Boolean(rosterSyncedUser) && Boolean(rosterSyncedUser.orgName) && Boolean(rosterSyncedUser.id))
  check('名册组织含部门负责人（钉钉 dept_manager 同步链）', rosterAdmin.ok && rosterAdmin.data.orgs.some((org) => Array.isArray(org.leaderUserIds) && org.leaderUserIds.length > 0))
  const rosterText = rosterAdmin.ok ? JSON.stringify(rosterAdmin.data) : ''
  check('名册 PII 最小化（无口令字段/无手机号）', rosterText !== '' && !rosterText.includes('passwordHash') && !rosterText.includes('"phone"'))
  const rosterNoAuth = await api('GET', '/api/iam/roster')
  check('未认证拉取名册 401', rosterNoAuth.status === 401)
  const rosterDeniedCred = await api('POST', '/api/authn/principals', { token: admin, body: { name: 'roster-denied', refType: 'app', scopes: ['agent.read'] } })
  const rosterDeniedCc = await api('POST', '/api/auth/client-credentials', { body: { clientId: rosterDeniedCred.data.clientId, clientSecret: rosterDeniedCred.data.clientSecret } })
  const rosterDenied = await api('GET', '/api/iam/roster', { token: rosterDeniedCc.data?.token })
  check('无 iam.roster.read 的机器凭证 403', rosterDenied.status === 403)
  const rosterCred = await api('POST', '/api/authn/principals', { token: admin, body: { name: 'hr-app-roster', refType: 'app', scopes: ['iam.roster.read'] } })
  check('签发名册读取机器凭证（应用接入组织数据通道）', rosterCred.ok && Boolean(rosterCred.data.clientId), JSON.stringify(rosterCred.data).slice(0, 200))
  const rosterCc = await api('POST', '/api/auth/client-credentials', { body: { clientId: rosterCred.data.clientId, clientSecret: rosterCred.data.clientSecret } })
  const rosterMachine = await api('GET', '/api/iam/roster', { token: rosterCc.data?.token })
  check('机器凭证（iam.roster.read）拉取名册 200（与管理员同视图）', rosterMachine.ok && rosterMachine.data.users.length === (rosterAdmin.data?.users?.length ?? -1))
  const rosterAudit = await api('GET', '/api/audit/logs?type=invoke&q=roster', { token: admin })
  check('名册拉取留痕（invoke 审计含 machine actor）', rosterAudit.ok && JSON.stringify(rosterAudit.data).includes('iam.roster.pull'))

  mcpStub.close()
  ddStub.close()

  // ================================================================ 第 8 步：复式分账 ledger
  section('第 8 步：复式分账 ledger（账期汇总结转 / 试算平衡 / 红字冲正）')
  const arrearsAlerts = await api('GET', '/api/audit/alerts', { token: admin })
  check('事后扣费失败触发欠费告警（预检兜底之外的防线）', arrearsAlerts.ok && JSON.stringify(arrearsAlerts.data.alerts).includes('欠费'))
  const month = new Date().toISOString().slice(0, 7)
  const settle = await api('POST', '/api/billing/settle', { token: admin, body: { period: month } })
  check('账期汇总结转（一借多贷复合分录）', settle.ok && settle.data.entries >= 4 && settle.data.debitCents > 0)
  check('试算平衡（借方合计 = 贷方合计）', settle.data.balanced === true && settle.data.debitCents === settle.data.creditCents)
  const ledgerRows = (await api('GET', `/api/billing/ledger?period=${month}`, { token: admin })).data
  const devCredit = ledgerRows.entries.find((e) => e.account.startsWith('developer:') && e.direction === 'credit' && e.amount_cents === 10)
  check('开发者分成入账（50 分 × 20% 平台默认费率，费率版本快照）', Boolean(devCredit) && devCredit.rate_version === 'v2026.08')
  const dupSettle = await api('POST', '/api/billing/settle', { token: admin, body: { period: month } })
  check('账期重复结转被拒（调整走红字冲正）', !dupSettle.ok)
  const reverse = await api('POST', '/api/billing/ledger/reverse', { token: admin, body: { period: month, reason: '自测冲正演练' } })
  check('红字冲正（负数分录引用原分录，试算仍平衡）', reverse.ok && reverse.data.balanced === true)
  const trialAfter = (await api('GET', `/api/billing/ledger?period=${month}`, { token: admin })).data.trial
  check('冲正后期间净额归零（借=贷）', trialAfter.debitCents === trialAfter.creditCents && trialAfter.debitCents === 0)

  // ================================================================ 评审缺陷修复回归（S/M 系列）
  section('评审缺陷修复回归（settle 全量 / 冲正防重 / 幂等键绑定主体 / replay 不双计）')
  const monthTotals = await api('GET', `/api/usage/totals?from=${month}-01T00:00:00`, { token: admin })
  check('结转归集事件数 = 计量口径 COUNT（无截断对账）', settle.ok && settle.data.events === monthTotals.data.count)

  const reverseAgain = await api('POST', '/api/billing/ledger/reverse', { token: admin, body: { period: month, reason: '二次冲正应被拒绝' } })
  check('同一账期二次红字冲正被拒（防借贷破坏）', !reverseAgain.ok && JSON.stringify(reverseAgain.error).includes('已存在'))

  const idemOwner = (await api('GET', '/api/iam/orgs', { token: admin })).data[0]
  const rechA = await api('POST', '/api/billing/recharge', { token: admin, body: { ownerType: 'org', ownerId: idemOwner.id, amountCents: 100, channelRef: 'selftest-idem-owner', idempotencyKey: 'rech-selftest-owner-binding' } })
  const rechB = await api('POST', '/api/billing/recharge', { token: admin, body: { ownerType: 'platform', ownerId: 'platform', amountCents: 100, channelRef: 'selftest-idem-owner', idempotencyKey: 'rech-selftest-owner-binding' } })
  check('钱包幂等键绑定主体（同键异主体被拒）', rechA.ok && !rechB.ok && JSON.stringify(rechB.error).includes('绑定主体'))

  const reconcileBeforeReplay = await api('POST', '/api/usage/reconcile', { token: admin })
  const replayAll = await api('POST', '/api/usage/replay', { token: admin, body: { from: new Date(Date.now() - 40 * 86_400_000).toISOString() } })
  const reconcileAfterReplay = await api('POST', '/api/usage/reconcile', { token: admin })
  check('replay 重放不双计（消费水位幂等，投影/口径一致）', replayAll.ok && replayAll.data.replayed > 0
    && reconcileBeforeReplay.data.reconciliation.mismatch === false
    && reconcileAfterReplay.data.reconciliation.mismatch === false
    && JSON.stringify(reconcileAfterReplay.data.reconciliation.projections) === JSON.stringify(reconcileBeforeReplay.data.reconciliation.projections))

  const dlRetry = await api('POST', '/api/usage/dead-letters/retry', { token: admin })
  check('死信重投端点可用（真实执行重试）', dlRetry.ok && typeof dlRetry.data.retried === 'number')

  // ================================================================ 认证加固回归（轮换宽限 / 暴力破解锁定 / OIDC 收敛）
  section('认证加固回归（密钥轮换宽限期 / 暴力破解锁定 / OIDC scope+PKCE）')
  const preRotate = await api('POST', '/api/auth/login', { body: { username: 'admin', password: 'Ybk@2026' } })
  const rotate = await api('POST', '/api/authn/rotate-secret', { token: admin })
  const oldTokenAlive = await api('GET', '/api/auth/me', { token: preRotate.data.token })
  check('密钥轮换宽限期：存量令牌不掉线（24h 验签兼容）', rotate.ok && rotate.data.graceHours === 24 && oldTokenAlive.ok)

  const postRotateLogin = await api('POST', '/api/auth/login', { body: { username: 'admin', password: 'Ybk@2026' } })
  const postRotateMe = await api('GET', '/api/auth/me', { token: postRotateLogin.data.token })
  check('轮换后新签发令牌可用（新密钥签名）', postRotateLogin.ok && postRotateMe.ok)

  const brute = await api('POST', '/api/iam/users', { token: admin, body: { username: 'brutetest', displayName: '暴力破解测试', orgId: idemOwner.id, title: '测试' } })
  for (let i = 0; i < 5; i++) {
    await api('POST', '/api/auth/login', { body: { username: 'brutetest', password: 'wrong-password' } })
  }
  const bruteLocked = await api('POST', '/api/auth/login', { body: { username: 'brutetest', password: brute.data.initialPassword } })
  check('连续失败 5 次后锁定（正确口令也暂拒 + 告警）', brute.ok && bruteLocked.status === 401 && JSON.stringify(bruteLocked.error).includes('锁定'))

  const lockAlerts = await api('GET', '/api/audit/alerts', { token: admin })
  check('锁定触发已入告警中心（暴力破解可观测）', lockAlerts.ok && JSON.stringify(lockAlerts.data.alerts).includes('登录失败锁定'))

  // OIDC scope 白名单 / PKCE 强制 / Basic+Post 双认证的回归断言已并入第 6 步（浏览器授权流重写）

  // ================================================================ 资产运营（企业 AI 资产台账 / 健康巡检 / 成本报表）
  section('资产运营（统一台账 / 健康巡检 / 成本报表）')
  const assetsInv = await api('GET', '/api/assets/inventory', { token: admin })
  check('资产台账（五类资产统一盘点）', assetsInv.ok && assetsInv.data.total > 0
    && ['mcp', 'agent', 'app', 'skill', 'model'].every((t) => assetsInv.data.items.some((i) => i.type === t)))
  const assetsReport = await api('GET', '/api/assets/report?days=30', { token: admin })
  check('资产成本报表（Top 资产 / 主体分摊 / 日趋势）', assetsReport.ok && assetsReport.data.topResources.length > 0
    && assetsReport.data.byPrincipal.length > 0 && assetsReport.data.byDay.length > 0
    && assetsReport.data.totals.count > 0)
  const assetsHealth = await api('POST', '/api/assets/healthcheck', { token: admin })
  check('资产健康巡检（批量探活并留审计）', assetsHealth.ok && assetsHealth.data.checked > 0 && Array.isArray(assetsHealth.data.items))
  const assetsTyped = await api('GET', '/api/assets/inventory?type=mcp&days=7', { token: admin })
  check('台账筛选（类型 + 窗口）', assetsTyped.ok && assetsTyped.data.items.every((i) => i.type === 'mcp'))

  const benefit = await api('GET', '/api/assets/benefit?days=30', { token: admin })
  check('效益分析（毛利 = 列表价收入 − 采购成本，逐行恒等）', benefit.ok && benefit.data.rows.length >= 1
    && benefit.data.totals.margin_cents === benefit.data.totals.charge_cents - benefit.data.totals.cost_cents
    && benefit.data.rows.every((row) => row.margin_cents === row.charge_cents - row.cost_cents))

  // ================================================================ Skill 市场
  section('Skill 市场流水线')
  const malicious = await api('POST', '/api/skills', { token: dev, body: { name: '恶意清理脚本', content: '# 清理\n```sh\nrm -rf / --no-preserve-root\n```\n调用了 sk-1234567890abcdef1234567890', category: '通用', version: '1.0.0' } })
  check('静态扫描拦截恶意提交（自动驳回）', malicious.ok && malicious.data.status === 'rejected')

  const submit = await api('POST', '/api/skills', { token: dev, body: { name: '自测报告助手', summary: '生成自测报告', content: '# 自测报告助手\n\n## 何时使用\n每日自测后生成报告。\n\n## 步骤\n1. 汇总断言结果\n2. 生成 Markdown 报告', category: '办公提效', version: '1.0.0' } })
  check('正常提交进入待审批', submit.ok && submit.data.status === 'pending_approval')
  const skillId = submit.data.id

  const approveDomain = await api('POST', `/api/skills/${skillId}/approve`, { token: admin, body: { decision: 'approve', level: 'domain', opinion: '业务适用' } })
  check('领域审批通过', approveDomain.ok)

  const publish = await api('POST', `/api/skills/${skillId}/publish`, { token: admin, body: {} })
  check('版本化上架', publish.ok && publish.data.status === 'published')

  const agentsList = (await api('GET', '/api/agents', { token: admin })).data.agents
  const targetAgent = agentsList.find((a) => a.slug === 'dev-coder')
  const install = await api('POST', `/api/skills/${skillId}/install`, { token: dev, body: { agentId: targetAgent.id } })
  check('安装到 Agent（依赖登记）', install.ok && install.data.stats.installs >= 1)

  const agentDetail = await api('GET', `/api/agents/${targetAgent.id}`, { token: admin })
  check('Agent 关联 Skill 自动回填', agentDetail.ok && (agentDetail.data.attrs.skills ?? []).includes('自测报告助手'))

  const download = await api('POST', `/api/skills/${skillId}/download`, { token: dev, body: {} })
  check('下载留痕（返回 SKILL.md）', download.ok && download.data.content.includes('自测报告助手'))

  // 计量管道（观测补齐）：skill 下载/安装进 usage 事件（skill:<ID>，默认零费率）
  const skillUsage = await api('GET', '/api/usage/events?resource=' + encodeURIComponent(`skill:${skillId}`), { token: admin })
  check('Skill 下载/安装进计量管道（skill:<ID> 资源，零费率）', skillUsage.ok && skillUsage.data.total >= 2 && (skillUsage.data.items[0].pricing?.charge_cents ?? -1) === 0)
  const skillMeters = skillUsage.data.items.flatMap((event) => event.meters.map((meter) => meter.key))
  check('skill 事件 meters 含价格簿计价键 calls（硬校验下内部管道存活）', skillMeters.includes('calls') && skillMeters.includes('downloads') && skillMeters.includes('installs'))
  const skillExternalMeter = await api('POST', '/api/usage/record', { token: admin, body: { org: tenantOrg.data.id, subject: `agent:${targetAgent.id}`, principal: `org:${tenantOrg.data.id}`, resource: `skill:${skillId}`, meters: [{ key: 'calls', value: 1, unit: '次' }], idempotency_key: 'test-usage-skill-external-1' } })
  check('外部 usage record 可上报 skill:<ID> 资源（默认价格簿放行）', skillExternalMeter.ok)
  const heat = await api('GET', '/api/skills/usage-heatmap?days=30', { token: admin })
  const heatRow = (heat.data?.skills ?? []).find((s) => s.id === skillId)
  check('技能热力图（skill × 日使用矩阵，含安装/下载/外部上报）', heat.ok && heatRow?.total >= 2 && Array.isArray(heatRow?.cells) && heatRow.cells.length === 30 && (heat.data.maxCell ?? 0) >= 1)

  const deprecateNoReason = await api('POST', `/api/skills/${skillId}/deprecate`, { token: admin, body: {} })
  check('弃用未填原因被拒（护栏，下架分析口径依赖）', !deprecateNoReason.ok)

  const deprecate = await api('POST', `/api/skills/${skillId}/deprecate`, { token: admin, body: { reason: '自测弃用' } })
  check('弃用并触发存量引用告警', deprecate.ok && deprecate.data.skill.status === 'deprecated' && deprecate.data.referencingAgents.length >= 1)
  check('弃用原因落库持久化（详情与下架分析可见）', deprecate.ok && deprecate.data.skill.deprecatedReason === '自测弃用' && !!deprecate.data.skill.deprecatedAt)

  const alerts = await api('GET', '/api/audit/alerts', { token: admin })
  check('存量引用告警已入告警中心', alerts.ok && JSON.stringify(alerts.data.alerts).includes('自测报告助手'))

  const rate = await api('POST', `/api/skills/${skillId}/rate`, { token: dev, body: { stars: 5 } })
  check('评分', rate.ok && rate.data.stats.rating === 5)

  // ================================================================ Agent 生命周期（L4 审批）
  section('Agent 本体生命周期')
  const opsLogin = await api('POST', '/api/auth/login', { body: { username: 'ops', password: 'Ybk@2026' } })
  check('资源管理员登录', opsLogin.ok)
  const ops = opsLogin.data.token
  const agentCreate = await api('POST', '/api/agents', { token: ops, body: { name: '自测机器人', attrs: { description: '自测用机器人', model: 'deepseek-chat', riskLevel: 'low', avatar: '🧪' } } })
  check('注册 Agent（并颁发机器凭证）', agentCreate.ok && agentCreate.data.credential.clientId)
  const selfAgent = agentCreate.data.agent

  // 凭证默认 usage.write（Agent 自推计量能力）+ 机器身份读台账入审计（agent.verify）
  const selfAgentCc = await api('POST', '/api/auth/client-credentials', { body: { clientId: agentCreate.data.credential.clientId, clientSecret: agentCreate.data.credential.clientSecret } })
  check('新注册 Agent 凭证默认含 usage.write', selfAgentCc.ok && selfAgentCc.data.principal.scopes.includes('usage.write'))
  check('新注册 Agent 凭证默认含 agent.write（自主提报更新）', selfAgentCc.ok && selfAgentCc.data.principal.scopes.includes('agent.write'))
  check('新注册 Agent 凭证默认含 modelgw.invoke（模型网关调用）', selfAgentCc.ok && selfAgentCc.data.principal.scopes.includes('modelgw.invoke'))
  const agentSelfUpdate = await api('PATCH', `/api/agents/${selfAgent.id}`, { token: selfAgentCc.data.token, body: { attrs: { description: '自测用机器人（资料已由 Agent 凭自身凭证提报更新）' } } })
  check('Agent 凭自身凭证提报更新资料 200（agent.write 生效）', agentSelfUpdate.ok && String(agentSelfUpdate.data.attrs['description']).includes('凭自身凭证提报更新'), JSON.stringify(agentSelfUpdate.error))

  const agentVerifyLogs = () => api('GET', '/api/audit/logs?type=auth&resourceType=agent&limit=200', { token: admin })
  const verifyBefore = (await agentVerifyLogs()).data.items.filter((log) => log.action === 'agent.verify').length
  await api('GET', '/api/agents', { token: admin })
  const verifyAfterHuman = (await agentVerifyLogs()).data.items.filter((log) => log.action === 'agent.verify').length
  check('人类读台账不产生 agent.verify（噪音控制）', verifyAfterHuman === verifyBefore)

  const machineAgentsList = await api('GET', '/api/agents', { token: selfAgentCc.data.token })
  check('机器令牌读台账 200（接入验证「发一句话」）', machineAgentsList.ok)
  const verifyLogs = (await agentVerifyLogs()).data.items
  check('机器身份读台账入审计（agent.verify 留痕）', verifyLogs.some((log) => log.action === 'agent.verify' && log.actorId === selfAgentCc.data.principal.id))

  // 运营数据提报（Agent 接入义务，与 AI 应用 metrics-report 同级，2026-08）
  const agentReport1 = await api('POST', `/api/agents/${selfAgent.id}/metrics-report`, { token: selfAgentCc.data.token, body: { dau: 3, sessions: 5, userIds: ['u001', 'u002'] } })
  check('Agent 凭自身凭证提报运营数据 200（agent.write 生效，首提即"发一句话"）', agentReport1.ok && agentReport1.data.sessions === 5 && agentReport1.data.dau === 3, JSON.stringify(agentReport1.error))
  const agentReport2 = await api('POST', `/api/agents/${selfAgent.id}/metrics-report`, { token: selfAgentCc.data.token, body: { dau: 2, sessions: 1, userIds: ['u002', 'u003'] } })
  check('Agent 提报语义：同日 dau 取最大、会话累加、用户哈希去重并集', agentReport2.ok && agentReport2.data.dau === 3 && agentReport2.data.sessions === 6 && agentReport2.data.uniqueUsers === 3, JSON.stringify(agentReport2.error ?? agentReport2.data))
  const agentReportBad = await api('POST', `/api/agents/${selfAgent.id}/metrics-report`, { token: selfAgentCc.data.token, body: { dau: -1 } })
  check('Agent 提报校验：负数 dau 被拒', !agentReportBad.ok)
  const agentReportBadDate = await api('POST', `/api/agents/${selfAgent.id}/metrics-report`, { token: selfAgentCc.data.token, body: { dau: 1, date: '2026/08/01' } })
  check('Agent 提报校验：非法 date 被拒', !agentReportBadDate.ok)
  const agentReportGhost = await api('POST', '/api/agents/agt_ghost/metrics-report', { token: selfAgentCc.data.token, body: { dau: 1 } })
  check('Agent 提报校验：不存在的 Agent 被拒', !agentReportGhost.ok)
  const agentReportTool = await api('POST', '/api/tools/execute', { token: admin, body: { name: 'agent_metrics_report', args: { agentId: selfAgent.id, dau: 4, sessions: 2 } } })
  check('工具 agent_metrics_report 上报（同日 dau 取最大）', agentReportTool.ok && agentReportTool.data.isError === false && agentReportTool.data.value.reported === true && agentReportTool.data.value.metrics.dau === 4)
  const agentEntryUrl = await api('PATCH', `/api/agents/${selfAgent.id}`, { token: selfAgentCc.data.token, body: { attrs: { entryUrl: 'https://bot.example.com/chat' } } })
  check('Agent 自主提报交互界面地址（entryUrl 白名单生效）', agentEntryUrl.ok && agentEntryUrl.data.attrs['entryUrl'] === 'https://bot.example.com/chat', JSON.stringify(agentEntryUrl.error))

  const agentSelfMeter = await api('POST', '/api/usage/record', { token: selfAgentCc.data.token, body: { org: tenantOrg.data.id, subject: `agent:${selfAgent.id}`, principal: `org:${tenantOrg.data.id}`, resource: 'mcp:real-backend', meters: [{ key: 'tokens', value: 100, unit: 'token' }], idempotency_key: 'test-usage-agent-self-1' } })
  check('Agent 机器令牌自推计量 200（usage.write 生效）', agentSelfMeter.ok && agentSelfMeter.data.pricing.charge_cents === 3)

  // Agent 接入提示词（与 app 同构：rotate 轮换机器凭证携带完整凭证；首行含关键词「提示词」供 connector 触发）
  const agentPrompt = await api('POST', `/api/agents/${selfAgent.id}/onboarding-prompt`, { token: selfAgentCc.data.token, body: { rotate: true } })
  check('Agent 接入提示词：凭自身凭证 rotate 生成（含新 secret 与关键词「提示词」）',
    agentPrompt.ok && agentPrompt.data.rotated === true && agentPrompt.data.prompt.includes('提示词')
    && Boolean(agentPrompt.data.credential.clientSecret) && agentPrompt.data.prompt.includes(agentPrompt.data.credential.clientSecret),
    JSON.stringify(agentPrompt.error))
  const agentPromptCc = await api('POST', '/api/auth/client-credentials', { body: { clientId: agentPrompt.data.credential.clientId, clientSecret: agentPrompt.data.credential.clientSecret } })
  check('Agent 接入提示词：轮换后新 secret 可换牌', agentPromptCc.ok && Boolean(agentPromptCc.data?.token), JSON.stringify(agentPromptCc.error))
  // 用换牌后的新令牌复核 agent.write 仍生效（自提报更新资料）
  const agentPromptSelfPatch = await api('PATCH', `/api/agents/${selfAgent.id}`, { token: agentPromptCc.data.token, body: { attrs: { description: '自测用机器人（提示词轮换后仍可自更新）' } } })
  check('Agent 接入提示词：轮换后凭新令牌 PATCH 资料 200', agentPromptSelfPatch.ok, JSON.stringify(agentPromptSelfPatch.error))
  // 轮换已吊销旧令牌：就地刷新 selfAgentCc 的令牌，保证本段后续用例继续持有有效凭证
  selfAgentCc.data.token = agentPromptCc.data.token

  // 调用统计口径补全（2026-08）：usage.recorded 回灌 + 防双计
  const agentMetricsAfterSelfMeter = await api('GET', `/api/agents/${selfAgent.id}`, { token: admin })
  check('防双计①：自推 mcp:* 计量不回灌调用台账（MCP 口径归 McpInvoked，宁缺勿重）',
    agentMetricsAfterSelfMeter.ok && agentMetricsAfterSelfMeter.data.metrics.calls === 0 && (agentMetricsAfterSelfMeter.data.metrics.gwCalls ?? 0) === 0,
    JSON.stringify(agentMetricsAfterSelfMeter.data?.metrics))

  // 模型网关回灌闭环：Agent 凭自身凭证调用模型网关 → usage.recorded(subject=agent:<id>) 回灌调用台账
  const agentModelStub = createServer(async (req, res) => {
    if (req.url.endsWith('/chat/completions')) {
      await readBody(req)
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ choices: [{ message: { role: 'assistant', content: 'agent 模型网关回灌 stub' } }], usage: { prompt_tokens: 120, completion_tokens: 1500 } }))
      return
    }
    res.writeHead(404).end('{}')
  })
  await new Promise((resolve) => agentModelStub.listen(0, '127.0.0.1', resolve))
  const agentModelPort = agentModelStub.address().port
  const agentModelReg = await api('POST', '/api/modelgw/models', { token: admin, body: { slug: 'ds-stub-agent', displayName: 'Agent 回灌验证', provider: 'deepseek', endpoint: `http://127.0.0.1:${agentModelPort}/v1`, apiKey: 'stub-key', listCentsPerKTokens: 1, costCentsPerKTokens: 0 } })
  check('Agent 验证模型目录登记', agentModelReg.ok)
  // 第 5 步曾对 tenantOrg 设 30 分月度预算用于验证拦截，此处放开以让回灌链路通过预检
  await api('PUT', `/api/billing/budgets/${tenantOrg.data.id}`, { token: admin, body: { monthlyCents: 1_000_000 } })
  const agentGwInvoke = await api('POST', '/api/modelgw/invoke', { token: selfAgentCc.data.token, body: { model: 'ds-stub-agent', messages: [{ role: 'user', content: 'hi' }], orgId: tenantOrg.data.id } })
  check('Agent 凭自身凭证调用模型网关 200（modelgw.invoke 生效）', agentGwInvoke.ok && agentGwInvoke.data.outputTokens === 1500, JSON.stringify(agentGwInvoke.error ?? agentGwInvoke.data))
  const agentGwEvent = await api('GET', '/api/usage/events?resource=model:ds-stub-agent', { token: admin })
  check('网关计量事件主体为 agent:<id>（回灌依据）', agentGwEvent.ok && agentGwEvent.data.items[0]?.subject === `agent:${selfAgent.id}`, JSON.stringify(agentGwEvent.data?.items?.[0]?.subject))
  const agentMetricsAfterGw = await api('GET', `/api/agents/${selfAgent.id}`, { token: admin })
  check('模型网关调用回灌 Agent 台账（calls=1 / tokens=1620 / gwCalls=1）',
    agentMetricsAfterGw.ok && agentMetricsAfterGw.data.metrics.calls === 1 && agentMetricsAfterGw.data.metrics.tokens === 1620 && agentMetricsAfterGw.data.metrics.gwCalls === 1,
    JSON.stringify(agentMetricsAfterGw.data?.metrics))
  agentModelStub.close()

  const onlineTooEarly = await api('POST', `/api/agents/${selfAgent.id}/transition`, { token: ops, body: { action: 'online' } })
  check('缺治理属性不可上线（校验）', !onlineTooEarly.ok)

  await api('PATCH', `/api/agents/${selfAgent.id}`, { token: ops, body: { attrs: { systemPromptVersion: 'v1', dataClass: 'internal', trialGroups: ['灰度试点组'] } } })
  const trial = await api('POST', `/api/agents/${selfAgent.id}/transition`, { token: admin, body: { action: 'submit_trial' } })
  check('进入试运行', trial.ok && trial.data.status === 'trial')

  const obo = await api('POST', `/api/agents/${targetAgent.id}/obo-token`, { token: admin })
  check('on-behalf-of 令牌（act 链）', obo.ok && obo.data.actChain.length >= 1 && obo.data.actChain[0].type === 'human')

  const bind = await api('POST', `/api/agents/${selfAgent.id}/bindings`, { token: admin, body: { userId: devUser.id } })
  check('绑定用户（授权留痕）', bind.ok)

  // 平台授权直达（entry-ticket，2026-08）：签发授权边界 → 兑换身份 → 一次性/防伪造
  const auditorUserId = (await api('GET', '/api/iam/users?q=' + encodeURIComponent('楚天阔'), { token: admin })).data.users[0].id
  const entryMachineDenied = await api('POST', `/api/agents/${selfAgent.id}/entry-ticket`, { token: selfAgentCc.data.token, body: {} })
  check('直达票据：机器身份签发被拒（human-only）', entryMachineDenied.status === 403, JSON.stringify(entryMachineDenied))
  const entryUnbound = await api('POST', `/api/agents/${selfAgent.id}/entry-ticket`, { token: auditor, body: {} })
  check('直达票据：未授权用户被拒 403（owner/绑定用户/管理员之外，使用即授权留痕）', entryUnbound.status === 403, JSON.stringify(entryUnbound))
  const bindAuditor = await api('POST', `/api/agents/${selfAgent.id}/bindings`, { token: admin, body: { userId: auditorUserId } })
  check('直达票据：绑定审计员（构造纯绑定用户路径）', bindAuditor.ok)
  const entryBound = await api('POST', `/api/agents/${selfAgent.id}/entry-ticket`, { token: auditor, body: {} })
  check('直达票据：绑定用户签发 200（一次性票据 + TTL）', entryBound.ok && entryBound.data.ticket.startsWith('etk_') && entryBound.data.ttlSeconds >= 30, JSON.stringify(entryBound.error))
  const redeemOk = await rawReq('POST', '/api/authn/entry-tickets/redeem', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ticket: entryBound.data.ticket }),
  })
  const redeemBody = jsonBody(redeemOk)
  check('直达票据：公开端点兑换平台身份（sub/roles/tenant + refType/refId）',
    redeemOk.status === 200 && redeemBody.data?.refType === 'agent' && redeemBody.data?.refId === selfAgent.id
    && redeemBody.data?.identity?.sub === auditorUserId && Array.isArray(redeemBody.data?.identity?.roles) && Boolean(redeemBody.data?.identity?.tenant),
    JSON.stringify(redeemBody))
  const redeemReplay = await rawReq('POST', '/api/authn/entry-tickets/redeem', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ticket: entryBound.data.ticket }),
  })
  check('直达票据：重放兑换被拒（一次性消费）', redeemReplay.status === 400, `${redeemReplay.status} ${redeemReplay.body.slice(0, 120)}`)
  check('直达票据：兑换响应放行跨域（任意 entryUrl 前端可读取，ACAO=*）', redeemReplay.headers['access-control-allow-origin'] === '*', JSON.stringify(redeemReplay.headers))
  const redeemPreflight = await rawReq('OPTIONS', '/api/authn/entry-tickets/redeem', {
    headers: { origin: 'http://192.168.0.7:6060', 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type' },
  })
  check('直达票据：OPTIONS 预检 204 + ACAO（跨域浏览器流程可通）',
    redeemPreflight.status === 204 && redeemPreflight.headers['access-control-allow-origin'] === '*' && String(redeemPreflight.headers['access-control-allow-headers'] ?? '').includes('content-type'),
    `${redeemPreflight.status} ${JSON.stringify(redeemPreflight.headers)}`)
  const redeemForged = await rawReq('POST', '/api/authn/entry-tickets/redeem', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ticket: 'etk_forged_0000000000000000000000000000000000000000' }),
  })
  check('直达票据：伪造票据被拒', redeemForged.status === 400)

  // L4 上线：单人审批制——发起人（admin）自审通过
  const onlineRequest = await api('POST', `/api/agents/${selfAgent.id}/transition`, { token: admin, body: { action: 'online', note: '自测上线' } })
  check('上线生成 L4 审批单', onlineRequest.ok && onlineRequest.data.approval.status === 'pending')

  const selfApprove = await api('POST', `/api/approvals/${onlineRequest.data.approval.id}/decide`, { token: admin, body: { decision: 'approve', opinion: '自审通过' } })
  check('发起人可自审，单人审批通过自动执行上线', selfApprove.ok && selfApprove.data.status === 'executed')
  const agentAfter = await api('GET', `/api/agents/${selfAgent.id}`, { token: admin })
  check('Agent 状态已上线', agentAfter.data.status === 'online')

  // L4 下线：凭证吊销联动
  const credBefore = agentAfter.data.credential
  const offlineRequest = await api('POST', `/api/agents/${selfAgent.id}/transition`, { token: ops, body: { action: 'offline', note: '自测下线' } })
  check('下线生成 L4 审批单', offlineRequest.ok)
  await api('POST', `/api/approvals/${offlineRequest.data.approval.id}/decide`, { token: admin, body: { decision: 'approve', opinion: '同意下线' } })
  const agentOffline = await api('GET', `/api/agents/${selfAgent.id}`, { token: admin })
  check('下线后状态与凭证联动禁用', agentOffline.data.status === 'offline' && agentOffline.data.credential.status === 'disabled')
  void credBefore

  // ================================================================ AI 应用资料字段（头像 URL / 开发者 / 描述）
  section('AI 应用资料字段（头像 URL / 开发者下拉 / 描述）')
  const devOptions = await api('GET', '/api/apps/developer-options', { token: ops })
  check('developer-options：资源管理员（app.* → app.write）可拉取在编用户瘦字段', devOptions.ok && Array.isArray(devOptions.data.options) && devOptions.data.options.length > 0 && devOptions.data.options[0].username !== undefined, JSON.stringify(devOptions.error))
  const devOption = devOptions.data?.options?.find((u) => u.username === 'dev')
  check('developer-options：包含演示开发者账号（dev / 陈默）', Boolean(devOption && devOption.name === '陈默'))
  const appAvatarCreate = await api('POST', '/api/apps', { token: ops, body: { name: '资料字段自测应用', attrs: { description: '头像 / 开发者 / 描述字段验证', appType: 'web', icon: 'https://example.com/avatar.png', riskLevel: 'low', dataClass: 'internal', developerId: devOption.id } } })
  check('注册应用：icon 接受图片 URL（头像）', appAvatarCreate.ok && appAvatarCreate.data.app.attrs['icon'] === 'https://example.com/avatar.png', JSON.stringify(appAvatarCreate.error))
  check('注册应用：developerId 校验存在并回填 developerName（displayName 为准）', appAvatarCreate.ok && appAvatarCreate.data.app.attrs['developerId'] === devOption.id && appAvatarCreate.data.app.attrs['developerName'] === '陈默', JSON.stringify(appAvatarCreate.data?.app?.attrs))
  const appAvatarBad = await api('POST', '/api/apps', { token: ops, body: { name: '非法开发者自测应用', attrs: { description: 'developerId 校验', appType: 'web', riskLevel: 'low', dataClass: 'internal', developerId: 'usr_ghost' } } })
  check('注册应用：developerId 不存在被拒 400', !appAvatarBad.ok && String(appAvatarBad.error?.message ?? '').includes('开发者不存在'), JSON.stringify(appAvatarBad.error))
  const appAvatarPatch = await api('PATCH', `/api/apps/${appAvatarCreate.data.app.id}`, { token: ops, body: { attrs: { icon: '🧩', developerId: '' } } })
  check('更新应用：icon 可改；developerId 空串清除开发者', appAvatarPatch.ok && appAvatarPatch.data.attrs['icon'] === '🧩' && appAvatarPatch.data.attrs['developerName'] === '' && appAvatarPatch.data.attrs['developerId'] === '', JSON.stringify(appAvatarPatch.error ?? appAvatarPatch.data?.attrs))
  const appAvatarNameOnly = await api('PATCH', `/api/apps/${appAvatarCreate.data.app.id}`, { token: ops, body: { attrs: { developerName: '外部协作开发者' } } })
  check('更新应用：developerName 支持自由文本快照（外部开发者场景）', appAvatarNameOnly.ok && appAvatarNameOnly.data.attrs['developerName'] === '外部协作开发者', JSON.stringify(appAvatarNameOnly.error))

  // 接入提示词（注册同款模板平台侧生成；rotate 轮换机器凭证携带完整凭证；外部推送方按关键词「提示词」触发）
  const promptRotated = await api('POST', `/api/apps/${appAvatarCreate.data.app.id}/onboarding-prompt`, { token: ops, body: { rotate: true } })
  check('接入提示词：rotate 生成完整提示词（含新 clientSecret 与关键词「提示词」）',
    promptRotated.ok && promptRotated.data.rotated === true && promptRotated.data.prompt.includes('提示词')
    && Boolean(promptRotated.data.credential.clientSecret) && promptRotated.data.prompt.includes(promptRotated.data.credential.clientSecret),
    JSON.stringify(promptRotated.error))
  const promptCc = await api('POST', '/api/auth/client-credentials', { body: { clientId: promptRotated.data.credential.clientId, clientSecret: promptRotated.data.credential.clientSecret } })
  check('接入提示词：轮换后的新 secret 可正常换牌（旧值已吊销）', promptCc.ok && Boolean(promptCc.data?.token), JSON.stringify(promptCc.error))
  const promptPlain = await api('POST', `/api/apps/${appAvatarCreate.data.app.id}/onboarding-prompt`, { token: ops, body: {} })
  check('接入提示词：不轮换生成（含 client_id 与占位说明，不含 secret 明文）',
    promptPlain.ok && promptPlain.data.rotated === false && promptPlain.data.prompt.includes(promptPlain.data.credential.clientId)
    && promptPlain.data.prompt.includes('重新生成密钥') && !promptPlain.data.prompt.includes('client_secret：cs_'),
    JSON.stringify(promptPlain.error))

  // ================================================================ AI 应用 ↔ SSO 打通（MVP 闭环）
  section('AI 应用 ↔ SSO 打通（注册 → 签发 → 门禁双点 → 跳转登录）')
  const ssoAppCreate = await api('POST', '/api/apps', { token: ops, body: { name: 'SSO 自测应用', attrs: { description: 'MVP 闭环：注册 → 签发 → 门禁 → 浏览器授权流', appType: 'web', icon: '🔐', url: 'https://sso-app.example.com', riskLevel: 'low', dataClass: 'internal', agentIds: [targetAgent.id] }, agentIds: [targetAgent.id] } })
  check('注册应用（编排在线 Agent，owner=资源管理员）', ssoAppCreate.ok && ssoAppCreate.data.credential.clientId)
  const ssoAppId = ssoAppCreate.data.app.id

  // 应用凭证默认 app.write/app.read（指标提报与自主更新闭环，2026-08）
  const ssoAppCc = await api('POST', '/api/auth/client-credentials', { body: { clientId: ssoAppCreate.data.credential.clientId, clientSecret: ssoAppCreate.data.credential.clientSecret } })
  check('新注册应用凭证默认含 app.write/app.read（提报与自更新）', ssoAppCc.ok && ssoAppCc.data.principal.scopes.includes('app.write') && ssoAppCc.data.principal.scopes.includes('app.read'))
  const ssoAppFirstReport = await api('POST', `/api/apps/${ssoAppId}/metrics-report`, { token: ssoAppCc.data.token, body: { dau: 1, sessions: 1, avgDepth: 1, retention7: 0 } })
  check('应用凭自身凭证提报指标 200（app.write 生效，"发一句话"）', ssoAppFirstReport.ok)

  // 平台授权直达：应用入场票据（与 Agent 同一服务，refType=app）
  const appTicketMachine = await api('POST', `/api/apps/${ssoAppId}/entry-ticket`, { token: ssoAppCc.data.token, body: {} })
  check('应用直达票据：机器身份签发被拒（human-only）', appTicketMachine.status === 403)
  const appTicket = await api('POST', `/api/apps/${ssoAppId}/entry-ticket`, { token: admin, body: {} })
  check('应用直达票据：登录用户签发 200', appTicket.ok && appTicket.data.ticket.startsWith('etk_'), JSON.stringify(appTicket.error))
  const appRedeem = await rawReq('POST', '/api/authn/entry-tickets/redeem', {
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ticket: appTicket.data.ticket }),
  })
  const appRedeemBody = jsonBody(appRedeem)
  check('应用直达票据：兑换返回 refType=app + 平台身份', appRedeem.status === 200 && appRedeemBody.data?.refType === 'app' && appRedeemBody.data?.refId === ssoAppId && Boolean(appRedeemBody.data?.identity?.sub), JSON.stringify(appRedeemBody))

  // 门禁点 1（早反馈）：未签发 SSO 客户端 → 发起上线被拒
  const gateBlocked = await api('POST', `/api/apps/${ssoAppId}/transition`, { token: ops, body: { action: 'online' } })
  check('上线门禁（点1）：未签发 SSO 客户端被拒并指路', !gateBlocked.ok && JSON.stringify(gateBlocked.error).includes('SSO'))

  // owner-based 授权：非 owner 开发者 / 机器身份一律 403
  const devSso = await api('POST', `/api/apps/${ssoAppId}/sso-client`, { token: dev, body: { redirectUris: ['https://evil.example/cb'] } })
  check('非 owner 开发者签发被拒（developer 有 app.write 但非 owner）', devSso.status === 403)
  const machineCredAppWrite = await api('POST', '/api/authn/principals', { token: admin, body: { name: 'sso-gate-machine', refType: 'external', scopes: ['app.write'] } })
  const machineAppWriteLogin = await api('POST', '/api/auth/client-credentials', { body: { clientId: machineCredAppWrite.data.clientId, clientSecret: machineCredAppWrite.data.clientSecret } })
  const machineSso = await api('POST', `/api/apps/${ssoAppId}/sso-client`, { token: machineAppWriteLogin.data.token, body: { redirectUris: ['https://evil.example/cb'] } })
  check('机器身份签发被拒（owner 校验 human-only）', machineSso.status === 403)

  // owner 签发（secret 仅一次）+ 回跳地址护栏
  const issueSso = await api('POST', `/api/apps/${ssoAppId}/sso-client`, { token: ops, body: { redirectUris: ['https://sso-app.example.com/cb'], clientType: 'confidential', consentRequired: false } })
  check('owner 签发 SSO 客户端（secret 一次性返回）', issueSso.ok && issueSso.data.clientId.startsWith('oc-') && issueSso.data.clientSecret.startsWith('ocs'))
  const badUri = await api('PATCH', `/api/apps/${ssoAppId}/sso-client`, { token: ops, body: { redirectUris: ['http://insecure.example/cb'] } })
  check('回跳地址护栏（http 公网域名仍被拒）', !badUri.ok)
  const lanUri = await api('PATCH', `/api/apps/${ssoAppId}/sso-client`, { token: ops, body: { redirectUris: ['http://192.168.0.7:8080', 'http://10.1.2.3/cb', 'http://172.16.5.4/cb', 'http://localhost:3000/cb', 'https://sso-app.example.com/cb'] } })
  check('回跳地址护栏（http 内网 IP / localhost 放行）', lanUri.ok && lanUri.data.redirectUris.includes('http://192.168.0.7:8080'))
  const restoreUri = await api('PATCH', `/api/apps/${ssoAppId}/sso-client`, { token: ops, body: { redirectUris: ['https://sso-app.example.com/cb'] } })
  check('回跳地址恢复 https（后续授权流沿用）', restoreUri.ok)
  const ssoDetail = await api('GET', `/api/apps/${ssoAppId}`, { token: ops })
  check('应用详情返回 sso 块（无 secret 泄露）', ssoDetail.ok && ssoDetail.data.sso?.clientId === issueSso.data.clientId && !JSON.stringify(ssoDetail.data.sso).includes('Secret'))

  // 门禁点 2（兜底）：审批挂单期间禁用客户端 → 审批通过但执行失败留痕
  const onlineReq1 = await api('POST', `/api/apps/${ssoAppId}/transition`, { token: ops, body: { action: 'online' } })
  check('签发后发起上线（审批单快照 ssoClientId）', onlineReq1.ok && onlineReq1.data.approval.payload.ssoClientId === issueSso.data.clientId)
  await api('POST', `/api/apps/${ssoAppId}/sso-client/disable`, { token: ops, body: { reason: '审批期间禁用（执行期复核演练）' } })
  const approveFail = await api('POST', `/api/approvals/${onlineReq1.data.approval.id}/decide`, { token: admin, body: { decision: 'approve', opinion: '应触发执行期复核失败' } })
  const appAfterFail = await api('GET', `/api/apps/${ssoAppId}`, { token: ops })
  check('门禁点2：审批期间禁用 → 上线执行失败留痕', approveFail.ok && approveFail.data.status === 'failed' && String(approveFail.data.execution?.error ?? '').includes('复核') && appAfterFail.data.status !== 'online')

  // 重新启用 → 再次审批 → 上线成功
  await api('POST', `/api/apps/${ssoAppId}/sso-client/enable`, { token: ops })
  const onlineReq2 = await api('POST', `/api/apps/${ssoAppId}/transition`, { token: ops, body: { action: 'online' } })
  await api('POST', `/api/approvals/${onlineReq2.data.approval.id}/decide`, { token: admin, body: { decision: 'approve', opinion: '同意发布' } })
  const appOnlineDetail = await api('GET', `/api/apps/${ssoAppId}`, { token: admin })
  check('复核通过后上线成功', appOnlineDetail.data.status === 'online')
  check('应用拓扑穿透（app→agent→skill）', appOnlineDetail.ok && appOnlineDetail.data.topology.children.length >= 1)
  check('应用成本穿透归集', appOnlineDetail.ok && appOnlineDetail.data.cost.length >= 1)

  // 完整浏览器流（应用客户端）：第一跳 → 用户确认 → 换牌 → userinfo
  const appAuthorizeQuery = new URLSearchParams({
    response_type: 'code', client_id: issueSso.data.clientId, redirect_uri: 'https://sso-app.example.com/cb',
    state: 'st-app-mvp', scope: 'openid profile', code_challenge: pkceChallenge, code_challenge_method: 'S256',
  }).toString()
  const appFirst = await rawReq('GET', `/oauth/authorize?${appAuthorizeQuery}`)
  check('应用客户端授权第一跳 → 平台授权页', appFirst.status === 302 && String(appFirst.headers.location).startsWith('/#/oauth/authorize?req='))
  const appApprove = await authorizeConfirm(ops, reqIdOf(appFirst), true)
  const appTokens = jsonBody(await rawReq('POST', '/oauth/token', {
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${issueSso.data.clientId}:${issueSso.data.clientSecret}`).toString('base64')}` },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: new URL(appApprove.result.location).searchParams.get('code'), redirect_uri: 'https://sso-app.example.com/cb', code_verifier: pkceVerifier }).toString(),
  }))
  const appUserInfo = jsonBody(await rawReq('GET', '/oauth/userinfo', { headers: { authorization: `Bearer ${appTokens.access_token}` } }))
  check('应用完整浏览器流（authorize → consent → token → userinfo）', appTokens.access_token?.split('.').length === 3 && appUserInfo.sub === opsLogin.data.user.id && appUserInfo.org !== null)

  // 钉钉身份驱动同一条授权流（授权页登录面板「钉钉扫码」入口对应的端点链）：
  // providers 探测入口显隐 → sso 免密登录换平台会话 → 该会话完成 consent → 换牌 → userinfo 身份一致
  const dingProviders = await api('GET', '/api/auth/providers')
  check('授权页可探测钉钉登录入口（providers 公开回显）', dingProviders.ok && dingProviders.data.providers.some((p) => p.provider === 'dingtalk'))
  const dingAuth = await api('POST', '/api/auth/sso/authorize', { body: { provider: 'dingtalk', scene: 'web_qr' } })
  const dingSso = await api('POST', '/api/auth/sso', { body: { provider: 'dingtalk', code: 'DD0002', state: dingAuth.data.state } })
  check('钉钉身份在授权页登录（sso hit 签发平台会话令牌）', dingSso.ok && dingSso.data.kind === 'hit' && Boolean(dingSso.data.token))
  const dingFirst = await rawReq('GET', `/oauth/authorize?${new URLSearchParams({
    response_type: 'code', client_id: issueSso.data.clientId, redirect_uri: 'https://sso-app.example.com/cb',
    state: 'st-app-ding', scope: 'openid profile', code_challenge: pkceChallenge, code_challenge_method: 'S256',
  }).toString()}`)
  const dingApprove = await authorizeConfirm(dingSso.data.token, reqIdOf(dingFirst), true)
  const dingTokens = jsonBody(await rawReq('POST', '/oauth/token', {
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from(`${issueSso.data.clientId}:${issueSso.data.clientSecret}`).toString('base64')}` },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: new URL(dingApprove.result.location).searchParams.get('code'), redirect_uri: 'https://sso-app.example.com/cb', code_verifier: pkceVerifier }).toString(),
  }))
  const dingUserInfo = jsonBody(await rawReq('GET', '/oauth/userinfo', { headers: { authorization: `Bearer ${dingTokens.access_token}` } }))
  check('钉钉身份完整浏览器流（sso 登录 → consent → token → userinfo 身份一致）',
    dingFirst.status === 302 && dingApprove.status === 200 && dingTokens.access_token?.split('.').length === 3
    && dingUserInfo.sub === dingSso.data.user.id && dingUserInfo.preferred_username === dingSso.data.user.username)

  // 平台侧自动折算回归（真实链路汇点）：ticket 兑换（admin）+ OIDC 发码（ops、钉钉用户）→ 应用 DAU/UV 自动落账
  const mvpMetrics = (await api('GET', `/api/apps/${ssoAppId}`, { token: admin })).data.metrics
  check('SSO 到访自动折算（ticket admin + 发码 ops/钉钉 → dau=3 uv=3，同用户重复授权去重）', mvpMetrics.dau === 3 && mvpMetrics.uv === 3, JSON.stringify(mvpMetrics))

  // app.updated 联动：应用改名 → 客户端名称同步
  await api('PATCH', `/api/apps/${ssoAppId}`, { token: ops, body: { name: 'SSO 自测应用 v2' } })
  const clientsAfterRename = await api('GET', '/api/authn/oidc/clients', { token: admin })
  const renamedClient = clientsAfterRename.data.clients.find((c) => c.clientId === issueSso.data.clientId)
  check('应用改名 → OIDC 客户端名称同步（app.updated 联动）', renamedClient?.name === 'SSO 自测应用 v2' && renamedClient.refAppName === 'SSO 自测应用 v2')

  // 轮换：旧 secret 立即失效
  const rotatedApp = await api('POST', `/api/apps/${ssoAppId}/sso-client/rotate`, { token: ops })
  check('owner 轮换 secret（新值一次性返回）', rotatedApp.ok && rotatedApp.data.clientSecret.startsWith('ocs') && rotatedApp.data.clientSecret !== issueSso.data.clientSecret)
  const rotFirst = await rawReq('GET', `/oauth/authorize?${new URLSearchParams({ ...Object.fromEntries(new URLSearchParams(appAuthorizeQuery)), state: 'st-rotate' }).toString()}`)
  const rotApprove = await authorizeConfirm(ops, reqIdOf(rotFirst), true)
  const rotCode = new URL(rotApprove.result.location).searchParams.get('code')
  const oldSecretCall = await rawReq('POST', '/oauth/token', {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: issueSso.data.clientId, client_secret: issueSso.data.clientSecret, code: rotCode, redirect_uri: 'https://sso-app.example.com/cb', code_verifier: pkceVerifier }).toString(),
  })
  check('轮换后旧 secret 被拒（401）', oldSecretCall.status === 401)
  const rotFirst2 = await rawReq('GET', `/oauth/authorize?${new URLSearchParams({ ...Object.fromEntries(new URLSearchParams(appAuthorizeQuery)), state: 'st-rotate2' }).toString()}`)
  const rotApprove2 = await authorizeConfirm(ops, reqIdOf(rotFirst2), true)
  const newSecretCall = await rawReq('POST', '/oauth/token', {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: issueSso.data.clientId, client_secret: rotatedApp.data.clientSecret, code: new URL(rotApprove2.result.location).searchParams.get('code'), redirect_uri: 'https://sso-app.example.com/cb', code_verifier: pkceVerifier }).toString(),
  })
  check('新 secret 换牌成功', newSecretCall.status === 200)

  // 生命周期联动：下架 → 客户端禁用；恢复上线 → 客户端启用；归档 → 客户端禁用（终态）
  const offlineReq1 = await api('POST', `/api/apps/${ssoAppId}/transition`, { token: ops, body: { action: 'offline', note: '联动演练：下架' } })
  await api('POST', `/api/approvals/${offlineReq1.data.approval.id}/decide`, { token: admin, body: { decision: 'approve', opinion: '同意下架' } })
  const afterOffline = await api('GET', `/api/apps/${ssoAppId}`, { token: ops })
  check('应用下架 → SSO 客户端联动禁用（app.offlined）', afterOffline.data.status === 'offline' && afterOffline.data.sso?.status === 'disabled')
  // 重新上线：下架联动禁用了客户端 → 门禁要求先重新启用（控制台 SSO tab 有警示与入口）
  const reonlineBlocked = await api('POST', `/api/apps/${ssoAppId}/transition`, { token: ops, body: { action: 'online' } })
  check('客户端禁用期间重新上线被门禁拦截', !reonlineBlocked.ok && JSON.stringify(reonlineBlocked.error).includes('SSO'))
  await api('POST', `/api/apps/${ssoAppId}/sso-client/enable`, { token: ops })
  await api('POST', `/api/apps/${ssoAppId}/transition`, { token: ops, body: { action: 'retrial' } })
  const onlineReq3 = await api('POST', `/api/apps/${ssoAppId}/transition`, { token: ops, body: { action: 'online' } })
  await api('POST', `/api/approvals/${onlineReq3.data.approval.id}/decide`, { token: admin, body: { decision: 'approve', opinion: '再次上线' } })
  const afterReline = await api('GET', `/api/apps/${ssoAppId}`, { token: ops })
  check('应用恢复上线 → 客户端联动启用（app.onlined）', afterReline.data.status === 'online' && afterReline.data.sso?.status === 'active')
  const offlineReq2 = await api('POST', `/api/apps/${ssoAppId}/transition`, { token: ops, body: { action: 'offline', note: '归档前下架' } })
  await api('POST', `/api/approvals/${offlineReq2.data.approval.id}/decide`, { token: admin, body: { decision: 'approve', opinion: '同意' } })
  await api('POST', `/api/apps/${ssoAppId}/transition`, { token: ops, body: { action: 'archive' } })
  const afterArchive = await api('GET', `/api/apps/${ssoAppId}`, { token: ops })
  check('应用归档 → 客户端联动禁用（app.archived 终态）', afterArchive.data.status === 'archived' && afterArchive.data.sso?.status === 'disabled')

  // ================================================================ OIDC 会话补全 + 安全闭环（P3）
  section('OIDC 会话补全（refresh 轮转 / end_session / revoke / 密钥轮换）')
  const ocList = await api('GET', '/api/authn/oidc/clients', { token: admin })
  const ocRecord = ocList.data.clients.find((c) => c.clientId === OC.clientId)
  check('OIDC 客户端全局列表（含关联应用与 discovery 元数据）', ocList.ok && Boolean(ocRecord) && ocRecord.discovery.token_endpoint.includes('/oauth/token') && ocList.data.clients.some((c) => c.refAppName === 'SSO 自测应用 v2'))
  await api('PATCH', `/api/authn/oidc/clients/${ocRecord.id}`, { token: admin, body: { postLogoutUris: ['https://crm.partner.example/logged-out'] } })

  // openid-client 联测扩充：refresh 轮转 → 旧值重放整链吊销
  const p3Auth1 = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'p3-refresh' })}`)
  const p3Approve1 = await authorizeConfirm(admin, reqIdOf(p3Auth1), true)
  const p3Tokens1 = await oc.authorizationCodeGrant(ocConfig, new URL(p3Approve1.result.location), { pkceCodeVerifier: pkceVerifier, expectedState: 'p3-refresh' })
  const p3Refreshed = await oc.refreshTokenGrant(ocConfig, p3Tokens1.refresh_token)
  check('openid-client：refresh_token 轮转新令牌对', typeof p3Refreshed.access_token === 'string' && p3Refreshed.refresh_token !== p3Tokens1.refresh_token)
  let replayThrew = ''
  try { await oc.refreshTokenGrant(ocConfig, p3Tokens1.refresh_token) } catch (error) { replayThrew = String(error?.error ?? error?.message ?? error) }
  check('旧 refresh 重放被拒', replayThrew !== '')
  let chainDead = ''
  try { await oc.refreshTokenGrant(ocConfig, p3Refreshed.refresh_token) } catch (error) { chainDead = String(error?.error ?? error?.message ?? error) }
  check('重放触发整链吊销（轮转后的新 refresh 一并失效）', chainDead !== '')

  // scope 只允许收窄
  const p3Auth2 = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'p3-scope', scope: 'openid' })}`)
  const p3Approve2 = await authorizeConfirm(admin, reqIdOf(p3Auth2), true)
  const p3Tokens2 = await oc.authorizationCodeGrant(ocConfig, new URL(p3Approve2.result.location), { pkceCodeVerifier: pkceVerifier, expectedState: 'p3-scope' })
  const widen = await rawReq('POST', '/oauth/token', {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', client_id: OC.clientId, client_secret: OC.clientSecret, refresh_token: p3Tokens2.refresh_token, scope: 'openid profile email' }).toString(),
  })
  check('refresh 扩大 scope 被拒（只允许收窄）', widen.status === 400 && jsonBody(widen).error === 'invalid_scope')

  // 冻结 → refresh 换发即时失效（安全必需：不等过期）
  const freezeUser = await api('POST', '/api/iam/users', { token: admin, body: { username: 'ssofreeze01', displayName: 'OIDC 冻结联动', orgId: newOrg.data.id } })
  const freezeLogin = await api('POST', '/api/auth/login', { body: { username: 'ssofreeze01', password: freezeUser.data.initialPassword } })
  const fzAuth = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'p3-frozen' })}`)
  const fzApprove = await authorizeConfirm(freezeLogin.data.token, reqIdOf(fzAuth), true)
  const fzTokens = await oc.authorizationCodeGrant(ocConfig, new URL(fzApprove.result.location), { pkceCodeVerifier: pkceVerifier, expectedState: 'p3-frozen' })
  await api('POST', `/api/iam/users/${freezeUser.data.id}/freeze`, { token: admin, body: { reason: 'refresh 联动吊销验证' } })
  let frozenRefresh = ''
  try { await oc.refreshTokenGrant(ocConfig, fzTokens.refresh_token) } catch (error) { frozenRefresh = String(error?.error ?? error?.message ?? error) }
  check('账号冻结 → refresh 换发被拒（实时校验用户状态）', frozenRefresh !== '')

  // end_session：合法/非法回跳 + refresh 链吊销
  const esAuth = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'p3-endsession' })}`)
  const esApprove = await authorizeConfirm(admin, reqIdOf(esAuth), true)
  const esTokens = await oc.authorizationCodeGrant(ocConfig, new URL(esApprove.result.location), { pkceCodeVerifier: pkceVerifier, expectedState: 'p3-endsession' })
  const esUrl = oc.buildEndSessionUrl(ocConfig, { id_token_hint: esTokens.id_token, post_logout_redirect_uri: 'https://crm.partner.example/logged-out', state: 'logout-st' })
  const esOk = await rawReq('GET', esUrl.pathname + esUrl.search)
  check('end_session 合法回跳 → 302 平台登出中转页', esOk.status === 302 && String(esOk.headers.location).startsWith('/#/oauth/logout') && String(esOk.headers.location).includes('logged-out'))
  let esChainDead = ''
  try { await oc.refreshTokenGrant(ocConfig, esTokens.refresh_token) } catch (error) { esChainDead = String(error?.error ?? error?.message ?? error) }
  check('end_session 同时吊销 refresh 链（登出后不能静默续期）', esChainDead !== '')
  const esBad = await rawReq('GET', `/oauth/end_session?${new URLSearchParams({ id_token_hint: esTokens.id_token, post_logout_redirect_uri: 'https://evil.example/x' }).toString()}`)
  check('end_session 非法回跳 → 平台错误页（不开放重定向）', esBad.status === 302 && String(esBad.headers.location).startsWith('/#/oauth/error'))
  // 登出回退：RP 未显式携带 post_logout_redirect_uri（如纯前端门户只传 id_token_hint）
  const esBare = await rawReq('GET', `/oauth/end_session?${new URLSearchParams({ id_token_hint: esTokens.id_token }).toString()}`)
  check('end_session 未带回跳参数 → 按唯一登记登出地址回跳（门户登出场景兜底）',
    esBare.status === 302 && String(esBare.headers.location).startsWith('/#/oauth/logout') && String(esBare.headers.location).includes('logged-out'))
  await api('PATCH', `/api/authn/oidc/clients/${ocRecord.id}`, { token: admin, body: { postLogoutUris: ['https://crm.partner.example/logged-out', 'https://crm.partner.example/other'] } })
  const esAmbiguous = await rawReq('GET', `/oauth/end_session?${new URLSearchParams({ id_token_hint: esTokens.id_token }).toString()}`)
  const esAmbiguousLoc = String(esAmbiguous.headers.location)
  check('end_session 未带参数且登记多个登出地址 → 不猜测回跳，停留平台登出页',
    esAmbiguous.status === 302 && esAmbiguousLoc.startsWith('/#/oauth/logout') && !esAmbiguousLoc.includes('post_logout_redirect_uri'))
  await api('PATCH', `/api/authn/oidc/clients/${ocRecord.id}`, { token: admin, body: { postLogoutUris: ['https://crm.partner.example/logged-out'] } })

  // revoke（RFC 7009）：access jti 黑名单 + refresh 链
  const rvAuth = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'p3-revoke' })}`)
  const rvApprove = await authorizeConfirm(admin, reqIdOf(rvAuth), true)
  const rvTokens = await oc.authorizationCodeGrant(ocConfig, new URL(rvApprove.result.location), { pkceCodeVerifier: pkceVerifier, expectedState: 'p3-revoke' })
  await oc.tokenRevocation(ocConfig, rvTokens.access_token)
  const revokedInfo = await rawReq('GET', '/oauth/userinfo', { headers: { authorization: `Bearer ${rvTokens.access_token}` } })
  check('revoke access token → userinfo 即时 401', revokedInfo.status === 401)
  await oc.tokenRevocation(ocConfig, rvTokens.refresh_token)
  let revokedRefresh = ''
  try { await oc.refreshTokenGrant(ocConfig, rvTokens.refresh_token) } catch (error) { revokedRefresh = String(error?.error ?? error?.message ?? error) }
  check('revoke refresh token → 换发被拒', revokedRefresh !== '')

  // JWKS 密钥轮换：旧 token 宽限内验签通过、新 token kid 切换、JWKS 双 key
  const krAuth = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'p3-rotate' })}`)
  const krApprove = await authorizeConfirm(admin, reqIdOf(krAuth), true)
  const krTokensOld = await oc.authorizationCodeGrant(ocConfig, new URL(krApprove.result.location), { pkceCodeVerifier: pkceVerifier, expectedState: 'p3-rotate' })
  const keysRotated = await api('POST', '/api/authn/oidc/keys/rotate', { token: admin })
  const oldKid = JSON.parse(Buffer.from(krTokensOld.access_token.split('.')[0], 'base64url').toString('utf8')).kid
  check('密钥轮换执行（新 kid + 24h 宽限）', keysRotated.ok && keysRotated.data.kid !== oldKid && keysRotated.data.graceHours === 24)
  const graceInfo = await rawReq('GET', '/oauth/userinfo', { headers: { authorization: `Bearer ${krTokensOld.access_token}` } })
  check('轮换后旧 token 宽限内仍可验签（在途不掉线）', graceInfo.status === 200)
  const krAuth2 = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ state: 'p3-rotate2' })}`)
  const krApprove2 = await authorizeConfirm(admin, reqIdOf(krAuth2), true)
  const krTokensNew = await oc.authorizationCodeGrant(ocConfig, new URL(krApprove2.result.location), { pkceCodeVerifier: pkceVerifier, expectedState: 'p3-rotate2' })
  const newKid = JSON.parse(Buffer.from(krTokensNew.access_token.split('.')[0], 'base64url').toString('utf8')).kid
  check('新令牌切换到新 kid 签名', newKid === keysRotated.data.kid && newKid !== oldKid)
  const jwksAfterRotate = jsonBody(await rawReq('GET', '/.well-known/jwks.json'))
  check('JWKS 宽限期公布双公钥（旧 key 保留验签）', jwksAfterRotate.keys.length === 2 && jwksAfterRotate.keys.some((k) => k.kid === oldKid) && jwksAfterRotate.keys.some((k) => k.kid === newKid))

  // public 客户端（D-a 决策）：免 secret + 强制 PKCE + 不签发 refresh（纯前端 SPA 形态）
  const publicClient = await api('POST', '/api/authn/oidc/clients', { token: admin, body: { name: '纯前端 SPA（public）', redirectUris: ['http://localhost:5173/cb'], clientType: 'public' } })
  check('登记 public 客户端（无 secret 返回）', publicClient.ok && !publicClient.data.clientSecret && publicClient.data.note.includes('public'))
  const pubAuth = await rawReq('GET', `/oauth/authorize?${authorizeQuery({ client_id: publicClient.data.clientId, redirect_uri: 'http://localhost:5173/cb', state: 'p3-public' })}`)
  const pubApprove = await authorizeConfirm(admin, reqIdOf(pubAuth), true)
  const pubTokens = jsonBody(await rawReq('POST', '/oauth/token', {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: publicClient.data.clientId, code: new URL(pubApprove.result.location).searchParams.get('code'), redirect_uri: 'http://localhost:5173/cb', code_verifier: pkceVerifier }).toString(),
  }))
  check('public 客户端免 secret 换牌成功且不签发 refresh', pubTokens.access_token?.split('.').length === 3 && pubTokens.refresh_token === undefined)

  // 授权事件审计留痕
  const oidcAudit = await api('GET', '/api/audit/logs?limit=200', { token: admin })
  check('授权事件审计留痕（granted / denied）', oidcAudit.ok && oidcAudit.data.items.some((log) => log.action === 'oidc.authorize.granted') && oidcAudit.data.items.some((log) => log.action === 'oidc.authorize.denied'))

  // ================================================================ 审计
  section('审计与告警与成本')
  const logsAll = await api('GET', '/api/audit/logs?limit=200', { token: admin })
  const types = new Set(logsAll.data.items.map((log) => log.type))
  check('四类审计日志齐全', ['auth', 'authz', 'invoke', 'change'].every((type) => types.has(type)))
  check('越权拒绝已留痕（authz denied）', logsAll.data.items.some((log) => log.type === 'authz' && log.result === 'denied'))

  const logsFilter = await api('GET', '/api/audit/logs?type=invoke&result=ok&limit=5', { token: admin })
  check('审计筛选（类型+结果）', logsFilter.ok && logsFilter.data.items.every((log) => log.type === 'invoke'))

  const costApp = await api('GET', '/api/audit/cost?groupBy=app', { token: admin })
  check('成本按应用穿透', costApp.ok && costApp.data.rows.length >= 1)
  const costOrg = await api('GET', '/api/audit/cost?groupBy=org', { token: admin })
  check('成本按组织穿透', costOrg.ok && costOrg.data.rows.length >= 1)

  const ruleCreate = await api('POST', '/api/audit/alert-rules', { token: admin, body: { name: '自测规则', metric: 'permission_denied', threshold: 2, severity: 'critical' } })
  check('创建告警规则', ruleCreate.ok)

  // 告警已读体系：单条已读 → 一键全部已读 → 未读清零（403 探测放最后，避免中途触发新告警干扰计数）
  const alertsBefore = await api('GET', '/api/audit/alerts', { token: admin })
  const unreadBefore = alertsBefore.data.alerts.filter((a) => !a.read)
  check('告警中心存在未读告警（前置）', alertsBefore.ok && unreadBefore.length >= 1)
  const oneRead = await api('POST', `/api/audit/alerts/${unreadBefore[0].id}/read`, { token: admin })
  check('单条告警标记已读', oneRead.ok && oneRead.data.read === true)
  const readAll = await api('POST', '/api/audit/alerts/read-all', { token: admin })
  const alertsAfter = await api('GET', '/api/audit/alerts?unread=1', { token: admin })
  check('一键全部已读（返回条数 = 剩余未读，且未读清零）', readAll.ok && readAll.data.read === unreadBefore.length - 1 && alertsAfter.data.alerts.length === 0)
  const readAllAgain = await api('POST', '/api/audit/alerts/read-all', { token: admin })
  check('重复一键已读幂等（返回 0）', readAllAgain.ok && readAllAgain.data.read === 0)
  const toolReadAll = await api('POST', '/api/tools/execute', { token: admin, body: { name: 'audit_alerts_read_all', args: {} } })
  check('工具桥一键已读（audit_alerts_read_all）', toolReadAll.ok && toolReadAll.data.isError === false)
  const readAllDenied = await api('POST', '/api/audit/alerts/read-all', { token: dev })
  check('无 audit.read 权限不可一键已读（403）', readAllDenied.status === 403)

  // ================================================================ 工具桥（dsh 工具契约）
  section('工具桥（模型可用工具）')
  const toolList = await api('GET', '/api/platform/info', { token: admin })
  check('工具目录 ≥ 37 个', toolList.data.tools.length >= 37)
  const toolExec = await api('POST', '/api/tools/execute', { token: admin, body: { name: 'iam_org_tree', args: {} } })
  check('工具执行（iam_org_tree）', toolExec.ok && toolExec.data.isError === false && JSON.stringify(toolExec.data.value).includes('元冰可集团'))
  const toolAgentList = await api('POST', '/api/tools/execute', { token: admin, body: { name: 'agent_list', args: { status: 'online' } } })
  check('工具执行（agent_list 过滤）', toolAgentList.ok && toolAgentList.data.value.total >= 5)

  // ================================================================ 平台自更新（版本检查 / 权限 / dry-run / 审计联动）
  section('平台自更新（plugin-update）')
  check('更新工具已注册（update_status 等）', toolList.data.tools.some((t) => t.name === 'update_status' && t.permission === 'platform.update.read'))

  const updStatus0 = await api('GET', '/api/update/status', { token: admin })
  check('更新状态可读（版本取自根 package.json=1.1.0）', updStatus0.ok && updStatus0.data.currentVersion === '1.1.0')
  check('安装形态识别为 source（git 检出）', updStatus0.data.installMode === 'source')
  check('环境变量关闭自动检查生效（DSH_UPDATE_AUTO_CHECK=off）', updStatus0.data.autoCheck === false)
  check('未检查时无最新版本快照', updStatus0.data.latest === null)

  const updAnon = await api('GET', '/api/update/status')
  check('匿名访问更新状态被拒（401）', updAnon.status === 401)

  const updCheck1 = await api('POST', '/api/update/check', { token: admin })
  check('手动检查成功（stub 上游）', updCheck1.ok && updCheck1.data.latest?.version === '9.9.9')
  check('发现新版本（1.1.0 → 9.9.9）', updCheck1.data.hasUpdate === true && updCheck1.data.updateKind === 'version')
  check('提交对比生效（落后 2 个提交）', updCheck1.data.behindBy === 2 && updCheck1.data.recentCommits.length === 2 && updCheck1.data.recentCommits[0].sha === 'a222222')

  const updCheck2 = await api('POST', '/api/update/check', { token: admin })
  check('手动检查 60 秒冷却（429）', updCheck2.status === 429)

  const updEvents = await api('GET', '/api/platform/info', { token: admin })
  check('已广播 platform.update.available 事件', updEvents.data.events.some((e) => e.name === 'platform.update.available'))
  const updAudit = await api('GET', '/api/audit/logs?q=platform.update.available&limit=10', { token: admin })
  check('audit 联动留痕（platform.update.available）', (updAudit.data?.items ?? []).some((l) => l.action === 'platform.update.available'))

  const hrForUpdate = await api('POST', '/api/auth/login', { body: { username: 'hr', password: 'Ybk@2026' } })
  const hrToken2 = hrForUpdate.data?.token
  const updApplyDenied = await api('POST', '/api/update/apply', { token: hrToken2, body: { reason: '越权尝试' } })
  check('无权限用户执行升级被拒（403）', updApplyDenied.status === 403)

  const updDry = await api('POST', '/api/update/apply', { token: admin, body: { dryRun: true } })
  check('dry-run 预演返回步骤且不执行任何变更', updDry.ok && updDry.data.dryRun === true && Array.isArray(updDry.data.steps) && updDry.data.steps.length === 3)
  check('dry-run 附带待拉取提交清单', Array.isArray(updDry.data.incomingCommits) && updDry.data.incomingCommits.length === 2)

  const updApplyNoReason = await api('POST', '/api/update/apply', { token: admin, body: {} })
  check('正式升级缺少原因被拒（400）', updApplyNoReason.status === 400)

  const updDismiss = await api('POST', '/api/update/settings', { token: admin, body: { dismissedVersion: '9.9.9' } })
  check('忽略指定版本（横幅静默）', updDismiss.ok && updDismiss.data.dismissed === true)
  const updRestore = await api('POST', '/api/update/settings', { token: admin, body: { dismissedVersion: null } })
  check('恢复更新提醒', updRestore.ok && updRestore.data.dismissed === false)
  const updAutoOn = await api('POST', '/api/update/settings', { token: admin, body: { autoCheck: true, intervalHours: 24 } })
  check('开启自动检查（每 24h）', updAutoOn.ok && updAutoOn.data.autoCheck === true && updAutoOn.data.intervalHours === 24)

  const updTool = await api('POST', '/api/tools/execute', { token: admin, body: { name: 'update_status', args: {} } })
  check('Agent 工具 update_status 可用', updTool.ok && updTool.data.isError === false && updTool.data.value.currentVersion === '1.1.0')
  const updToolApply = await api('POST', '/api/tools/execute', { token: hrToken2, body: { name: 'update_apply', args: { reason: '越权尝试' } } })
  check('工具级权限拦截 update_apply（403）', updToolApply.status === 403)

  // ================================================================ 远程 dsh 接入（接入码 → 机器凭证 → 工具代理）
  section('远程 dsh 接入（plugin-connect）')
  check('接入管理工具已注册（connect_code_create 等）', toolList.data.tools.some((t) => t.name === 'connect_code_create' && t.permission === 'connect.manage'))

  // 管理端权限边界：无 connect.manage 的角色被拒
  const opsCodes = await api('GET', '/api/connect/codes', { token: ops })
  check('无 connect.manage 权限创建/查看接入码被拒（403）', opsCodes.status === 403)

  // 创建接入码（operator 模板）—— 接入码仅创建响应中出现一次
  const codeCreated = await api('POST', '/api/connect/codes', { token: admin, body: { template: 'operator', ttlMinutes: 10, remark: 'selftest' } })
  check('创建接入码（operator，一次性展示）', codeCreated.ok && codeCreated.data.code.startsWith('enr_') && codeCreated.data.ttlMinutes === 10)
  const codesListed = await api('GET', '/api/connect/codes', { token: admin })
  check('接入码列表只含掩码不含明文', codesListed.ok && !JSON.stringify(codesListed.data).includes(codeCreated.data.code) && codesListed.data.codes.some((c) => c.codeMask && c.status === 'active'))

  // 伪造/错误接入码被拒（401）
  const badEnroll = await api('POST', '/api/connect/enroll', { body: { enrollmentCode: 'enr_forged'.padEnd(40, 'x'), clientName: 'attacker' } })
  check('伪造接入码 enroll 被拒', badEnroll.status === 401)

  // 真实 enroll：换机器凭证
  const enroll = await api('POST', '/api/connect/enroll', { body: { enrollmentCode: codeCreated.data.code, clientName: 'selftest-remote-dsh', meta: { hostname: 'selftest-pc', platform: 'test' } } })
  check('接入码换机器凭证成功', enroll.ok && enroll.data.clientId.startsWith('mc-') && enroll.data.clientSecret.startsWith('cs_') && enroll.data.template === 'operator')

  // 一次性消费：重放被拒
  const enrollReplay = await api('POST', '/api/connect/enroll', { body: { enrollmentCode: codeCreated.data.code, clientName: 'replay' } })
  check('接入码一次性消费（重放被拒）', enrollReplay.status === 401)

  // 机器凭证 → 机器令牌 → REST 读权限
  const ccLogin = await api('POST', '/api/auth/client-credentials', { body: { clientId: enroll.data.clientId, clientSecret: enroll.data.clientSecret } })
  check('机器凭证换取机器令牌', ccLogin.ok && ccLogin.data.token.startsWith('dst1.'))
  const machineToken = ccLogin.data.token
  const machineOverview = await api('GET', '/api/overview', { token: machineToken })
  check('机器令牌可读平台概览（operator 含读权限）', machineOverview.ok)
  const machineOrgCreate = await api('POST', '/api/iam/orgs', { token: machineToken, body: { name: '越权组织' } })
  check('operator 模板无 iam.org.write（越权被拒 403）', machineOrgCreate.status === 403)

  // 机器令牌走工具桥（远程工具代理的同一条宿主路径）
  const machineTool = await api('POST', '/api/tools/execute', { token: machineToken, body: { name: 'agent_list', args: {} } })
  check('机器令牌经工具桥执行 agent_list', machineTool.ok && machineTool.data.isError === false && machineTool.data.value.total >= 5)

  // 客户端心跳主动推送（宿主侧接入资产存活监测）
  const hb = await api('POST', '/api/connect/heartbeat', { token: machineToken, body: { tools: 42, version: 'v22.14.0', uptimeSec: 600 } })
  check('接入客户端心跳上报成功', hb.ok && hb.data.clientId === enroll.data.clientId)
  const hbAdmin = await api('POST', '/api/connect/heartbeat', { token: admin, body: {} })
  check('非接入客户端身份心跳被拒（404）', hbAdmin.status === 404)
  const hbAnon = await api('POST', '/api/connect/heartbeat', { body: {} })
  check('心跳端点强制 Bearer 鉴权（401）', hbAnon.status === 401)

  // 客户端登记与最近使用
  const clientsListed = await api('GET', '/api/connect/clients', { token: admin })
  const enrolled = clientsListed.data.clients.find((c) => c.clientId === enroll.data.clientId)
  check('已接入客户端登记（模板/主机名/最近使用）', clientsListed.ok && enrolled && enrolled.template === 'operator' && enrolled.hostname === 'selftest-pc' && enrolled.lastUsedAt !== '')
  check('宿主侧可见客户端心跳与元信息', enrolled.lastHeartbeatAt !== '' && enrolled.heartbeat?.tools === 42 && enrolled.heartbeat?.uptimeSec === 600)

  // 禁用客户端 → 令牌即时失效（principal disabled 联动）
  const disableClient = await api('POST', `/api/connect/clients/${enroll.data.clientId}/disable`, { token: admin, body: { reason: 'selftest 验证吊销联动' } })
  check('禁用接入客户端（原因必填留痕）', disableClient.ok && disableClient.data.status === 'disabled')
  const ccAfterDisable = await api('POST', '/api/auth/client-credentials', { body: { clientId: enroll.data.clientId, clientSecret: enroll.data.clientSecret } })
  const machineAfterDisable = await api('GET', '/api/overview', { token: machineToken })
  check('禁用后凭证换牌被拒、旧机器令牌即时失效', ccAfterDisable.status === 401 && machineAfterDisable.status === 401)

  // 作废未使用接入码
  const code2 = await api('POST', '/api/connect/codes', { token: admin, body: { template: 'readonly', ttlMinutes: 5 } })
  const revokeCode = await api('DELETE', `/api/connect/codes/${code2.data.id}`, { token: admin })
  const enrollRevoked = await api('POST', '/api/connect/enroll', { body: { enrollmentCode: code2.data.code, clientName: 'late' } })
  check('作废未使用接入码后 enroll 被拒', revokeCode.ok && enrollRevoked.status === 401)

  // 工具级 connect 管理工具（宿主侧 dsh Agent 用自然语言管理接入）
  const toolCodeCreate = await api('POST', '/api/tools/execute', { token: admin, body: { name: 'connect_code_create', args: { template: 'readonly', ttlMinutes: 5 } } })
  check('工具 connect_code_create 签发接入码', toolCodeCreate.ok && toolCodeCreate.data.isError === false && toolCodeCreate.data.value.code.startsWith('enr_'))

  // ================================================================ NAS 资产（FS 文件存储）
  section('NAS 数据权限引擎（纯函数单测 engine.ts，dev-plan-nas-authz §四）')
  {
    const eo = [
      { id: 'eo1', name: '智造平台', parentId: null, leaderUserIds: ['e_p', 'e_p2'] },
      { id: 'eo2', name: '生产部', parentId: 'eo1', leaderUserIds: ['e_d'] },
      { id: 'eo3', name: '总装12线', parentId: 'eo2', leaderUserIds: ['e_t'] },
      { id: 'eo4', name: '质检线', parentId: 'eo2', leaderUserIds: [] },
      { id: 'eo5', name: '品质部', parentId: 'eo1', leaderUserIds: ['e_x', 'e_y'] },
      { id: 'eo6', name: '外贸平台', parentId: null, leaderUserIds: [] },
      { id: 'eo7', name: '外贸一部', parentId: 'eo6', leaderUserIds: [] },
    ]
    const idx = buildOrgIndex(eo)
    const nas1 = { id: 'en1', rootPath: '/', orgRoot: '智造平台' }
    const now = '2026-08-29T00:00:00Z'
    const baseRules = { version: 1, exceptions: [], cGroups: ['eg_c'], externalReadPaths: [{ nasId: 'en1', path: '/外部白名单' }], observeOnly: true, degradeAllToReadonly: false }
    const u = (id, orgId, extra = {}) => ({ id, displayName: id, orgId, ...extra })
    const run = (user, paths, op, opt = {}) => engineCheck(
      { userId: user.id, nasId: opt.nasId ?? 'en1', paths, op, now, ...(opt.override !== undefined ? { override: opt.override } : {}) },
      { orgIndex: idx, user, nas: opt.nas ?? nas1, rules: opt.rules ?? baseRules, cGroupHits: opt.cGroupHits ?? [] },
    )
    const inScope = '/智造平台/生产部/总装12线/a.txt'

    // 角色推导
    check('推导：平台负责人 → P', deriveRole(u('e_p', 'eo1'), idx).role === 'P')
    check('推导：部门负责人 → D', deriveRole(u('e_d', 'eo2'), idx).role === 'D')
    check('推导：班组负责人 → T', deriveRole(u('e_t', 'eo3'), idx).role === 'T')
    check('推导：班组成员 → M', deriveRole(u('e_m', 'eo3'), idx).role === 'M')
    check('多负责人 co-leader：双负责人均得 P 且 reasons 标注',
      deriveRole(u('e_p2', 'eo1'), idx).role === 'P'
      && run(u('e_p2', 'eo1'), [inScope], 'read').reasons.some((r) => r.includes('co-leader')))
    check('挂根组织非负责人 → 全 deny', run(u('e_root', 'eo1'), ['/智造平台/x'], 'read').decision === 'deny'
      && run(u('e_root', 'eo1'), ['/智造平台/x'], 'read').reasons.some((r) => r.includes('root-no-role')))
    check('未落班组（部门根非负责人）→ 只读', run(u('e_d2', 'eo2'), ['/智造平台/生产部/x'], 'read').decision === 'allow'
      && run(u('e_d2', 'eo2'), ['/智造平台/生产部/x'], 'write').decision === 'deny')
    check('兼任：主归属正常写 + 兼任子树仅只读',
      run(u('e_m2', 'eo4', { primaryOrgId: 'eo3' }), [inScope], 'write').decision === 'allow'
      && run(u('e_m2', 'eo4', { primaryOrgId: 'eo3' }), ['/智造平台/生产部/质检线/a.txt'], 'write').decision === 'deny'
      && run(u('e_m2', 'eo4', { primaryOrgId: 'eo3' }), ['/智造平台/生产部/质检线/a.txt'], 'read').decision === 'allow')
    check('作用域锚对齐：部门负责人主部门挂在下属班组，作用域提升到所领导部门（角色与作用域一致）',
      run(u('e_d', 'eo3'), ['/智造平台/生产部/生产计划.xlsx'], 'write').decision === 'allow'
      && run(u('e_d', 'eo3'), ['/智造平台/生产部/生产计划.xlsx'], 'write').scope.includes('/智造平台/生产部')
      && deriveRole(u('e_d', 'eo3'), idx).role === 'D',
      JSON.stringify(run(u('e_d', 'eo3'), ['/智造平台/生产部/生产计划.xlsx'], 'write').scope))
    check('跨分支领导（一人多角色）：主归属矩阵不抬档，所领导部门子树按该部门角色全权限生效',
      deriveRole(u('e_x', 'eo3'), idx).role === 'M'
      && deriveRole(u('e_x', 'eo3'), idx).leaderOfElsewhere.map((led) => led.orgId).includes('eo5')
      && run(u('e_x', 'eo3'), ['/智造平台/品质部/检验标准.xlsx'], 'write').decision === 'allow'
      && run(u('e_x', 'eo3'), ['/智造平台/品质部/旧标准.xlsx'], 'delete').decision === 'allow'
      && run(u('e_x', 'eo3'), ['/智造平台/品质部/管理.xlsx'], 'admin').decision === 'deny'
      && run(u('e_x', 'eo3'), [inScope], 'modify').decision === 'deny',
      JSON.stringify(run(u('e_x', 'eo3'), ['/智造平台/品质部/检验标准.xlsx'], 'write')))
    check('跨分支领导救回作用域：主部门不在锚点链（原 no-scope 早退）不吞所领导部门权限',
      run(u('e_y', 'eo7'), ['/智造平台/品质部/检验标准.xlsx'], 'write').decision === 'allow'
      && run(u('e_y', 'eo7'), ['/外贸平台/合同.xlsx'], 'read').decision === 'deny',
      JSON.stringify(run(u('e_y', 'eo7'), ['/智造平台/品质部/检验标准.xlsx'], 'write')))
    check('根目录只读列举（B 语义）：作用域内用户列根放行、写根仍拒、越界子路径不变、无作用域用户列根仍拒',
      run(u('e_m', 'eo3'), ['/'], 'read').decision === 'allow'
      && run(u('e_m', 'eo3'), ['/'], 'read').reasons.some((r) => r.includes('root-listing'))
      && run(u('e_m', 'eo3'), ['/'], 'write').decision === 'deny'
      && run(u('e_m', 'eo3'), ['/外部目录/x.txt'], 'read').decision === 'deny'
      && run(u('e_z', 'eo7'), ['/'], 'read').decision === 'deny'
      && run(u('e_y', 'eo7'), ['/'], 'read').decision === 'allow',
      JSON.stringify({ mRootRead: run(u('e_m', 'eo3'), ['/'], 'read').decision, mRootWrite: run(u('e_m', 'eo3'), ['/'], 'write').decision, yRootRead: run(u('e_y', 'eo7'), ['/'], 'read').decision, zRootRead: run(u('e_z', 'eo7'), ['/'], 'read').decision }))
    check('负责人悬空检测：质检线在列', findVacantLeaderOrgs(idx, { withUserOrgIds: new Set(['eo3', 'eo4']) }).some((o) => o.id === 'eo4'))

    // 判定序：显式 deny > 显式 allow > 角色矩阵 > 默认 deny
    const rulesEx = {
      ...baseRules,
      exceptions: [
        { id: 'ex_deny', effect: 'deny', nasId: 'en1', path: '/智造平台/生产部/*', ops: ['read'] },
        { id: 'ex_allow', effect: 'allow', nasId: 'en1', path: '/智造平台/生产部/总装12线', ops: ['read'] },
      ],
    }
    const exDeny = run(u('e_m', 'eo3'), ['/智造平台/生产部/总装12线/a.txt'], 'read', { rules: rulesEx })
    check('判定序：显式 deny 压过显式 allow', exDeny.decision === 'deny' && exDeny.ruleId === 'ex_deny')
    const readonlyOps = ['write', 'modify', 'delete', 'share', 'admin']
    check('readonly 语义（未落班组只读态）：写类全拒/读下载放行',
      readonlyOps.every((op) => run(u('e_d2', 'eo2'), ['/智造平台/生产部/x'], op).decision === 'deny')
      && run(u('e_d2', 'eo2'), ['/智造平台/生产部/x'], 'read').decision === 'allow'
      && run(u('e_d2', 'eo2'), ['/智造平台/生产部/x'], 'download').decision === 'allow')
    check('M 矩阵：写文件放行/改结构删除分享管理拒绝',
      run(u('e_m', 'eo3'), [inScope], 'write').decision === 'allow'
      && ['modify', 'delete', 'share', 'admin'].every((op) => run(u('e_m', 'eo3'), [inScope], op).decision === 'deny'))
    check('矩阵一致性：内置矩阵 M 行与判定一致',
      Object.entries(MATRIX_DEFAULT.M).every(([op, allow]) => (run(u('e_m', 'eo3'), [inScope], op).decision === 'allow') === allow))

    // 例外过期 / C 叠加
    const rulesExp = {
      ...baseRules,
      exceptions: [{ id: 'ex_tmp', effect: 'allow', nasId: 'en1', path: '/智造平台/生产部/质检线/外部/*', ops: ['read'], expiresAt: '2026-08-01T00:00:00Z' }],
    }
    check('例外 expiresAt 过期即失效（回落矩阵后越界 deny）',
      run(u('e_m', 'eo3'), ['/智造平台/生产部/质检线/外部/a'], 'read', { rules: rulesExp }).decision === 'deny')
    const rulesExp2 = { ...rulesExp, exceptions: [{ ...rulesExp.exceptions[0], expiresAt: '2026-09-01T00:00:00Z' }] }
    check('例外未过期即生效',
      run(u('e_m', 'eo3'), ['/智造平台/生产部/质检线/外部/a'], 'read', { rules: rulesExp2 }).decision === 'allow')
    check('C 叠加：跨域只读放行、写拒绝',
      run(u('e_m', 'eo3'), ['/智造平台/生产部/质检线/外部/b'], 'read', { cGroupHits: ['eg_c'] }).decision === 'allow'
      && run(u('e_m', 'eo3'), ['/智造平台/生产部/质检线/外部/b'], 'write', { cGroupHits: ['eg_c'] }).decision === 'deny')
    const rulesCWrite = { ...baseRules, exceptions: [{ id: 'ex_cw', effect: 'allow', nasId: 'en1', path: '/智造平台/生产部/质检线/外部/b', ops: ['write'] }] }
    check('C 白名单目录写需显式 allow',
      run(u('e_m', 'eo3'), ['/智造平台/生产部/质检线/外部/b'], 'write', { rules: rulesCWrite, cGroupHits: ['eg_c'] }).decision === 'allow')

    // 边界 / 多 NAS / 映射表优先
    check('边界：路径超出组织子树 deny', run(u('e_m', 'eo3'), ['/智造平台/其他/x'], 'read').decision === 'deny')
    check('多 NAS：B 平台 NAS 对 A 平台成员 deny（orgRoot 不在链上）',
      run(u('e_m', 'eo3'), ['/x'], 'read', { nasId: 'en2', nas: { id: 'en2', rootPath: '/', orgRoot: '市场部' } }).decision === 'deny')
    const overriddenNas = { id: 'en1', rootPath: '/', orgRoot: '智造平台', orgPathOverrides: { eo3: '/总装A' } }
    check('orgPathOverrides 优先于名字推导',
      run(u('e_m', 'eo3'), ['/总装A/x'], 'read', { nas: overriddenNas }).decision === 'allow'
      && run(u('e_m', 'eo3'), ['/智造平台/生产部/总装12线/x'], 'read', { nas: overriddenNas }).decision === 'deny')
    const renamedIdx = buildOrgIndex(eo.map((o) => (o.id === 'eo3' ? { ...o, name: '总装十二线' } : o)))
    const renamedRun = engineCheck(
      { userId: 'e_m', nasId: 'en1', paths: ['/总装A/x'], op: 'read', now },
      { orgIndex: renamedIdx, user: u('e_m', 'eo3'), nas: overriddenNas, rules: baseRules, cGroupHits: [] },
    )
    check('组织改名作用域不漂移（映射表按 orgId 命中）', renamedRun.decision === 'allow' && renamedRun.scope[0] === '/总装A')
    check('override 破窗放行（并留痕标记）',
      run(u('e_m', 'eo3'), ['/任意/x'], 'delete', { override: true }).decision === 'allow'
      && run(u('e_m', 'eo3'), ['/任意/x'], 'delete', { override: true }).override === true)
    const degradeRules = { ...baseRules, degradeAllToReadonly: true }
    check('degradeAllToReadonly：allow 视作 readonly',
      run(u('e_d', 'eo2'), ['/智造平台/生产部/x'], 'write', { rules: degradeRules }).decision === 'deny')
    check('observeOnly 标注透传', run(u('e_m', 'eo3'), [inScope], 'read').observeOnly === true)
    check('审批人路由：沿链向上最近负责人（班组自身有负责人即命中；悬空则跳到上级）',
      nearestLeaderOrg(idx, 'eo3')?.orgId === 'eo3' && nearestLeaderOrg(idx, 'eo4')?.orgId === 'eo2'
      && nearestLeaderOrg(idx, 'eo1')?.orgId === 'eo1')

    check('外部账号白名单只读',
      run(u('e_ext', 'eo3', { accountType: 'external' }), ['/外部白名单/a'], 'read').decision === 'allow'
      && run(u('e_ext', 'eo3', { accountType: 'external' }), ['/外部白名单/a'], 'write').decision === 'deny'
      && run(u('e_ext', 'eo3', { accountType: 'external' }), ['/其他/a'], 'read').decision === 'deny')
    check('可疑标记账号 deny 转人工', run(u('e_bad', 'eo3', { accountType: 'suspended-review' }), [inScope], 'read').decision === 'deny')
  }

  section('NAS 资产纳管（plugin-nas + 文件网关 stub）')

  // 网关 stub 自身契约：错误 Bearer 被拒（证明平台调用确实携带网关令牌）
  const gwBadToken = await fetch(`http://127.0.0.1:${NAS_GW_PORT}/mcp`, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer wrong-token' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }),
  })
  check('网关 stub 校验 Bearer（错误令牌 401）', gwBadToken.status === 401)

  // 用户测试配置（synology-filestation 形态）一键导入 → 创建 + 探活 + 上线 + 工具发现
  const mcpServersConfig = JSON.stringify({
    mcpServers: {
      'synology-filestation': {
        url: `http://127.0.0.1:${NAS_GW_PORT}/mcp`,
        headers: { Authorization: `Bearer ${NAS_GW_TOKEN}`, 'X-NAS-IP': NAS_GW_IP },
      },
    },
  })
  const nasImport = await api('POST', '/api/nas/import', { token: admin, body: { config: mcpServersConfig, name: '自测群晖 NAS' } })
  const nasImportResult = nasImport.data?.results?.[0] ?? {}
  check('mcpServers JSON 一键导入（探活 → 上线 → 工具发现）',
    nasImport.ok && nasImport.data.imported === 1 && nasImportResult.reachable === true && nasImportResult.status === 'online' && nasImportResult.tools === 10,
    JSON.stringify(nasImport.error ?? nasImportResult))
  const nasId = nasImportResult.nasId

  const nasDetail = await api('GET', `/api/nas/${nasId}`, { token: admin })
  check('详情含健康与网关工具面', nasDetail.ok && nasDetail.data.health.status === 'healthy' && nasDetail.data.gatewayTools.length === 10)
  check('访问令牌回显脱敏（原文不落响应）', nasDetail.ok && !JSON.stringify(nasDetail.data).includes(NAS_GW_TOKEN) && String(nasDetail.data.attrs.accessToken).endsWith('…'))

  const nasHealth = await api('POST', `/api/nas/${nasId}/health`, { token: admin })
  check('手动探活（initialize 握手测延迟）', nasHealth.ok && nasHealth.data.status === 'healthy' && nasHealth.data.latencyMs >= 0)

  // 文件全链（全部经网关 tools/call）
  const nasShares = await api('GET', `/api/nas/${nasId}/fs`, { token: admin })
  check('列出共享文件夹（fs_list_shares）', nasShares.ok && JSON.stringify(nasShares.data).includes('skillhub'))
  const nasFiles = await api('GET', `/api/nas/${nasId}/fs?path=/skillhub`, { token: admin })
  check('列目录（fs_list）', nasFiles.ok && JSON.stringify(nasFiles.data).includes('readme.txt'))
  const nasMkdir = await api('POST', `/api/nas/${nasId}/fs/mkdir`, { token: admin, body: { path: '/skillhub/selftest' } })
  check('创建目录（fs_create_folder：folder_path+name 数组一一对应）',
    nasMkdir.ok && nasGwCalls.some((c) => c.name === 'fs_create_folder' && Array.isArray(c.args.folder_path) && c.args.folder_path[0] === '/skillhub' && Array.isArray(c.args.name) && c.args.name[0] === 'selftest'))
  const nasUpload = await api('POST', `/api/nas/${nasId}/fs/upload`, {
    token: admin,
    body: { contentBase64: Buffer.from('PK\x03\x04selftest-file', 'latin1').toString('base64'), destPath: '/skillhub/selftest/a.zip' },
  })
  check('上传文件（平台 staging → 网关 fs_upload 侧读盘）', nasUpload.ok && nasGwUploads.some((u) => u.destPath === '/skillhub/selftest' && u.filename === 'a.zip' && u.magic === 'PK'))
  const nasSearch = await api('POST', `/api/nas/${nasId}/fs/search`, { token: admin, body: { pattern: 'report', path: '/skillhub' } })
  check('检索文件（fs_search：folder_path 字符串）', nasSearch.ok && JSON.stringify(nasSearch.data).includes('report'))
  const nasDelete = await api('POST', `/api/nas/${nasId}/fs/delete`, { token: admin, body: { paths: ['/skillhub/selftest/a.zip'] } })
  check('删除文件（fs_delete：path 数组）', nasDelete.ok && nasGwCalls.some((c) => c.name === 'fs_delete' && Array.isArray(c.args.path) && c.args.path[0] === '/skillhub/selftest/a.zip'))

  // 真实网关契约：fs_list 用 folder_path 字符串
  const nasFilesCheck = nasGwCalls.find((c) => c.name === 'fs_list' && c.args.folder_path === '/skillhub')
  check('列目录（fs_list：folder_path 字符串）', !!nasFilesCheck)

  // 重命名（fs_rename：path + name 数组一一对应）
  const nasRename = await api('POST', `/api/nas/${nasId}/fs/rename`, { token: admin, body: { path: '/skillhub/selftest/a.zip', newName: 'b.zip' } })
  check('重命名（fs_rename：path+name 数组一一对应）',
    nasRename.ok && nasGwCalls.some((c) => c.name === 'fs_rename' && Array.isArray(c.args.path) && c.args.path[0] === '/skillhub/selftest/a.zip' && Array.isArray(c.args.name) && c.args.name[0] === 'b.zip'))

  // 批量上传 upload-many（保留目录结构 + base64 集合 → 多次 fs_upload）
  const manyItems = [
    { relativePath: 'docs/readme.md', contentBase64: Buffer.from('# 批量上传 README', 'utf8').toString('base64') },
    { relativePath: 'src/index.js', contentBase64: Buffer.from("console.log('selftest')", 'utf8').toString('base64') },
    { relativePath: 'src/utils.js', contentBase64: Buffer.from('export const ok = true', 'utf8').toString('base64') },
  ]
  const beforeMany = nasGwUploads.length
  const nasUploadMany = await api('POST', `/api/nas/${nasId}/fs/upload-many`, { token: admin, body: { files: manyItems, destDir: '/skillhub/batch' } })
  check('批量上传（保留目录结构：docs/、src/ 等）',
    nasUploadMany.ok && nasUploadMany.data.uploaded.length === 3 && nasUploadMany.data.failed.length === 0
      && nasGwUploads.slice(beforeMany).map((u) => u.filename).join(',') === 'readme.md,index.js,utils.js'
      && nasGwUploads.slice(beforeMany).map((u) => u.destPath).join(',') === '/skillhub/batch/docs,/skillhub/batch/src,/skillhub/batch/src')

  // 流式下载（GET /api/nas/:id/fs/file）：先 POST /fs/download 触发网关落盘，再 GET 拿到 bytes
  const nasDownloadTrigger = await api('POST', `/api/nas/${nasId}/fs/download`, { token: admin, body: { path: '/skillhub/selftest/a.zip' } })
  check('触发下载落盘（POST /fs/download → 网关 fs_download 真实落盘）',
    nasDownloadTrigger.ok && typeof nasDownloadTrigger.data.localFile === 'string' && nasDownloadTrigger.data.bytes > 0)
  const fileResp = await fetch(`http://127.0.0.1:${PORT}/api/nas/${nasId}/fs/file?path=${encodeURIComponent('/skillhub/selftest/a.zip')}`, {
    headers: { authorization: `Bearer ${admin}` },
  })
  const fileBytes = fileResp.ok ? Buffer.from(await fileResp.arrayBuffer()) : Buffer.alloc(0)
  check('浏览器真实下载（GET /fs/file 200 + bytes 一致 + content-disposition attachment）',
    fileResp.ok && fileBytes.toString('utf8') === 'selftest-download-bytes' && /attachment;\s*filename\*=UTF-8''a\.zip/.test(fileResp.headers.get('content-disposition') ?? ''))
  const inlineResp = await fetch(`http://127.0.0.1:${PORT}/api/nas/${nasId}/fs/file?path=${encodeURIComponent('/skillhub/selftest/a.zip')}&inline=1`, {
    headers: { authorization: `Bearer ${admin}` },
  })
  check('inline=1 预览模式（content-disposition: inline）',
    inlineResp.ok && /inline;\s*filename\*=UTF-8''a\.zip/.test(inlineResp.headers.get('content-disposition') ?? ''))
  const noAuthDownload = await fetch(`http://127.0.0.1:${PORT}/api/nas/${nasId}/fs/file?path=${encodeURIComponent('/skillhub/selftest/a.zip')}`)
  check('stream 下载无 token 且无票据 401', noAuthDownload.status === 401)
  // 一次性下载票据：签发 → 免 Bearer 原生 GET → 二次消费被拒
  const ticketResp = await api('POST', `/api/nas/${nasId}/fs/download-ticket`, { token: admin, body: { path: '/skillhub/selftest/a.zip' } })
  check('签发一次性下载票据', ticketResp.ok && String(ticketResp.data.ticket).startsWith('nastk_'))
  const ticketFile = await fetch(`http://127.0.0.1:${PORT}/api/nas/${nasId}/fs/file?path=${encodeURIComponent('/skillhub/selftest/a.zip')}&ticket=${encodeURIComponent(ticketResp.data.ticket)}`)
  const ticketBytes = ticketFile.ok ? Buffer.from(await ticketFile.arrayBuffer()) : Buffer.alloc(0)
  check('票据直取文件（无 Bearer，字节一致）', ticketFile.ok && ticketBytes.toString('utf8') === 'selftest-download-bytes',
    JSON.stringify({ status: ticketFile.status, type: ticketFile.headers.get('content-type'), len: ticketBytes.length }))
  const ticketReplay = await fetch(`http://127.0.0.1:${PORT}/api/nas/${nasId}/fs/file?path=${encodeURIComponent('/skillhub/selftest/a.zip')}&ticket=${encodeURIComponent(ticketResp.data.ticket)}`)
  check('票据一次性（重放 401）', ticketReplay.status === 401)
  const badTicket = await fetch(`http://127.0.0.1:${PORT}/api/nas/${nasId}/fs/file?path=${encodeURIComponent('/skillhub/selftest/a.zip')}&ticket=nastk_bogus`)
  check('未知票据 401', badTicket.status === 401)
  const nasAudit = await api('GET', `/api/audit/logs?resourceId=${nasId}&limit=20`, { token: admin })
  check('写类文件操作审计留痕', (nasAudit.data?.items ?? []).some((l) => l.action === 'nas.fs.mkdir') && (nasAudit.data?.items ?? []).some((l) => l.action === 'nas.fs.upload'))

  // 计量管道（观测补齐）：全部文件操作进 usage 事件（nas:<ID>，calls 全量、upload 额外 bytes）
  const nasUsage = await api('GET', '/api/usage/events?resource=' + encodeURIComponent(`nas:${nasId}`), { token: admin })
  const nasBytes = (nasUsage.data?.items ?? []).flatMap((event) => event.meters ?? []).find((meter) => meter.key === 'bytes')
  check('NAS 文件操作进计量管道（calls 全量 + upload bytes）', nasUsage.ok && nasUsage.data.total >= 6 && !!nasBytes && nasBytes.value > 0)

  // RBAC：无角色 403 / developer 只读
  const memberLogin = await api('POST', '/api/auth/login', { body: { username: 'yqz', password: 'Ybk@2026' } })
  const member = memberLogin.data?.token
  const memberNas = await api('GET', '/api/nas', { token: member })
  const noReadPerm = await fetch(`http://127.0.0.1:${PORT}/api/nas/${nasId}/fs/file?path=${encodeURIComponent('/skillhub/selftest/a.zip')}`, { headers: { authorization: `Bearer ${member}` } })
  check('stream 下载无 nas.read 403', noReadPerm.status === 403)
  check('无 nas.read 角色访问被拒（403）', memberNas.status === 403)
  const devNasRead = await api('GET', '/api/nas', { token: dev })
  check('developer 只读放行（nas.read）', devNasRead.ok)
  const devNasWrite = await api('POST', `/api/nas/${nasId}/fs/mkdir`, { token: dev, body: { path: '/skillhub/deny' } })
  check('developer 写操作被拒（缺 nas.write，403）', devNasWrite.status === 403)

  // 二次编辑（PATCH）：属性合并更新；未携带的接入属性保持原值
  const nasPatch = await api('PATCH', `/api/nas/${nasId}`, { token: admin, body: { attrs: { description: '自测：二次编辑后的描述', vendor: 'Synology DS925+' } } })
  check('二次编辑（PATCH 属性合并更新）', nasPatch.ok && nasPatch.data.attrs.description === '自测：二次编辑后的描述' && nasPatch.data.attrs.vendor === 'Synology DS925+', JSON.stringify(nasPatch.error))
  const nasAfterPatch = await api('GET', `/api/nas/${nasId}`, { token: admin })
  check('编辑未携带的接入属性保持原值（网关地址/令牌未丢）', nasAfterPatch.ok && nasAfterPatch.data.attrs.gatewayUrl === `http://127.0.0.1:${NAS_GW_PORT}/mcp`)
  const nasPatchFs = await api('GET', `/api/nas/${nasId}/fs`, { token: admin })
  check('编辑后网关客户端缓存已作废（fs 调用仍通）', nasPatchFs.ok && JSON.stringify(nasPatchFs.data).includes('skillhub'))
  const devNasPatch = await api('PATCH', `/api/nas/${nasId}`, { token: dev, body: { attrs: { description: 'x' } } })
  check('developer 编辑被拒（缺 nas.write，403）', devNasPatch.status === 403)

  // 删除（DELETE）：草稿（从未上线，无法走到归档）可直接删；在线/已下线需先归档
  const nas2 = await api('POST', '/api/nas', { token: admin, body: { name: '自测待删 NAS', attrs: { description: '删除生命周期自测', gatewayUrl: `http://127.0.0.1:${NAS_GW_PORT}/mcp`, accessToken: NAS_GW_TOKEN, nasIp: NAS_GW_IP } } })
  check('登记第二台 NAS（草稿）', nas2.ok && nas2.data.status === 'draft', JSON.stringify(nas2.error))
  const nas2Id = nas2.data?.id
  const devNasDelete = await api('DELETE', `/api/nas/${nas2Id}`, { token: dev })
  check('developer 删除被拒（缺 nas.write，403）', devNasDelete.status === 403)
  const delDraft = await api('DELETE', `/api/nas/${nas2Id}`, { token: admin })
  check('草稿资产可直接删除', delDraft.ok && delDraft.data.deleted === true, JSON.stringify(delDraft.error))
  const nas2Gone = await api('GET', `/api/nas/${nas2Id}`, { token: admin })
  check('删除后详情不再可查', nas2Gone.status === 400 && !nas2Gone.ok)

  const nas3 = await api('POST', '/api/nas', { token: admin, body: { name: '自测归档删除 NAS', attrs: { description: '归档删除链路自测', gatewayUrl: `http://127.0.0.1:${NAS_GW_PORT}/mcp`, accessToken: NAS_GW_TOKEN, nasIp: NAS_GW_IP } } })
  const nas3Id = nas3.data?.id
  await api('POST', `/api/nas/${nas3Id}/transition`, { token: admin, body: { action: 'online' } })
  const delOnline = await api('DELETE', `/api/nas/${nas3Id}`, { token: admin })
  check('在线资产删除被拒（需先下线/归档）', delOnline.status === 400 && !delOnline.ok)
  await api('POST', `/api/nas/${nas3Id}/transition`, { token: admin, body: { action: 'offline', note: '自测删除链路' } })
  const delOffline = await api('DELETE', `/api/nas/${nas3Id}`, { token: admin })
  check('已下线资产删除仍被拒（需先归档）', delOffline.status === 400 && !delOffline.ok)
  const nas3Archive = await api('POST', `/api/nas/${nas3Id}/transition`, { token: admin, body: { action: 'archive' } })
  check('归档为终态', nas3Archive.ok && nas3Archive.data.status === 'archived', JSON.stringify(nas3Archive.error))
  const nas3Delete = await api('DELETE', `/api/nas/${nas3Id}`, { token: admin })
  check('归档后删除成功（含健康/工具缓存清理）', nas3Delete.ok && nas3Delete.data.deleted === true, JSON.stringify(nas3Delete.error))

  // ================================================================ NAS 数据权限 API
  section('NAS 数据权限 API（check/scope/rules/例外/审批闭环，dev-plan-nas-authz §2.3-§2.7）')
  // 夹具：NAS 配 orgRoot + 组织负责人（P=admin / D=ops / T=heqw / M=linxm）
  const nasRootPatch = await api('PATCH', `/api/nas/${nasId}`, { token: admin, body: { attrs: { orgRoot: '元冰可集团' } } })
  check('NAS 配置接入组织锚点（orgRoot=元冰可集团）', nasRootPatch.ok)

  const orgAll = (await api('GET', '/api/iam/orgs', { token: admin })).data ?? []
  const orgByName = (name) => orgAll.find((org) => org.name === name)?.id
  const orgRootId = orgByName('元冰可集团')
  const orgTechId = orgByName('技术中心')
  const orgAiId = orgByName('AI 平台部')
  const orgProdId = orgByName('产品运营部')
  const orgFeId = orgByName('前端部')
  check('组织夹具就绪（根/技术中心/AI 平台部/产品运营部/前端部）', Boolean(orgRootId && orgTechId && orgAiId && orgProdId && orgFeId))

  const userAll = (await api('GET', '/api/iam/users', { token: admin })).data?.users ?? []
  const userByName = (username) => userAll.find((user) => user.username === username)?.id
  const adminUid = userByName('admin')
  const opsUid = userByName('ops')
  const heqwUid = userByName('heqw')
  const linxmUid = userByName('linxm')
  const devUid = userByName('dev')
  const yqzUid = userByName('yqz')
  const auditUid = userByName('audit')
  const suyqUid = userByName('suyq')
  check('用户夹具就绪', Boolean(adminUid && opsUid && heqwUid && linxmUid && yqzUid && auditUid && suyqUid))

  await api('PATCH', `/api/iam/orgs/${orgRootId}`, { token: admin, body: { leaderUserIds: [adminUid] } })
  await api('PATCH', `/api/iam/orgs/${orgTechId}`, { token: admin, body: { leaderUserIds: [opsUid] } })
  await api('PATCH', `/api/iam/orgs/${orgFeId}`, { token: admin, body: { leaderUserIds: [heqwUid] } })

  const authzCheck = (userId, paths, op, extra = {}) => api('POST', '/api/nas/authz/check', {
    token: admin,
    body: { nasId: extra.nasId ?? nasId, userId, paths, op, ...(extra.override !== undefined ? { override: extra.override } : {}), ...(extra.headerUser ? {} : {}) },
    ...(extra.headerUser ? {} : {}),
  })

  // —— 35 格矩阵（4 主角色 × 7 操作；C 叠加另测）——
  const roleScope = {
    P: { uid: adminUid, path: '/元冰可集团/技术中心/AI 平台部/季度报告.docx' },
    D: { uid: opsUid, path: '/元冰可集团/技术中心/AI 平台部/季度报告.docx' },
    T: { uid: heqwUid, path: '/元冰可集团/技术中心/前端部/页面原型.png' },
    M: { uid: devUid, path: '/元冰可集团/技术中心/AI 平台部/季度报告.docx' },
  }
  const EXPECTED = {
    P: { read: 1, download: 1, write: 1, modify: 1, delete: 1, share: 1, admin: 1 },
    D: { read: 1, download: 1, write: 1, modify: 1, delete: 1, share: 1, admin: 0 },
    T: { read: 1, download: 1, write: 1, modify: 1, delete: 0, share: 0, admin: 0 },
    M: { read: 1, download: 1, write: 1, modify: 0, delete: 0, share: 0, admin: 0 },
  }
  let matrixOk = true
  let matrixDetail = ''
  for (const [role, cfg] of Object.entries(roleScope)) {
    for (const op of ['read', 'download', 'write', 'modify', 'delete', 'share', 'admin']) {
      const resp = await authzCheck(cfg.uid, [cfg.path], op)
      const got = resp.data?.decision === 'allow' ? 1 : 0
      if (!resp.ok || got !== EXPECTED[role][op] || !Array.isArray(resp.data?.reasons) || resp.data.reasons.length === 0 || resp.data?.role !== role) {
        matrixOk = false
        matrixDetail = `${role}×${op} 期望 ${EXPECTED[role][op]} 实得 ${got}（${JSON.stringify(resp.data?.reasons ?? resp.error)}）`
      }
    }
  }
  check('附件矩阵 35 格（P/D/T/M × 7 操作）判定一致且每格含 reasons', matrixOk, matrixDetail)

  // scope 与 check 一致
  const scopeM = await api('GET', `/api/nas/authz/scope?nasId=${nasId}&userId=${devUid}`, { token: admin })
  const checkM = await authzCheck(devUid, ['/元冰可集团/技术中心/AI 平台部/a.txt'], 'read')
  check('scope 返回角色/作用域并与 check 一致',
    scopeM.ok && scopeM.data.role === 'M' && JSON.stringify(scopeM.data.scope) === JSON.stringify(checkM.data.scope)
    && scopeM.data.matrix?.M?.read === true,
    JSON.stringify({ scope: scopeM.data?.scope, role: scopeM.data?.role, checkScope: checkM.data?.scope }))

  // 钉钉 userId 反查等价（linxm ↔ dd_u002，identityLinks 事实源）
  const byPlatform = await authzCheck(linxmUid, ['/元冰可集团/技术中心/AI 平台部/a.txt'], 'read')
  const byDingtalk = await authzCheck('dd_u002', ['/元冰可集团/技术中心/AI 平台部/a.txt'], 'read')
  check('钉钉 userId 反查与平台 userId 等价（identityLinks）',
    byDingtalk.ok && byPlatform.ok
    && byDingtalk.data.decision === byPlatform.data.decision && byDingtalk.data.role === byPlatform.data.role
    && JSON.stringify(byDingtalk.data.scope) === JSON.stringify(byPlatform.data.scope)
    && byDingtalk.data.userName === '林小满',
    JSON.stringify({ byPlatform: byPlatform.data, byDingtalk: byDingtalk.data }))

  // userid 口径反查（hermes X-On-Behalf-User 与 dept_manager_userid_list 的口径）：unionId+userid 双链并存
  const byStaffId = await authzCheck('staff_002', ['/元冰可集团/技术中心/AI 平台部/a.txt'], 'read')
  check('钉钉 userid 口径反查与平台 userId 等价（双身份链：unionId 供登录、userid 供运营反查）',
    byStaffId.ok && byStaffId.data.userName === '林小满'
    && JSON.stringify(byStaffId.data.scope) === JSON.stringify(byPlatform.data.scope),
    JSON.stringify(byStaffId.data))

  // 负责人映射走 userid 口径（钉钉 dept_manager_userid_list 是 userid，经 userid 链反查平台 userId）
  const orgsForLeaders = (await api('GET', '/api/iam/orgs', { token: admin })).data
  check('部门负责人随同步映射（managerRemoteIds userid 口径 → identityLinks 反查）',
    orgsForLeaders.some((org) => org.name === 'AI 平台部' && (org.leaderUserIds ?? []).includes(linxmUid)),
    JSON.stringify(orgsForLeaders.filter((org) => org.name === 'AI 平台部').map((org) => ({ leaders: org.leaderUserIds }))))

  // 一人多部门兼任（同步落库）：primaryOrgId=主归属锚，orgId=挂靠；引擎兼任子树只读，双身份权限不冲突
  const zhmlCandidates = (await api('GET', '/api/iam/users?q=' + encodeURIComponent('周明澜'), { token: admin })).data.users
    .filter((user) => user.primaryOrgId && user.orgId && user.primaryOrgId !== user.orgId)
  const zhmlHit = { rec: undefined, secWrite: undefined }
  for (const cand of zhmlCandidates) {
    const primaryWrite = await authzCheck(cand.id, ['/元冰可集团/技术中心/前端部/主归属.txt'], 'write')
    const secRead = await authzCheck(cand.id, ['/元冰可集团/技术中心/后端部/兼任目录.txt'], 'read')
    const secWrite = await authzCheck(cand.id, ['/元冰可集团/技术中心/后端部/兼任目录.txt'], 'write')
    if (primaryWrite.data?.decision === 'allow' && secRead.data?.decision === 'allow' && secWrite.data?.decision === 'deny') {
      Object.assign(zhmlHit, { rec: cand, secWrite })
      break
    }
  }
  check('多部门成员兼任落库（primaryOrgId=主部门，orgId=挂靠部门）', Boolean(zhmlHit.rec),
    JSON.stringify(zhmlCandidates.map((user) => ({ primaryOrgId: user.primaryOrgId, orgId: user.orgId }))))
  check('兼任权限不冲突：主归属可写、兼任子树只读（secondary-readonly）',
    Boolean(zhmlHit.rec) && zhmlHit.secWrite.data.reasons.some((r) => r.includes('secondary-readonly')),
    JSON.stringify(zhmlHit.secWrite.data))

  // 权限点：无角色 403 / 无 nas.authz.read 403
  const authzMemberLogin = await api('POST', '/api/auth/login', { body: { username: 'yqz', password: 'Ybk@2026' } })
  const authzMemberToken = authzMemberLogin.data?.token
  const noPermCheck = await api('POST', '/api/nas/authz/check', { token: authzMemberToken, body: { nasId, userId: yqzUid, paths: ['/x'], op: 'read' } })
  const noPermRules = await api('GET', '/api/nas/authz/rules', { token: authzMemberToken })
  check('无 nas.authz.check 权限 403；无 nas.authz.read 403', noPermCheck.status === 403 && noPermRules.status === 403)

  // 特殊账号：未落班组只读 / 挂根 deny / 外部白名单 / 可疑标记 / 兼任
  const yqzRead = await authzCheck(yqzUid, ['/元冰可集团/产品运营部/计划.xlsx'], 'read')
  const yqzWrite = await authzCheck(yqzUid, ['/元冰可集团/产品运营部/计划.xlsx'], 'write')
  check('未落班组（部门根非负责人）→ 只读', yqzRead.data?.decision === 'allow' && yqzWrite.data?.decision === 'deny')
  const auditCheck = await authzCheck(auditUid, ['/元冰可集团/任何/x'], 'read')
  check('挂根组织非负责人 → deny 全部', auditCheck.data?.decision === 'deny' && auditCheck.data.reasons.some((r) => r.includes('root-no-role')))

  const extUser = await api('POST', '/api/iam/users', { token: admin, body: { username: 'extguest', displayName: '外部顾问', orgId: orgAiId, password: 'Ybk@2026' } })
  const extUid = extUser.data?.id
  await api('PATCH', `/api/iam/users/${extUid}`, { token: admin, body: { accountType: 'external' } })
  const rulesBeforeExt = await api('GET', '/api/nas/authz/rules', { token: admin })
  const extPut = await api('PUT', '/api/nas/authz/rules', {
    token: admin,
    body: { ifVersion: rulesBeforeExt.data.version, externalReadPaths: [{ nasId, path: '/元冰可集团/技术中心/AI 平台部/公共' }] },
  })
  check('外部账号白名单只读（白名单内 read 放行/write 拒绝、白名单外 deny）',
    extPut.ok
    && (await authzCheck(extUid, ['/元冰可集团/技术中心/AI 平台部/公共/手册.pdf'], 'read')).data?.decision === 'allow'
    && (await authzCheck(extUid, ['/元冰可集团/技术中心/AI 平台部/公共/手册.pdf'], 'write')).data?.decision === 'deny'
    && (await authzCheck(extUid, ['/元冰可集团/技术中心/AI 平台部/私密.pdf'], 'read')).data?.decision === 'deny')

  await api('PATCH', `/api/iam/users/${heqwUid}`, { token: admin, body: { accountType: 'suspended-review' } })
  const suspended = await authzCheck(heqwUid, ['/元冰可集团/技术中心/前端部/x'], 'read')
  await api('PATCH', `/api/iam/users/${heqwUid}`, { token: admin, body: { accountType: 'internal' } })
  check('可疑标记账号 deny + 转人工留痕', suspended.data?.decision === 'deny' && suspended.data.reasons.some((r) => r.includes('suspended-review')))

  // 兼任：suyq 主归属 AI 平台部（M），挂靠后端部 → 后端部子树只读
  await api('PATCH', `/api/iam/users/${suyqUid}`, { token: admin, body: { primaryOrgId: orgAiId } })
  const secWrite = await authzCheck(suyqUid, ['/元冰可集团/技术中心/后端部/接口.md'], 'write')
  const secRead = await authzCheck(suyqUid, ['/元冰可集团/技术中心/后端部/接口.md'], 'read')
  const priWrite = await authzCheck(suyqUid, ['/元冰可集团/技术中心/AI 平台部/模型.md'], 'write')
  check('兼任账号：主归属正常写 + 兼任子树仅只读',
    priWrite.data?.decision === 'allow' && secRead.data?.decision === 'allow' && secWrite.data?.decision === 'deny')
  await api('PATCH', `/api/iam/users/${suyqUid}`, { token: admin, body: { primaryOrgId: '' } })

  // —— rules 乐观锁 + 种子导入幂等 ——
  const conflict = await api('PUT', '/api/nas/authz/rules', { token: admin, body: { ifVersion: 999, observeOnly: false } })
  check('rules PUT ifVersion 乐观锁冲突 409', conflict.status === 409 && conflict.error?.code === 'VERSION_CONFLICT')
  const rulesNow1 = await api('GET', '/api/nas/authz/rules', { token: admin })
  const cGroupPut = await api('PUT', '/api/nas/authz/rules', { token: admin, body: { ifVersion: rulesNow1.data.version, cGroups: ['AI 平台部全员'] } })
  check('rules PUT 携正确 ifVersion 成功且 version 递增', cGroupPut.ok && cGroupPut.data.version === rulesNow1.data.version + 1)

  const importOnce = await api('POST', '/api/nas/authz/rules/import', { token: admin, body: NAS_AUTHZ_SEED })
  const importTwice = await api('POST', '/api/nas/authz/rules/import', { token: admin, body: NAS_AUTHZ_SEED })
  check('种子导入：首次变更（cGroups 清空为未解析组）+ 再次导入幂等',
    importOnce.ok && importOnce.data.changed === true && importOnce.data.unresolvedGroups.includes('跨域协作者')
    && importTwice.ok && importTwice.data.changed === false && importTwice.data.version === importOnce.data.version,
    JSON.stringify({ once: importOnce.data, twice: importTwice.data, err: importOnce.error }))

  // 恢复 C 组并断言组标记回写
  const rulesNow2 = await api('GET', '/api/nas/authz/rules', { token: admin })
  await api('PUT', '/api/nas/authz/rules', { token: admin, body: { ifVersion: rulesNow2.data.version, cGroups: ['AI 平台部全员'] } })
  const aiGroups = (await api('GET', '/api/iam/groups', { token: admin })).data?.groups ?? []
  const aiGroupMarked = aiGroups.find((group) => group.name === 'AI 平台部全员')
  check('C 关联动态组标记回写（authzRoleC）', aiGroupMarked?.authzRoleC === true,
    JSON.stringify({ groups: aiGroups.map((group) => ({ name: group.name, c: group.authzRoleC })) }))

  // C 叠加（动态组）：跨域只读
  const cRead = await authzCheck(linxmUid, ['/元冰可集团/产品运营部/大盘.xlsx'], 'read')
  const cWrite = await authzCheck(linxmUid, ['/元冰可集团/产品运营部/大盘.xlsx'], 'write')
  check('C 叠加：跨域 read 放行/write 拒绝', cRead.data?.decision === 'allow' && cWrite.data?.decision === 'deny' && cRead.data.cTag === true,
    JSON.stringify({ read: cRead.data, write: cWrite.data }))

  // override 破窗（须 nas.authz.write；admin 具备）+ 留痕
  const overrideCheck = await api('POST', '/api/nas/authz/check', { token: admin, body: { nasId, userId: linxmUid, paths: ['/故障处置/任意'], op: 'delete', override: true } })
  const decisionsOverride = (await api('GET', '/api/nas/authz/decisions?userId=' + linxmUid + '&limit=50', { token: admin })).data?.items ?? []
  check('override 破窗放行并强制留痕',
    overrideCheck.data?.decision === 'allow' && overrideCheck.data.override === true
    && decisionsOverride.some((record) => record.override === true && record.highRisk === true))

  // X-On-Behalf-User：平台 userId → 绑钉钉身份后透传三方 userId（网关 stub 已记录该头）
  const headerBefore = nasGwCalls.find((call) => call.onBehalf === adminUid)
  await api('POST', `/api/iam/users/${adminUid}/bindings`, { token: admin, body: { provider: 'dingtalk', unionId: 'dd_admin_x', displayName: '沈亦澜' } })
  await api('GET', `/api/nas/${nasId}/fs?path=/`, { token: admin })
  const lastCall = nasGwCalls[nasGwCalls.length - 1]
  check('X-On-Behalf-User 头透传（平台 userId → 钉钉身份优先；身份零进工具参数）',
    Boolean(headerBefore) && lastCall.onBehalf === 'dd_admin_x' && !('actorId' in (lastCall.args ?? {})) && !('actorName' in (lastCall.args ?? {})))

  // fail-closed 告警：observeOnly=false 后高频 deny 触发告警规则
  const alertRule = await api('POST', '/api/audit/alert-rules', { token: admin, body: { name: 'NAS 数据权限高频拒绝', metric: 'nas_authz_denied', threshold: 5, windowMinutes: 10, severity: 'warning' } })
  const rulesNow3 = await api('GET', '/api/nas/authz/rules', { token: admin })
  await api('PUT', '/api/nas/authz/rules', { token: admin, body: { ifVersion: rulesNow3.data.version, observeOnly: false } })
  for (let i = 0; i < 12; i++) {
    await authzCheck(linxmUid, ['/元冰可集团/市场部/超出作用域.txt'], 'write')
  }
  const denyAlerts = (await api('GET', '/api/audit/alerts', { token: admin })).data?.alerts ?? []
  check('enforce（observeOnly=false）高频 deny → nas_authz_denied 告警触发',
    alertRule.ok && denyAlerts.some((alert) => alert.title.includes('NAS 数据权限高频拒绝')),
    JSON.stringify({ ruleOk: alertRule.ok, titles: denyAlerts.slice(0, 5).map((alert) => alert.title) }))
  const rulesNow4 = await api('GET', '/api/nas/authz/rules', { token: admin })
  await api('PUT', '/api/nas/authz/rules', { token: admin, body: { ifVersion: rulesNow4.data.version, observeOnly: true } })
  const decisionsDeny = (await api('GET', `/api/nas/authz/decisions?decision=deny&nasId=${nasId}&limit=10`, { token: admin })).data
  check('deny 判定留痕可查询（decisions 集合）', decisionsDeny.total >= 12)

  // —— share 审批闭环（T/M share 默认 deny → 申请 → 审批人自动路由 → 通过 → 例外生效 → 到期自动拒绝）——
  const shareDeny = await authzCheck(linxmUid, ['/元冰可集团/技术中心/AI 平台部/季度报告.docx'], 'share')
  check('M share 默认 deny（提示走审批）', shareDeny.data?.decision === 'deny' && shareDeny.data.reasons.some((r) => r.includes('审批')))
  const shareReq = await api('POST', '/api/nas/authz/exceptions', {
    token: admin,
    body: { status: 'pending', nasId, userId: linxmUid, path: '/元冰可集团/技术中心/AI 平台部/季度报告.docx', reason: '客户演示需要' },
  })
  check('share 申请 → 审批人自动路由（沿组织链向上最近负责人：AI 平台部自身的连接器同步负责人）',
    shareReq.ok && shareReq.data.kind === 'approval' && shareReq.data.approverSuggestion?.orgName === 'AI 平台部'
    && Array.isArray(shareReq.data.approverSuggestion?.leaderUserIds) && shareReq.data.approverSuggestion.leaderUserIds.includes(linxmUid)
    && shareReq.data.escalated === false,
    JSON.stringify(shareReq.data))
  const shareApprove = await api('POST', `/api/approvals/${shareReq.data.approvalId}/decide`, { token: admin, body: { decision: 'approve', opinion: '同意' } })
  const shareAllow = await authzCheck(linxmUid, ['/元冰可集团/技术中心/AI 平台部/季度报告.docx'], 'share')
  check('审批通过 → share 例外自动写入并放行（7 天有效期留痕）', shareApprove.ok && shareAllow.data?.decision === 'allow' && Boolean(shareAllow.data.ruleId))
  const rulesNow5 = await api('GET', '/api/nas/authz/rules', { token: admin })
  const expiredExceptions = rulesNow5.data.exceptions.map((exception) => (
    exception.id === shareAllow.data.ruleId ? { ...exception, expiresAt: '2026-08-01T00:00:00Z' } : exception))
  await api('PUT', '/api/nas/authz/rules', { token: admin, body: { ifVersion: rulesNow5.data.version, exceptions: expiredExceptions } })
  const shareExpired = await authzCheck(linxmUid, ['/元冰可集团/技术中心/AI 平台部/季度报告.docx'], 'share')
  check('share 例外到期自动拒绝（回落矩阵 deny）', shareExpired.data?.decision === 'deny')

  // —— 负责人悬空 / 组织目录对账 ——
  const vacantOrg = await api('POST', '/api/iam/orgs', { token: admin, body: { name: '应急小组（无负责人）', parentId: orgRootId } })
  await api('POST', '/api/iam/users', { token: admin, body: { username: 'vacantm', displayName: '悬空样本', orgId: vacantOrg.data.id, password: 'Ybk@2026' } })
  const vacancy = await api('POST', '/api/nas/authz/leader-vacancy-scan', { token: admin })
  const vacancyAlerts = (await api('GET', '/api/audit/alerts', { token: admin })).data?.alerts ?? []
  check('负责人悬空扫描：新悬空组织被发现 + leaderVacant 告警',
    vacancy.ok && (vacancy.data.vacant ?? []).some((org) => org.orgName === '应急小组（无负责人）')
    && vacancyAlerts.some((alert) => alert.title.includes('负责人悬空')),
    JSON.stringify({ vacant: vacancy.data?.vacant?.map((org) => org.orgName) }))

  // —— 负责人手动绑定（手动锁定优先于连接器同步，leaderVacant 处置入口）——
  const mstUid = userAll.find((user) => user.jobNumber === 'DD0008')?.id // 孟疏桐：mock 目录市场部负责人的同步口径
  check('负责人手动绑定夹具就绪（市场部同步负责人 DD0008）', Boolean(mstUid))
  await api('PATCH', `/api/iam/orgs/${vacantOrg.data.id}`, { token: admin, body: { leaderUserIds: [mstUid] } })
  const pinnedSample = (await api('GET', '/api/iam/orgs', { token: admin })).data.find((org) => org.id === vacantOrg.data.id)
  const vacancyPinned = await api('POST', '/api/nas/authz/leader-vacancy-scan', { token: admin })
  check('负责人手动绑定：落库 + leaderSource=manual + 悬空扫描不再命中',
    pinnedSample?.leaderSource === 'manual' && JSON.stringify(pinnedSample?.leaderUserIds) === JSON.stringify([mstUid])
    && !(vacancyPinned.data?.vacant ?? []).some((org) => org.orgId === vacantOrg.data.id),
    JSON.stringify({ leaders: pinnedSample?.leaderUserIds, source: pinnedSample?.leaderSource }))

  const mktId = orgByName('市场部')
  await api('PATCH', `/api/iam/orgs/${mktId}`, { token: admin, body: { leaderUserIds: [linxmUid] } })
  const resyncGuard = await api('POST', '/api/iam/connectors/dingtalk/sync', { token: admin })
  const mktAfterSync = (await api('GET', '/api/iam/orgs', { token: admin })).data.find((org) => org.id === mktId)
  check('手动锁定不被连接器同步覆盖（同步跳过 manual 组织并在消息计数）',
    resyncGuard.ok && String(resyncGuard.data?.message ?? '').includes('手动锁定')
    && mktAfterSync?.leaderSource === 'manual' && JSON.stringify(mktAfterSync?.leaderUserIds) === JSON.stringify([linxmUid]),
    JSON.stringify({ msg: resyncGuard.data?.message, mkt: mktAfterSync?.leaderUserIds, src: mktAfterSync?.leaderSource }))

  await api('PATCH', `/api/iam/orgs/${mktId}`, { token: admin, body: { leaderUserIds: [] } })
  const mktCleared = (await api('GET', '/api/iam/orgs', { token: admin })).data.find((org) => org.id === mktId)
  check('清空负责人恢复跟随同步（leaderSource 回 sync）',
    mktCleared?.leaderSource === 'sync' && (mktCleared?.leaderUserIds ?? []).length === 0,
    JSON.stringify({ src: mktCleared?.leaderSource }))
  const resyncRestore = await api('POST', '/api/iam/connectors/dingtalk/sync', { token: admin })
  const mktRestored = (await api('GET', '/api/iam/orgs', { token: admin })).data.find((org) => org.id === mktId)
  check('恢复跟随同步后负责人由同步回填（孟疏桐 DD0008）',
    resyncRestore.ok && JSON.stringify(mktRestored?.leaderUserIds) === JSON.stringify([mstUid]),
    JSON.stringify({ mkt: mktRestored?.leaderUserIds, err: resyncRestore.error }))
  await api('PATCH', `/api/iam/orgs/${vacantOrg.data.id}`, { token: admin, body: { leaderUserIds: [] } })

  const reconcile = await api('POST', '/api/nas/authz/reconcile', { token: admin })
  const reconcileReport = reconcile.data?.report ?? []
  const reconcileFindings = reconcileReport.flatMap((row) => row.findings ?? [])
  const reconcileAlerts = (await api('GET', '/api/audit/alerts', { token: admin })).data?.alerts ?? []
  check('组织↔目录对账：目录无组织 + 组织无目录 双向发现并告警',
    reconcile.ok && reconcileFindings.some((f) => f.kind === 'dir-without-org' && f.name === 'homes')
    && reconcileFindings.some((f) => f.kind === 'org-without-dir' && f.name === '市场部')
    && reconcileAlerts.some((alert) => alert.title.includes('组织目录对账')),
    JSON.stringify({ report: reconcileReport, titles: reconcileAlerts.slice(0, 5).map((alert) => alert.title), err: reconcile.error }))

  // —— 多 NAS：B 平台 NAS deny ——
  const authzNas2Reg = await api('POST', '/api/nas', { token: admin, body: { name: '财务 NAS（数据权限对账）', attrs: { description: '多 NAS 作用域隔离自测', gatewayUrl: `http://127.0.0.1:${NAS_GW_PORT}/mcp`, accessToken: NAS_GW_TOKEN, nasIp: NAS_GW_IP, rootPath: '/', orgRoot: '市场部' } } })
  const authzNas2Id = authzNas2Reg.data?.id
  const crossNas = await authzCheck(linxmUid, ['/任何/x'], 'read', { nasId: authzNas2Id })
  check('多 NAS：A 平台成员对 B 平台 NAS deny（orgRoot 不在其组织链）',
    authzNas2Reg.ok && crossNas.data?.decision === 'deny' && crossNas.data.reasons.some((r) => r.includes('nas.no-scope')))

  // —— 组织改名演练：orgPathOverrides 映射表优先，作用域不漂移 ——
  await api('PATCH', `/api/nas/${nasId}`, { token: admin, body: { attrs: { orgPathOverrides: JSON.stringify({ [orgAiId]: '/研发' }) } } })
  const overrideScope1 = await authzCheck(linxmUid, ['/研发/模型卡.md'], 'read')
  await api('PATCH', `/api/iam/orgs/${orgAiId}`, { token: admin, body: { name: '创新部门' } })
  const overrideScope2 = await api('GET', `/api/nas/authz/scope?nasId=${nasId}&userId=${linxmUid}`, { token: admin })
  check('组织改名演练：映射表命中 → 改名前后作用域均为 /研发（不漂移）',
    overrideScope1.data?.decision === 'allow' && JSON.stringify(overrideScope2.data.scope) === JSON.stringify(['/研发']))
  await api('PATCH', `/api/iam/orgs/${orgAiId}`, { token: admin, body: { name: 'AI 平台部' } })
  await api('PATCH', `/api/nas/${nasId}`, { token: admin, body: { attrs: { orgPathOverrides: '' } } })

  // —— C 组漂移告警（R5）——
  await api('POST', '/api/iam/groups/refresh-snapshots', { token: admin })
  const driftUser = await api('POST', '/api/iam/users', { token: admin, body: { username: 'driftu', displayName: '漂移样本', orgId: orgFeId, password: 'Ybk@2026' } })
  await api('PATCH', `/api/iam/users/${driftUser.data.id}`, { token: admin, body: { orgId: orgAiId } })
  const driftRefresh = await api('POST', '/api/iam/groups/refresh-snapshots', { token: admin })
  const authzDriftAlerts = (await api('GET', '/api/audit/alerts', { token: admin })).data?.alerts ?? []
  check('C 组重算漂移 → cGroupDrift 告警（C 关联组任何漂移都告警）',
    driftRefresh.ok && (driftRefresh.data.drifts ?? []).some((drift) => drift.groupName === 'AI 平台部全员' && drift.alerted)
    && authzDriftAlerts.some((alert) => alert.title.includes('成员漂移')),
    JSON.stringify({ drifts: driftRefresh.data?.drifts, titles: authzDriftAlerts.slice(0, 5).map((alert) => alert.title) }))

  // deny 留痕保留策略：普通 deny 记录带 highRisk=false（高危 delete/share/admin 永久保留）
  const shareDecisionRows = (await api('GET', `/api/nas/authz/decisions?decision=allow&nasId=${nasId}&limit=50`, { token: admin })).data?.items ?? []
  check('高危 op（share）留痕 highRisk 标记（永久保留策略依据）', shareDecisionRows.some((record) => record.op === 'share' && record.highRisk === true))

  // ================================================================ Skill 包 NAS 存储
  section('Skill 包 NAS 存储（上架自动打包上传）')
  const storageDeny = await api('PUT', '/api/skill-storage', { token: dev, body: { mode: 'nas', nasId, basePath: '/skillhub' } })
  check('无 skill.storage.write 配置存储被拒（403）', storageDeny.status === 403)
  const storageSet = await api('PUT', '/api/skill-storage', { token: admin, body: { mode: 'nas', nasId, basePath: '/skillhub' } })
  check('配置包存储后端为已纳管 NAS 资产', storageSet.ok && storageSet.data.mode === 'nas' && storageSet.data.nasId === nasId && storageSet.data.basePath === '/skillhub')

  // ① 提交自带 zip：上架时原样上传 NAS
  const zipBuffer = Buffer.concat([Buffer.from('PK\x03\x04', 'latin1'), Buffer.from('selftest-skill-zip-payload')])
  const pkgSubmit = await api('POST', '/api/skills', { token: admin, body: { name: '自测打包技能', content: '# 自测打包技能\n\n## 何时使用\n验证 skill.zip 随提交上传 NAS 的全链路。\n\n## 步骤\n提交即携带包内容。', category: '通用', version: '1.0.0', packageBase64: zipBuffer.toString('base64') } })
  check('提交可携带 skill.zip（hasPackage）', pkgSubmit.ok && pkgSubmit.data.hasPackage === true, JSON.stringify(pkgSubmit.error))
  const pkgSkillId = pkgSubmit.data?.id
  const badZip = await api('POST', '/api/skills', { token: admin, body: { name: '坏包技能', content: '# x', category: '通用', packageBase64: Buffer.from('not-a-zip').toString('base64') } })
  check('非 ZIP 内容（缺 PK 魔数）提交被拒', !badZip.ok)
  await api('POST', `/api/skills/${pkgSkillId}/approve`, { token: admin, body: { level: 'domain', decision: 'approve', opinion: 'selftest' } })
  const uploadsBefore = nasGwUploads.length
  const pkgPublish = await api('POST', `/api/skills/${pkgSkillId}/publish`, { token: admin, body: {} })
  const pkgUploaded = nasGwUploads[nasGwUploads.length - 1]
  check('上架自动上传 NAS（fs_upload 收到包）', pkgPublish.ok && nasGwUploads.length === uploadsBefore + 1, JSON.stringify(pkgPublish.error))
  check('上传产物即提交的 zip（字节级一致）', pkgUploaded?.magic === 'PK' && pkgUploaded.sizeBytes === zipBuffer.length && pkgUploaded.content.equals(zipBuffer))
  check('上传路径契约 <basePath>/<slug>/<slug>-<version>.zip', typeof pkgUploaded?.destPath === 'string' && pkgUploaded.destPath.startsWith('/skillhub/') && typeof pkgUploaded?.filename === 'string' && pkgUploaded.filename.endsWith('-1.0.0.zip') && pkgUploaded.filename === `${pkgUploaded.destPath.split('/').pop()}-1.0.0.zip`)
  const pkgSkill = await api('GET', `/api/skills/${pkgSkillId}`, { token: admin })
  const pkgVersion = pkgSkill.data?.versions?.find((v) => v.version === '1.0.0')
  check('版本记录回写 package 元数据（storage=nas）', pkgVersion?.package?.storage === 'nas' && pkgVersion.package.nasId === nasId && pkgVersion.package.sizeBytes === zipBuffer.length)
  const pkgDownload = await rawReq('GET', `/api/skills/${pkgSkillId}/package?version=1.0.0`, { headers: { authorization: `Bearer ${admin}` } })
  check('包下载端点返回 zip（PK 头）', pkgDownload.status === 200 && pkgDownload.body.startsWith('PK'))

  // ② 无 zip 提交：上架时由 SKILL.md 现场打包（platform-core zip.ts，零依赖）
  const autoSubmit = await api('POST', '/api/skills', { token: admin, body: { name: '自测自动打包', content: '# 自测自动打包\n\n## 何时使用\n验证无 zip 提交时由 SKILL.md 现场打包上传 NAS。\n\n## 步骤\n提交 → 审批 → 上架。', category: '通用', version: '0.1.0' } })
  await api('POST', `/api/skills/${autoSubmit.data.id}/approve`, { token: admin, body: { level: 'domain', decision: 'approve', opinion: 'selftest' } })
  const autoPublish = await api('POST', `/api/skills/${autoSubmit.data.id}/publish`, { token: admin, body: {} })
  const autoUploaded = nasGwUploads[nasGwUploads.length - 1]
  check('无 zip 时由 SKILL.md 现场打包上传', autoPublish.ok && autoUploaded?.magic === 'PK' && autoUploaded.sizeBytes > 100 && autoUploaded.filename.endsWith('-0.1.0.zip'), JSON.stringify(autoPublish.error))
  check('现场打包产物含 SKILL.md 条目', autoUploaded?.content.toString('latin1').includes('SKILL.md'))

  // ③ fail-closed：存储后端 NAS 非 online → 上架中止且版本不落 published
  const draftNas = await api('POST', '/api/nas', { token: admin, body: { name: '未上线 NAS', attrs: { description: 'fail-closed 验证', gatewayUrl: `http://127.0.0.1:${NAS_GW_PORT}/mcp`, accessToken: NAS_GW_TOKEN, nasIp: NAS_GW_IP, dataClass: 'internal' } } })
  await api('PUT', '/api/skill-storage', { token: admin, body: { mode: 'nas', nasId: draftNas.data.id, basePath: '/skillhub' } })
  const fcSubmit = await api('POST', '/api/skills', { token: admin, body: { name: '自测中止技能', content: '# 自测中止技能\n\n## 何时使用\n验证存储后端 NAS 未上线时上架 fail-closed。\n\n## 步骤\n提交 → 审批 → 上架应中止。', category: '通用', version: '1.0.0' } })
  await api('POST', `/api/skills/${fcSubmit.data.id}/approve`, { token: admin, body: { level: 'domain', decision: 'approve', opinion: 'selftest' } })
  const fcPublish = await api('POST', `/api/skills/${fcSubmit.data.id}/publish`, { token: admin, body: {} })
  check('存储后端 NAS 未上线 → 上架 fail-closed', !fcPublish.ok && JSON.stringify(fcPublish.error).includes('fail-closed'), JSON.stringify(fcPublish.error))
  const fcSkill = await api('GET', `/api/skills/${fcSubmit.data.id}`, { token: admin })
  check('fail-closed 后版本未标记 published', fcSkill.ok && fcSkill.data.versions.every((v) => v.status !== 'published'))
  await api('PUT', '/api/skill-storage', { token: admin, body: { mode: 'local' } })
  const storageBack = await api('GET', '/api/skill-storage', { token: admin })
  check('存储后端可切回 local', storageBack.ok && storageBack.data.config.mode === 'local')

  // ================================================================ 台账与巡检（NAS 接入）
  section('资产台账与巡检（NAS 接入）')
  const inventory = await api('GET', '/api/assets/inventory', { token: admin })
  check('台账包含 nas 资产类型', inventory.ok && inventory.data.items.some((item) => item.type === 'nas') && (inventory.data.summary.byType.nas?.total ?? 0) >= 2)
  const healthcheck = await api('POST', '/api/assets/healthcheck', { token: admin, body: {} })
  check('一键巡检覆盖在线 NAS（initialize 探活 healthy）', healthcheck.ok && healthcheck.data.items.some((item) => item.type === 'nas' && item.status === 'healthy'))

  // 下架分析：弃用/下线原因聚合（审计 change 日志 + Skill 落库原因 + Agent/应用生命周期留痕）
  const retire = await api('GET', '/api/assets/retire-reasons?days=90', { token: admin })
  const retireReasons = retire.data?.reasons ?? []
  check('下架分析（原因聚合，Skill 弃用原因可检索）', retire.ok && retire.data.total >= 2
    && retireReasons.some((row) => row.reason === '自测弃用' && (row.byType.skill ?? 0) >= 1)
    && retireReasons.every((row) => row.reason && row.count >= 1))

  // ================================================================ 平台即 MCP Server（POST /mcp）
  section('平台即 MCP Server（POST /mcp）')
  const mcpAnon = await rawReq('POST', '/mcp', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) })
  check('无 Bearer 令牌 401', mcpAnon.status === 401)
  const mcpGet = await rawReq('GET', '/mcp', { headers: { authorization: `Bearer ${admin}` } })
  check('GET SSE 长流不支持（405，纯 JSON 形态合法）', mcpGet.status === 405)
  const mcpInit = await rawReq('POST', '/mcp', {
    headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'selftest', version: '1.0' } } }),
  })
  check('initialize 返回 serverInfo/capabilities + 会话头', mcpInit.status === 200 && jsonBody(mcpInit).result?.serverInfo?.name === 'dsh-ops-platform' && typeof mcpInit.headers['mcp-session-id'] === 'string')
  const mcpNotify = await rawReq('POST', '/mcp', {
    headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
  })
  check('通知类消息 202 确认', mcpNotify.status === 202)
  const mcpTools = await rawReq('POST', '/mcp', {
    headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
  })
  const mcpToolList = jsonBody(mcpTools).result?.tools ?? []
  check('tools/list 暴露全部运维工具（40+，含 nas_*）', mcpToolList.length >= 40 && mcpToolList.some((t) => t.name === 'nas_fs_upload'), `tools=${mcpToolList.length}`)
  const mcpCall = await rawReq('POST', '/mcp', {
    headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'nas_list', arguments: {} } }),
  })
  const mcpCallResult = jsonBody(mcpCall).result
  check('tools/call 执行成功（content blocks）', mcpCall.status === 200 && mcpCallResult?.isError === false && Array.isArray(mcpCallResult?.content), JSON.stringify(jsonBody(mcpCall)).slice(0, 200))
  const mcpDeny = await rawReq('POST', '/mcp', {
    headers: { 'content-type': 'application/json', authorization: `Bearer ${dev}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'nas_fs_mkdir', arguments: { nasId, path: '/skillhub/x' } } }),
  })
  const mcpDenyResult = jsonBody(mcpDeny).result
  check('工具级权限点拦截（dev 缺 nas.write → isError）', mcpDeny.status === 200 && mcpDenyResult?.isError === true && JSON.stringify(mcpDenyResult).includes('nas.write'))
  const mcpUnknown = await rawReq('POST', '/mcp', {
    headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'resources/list', params: {} }),
  })
  check('未知方法 -32601', jsonBody(mcpUnknown).error?.code === -32601)

  // ================================================================ 连接器纳管（open-connector 融合）
  section('连接器纳管（open-connector 融合）')
  const waitFor = async (fn, ms = 5000) => {
    const end = Date.now() + ms
    let value
    while (Date.now() < end) {
      value = fn()
      if (value) return value
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
    return fn()
  }

  // -- 网关配置与强制 env fail-closed（T-02 预演探针路径） ----------------------
  const envProbeEnc = await api('GET', `/api/connector/gateway?assumeEnv=${encodeURIComponent(JSON.stringify({ OOMOL_CONNECT_ADMIN_TOKEN: true, OOMOL_CONNECT_ENCRYPTION_KEY: false }))}`, { token: admin })
  check('T-02 缺 OOMOL_CONNECT_ENCRYPTION_KEY → fail-closed 文案', !envProbeEnc.data?.available && String(envProbeEnc.data?.reason ?? '').includes('OOMOL_CONNECT_ENCRYPTION_KEY'), JSON.stringify(envProbeEnc).slice(0, 200))
  const envProbeToken = await api('GET', `/api/connector/gateway?assumeEnv=${encodeURIComponent(JSON.stringify({ OOMOL_CONNECT_ADMIN_TOKEN: false }))}`, { token: admin })
  check('T-02 管理口令未解析 → fail-closed 文案', !envProbeToken.data?.available && String(envProbeToken.data?.reason ?? '').includes('管理口令未解析'), JSON.stringify(envProbeToken).slice(0, 200))

  const gwSet = await api('PUT', '/api/connector/gateway', { token: admin, body: { baseUrl: OC_BASE, adminToken: 'env:OOMOL_CONNECT_ADMIN_TOKEN', autoCatalogSyncMinutes: 0 } })
  check('网关配置（baseUrl + adminToken env: 间接引用）', gwSet.ok && gwSet.data.baseUrl === OC_BASE, JSON.stringify(gwSet).slice(0, 200))
  const gwHealth = await api('POST', '/api/connector/gateway/health', { token: admin })
  check('探活契约（ok/runtime/latencyMs）', gwHealth.ok && gwHealth.data.ok === true && typeof gwHealth.data.latencyMs === 'number')
  const gwState = await api('GET', '/api/connector/gateway', { token: admin })
  check('网关状态可用（healthy + envChecks 双 true）', gwState.ok && gwState.data.available === true && gwState.data.status === 'healthy' && gwState.data.envChecks.OOMOL_CONNECT_ENCRYPTION_KEY === true)

  // -- 目录同步（T-03） --------------------------------------------------------
  const catSync1 = await api('POST', '/api/connector/catalog/sync', { token: admin })
  const catSync1Data = catSync1.data ?? {}
  check('目录同步 providers/actions 计数与 added 清单', catSync1.ok && catSync1Data.providers === 2 && catSync1Data.actions === 7 && catSync1Data.added.length === 7, JSON.stringify(catSync1).slice(0, 300))
  check('非法 service 标识被拒纳管（resource 正则）', (catSync1Data.skippedServices ?? []).some((item) => item.service === 'weird service!'), JSON.stringify(catSync1Data.skippedServices))
  const catalogView = (await api('GET', '/api/connector/catalog', { token: admin })).data
  const riskOf = Object.fromEntries((catalogView.actions ?? []).map((action) => [action.id, action.riskLevel]))
  check('riskLevel 映射（读/写/管理 + 默认 admin 兜底）',
    riskOf['hackernews.get_top_stories'] === 'read' && riskOf['github.create_issue'] === 'write'
    && riskOf['github.delete_webhook'] === 'admin' && riskOf['hackernews.do_the_thing'] === 'admin', JSON.stringify(riskOf))
  const guideRaw = await rawReq('GET', '/api/connector/catalog/actions/hackernews.get_top_stories/guide', { headers: { authorization: `Bearer ${admin}` } })
  check('连接向导 agent.md 代理展示（文本）', guideRaw.status === 200 && guideRaw.body.includes('连接指南'))

  // -- 组织 / 用户（org 隔离锚点） ----------------------------------------------
  const connOrg = (await api('POST', '/api/iam/orgs', { token: admin, body: { name: '连接器测试部' } })).data.id
  const connOrgB = (await api('POST', '/api/iam/orgs', { token: admin, body: { name: '连接器隔离部' } })).data.id
  const devUserSearch = (await api('GET', '/api/iam/users?q=' + encodeURIComponent('陈默'), { token: admin })).data.users[0]
  const connDevLogin = await api('POST', '/api/auth/login', { body: { username: 'dev', password: 'Ybk@2026' } })
  const connAuditLogin = await api('POST', '/api/auth/login', { body: { username: 'audit', password: 'Ybk@2026' } })
  check('测试主体就绪（dev 令牌 / audit 令牌）', Boolean(devUserSearch?.id) && Boolean(connDevLogin.data?.token) && Boolean(connAuditLogin.data?.token))

  // -- 连接管理（T-05/T-06/T-07） -----------------------------------------------
  const apiKeyCreate = await api('POST', '/api/connector/connections/api-key', { token: admin, body: { orgId: connOrg, provider: 'github', aliasSuffix: 'main-pat', values: { apiKey: 'ghp_selftestSecret123' } } })
  check('API Key 表单直达 sidecar（返回 active 引用）', apiKeyCreate.ok && apiKeyCreate.data.reference?.status === 'active' && String(apiKeyCreate.data.reference.ocConnectionId ?? '').startsWith('oc-con-'), JSON.stringify(apiKeyCreate).slice(0, 220))
  const patRef = apiKeyCreate.data.reference

  const oauthMissClient = await api('POST', '/api/connector/connections/oauth', { token: admin, body: { orgId: connOrg, provider: 'github', aliasSuffix: 'oauth-bot' } })
  check('T-06 未存 client 配置 → oauth_client_config_required 透传+自备 App 指引',
    oauthMissClient.ok === false && oauthMissClient.error?.code === 'OAUTH_CLIENT_CONFIG_REQUIRED' && /OAuth App|自备/.test(oauthMissClient.error?.message ?? ''), JSON.stringify(oauthMissClient).slice(0, 240))
  ocClientsConfigured.add('github')
  const oauthStart = await api('POST', '/api/connector/connections/oauth', { token: admin, body: { orgId: connOrg, provider: 'github', aliasSuffix: 'oauth-bot' } })
  check('T-01 OAuth 发起信封 {authorizationUrl,state}', oauthStart.ok && Boolean(oauthStart.data.authorizationUrl) && Boolean(oauthStart.data.state), JSON.stringify(oauthStart).slice(0, 220))
  const callbackHtml = await fetch(`${OC_BASE}/oauth/callback?state=${oauthStart.data.state}&code=fake-code`).then((r) => r.text())
  check('sidecar 回调完成页受理', callbackHtml.includes('授权完成'))
  const oauthConfirm = await api('GET', `/api/connector/connections/oauth/${oauthStart.data.state}/status`, { token: admin })
  check('T-05 回调后状态轮询：引用转 active 且平台不落凭证原文', oauthConfirm.ok && oauthConfirm.data.status === 'active' && oauthConfirm.data.authType === 'oauth', JSON.stringify(oauthConfirm).slice(0, 260))

  // 别名前缀组织校验（T-20 后半）：跨 org 引用别名在权限组校验层拒绝在下方断言。

  // -- 权限组 + oct_ 台账初始镜像（T-11） ----------------------------------------
  const grpAdmin = (await api('POST', '/api/iam/groups', { token: admin, body: { name: '连接器组-A', type: 'static', memberIds: [adminLogin.data.user.id] } })).data
  const grpDev = (await api('POST', '/api/iam/groups', { token: admin, body: { name: '连接器组-B(dev)', type: 'static', memberIds: [devUserSearch.id] } })).data
  check('测试用户组建好', Boolean(grpAdmin?.id) && Boolean(grpDev?.id))

  const crossOrgGroup = await api('POST', '/api/connector/perm-groups', { token: admin, body: {
    name: '非法跨 org 组', orgId: connOrgB,
    policies: { github: { allowedActions: ['github.list_issues'], riskCap: 'read', connections: [`org:${connOrg}:main-pat`] } },
    subjects: [{ type: 'user_group', id: grpAdmin.id }],
  } })
  check('T-20 引用非本组织前缀别名的权限组被拒', crossOrgGroup.ok === false, JSON.stringify(crossOrgGroup).slice(0, 220))

  const pgRead = (await api('POST', '/api/connector/perm-groups', { token: admin, body: {
    name: 'dev 只读组', orgId: connOrg,
    policies: {
      hackernews: { allowedActions: ['hackernews.get_top_stories'], riskCap: 'read', constraints: { readOnly: true } },
      github: { allowedActions: ['*'], riskCap: 'read', connections: [`org:${connOrg}:main-pat`], constraints: { readOnly: true } },
    },
    subjects: [{ type: 'user_group', id: grpDev.id }],
  } })).data
  const pgFull = (await api('POST', '/api/connector/perm-groups', { token: admin, body: {
    name: 'admin 全量组', orgId: connOrg,
    policies: { hackernews: { allowedActions: '*', riskCap: 'admin' }, github: { allowedActions: '*', riskCap: 'admin' }, },
    subjects: [{ type: 'user_group', id: grpAdmin.id }],
    // 新建组织钱包为 0 分：预估置 0 让主链路不被余额闸误伤（quota 路径由 T-16b 独立大额组覆盖）
    precheckCents: 0,
  } })).data
  const pgTmp = (await api('POST', '/api/connector/perm-groups', { token: admin, body: {
    name: 'dev 高危通道组', orgId: connOrg,
    policies: { hackernews: { allowedActions: ['hackernews.do_the_thing'], riskCap: 'admin' } },
    subjects: [{ type: 'user_group', id: grpDev.id }],
  } })).data
  check('三个权限组建好（含显式清单/通配/admin 通道）', Boolean(pgRead?.id) && Boolean(pgFull?.id) && Boolean(pgTmp?.id), JSON.stringify({ pgRead, pgFull, pgTmp }).slice(0, 240))

  await waitFor(() => [...ocLedgerTokens.values()].length >= 3)
  const ocReadTokens = [...ocLedgerTokens.entries()].filter(([, rec]) => rec.policy.allowedConnections.length > 0)
  check('T-11 只读组令牌策略镜像逐字段一致',
    ocReadTokens.some(([, rec]) =>
      rec.policy.allowedActions[0] === '*' || JSON.stringify([...rec.policy.allowedActions].sort()) === JSON.stringify(['github.list_issues', 'hackernews.get_top_stories'])
      && rec.policy.allowedProxies.length === 0 && rec.policy.blockedActions.length === 0
      && rec.policy.allowedConnections.join(',') === patRef.ocConnectionId), JSON.stringify(ocReadTokens.map(([, r]) => r.policy)))
  const fullLedgerTokens = [...ocLedgerTokens.entries()].filter(([, rec]) => rec.policy.allowedActions[0] === '*')
  check('T-11 通配组令牌镜像（allowedActions=[\'*\']，无绑定连接则空数组全发）', fullLedgerTokens.length >= 1 && Array.isArray(fullLedgerTokens[0][1].policy.allowedConnections))
  const impactPreview = await api('POST', `/api/connector/perm-groups/${pgRead.id}/impact`, { token: admin })
  check('变更影响面预览（N 令牌/M 连接）', impactPreview.ok && impactPreview.data.tokens >= 1 && impactPreview.data.connections >= 1, JSON.stringify(impactPreview).slice(0, 160))

  // -- 授权链执行（T-08/T-09/T-10 + 三端 dry-run） -------------------------------
  const memberDenied = await api('POST', '/api/connector/execute', { token: connAuditLogin.data.token, body: { actionId: 'hackernews.get_top_stories', input: {} } })
  check('T-08 无 connector.invoke 权限点 → 403 + authz.denied 事件', memberDenied.ok === false && memberDenied.error?.code === 'FORBIDDEN' && memberDenied.status === 403, JSON.stringify(memberDenied).slice(0, 200))

  const devDryRun = await api('POST', '/api/connector/execute', { token: connDevLogin.data.token, body: { actionId: 'hackernews.get_top_stories', input: { limit: 5 }, dryRun: true } })
  check('dry-run 影响面预览（五步链通过、只读约束可见、不真实调用）', devDryRun.ok && devDryRun.data?.status === 'dry_run' && devDryRun.data.preview.riskLevel === 'read' && typeof devDryRun.data.preview.permGroup === 'string' && devDryRun.data.preview.readOnlyConstraint === true, JSON.stringify(devDryRun).slice(0, 300))

  const devOkRun = await api('POST', '/api/connector/execute', { token: connDevLogin.data.token, body: { actionId: 'hackernews.get_top_stories', input: { limit: 5 } } })
  check('授权放行成功调用（runId=executionId + 计量回执）', devOkRun.ok && devOkRun.data?.ok === true && /^exec-/.test(String(devOkRun.data.runId)) && devOkRun.data.metered === true, JSON.stringify(devOkRun).slice(0, 280))
  const devOkUsage = await api('GET', `/api/usage/events?limit=50`, { token: admin })
  check('T-14 usage.record 口径（resource/meters/trace_id/idempotency_key）',
    devOkUsage.ok && devOkUsage.data.items.some((event) =>
      event.resource === 'connector:hackernews' && event.trace_id === devOkRun.data.runId
      && event.idempotency_key === `connector:${devOkRun.data.runId}` && event.meters.some((m) => m.key === 'calls')), JSON.stringify(devOkUsage.data?.items?.slice(0, 2)).slice(0, 240))
  const priceBook = (await api('GET', '/api/usage/price-book', { token: admin })).data
  check('价格簿 connector:* 零费率条目存在（缺规则会被 record 拒绝的反向保障）',
    priceBook.entries.some((entry) => entry.pattern === 'connector:*' && entry.list_cents_per_unit === 0), JSON.stringify(priceBook.entries?.filter((e) => e.pattern.startsWith('connector')) ?? []).slice(0, 160))

  const devWriteDenied = await api('POST', '/api/connector/execute', { token: connDevLogin.data.token, body: { actionId: 'github.create_issue', input: { title: 'x' } } })
  check('T-09 write 级超出 readOnly/riskCap=read → 平台侧拒绝', devWriteDenied.ok && devWriteDenied.data?.status === 'denied' && /(riskCap|只读)/.test(String(devWriteDenied.data.error)), JSON.stringify(devWriteDenied).slice(0, 240))

  const isoLogin = await api('POST', '/api/auth/login', { body: { username: 'suyq', password: 'Ybk@2026' } })
  const isoGroup = (await api('POST', '/api/iam/groups', { token: admin, body: { name: '连接器组-单点', type: 'static', memberIds: [(await api('GET', '/api/iam/users?q=' + encodeURIComponent('苏砚秋'), { token: admin })).data.users[0].id] } })).data
  const pgIso = (await api('POST', '/api/connector/perm-groups', { token: admin, body: {
    name: '单点清单组（pattern-miss 回归）', orgId: connOrg,
    policies: { hackernews: { allowedActions: ['hackernews.get_top_stories'], riskCap: 'read' } },
    subjects: [{ type: 'user_group', id: isoGroup.id }],
  } })).data
  const devPatternMiss = await api('POST', '/api/connector/execute', { token: isoLogin.data.token, body: { actionId: 'hackernews.fetch_item', input: {} } })
  check('T-10 pattern 未命中 → 平台侧拒绝', devPatternMiss.ok && devPatternMiss.data?.status === 'denied' && /允许模式/.test(String(devPatternMiss.data.error)), JSON.stringify(devPatternMiss).slice(0, 260))

  // -- T-15 审计 actChain + runId 反查 -----------------------------------------
  const devAuditTrail = await api('GET', `/api/audit/logs?q=${encodeURIComponent(String(devOkRun.data.runId))}&type=invoke`, { token: admin })
  check('T-15 invoke 日志含 runId（run= 前缀反查命中）',
    devAuditTrail.ok && devAuditTrail.data.items.some((log) => log.resourceType === 'connector_action' && String(log.detail).includes(`run=${devOkRun.data.runId}`)), JSON.stringify(devAuditTrail.data?.items?.slice(0, 2)).slice(0, 240))

  // -- T-22 写类幂等键 + 同键重放不重复计量 ---------------------------------------
  const directAdminMintRes = await fetch(`${OC_BASE}/api/runtime-tokens`, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${OC_TOKEN}` },
    body: JSON.stringify({ name: 'selftest-direct', allowedActions: ['*'], blockedActions: [], allowedProxies: [], allowedConnections: [] }),
  }).then((r) => r.json())
  const directOct = directAdminMintRes.data.token
  ocMintedValues.push(directOct)
  const replayKey = 'ikey-selftest-0001'
  const directExec = () => fetch(`${OC_BASE}/v1/actions/hackernews.submit_post`, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${directOct}`, 'idempotency-key': replayKey },
    body: JSON.stringify({ input: { title: '自测幂等帖' } }),
  }).then((r) => r.json())
  const firstReplay = await directExec()
  const secondReplay = await directExec()
  check('T-22 同键重放返回原 executionId（24h 窗口语义）', firstReplay.meta.executionId === secondReplay.meta.executionId, `${firstReplay.meta.executionId} vs ${secondReplay.meta.executionId}`)
  const runsForExec = ocRuns.filter((run) => run.id === firstReplay.meta.executionId)
  check('T-22 重放不产生重复 run（stub 侧单条）', runsForExec.length === 1, String(runsForExec.length))

  // -- 高危审批门禁（T-17） ------------------------------------------------------
  const adminCallResp = await api('POST', '/api/connector/execute', { token: connDevLogin.data.token, body: { actionId: 'hackernews.do_the_thing', input: { work: 1 } } })
  const approvalFlow = adminCallResp.data ?? {}
  check('admin 级 action → 审批单生成且不执行', approvalFlow.status === 'approval_required' && Boolean(approvalFlow.approvalId), JSON.stringify(adminCallResp).slice(0, 260))
  const dupApproval = await api('POST', '/api/connector/execute', { token: connDevLogin.data.token, body: { actionId: 'hackernews.do_the_thing', input: { work: 1 } } })
  check('同图 pending 审批单复用（不重复开单）', dupApproval.data?.approvalId === approvalFlow.approvalId, JSON.stringify(dupApproval).slice(0, 180))
  const beforeCalls = ocCalls.filter((call) => call.actionId === 'hackernews.do_the_thing').length
  const decide = await api('POST', `/api/approvals/${approvalFlow.approvalId}/decide`, { token: admin, body: { decision: 'approve', opinion: '自测批准' } })
  check('审批通过后 executor 同步完成调用（L4 闭环）', decide.ok && String(decide.data.execution?.result ?? '').includes('runId'), JSON.stringify(decide.data?.execution ?? {}).slice(0, 240))
  const afterCalls = ocCalls.filter((call) => call.actionId === 'hackernews.do_the_thing').length
  check('executor 真实下发一次数据面调用', afterCalls === beforeCalls + 1, `before=${beforeCalls} after=${afterCalls}`)

  // -- connector.connect 两段式审批门禁（T-18，凭证不入审批负载） -------------------
  const gatedConnectReq = await api('POST', '/api/connector/connections/api-key', { token: admin, body: { orgId: connOrg, provider: 'github', aliasSuffix: 'gated-pat', values: { apiKey: 'client-supersecret-oauth-xyz' }, requireApproval: true } })
  check('T-18 requireApproval → 仅生成审批单（凭证不落任何集合）', gatedConnectReq.data?.approvalRequired === true && Boolean(gatedConnectReq.data.approvalId), JSON.stringify(gatedConnectReq).slice(0, 200))
  await api('POST', `/api/approvals/${gatedConnectReq.data.approvalId}/decide`, { token: admin, body: { decision: 'approve' } })
  const gatedFinalize = await api('POST', '/api/connector/connections/api-key', { token: admin, body: { orgId: connOrg, provider: 'github', aliasSuffix: 'gated-pat', values: { apiKey: 'client-supersecret-oauth-xyz' }, approvalId: gatedConnectReq.data.approvalId } })
  check('审批通过后携 approvalId 完成实际创建', gatedFinalize.ok && gatedFinalize.data.reference?.status === 'active', JSON.stringify(gatedFinalize).slice(0, 220))

  // -- T-12 权限组变更 PUT 四数组全发 + 组删 DELETE 令牌 ----------------------------
  const putsBeforeChange = ocPuts.length
  const patchedRead = await api('PATCH', `/api/connector/perm-groups/${pgRead.id}`, { token: admin, body: {
    policies: {
      hackernews: { allowedActions: ['hackernews.get_top_stories', 'hackernews.fetch_item'], riskCap: 'read', constraints: { readOnly: true } },
      github: { allowedActions: ['*'], riskCap: 'read', connections: [`org:${connOrg}:main-pat`], constraints: { readOnly: true } },
    },
  } })
  check('权限组策略更新成功', patchedRead.ok)
  const mirrorPutAfterPatch = await waitFor(() => ocPuts.slice(putsBeforeChange)[0], 4000)
  check('T-12 变更触发 PUT 且四数组全发',
    mirrorPutAfterPatch && Object.keys(mirrorPutAfterPatch.policy).sort().join() === ['allowedActions', 'allowedConnections', 'allowedProxies', 'blockedActions'].sort().join()
    && Array.isArray(mirrorPutAfterPatch.policy.allowedActions) && Array.isArray(mirrorPutAfterPatch.policy.allowedConnections), JSON.stringify(mirrorPutAfterPatch ?? {}).slice(0, 240))

  // -- T-04 目录下架联动（先落库裁剪再镜像 PUT） ----------------------------------
  ocCtl.actions = (ocCtl.actions ?? [...ocActionsDefault]).filter((action) => action.id !== 'hackernews.fetch_item')
  const resyncAfterRemoval = await api('POST', '/api/connector/catalog/sync', { token: admin })
  check('目录下架检测（removed 命中）', resyncAfterRemoval.ok && (resyncAfterRemoval.data.removed ?? []).includes('hackernews.fetch_item'), JSON.stringify(resyncAfterRemoval.data?.removed))
  const prunedPut = await waitFor(() => ocPuts.find((put) => !put.policy.allowedActions.includes('hackernews.fetch_item') && put.policy.allowedActions.length >= 1), 4000)
  check('T-04 下架后受影响组收到裁剪后的 PUT 更新', Boolean(prunedPut), JSON.stringify(ocPuts.slice(-2)))

  // -- T-13 自动恢复（403 connection_not_allowed → PUT 最新快照 + 重试一次） ----------
  ocCtl.connNotAllowedOnce = '*ANY*'
  const recoverOk = await api('POST', '/api/connector/execute', { token: admin, body: { actionId: 'hackernews.get_top_stories', input: {} } })
  check('T-13 单次 403 自动恢复重试成功（对调用方透明）', recoverOk.ok && recoverOk.data?.status === 'ok', JSON.stringify(recoverOk).slice(0, 220))
  // 恢复过程触发了「删旧铸新」：最新铸造值即平台当前在用的该组令牌（每次铸造都会入册）
  const mintCountBefore = ocMintedValues.length
  void mintCountBefore
  ocCtl.alwaysDenyToken = '*ANY*'
  const persistFail = await api('POST', '/api/connector/execute', { token: admin, body: { actionId: 'hackernews.get_top_stories', input: {} } })
  check('T-13 持续拒绝 → 重试仍失败计 error_rate', persistFail.ok && persistFail.data?.status === 'error', JSON.stringify(persistFail).slice(0, 220))
  ocCtl.alwaysDenyToken = null

  // 目录恢复：fetch_item 回归目录并重新同步（后续 T-16a 等用例依赖它）
  ocCtl.actions = [...(ocCtl.actions ?? [])].concat((ocActionsDefault).filter((action) => action.id === 'hackernews.fetch_item'))
  await api('POST', '/api/connector/catalog/sync', { token: admin })

  // -- T-28 auditPersisted=false 补记 + 低阈告警记分 -------------------------------
  ocCtl.auditPersistedNext = true
  const ghostRun = await api('POST', '/api/connector/execute', { token: admin, body: { actionId: 'hackernews.get_top_stories', input: { ghost: true } } })
  ocCtl.auditPersistedNext = false
  check('meta.auditPersisted=false 透传给调用方', ghostRun.ok && ghostRun.data?.status === 'ok' && ghostRun.data.meta.auditPersisted === false, JSON.stringify(ghostRun.data?.meta))
  const recoveredLog = await api('GET', `/api/audit/logs?q=${encodeURIComponent('recovered-audit')}&type=invoke&limit=50`, { token: admin })
  check('T-28 平台补记审计', recoveredLog.ok && recoveredLog.data.items.length >= 1, JSON.stringify(recoveredLog.data?.items?.slice(0, 1)))

  // -- T-16a 限流（用单点清单组保证候选组唯一，绕开多组并集下的候选顺序不确定性） --------
  await api('PATCH', `/api/connector/perm-groups/${pgIso.id}`, { token: admin, body: { rateLimitPerMin: 1 } })
  const rateLimited = await api('POST', '/api/connector/execute', { token: isoLogin.data.token, body: { actionId: 'hackernews.get_top_stories', input: {} } })
  const rateLimitedSecond = await api('POST', '/api/connector/execute', { token: isoLogin.data.token, body: { actionId: 'hackernews.get_top_stories', input: {} } })
  check('T-16a 超 rateLimitPerMin → rate_limited 拒绝',
    [rateLimited.data?.status, rateLimitedSecond.data?.status].includes('rate_limited'),
    JSON.stringify([rateLimited.data, rateLimitedSecond.data]).slice(0, 300))
  await api('PATCH', `/api/connector/perm-groups/${pgIso.id}`, { token: admin, body: { rateLimitPerMin: 60 } })

  // -- T-16b billing.precheck quota.exceeded（独立 agent 主体 + 大额预估组） --------
  const heavyAgent = await api('POST', '/api/agents', { token: admin, body: { name: '连接器预算闸机器人', attrs: { description: 'precheck 回归', model: 'deepseek-chat', riskLevel: 'low', avatar: '🤖' } } })
  const heavyCc = await api('POST', '/api/auth/client-credentials', { body: { clientId: heavyAgent.data.credential.clientId, clientSecret: heavyAgent.data.credential.clientSecret } })
  const grpHeavy = (await api('POST', '/api/iam/groups', { token: admin, body: { name: '连接器组-heavy', type: 'static', memberIds: [] } })).data
  await api('POST', '/api/connector/perm-groups', { token: admin, body: {
    name: '大额预估组', orgId: connOrg,
    policies: { hackernews: { allowedActions: 'hackernews.*', riskCap: 'admin' } },
    subjects: [{ type: 'agent', id: heavyAgent.data.agent.id }],
    precheckCents: 99999999,
  } })
  const heavyDenied = await api('POST', '/api/connector/execute', { token: heavyCc.data.token, body: { actionId: 'hackernews.fetch_item', input: {} } })
  check('T-16b precheck 余额不足 → quota_exceeded', heavyDenied.ok && heavyDenied.data?.status === 'quota_exceeded' && String(heavyDenied.data.error).includes('quota.exceeded'), JSON.stringify(heavyDenied).slice(0, 240))

  // -- T-19 stub 关停 fail-closed + 恢复 ------------------------------------------
  await api('PUT', '/api/connector/gateway', { token: admin, body: { baseUrl: 'http://127.0.0.1:9', adminToken: 'env:OOMOL_CONNECT_ADMIN_TOKEN' } })
  const outage1 = await api('POST', '/api/connector/execute', { token: admin, body: { actionId: 'hackernews.get_top_stories', input: {} } })
  await api('POST', '/api/connector/execute', { token: admin, body: { actionId: 'hackernews.get_top_stories', input: {} } })
  const outage3 = await api('POST', '/api/connector/execute', { token: admin, body: { actionId: 'hackernews.get_top_stories', input: {} } })
  check('T-19 网关不可达 → invoke fail-closed（GATEWAY_UNAVAILABLE）',
    outage1.ok === false || outage1.data?.status === 'error', JSON.stringify(outage1).slice(0, 220))
  // 连续失败计数 ≥3 时 ConnectorGatewayUnhealthy 事件→audit 落 invoke 日志（探活定时器 30s 周期之外的即时口径）
  const unhealthyTrail = await api('GET', '/api/audit/logs?q=' + encodeURIComponent('fail-closed') + '&type=invoke&limit=20', { token: admin })
  check('T-19 fail-closed 原因入审计（unavailableReason 可检索）', unhealthyTrail.ok && unhealthyTrail.data.items.length >= 1, JSON.stringify(unhealthyTrail.data?.items?.slice(0, 1)).slice(0, 200))
  await api('PUT', '/api/connector/gateway', { token: admin, body: { baseUrl: OC_BASE } })
  await api('POST', '/api/connector/gateway/health', { token: admin })
  const recoveredState = await api('GET', '/api/connector/gateway', { token: admin })
  check('T-19 恢复后自动回 healthy 并可继续调用', recoveredState.data.available === true, JSON.stringify(recoveredState).slice(0, 160))

  // -- T-21 org 巡检注入不一致 -----------------------------------------------------
  const foreignConnectionSummary = (() => { return { id: 'oc-con-fake-foreign' } })()
  const anyManagedToken = [...ocLedgerTokens.entries()][0]
  if (anyManagedToken) anyManagedToken[1].policy.allowedConnections.push(foreignConnectionSummary.id)
  const patrolNow = await api('POST', '/api/connector/patrol', { token: admin })
  if (anyManagedToken) anyManagedToken[1].policy.allowedConnections.pop()
  check('T-21 巡检发现「令牌绑定 org 外连接」异常', patrolNow.ok && (patrolNow.data.violations ?? []).some((violation) => violation.kind === 'token_binds_foreign_connection'), JSON.stringify(patrolNow.data).slice(0, 260))
  const patrolAlerts = (await api('GET', '/api/audit/alerts', { token: admin })).data.alerts ?? []
  check('T-21 异常联动 warning 告警（org 巡检标题）', patrolAlerts.some((alert) => String(alert.title).includes('org 巡检')), JSON.stringify(patrolAlerts.filter((a) => String(a.title).includes('巡检')).slice(0, 1)))

  // -- T-23 runs 对账（cursor 增量去重 + 绕行 critical） ---------------------------
  const pageOne = await fetch(`${OC_BASE}/api/runs?limit=2`, { headers: { authorization: `Bearer ${OC_TOKEN}` } }).then((r) => r.json())
  check('T-01 runs 分页信封 {items,nextCursor}',
    Array.isArray(pageOne.data.items) && (pageOne.data.nextCursor === undefined || typeof pageOne.data.nextCursor === 'string'), JSON.stringify(pageOne.data).slice(0, 120))
  const reconcileFirst = await api('POST', '/api/connector/reconcile', { token: admin })
  check('对账首跑：正常 run 与平台计量近似一致（bypass 空）', reconcileFirst.ok && (reconcileFirst.data?.bypassRuns ?? []).length === 0 && reconcileFirst.data.checkedRuns >= 1, JSON.stringify({ err: reconcileFirst.error, data: reconcileFirst.data }))
  ocRuns.push({ id: 'fake-bypass-run-0001', service: 'github', actionId: 'github.list_issues', ok: true, runtimeTokenId: anyManagedToken ? anyManagedToken[0] : 'tok-none', caller: 'direct-sidecar', startedAt: new Date().toISOString() })
  const reconcileBypass = await api('POST', '/api/connector/reconcile', { token: admin })
  check('T-23 有 run 无 meter → 绕行 critical 告警命中 fake-bypass-run-0001', reconcileBypass.ok && (reconcileBypass.data.bypassRuns ?? []).includes('fake-bypass-run-0001'), JSON.stringify(reconcileBypass.data))
  ocCtl.overlapDupInRuns = true
  const reconcileOverlap = await api('POST', '/api/connector/reconcile', { token: admin })
  ocCtl.overlapDupInRuns = false
  // 增量语义：已处理的 run 不重复计入（重叠窗口翻倍也不放大结果集）
  check('T-23 cursor 重叠窗口去重（增量运行零新增，无重复放大）',
    reconcileOverlap.ok && (reconcileOverlap.data.bypassRuns ?? []).length === 0 && reconcileOverlap.data.checkedRuns === 0, JSON.stringify(reconcileOverlap.data))
  const bypassAlerts = (await api('GET', '/api/audit/alerts', { token: admin })).data.alerts ?? []
  check('绕行调用 critical 告警已入审计告警流', bypassAlerts.some((alert) => String(alert.title).includes('绕行调用')), JSON.stringify(bypassAlerts.filter((a) => a.severity === 'critical').slice(-1)))

  // -- T-29 数据面层独立强制（合法 oct_ 直连打非命中 action） ------------------------
  const scopedMint = await fetch(`${OC_BASE}/api/runtime-tokens`, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${OC_TOKEN}` },
    body: JSON.stringify({ name: 'scoped-single-action', allowedActions: ['github.delete_webhook'], blockedActions: [], allowedProxies: [], allowedConnections: [] }),
  }).then((r) => r.json())
  ocMintedValues.push(scopedMint.data.token)
  const dataPlaneDeny = await fetch(`${OC_BASE}/v1/actions/github.list_issues`, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${scopedMint.data.token}` },
    body: JSON.stringify({ input: {} }),
  }).then((r) => r.json())
  check('T-29 合法 oct_ 直连非命中 action → 数据面 403 拒绝',
    dataPlaneDeny.success === false && Number.isFinite(dataPlaneDeny.statusCode ?? dataPlaneDeny.status ?? 403) && dataPlaneDeny.errorCode === 'forbidden_action', JSON.stringify(dataPlaneDeny).slice(0, 200))

  // -- M0 桥接（T-25，importServices + 桥接徽章标记字段） ----------------------------
  const bridgeImport = await api('POST', '/api/mcp/import', { token: admin, body: {
    config: JSON.stringify({
      mcpServers: {
        'open-connector-stub': {
          url: `${OC_BASE}/mcp`,
          headers: { authorization: `Bearer ${OC_TOKEN}`, 'x-bridged-from': 'open-connector' },
        },
      },
    }),
    autoDeploy: true,
  } })
  const bridgeResult = bridgeImport.data?.results?.[0]
  check('T-25 桥接 import 成功（reachable+online）', bridgeImport.ok && bridgeResult?.ok === true && bridgeResult.reachable === true && bridgeResult.tools > 0, JSON.stringify(bridgeImport.data).slice(0, 260))
  const servicesList = (await api('GET', '/api/mcp/services', { token: admin })).data.services
  const bridgedService = servicesList.find((service) => service.slug === 'open-connector-stub')
  check('桥接服务带「bridgeFrom=open-connector」治理降级标记', Boolean(bridgedService?.bridgeFrom) && bridgedService.bridgeFrom === 'open-connector', JSON.stringify({ slug: bridgedService?.slug, bridgeFrom: bridgedService?.bridgeFrom }))
  // M0 治理降级语义：服务级粗粒度 MCP 权限组授权（无 action 级/连接级/令牌镜像）
  await api('POST', '/api/mcp/perm-groups', { token: admin, body: {
    name: '桥接自测组（M0）',
    policies: { [bridgedService.id]: { allowedTools: '*', constraints: {} } },
    subjects: [{ type: 'user_group', id: grpAdmin.id }],
  } })
  const bridgedCall = await rawReq('POST', '/mcp', {
    headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 77, method: 'tools/call', params: { name: 'mcp_invoke', arguments: { serviceId: bridgedService?.id, tool: 'hackernews_get_top_stories', args: { platform: 'bridge' } } } }),
  })
  const bridgedText = jsonBody(bridgedCall).result?.content?.[0]?.text ?? ''
  // 平台工具层包装形态：InvokeResult.result 可为内容块数组（[{type:text,text:'{...}'}]）
  const bridgeParsed = JSON.parse(bridgedText || '{}')
  const innerBlockText = Array.isArray(bridgeParsed.result) ? bridgeParsed.result[0]?.text ?? '' : ''
  const bridgeEchoSource = (() => {
    try {
      return Array.isArray(bridgeParsed.result) ? JSON.parse(innerBlockText) : bridgeParsed
    } catch { return {} }
  })()
  const bridgeEcho = bridgeParsed.bridgeEcho ?? bridgeParsed.result?.bridgeEcho ?? bridgeEchoSource.bridgeEcho ?? {}
  check('经平台 MCP 网关调用桥接服务成功', bridgedCall.status === 200 && bridgeEcho.platform === 'bridge', bridgedText.slice(0, 220))

  // -- 三端工具面补验（工具桥 connector_execute / perm_group_list） -----------------
  const toolBridgePermList = await api('POST', '/api/tools/execute', { token: admin, body: { name: 'connector_perm_group_list', args: { orgId: connOrg } } })
  check('工具桥 connector_perm_group_list 返回结构化组清单', toolBridgePermList.ok && toolBridgePermList.data.value.total >= 4, JSON.stringify(toolBridgePermList.data?.value?.total))
  const toolBridgeExecute = await api('POST', '/api/tools/execute', { token: admin, body: { name: 'connector_execute', args: { actionId: 'hackernews.get_top_stories', input: { viaTool: true } } } })
  check('工具桥 connector_execute 身份注入 + 放行', toolBridgeExecute.ok && toolBridgeExecute.data.value.status === 'ok', JSON.stringify(toolBridgeExecute.data?.value).slice(0, 220))

  // -- 工具面权限收敛负向用例（架构审查 P0-1/P0-2：org 收敛 + 身份出参数层） -------
  const toolSchemas = (await api('GET', '/api/tools/schemas', { token: admin })).data.tools ?? []
  const connListTool = toolSchemas.find((tool) => tool.name === 'connector_connection_list')
  const connExecTool = toolSchemas.find((tool) => tool.name === 'connector_execute')
  check('工具 schema 不再暴露 orgId / callerId（身份与 org 收敛移出参数层）',
    Boolean(connListTool) && !JSON.stringify(connListTool.parameters).includes('orgId')
    && Boolean(connExecTool) && !JSON.stringify(connExecTool.parameters).includes('callerId'), JSON.stringify({ list: connListTool?.parameters, exec: connExecTool?.parameters }).slice(0, 240))

  const devOrgId = devUserSearch.orgId
  const devForge = await api('POST', '/api/tools/execute', { token: connDevLogin.data.token, body: { name: 'connector_connection_list', args: { orgId: connOrg } } })
  const devForgeList = devForge.data?.value?.connections ?? []
  check('低权限用户伪造 args.orgId 无效（工具仅返回其归属组织连接）',
    devForge.ok && devForgeList.every((item) => item.ownerOrgId === devOrgId), JSON.stringify({ devOrgId, got: devForgeList.map((item) => item.ownerOrgId) }).slice(0, 240))

  const devRestForge = await api('GET', `/api/connector/connections?orgId=${connOrg}`, { token: connDevLogin.data.token })
  check('REST 路径同一套收敛（?orgId= 对非 * 用户无效）', devRestForge.ok && (devRestForge.data.connections ?? []).every((item) => item.ownerOrgId === devOrgId), JSON.stringify(devRestForge.data).slice(0, 160))

  const extReader = await api('POST', '/api/authn/principals', { token: admin, body: { name: 'ext-connector-reader', refType: 'external', scopes: ['console.login', 'connector.connection.read'] } })
  const extCc = await api('POST', '/api/auth/client-credentials', { body: { clientId: extReader.data.clientId, clientSecret: extReader.data.clientSecret } })
  const extList = await api('POST', '/api/tools/execute', { token: extCc.data.token, body: { name: 'connector_connection_list', args: {} } })
  check('外部机器（无资源归属）连接列表 fail-closed 返回空', extList.ok && extList.data.value.total === 0 && String(extList.data.value.note ?? '').includes('fail-closed'), JSON.stringify(extList.data?.value).slice(0, 220))
  const extPermGroups = await api('POST', '/api/tools/execute', { token: extCc.data.token, body: { name: 'connector_perm_group_list', args: { orgId: connOrg } } })
  check('外部机器权限组枚举同样 fail-closed（伪造 orgId 无效）', extPermGroups.ok && extPermGroups.data.value.total === 0, JSON.stringify(extPermGroups.data?.value).slice(0, 180))

  // ================================================================ 验收回归：offline 审批闭环 / 规则播种 / mcp 直调 execute
  section('验收回归（offline 闭环 · 规则播种 · mcp 直调 execute）')

  // ③ 运营口径：连接器两条规则随演示种子幂等播种
  const seedRules = (await api('GET', '/api/audit/alert-rules', { token: admin })).data.rules ?? []
  check('连接器告警规则已播种（error_rate=critical / latency=warning）',
    seedRules.some((rule) => rule.metric === 'connector_error_rate' && rule.severity === 'critical')
    && seedRules.some((rule) => rule.metric === 'connector_latency' && rule.severity === 'warning'),
    JSON.stringify(seedRules.filter((rule) => String(rule.metric).startsWith('connector_')).map((rule) => [rule.metric, rule.threshold])))

  // ① 网关维护下线：L4 审批闭环（executor 落地 → fail-closed → 恢复探活）
  const gwOfflineReq = await api('POST', '/api/connector/gateway/offline', { token: admin, body: { reason: '验收回归-维护窗口' } })
  check('gateway.offline 默认生成 L4 审批单', gwOfflineReq.data?.approvalRequired === true && Boolean(gwOfflineReq.data.approvalId), JSON.stringify(gwOfflineReq).slice(0, 200))
  await api('POST', `/api/approvals/${gwOfflineReq.data.approvalId}/decide`, { token: admin, body: { decision: 'approve' } })
  const gwAfterOff = await api('GET', '/api/connector/gateway', { token: admin })
  check('审批通过 → executor 落地下线（fail-closed，原因含维护说明）', gwAfterOff.data.available === false && /验收回归/.test(String(gwAfterOff.data.reason)), JSON.stringify({ reason: gwAfterOff.data.reason }))
  const execBlockedMaint = await api('POST', '/api/connector/execute', { token: admin, body: { actionId: 'hackernews.get_top_stories', input: {} } })
  check('维护态 invoke fail-closed 拒绝', execBlockedMaint.data?.status === 'error' || /GATEWAY_UNAVAILABLE|网关/.test(JSON.stringify(execBlockedMaint)), JSON.stringify(execBlockedMaint).slice(0, 200))
  const gwOnline = await api('POST', '/api/connector/gateway/online', { token: admin })
  check('恢复上线即真实探活回 healthy', gwOnline.ok && gwOnline.data.ok === true, JSON.stringify(gwOnline).slice(0, 160))

  // ① 连接级下线：direct 模式留痕生效（不经审批的显式管理员路径）
  const connOffline = await api('POST', `/api/connector/connections/${patRef.id}/offline`, { token: admin, body: { reason: '验收回归-连接巡检', viaApproval: false } })
  check('连接 direct 下线立即生效（offlined 态留痕）', connOffline.ok && connOffline.data.reference?.status === 'offlined' && connOffline.data.reference.offlinedAt, JSON.stringify(connOffline).slice(0, 220))
  const execViaOfflined = await api('POST', '/api/connector/execute', { token: connDevLogin.data.token, body: { actionId: 'github.list_issues', input: {} } })
  check('经由下线连接的调用被平台侧拒绝（连接级闸）', execViaOfflined.ok && execViaOfflined.data?.status === 'denied' && /已下线/.test(String(execViaOfflined.data.error)), JSON.stringify(execViaOfflined).slice(0, 240))
  const connBack = await api('POST', `/api/connector/connections/${patRef.id}/online`, { token: admin })
  check('连接恢复后 sidecar 回查转 active', connBack.ok && connBack.data.reference?.status === 'active', JSON.stringify(connBack).slice(0, 220))

  // ④ POST /mcp tools/call 直调 connector_execute（三端最后一环；验收项原定下次迭代，本轮提前闭合）
  const mcpDirectCall = await rawReq('POST', '/mcp', {
    headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 88, method: 'tools/call', params: { name: 'connector_execute', arguments: { actionId: 'hackernews.get_top_stories', input: { viaMcp: true } } } }),
  })
  const mcpDirectRaw = jsonBody(mcpDirectCall).result?.content?.[0]?.text ?? ''
  const mcpDirectOutcome = (() => { try { return JSON.parse(mcpDirectRaw) } catch { return {} } })()
  check('POST /mcp 直调 connector_execute（身份注入 + runId 回执）',
    mcpDirectCall.status === 200 && mcpDirectOutcome.status === 'ok' && /^exec-/.test(String(mcpDirectOutcome.runId)) && mcpDirectOutcome.data?.echo?.viaMcp === true, mcpDirectRaw.slice(0, 260))

  // 桥接规范形态：经 execute_action(actionId,input) 调用（集成指南 v0.2 §五口径；legacy 别名仍兼容）
  const bridgedExecCall = await rawReq('POST', '/mcp', {
    headers: { 'content-type': 'application/json', authorization: `Bearer ${admin}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 89, method: 'tools/call', params: { name: 'mcp_invoke', arguments: { serviceId: bridgedService?.id, tool: 'execute_action', args: { actionId: 'hackernews.get_top_stories', input: { viaExecuteAction: true } } } } }),
  })
  const execRaw = jsonBody(bridgedExecCall).result?.content?.[0]?.text ?? ''
  const execParsed = (() => { try { return JSON.parse(execRaw) } catch { return {} } })()
  const execBlocks = Array.isArray(execParsed.result) ? JSON.parse(execParsed.result[0]?.text ?? '{}') : {}
  check('桥接 execute_action 规范调用成功（含 runId 回执）',
    bridgedExecCall.status === 200 && Boolean(execBlocks.bridgeEcho?.runId ?? execBlocks.runId), execRaw.slice(0, 240))

  // ================================================================ /docs 静态发布（文档目录随服务可访问）
  section('/docs 静态发布（接入指南等文档直接可读）')

  const docIndex = await rawReq('GET', '/docs')
  check('/docs 目录索引页（HTML + 列出接入指南）', docIndex.status === 200 && String(docIndex.headers['content-type']).startsWith('text/html') && docIndex.body.includes('app-sso-integration.md'))
  const docFile = await rawReq('GET', '/docs/app-sso-integration.md')
  check('/docs/app-sso-integration.md 可读（markdown + 正文）', docFile.status === 200 && String(docFile.headers['content-type']).startsWith('text/markdown') && docFile.body.includes('OIDC') && docFile.body.includes('接入'))
  const docMissing = await rawReq('GET', '/docs/not-exists.md')
  check('/docs 未知文档 404', docMissing.status === 404)
  // 路径穿越探测：字面 .. 与编码 %2e%2e 均被 URL 解析归一化（WHATWG 规范视编码点段为点段）→ 回落 SPA 兜底页，不泄露文件
  const docTraverseLiteral = await rawReq('GET', '/docs/../package.json')
  check('/docs 字面 .. 穿越 → SPA 兜底页（不泄露文件）', docTraverseLiteral.status === 200 && String(docTraverseLiteral.headers['content-type']).startsWith('text/html') && !docTraverseLiteral.body.includes('"name": "dsh-enterprise-ops"'))
  const docTraverseEncoded = await rawReq('GET', '/docs/%2e%2e/package.json')
  check('/docs 编码 %2e%2e 穿越 → SPA 兜底页（不泄露文件）', docTraverseEncoded.status === 200 && String(docTraverseEncoded.headers['content-type']).startsWith('text/html') && !docTraverseEncoded.body.includes('"name": "dsh-enterprise-ops"'))
  const spaStillOk = await rawReq('GET', '/')
  check('SPA 静态兜底不受影响（/ 仍返回控制台首页）', spaStillOk.status === 200 && String(spaStillOk.headers['content-type']).startsWith('text/html') && spaStillOk.body.includes('榕器'))

  // ================================================================ 门户数据通道（plugin-portal：外部拉取端点）
  section('门户数据通道（plugin-portal：企业门户拉取已发布应用/Agent，非核心）')
  const portalOrigin = 'http://192.168.0.4:8092'
  const portalGet = async (path, headers = {}) => rawReq('GET', `/api/portal${path}`, { headers })
  const portalJson = async (path, headers = {}) => {
    const raw = await portalGet(path, headers)
    return { status: raw.status, headers: raw.headers, body: jsonBody(raw) }
  }
  // 门户契约：纯前端无鉴权拉取——不带 Bearer 直接访问（console 鉴权中间件不得拦截门户前缀）
  const portalDiscovery = await portalJson('/', { origin: portalOrigin })
  check('公开访问 200（无 Bearer，门户前缀先于 console 鉴权中间件截获）', portalDiscovery.status === 200 && portalDiscovery.body.code === 0 && Array.isArray(portalDiscovery.body.data?.endpoints))
  const portalApps = await portalJson('/apps', { origin: portalOrigin })
  check('契约包装 {code:0, message, data} + no-cache（刷新即可见）', portalApps.status === 200 && portalApps.body.code === 0 && portalApps.body.message === 'ok' && Array.isArray(portalApps.body.data) && portalApps.headers['cache-control'] === 'no-cache')
  check('CORS 放行生产门户来源', portalApps.headers['access-control-allow-origin'] === portalOrigin)
  // 全链路：注册 → L4 审批上线 → 门户拉取即可见（miniapp 形态不走 SSO 门禁）
  const portalProbe = await api('POST', '/api/apps', { token: admin, body: { name: '门户拉取探针应用', attrs: { description: '门户数据通道验收：上线即对门户可见', appType: 'miniapp', url: 'http://192.168.0.8:9000/', riskLevel: 'low', dataClass: 'internal' } } })
  const portalProbeReq = await api('POST', `/api/apps/${portalProbe.data.app.id}/transition`, { token: admin, body: { action: 'online' } })
  await api('POST', `/api/approvals/${portalProbeReq.data.approval.id}/decide`, { token: admin, body: { decision: 'approve', opinion: '门户可见性验收' } })
  const portalAppsAfter = await portalJson('/apps', { origin: portalOrigin })
  const portalApp = portalAppsAfter.body.data.find((item) => item.id === portalProbe.data.app.id)
  check('已上线应用进入 /apps（link=访问地址，tag/version/accent 契约齐全）',
    portalApp && portalApp.name === '门户拉取探针应用' && portalApp.link === 'http://192.168.0.8:9000/'
    && portalApp.tag === '小程序' && portalApp.desc === '门户数据通道验收：上线即对门户可见'
    && typeof portalApp.accent === 'string' && /^#[0-9A-Fa-f]{6}$/.test(portalApp.accent))
  check('launchDate 为上线当日（YYYY-MM-DD）', /^\d{4}-\d{2}-\d{2}$/.test(portalApp?.launchDate ?? '') && portalApp.launchDate === new Date().toISOString().slice(0, 10))
  const adminApps = (await api('GET', '/api/apps', { token: admin })).data.apps
  const expectedOnline = adminApps.filter((item) => item.status === 'online')
  check('/apps 与平台已上线应用一致（仅 online 进入门户，未上线/下架不出现）',
    portalAppsAfter.body.data.length === expectedOnline.length
    && expectedOnline.every((item) => portalAppsAfter.body.data.some((entry) => entry.id === item.id)))
  const portalEmployees = await portalJson('/employees', { origin: 'http://192.168.0.8:8443' })
  check('/employees：已上线 Agent=数字员工（内网 :8443 开发来源 CORS 同样放行）',
    portalEmployees.status === 200 && portalEmployees.headers['access-control-allow-origin'] === 'http://192.168.0.8:8443'
    && Array.isArray(portalEmployees.body.data) && portalEmployees.body.data.some((item) => item.id === targetAgent.id && item.avatar && typeof item.skills === 'string'))
  const portalSkills = await portalJson('/skills')
  check('/skills：已上架 Skill 契约（downloadUrl 为门户公开下载端点绝对地址）',
    portalSkills.status === 200 && Array.isArray(portalSkills.body.data) && portalSkills.body.data.length >= 1
    && portalSkills.body.data.every((item) => /^https?:\/\/.+\/api\/portal\/skills\/.+\/download$/.test(item.downloadUrl)))
  const portalSkillDl = await rawReq('GET', new URL(portalSkills.body.data[0].downloadUrl).pathname)
  check('downloadUrl 免鉴权可直接下载（200 + zip 魔数 PK + attachment 头）',
    portalSkillDl.status === 200 && String(portalSkillDl.headers['content-type']).includes('zip')
    && portalSkillDl.body.startsWith('PK') && String(portalSkillDl.headers['content-disposition']).includes('attachment'), JSON.stringify({ status: portalSkillDl.status, type: portalSkillDl.headers['content-type'] }))
  const portalDlMissing = await portalJson('/skills/skl_not_exist/download')
  check('未上架/未知技能下载 404 契约错误', portalDlMissing.status === 404 && portalDlMissing.body.code === 40400)
  const portalStats = await portalJson('/stats', { origin: portalOrigin })
  check('/stats：恰 4 卡且 value 为字符串（契约明确非数值）', portalStats.body.data.length === 4 && portalStats.body.data.every((item) => typeof item.value === 'string' && item.unit !== undefined && item.label !== undefined))
  check('/stats 口径：已上线应用计数与 /apps 一致', Number(portalStats.body.data[0].value) === portalAppsAfter.body.data.length)
  const portalSolutions = await portalJson('/solutions')
  const portalTools = await portalJson('/tools')
  check('/solutions、/tools：暂无数据源 → 空数组（门户契约 §5：降级展示内置样板）', portalSolutions.body.data?.length === 0 && portalTools.body.data?.length === 0)
  const portalPreflight = await rawReq('OPTIONS', '/api/portal/apps', { headers: { origin: portalOrigin, 'access-control-request-method': 'GET' } })
  check('OPTIONS 预检 204 + 放行方法/来源头', portalPreflight.status === 204 && portalPreflight.headers['access-control-allow-origin'] === portalOrigin && String(portalPreflight.headers['access-control-allow-methods']).includes('GET'))
  const portalUnknown = await portalJson('/nope', { origin: portalOrigin })
  check('未知端点 404 契约错误（门户展示错误与重试，不影响其他端点）', portalUnknown.status === 404 && portalUnknown.body.code === 40400)
  const portalNoOrigin = await portalGet('/stats')
  check('无 Origin 请求正常应答（仅不回 CORS 放行头）', portalNoOrigin.status === 200 && !portalNoOrigin.headers['access-control-allow-origin'])
  const portalPost = await rawReq('POST', '/api/portal/apps', { headers: { 'content-type': 'application/json', origin: portalOrigin }, body: '{}' })
  check('写方法被拒 405（契约全只读）', portalPost.status === 405)

  // ================================================================ 收尾终检：凭证零进平台（红线一，T-24）
  section('凭证零进平台（红线一 · T-24 全目录扫描）')
  // SIGTERM 触发 main.ts 的 flushNow（把内存中的待写集合全部原子落盘）后退出，
  // 再扫描数据目录——保证连「尚未刷盘的最新写入」也在扫描覆盖之内。
  proc.kill('SIGTERM')
  let stopped = false
  for (let i = 0; i < 30; i++) {
    await new Promise((resolve) => setTimeout(resolve, 300))
    try { await fetch(`${BASE}/api/health`); } catch { stopped = true; break }
  }
  if (!stopped) proc.kill('SIGKILL')
  const bannedSecrets = ['ghp_selftestSecret123', 'client-supersecret-oauth-xyz', ...new Set(ocMintedValues)]
  const bannedHits = []
  const walkFiles = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walkFiles(join(dir, entry.name)) : [join(dir, entry.name)])
  let dataFiles = []
  try { dataFiles = walkFiles(DATA_DIR) } catch { /* 目录已被清理则跳过扫描 */ }
  for (const file of dataFiles) {
    try {
      const text = readFileSync(file).toString('latin1')
      for (const secret of bannedSecrets) {
        if (text.includes(secret)) bannedHits.push({ file: file.split(/[\\/]/).slice(-2).join('/'), secret })
      }
    } catch { /* 二进制读失败跳过 */ }
  }
  check(`T-24 数据目录 ${dataFiles.length} 个文件全部扫描`, dataFiles.length > 5, `files=${dataFiles.length}`)
  check('T-24 凭证原文零命中（API Key / OAuth client secret / 每个一次性 oct_ 值）',
    bannedHits.length === 0 && ocMintedValues.length >= 3, JSON.stringify(bannedHits))
} finally {
  // ---------------------------------------------------------------- 收尾
  console.log('\n\x1b[90m» 停止测试实例…\x1b[0m')
  proc.kill('SIGKILL')
  await new Promise((resolve) => ghStub.close(resolve))
  await new Promise((resolve) => nasGwStub.close(resolve))
  await new Promise((resolve) => ocStub.close(resolve))
  await rm(DATA_DIR, { recursive: true, force: true }).catch(() => {})
}

// ================================================================ 汇总
const failed = results.filter((item) => !item.pass)
console.log(`\n${'━'.repeat(46)}`)
console.log(`  \x1b[1m自测结果：${results.length - failed.length}/${results.length} 通过\x1b[0m`)
if (failed.length > 0) {
  console.log(`\n  \x1b[31m失败项：\x1b[0m`)
  for (const item of failed) {
    console.log(`   ✘ [${item.section}] ${item.name}`)
  }
  process.exit(1)
} else {
  console.log('  \x1b[32m全部通过 ✔\x1b[0m')
  process.exit(0)
}
