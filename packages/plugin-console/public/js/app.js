/** 应用外壳：路由 + 布局 + 侧边栏 + 顶栏 + ⌘K 命令面板。 */
import { icon } from './icons.js'
import { session, api } from './api.js'
import { $, $$, h, toast, esc } from './ui.js'
import { openCmdk } from './cmdk.js'

import { renderLogin } from './pages/login.js'
import { renderDashboard } from './pages/dashboard.js'
import { renderIam } from './pages/iam.js'
import { renderAuthn } from './pages/authn.js'
import { renderMcp } from './pages/mcp.js'
import { renderNas } from './pages/nas.js'
import { renderNasAuthz } from './pages/nas-authz.js'
import { renderConnectors } from './pages/connectors.js'
import { renderSkills } from './pages/skills.js'
import { renderAgents } from './pages/agents.js'
import { renderApps } from './pages/apps.js'
import { renderAudit } from './pages/audit.js'
import { renderApprovals } from './pages/approvals.js'
import { renderAssets } from './pages/assets.js'
import { renderPlatform } from './pages/platform.js'
import { renderConnect } from './pages/connect.js'
import { renderOauthAuthorize, renderOauthError, renderOauthLogout } from './pages/oauth.js'
import { mountUpdateBadge, openUpdateDrawer } from './update.js'

const NAV = [
  { section: '总览', items: [
    { path: '#/dashboard', label: '工作台', icon: 'dashboard', perm: 'console.login' },
  ] },
  { section: 'AI 资源', items: [
    { path: '#/skills', label: 'Skill 市场', icon: 'sparkles', perm: 'skill.read', badge: 'skills' },
    { path: '#/agents', label: 'Agent 本体', icon: 'bot', perm: 'agent.read' },
    { path: '#/apps', label: 'AI 应用', icon: 'app', perm: 'app.read' },
    { path: '#/mcp', label: 'MCP 服务', icon: 'plug', perm: 'mcp.service.read' },
    { path: '#/nas', label: 'NAS 存储', icon: 'server', perm: 'nas.read' },
    { path: '#/nas-authz', label: '数据权限', icon: 'shield', perm: 'nas.authz.read' },
    { path: '#/connectors', label: '连接器', icon: 'plug', perm: 'connector.catalog.read' },
  ] },
  { section: '治理与运营', items: [
    { path: '#/assets', label: '资产运营', icon: 'layers', perm: 'usage.read' },
    { path: '#/approvals', label: '审批中心', icon: 'checkSquare', perm: 'approval.read', badge: 'approvals' },
    { path: '#/audit', label: '审计与告警', icon: 'scroll', perm: 'audit.read', badge: 'alerts' },
    { path: '#/authn', label: '认证与令牌', icon: 'key', perm: 'authn.principal.read' },
  ] },
  { section: '组织', items: [
    { path: '#/iam', label: '组织与账号', icon: 'users', perm: 'iam.user.read' },
    { path: '#/iam?tab=roles', label: '角色权限', icon: 'shield', perm: 'iam.org.read' },
    { path: '#/iam?tab=connectors', label: '三方集成', icon: 'link', perm: 'iam.org.read' },
  ] },
  { section: '平台', items: [
    { path: '#/connect', label: '平台接入', icon: 'fingerprint', perm: 'connect.manage' },
    { path: '#/platform', label: '插件与工具', icon: 'puzzle', perm: 'console.login' },
  ] },
]

const app = $('#app')

function currentHash() { return location.hash || '#/dashboard' }

function navigate() {
  const hash = currentHash()
  const [path, query] = hash.split('?')
  const params = new URLSearchParams(query ?? '')
  const page = path.replace(/^#\//, '') || 'dashboard'

  // OAuth 协议页（授权/错误/登出）：独立于控制台外壳，无会话也放行（页面自带登录面板）
  if (page.startsWith('oauth/')) {
    const oauthBuilders = {
      'oauth/authorize': renderOauthAuthorize,
      'oauth/error': renderOauthError,
      'oauth/logout': renderOauthLogout,
    }
    ;(oauthBuilders[page] ?? renderOauthError)(app, params)
    return
  }

  if (!session.token) {
    renderLogin(app)
    return
  }

  const builders = {
    dashboard: renderDashboard,
    iam: renderIam,
    authn: renderAuthn,
    mcp: renderMcp,
    nas: renderNas,
    'nas-authz': renderNasAuthz,
    connectors: renderConnectors,
    skills: renderSkills,
    agents: renderAgents,
    apps: renderApps,
    assets: renderAssets,
    audit: renderAudit,
    approvals: renderApprovals,
    platform: renderPlatform,
    connect: renderConnect,
  }
  const builder = builders[page] ?? renderDashboard
  renderShell(page, params, builder)
}

function renderShell(page, params, builder) {
  app.innerHTML = `
    <div class="layout">
      <aside class="sidebar">
        <div class="sidebar-brand">
          <img class="brand-mark brand-logo" src="/rongqi_ai.png" alt="榕器">
          <div>
            <div class="brand-name" style="white-space:normal;font-size:13px;line-height:1.35">榕器|企业AI资源管理平台</div>
            <div class="brand-sub">DeepSeek Harness · 一切皆插件</div>
          </div>
        </div>
        <nav class="sidebar-nav" id="nav"></nav>
        <div class="sidebar-footer" id="sidebar-footer"></div>
      </aside>
      <div class="main">
        <header class="topbar">
          <div class="topbar-search" id="cmdk-trigger">
            ${icon('search', 15)}
            <span>搜索资源、执行操作…</span>
            <kbd>⌘K</kbd>
          </div>
          <div class="topbar-right">
            <button class="icon-btn" id="btn-refresh" title="刷新数据">${icon('refresh')}</button>
            <div style="position:relative" id="update-host"></div>
            <div style="position:relative" id="alert-host"></div>
            <div class="avatar" id="avatar" title="${esc(session.user?.displayName ?? '')}">${esc((session.user?.displayName ?? '?').slice(0, 1))}</div>
          </div>
        </header>
        <main class="content" id="page-content"></main>
      </div>
    </div>`

  // 侧边导航
  const nav = $('#nav')
  for (const section of NAV) {
    const visible = section.items.filter((item) => session.can(item.perm))
    if (!visible.length) continue
    const sec = h(`<div class="nav-section"><div class="nav-section-title">${esc(section.section)}</div></div>`)
    for (const item of visible) {
      const active = currentHash().split('?')[0] === item.path
      const el = h(`<div class="nav-item ${active ? 'active' : ''}">${icon(item.icon)}<span>${esc(item.label)}</span><span class="nav-badge hidden"></span></div>`)
      el.onclick = () => { location.hash = item.path }
      item._badgeEl = el.querySelector('.nav-badge')
      sec.appendChild(el)
    }
    nav.appendChild(sec)
  }

  // 侧边栏底部用户信息
  const footer = $('#sidebar-footer')
  footer.innerHTML = `
    <div class="flex" style="gap:10px">
      <div class="avatar sm">${esc((session.user?.displayName ?? '?').slice(0, 1))}</div>
      <div class="grow" style="min-width:0">
        <div class="fs-13 ellipsis" style="color:#e5e7eb">${esc(session.user?.displayName ?? '')}</div>
        <div class="fs-11 text-4 ellipsis">${esc(session.user?.roles?.[0] ?? '成员')}</div>
      </div>
      <button class="icon-btn" id="btn-logout" title="退出登录" style="width:28px;height:28px">${icon('logout', 15)}</button>
    </div>`
  $('#btn-logout').onclick = async () => {
    try { await api.post('/api/auth/logout') } catch { /* ignore */ }
    session.clear()
    location.hash = '#/login'
    navigate()
  }
  $('#btn-refresh').onclick = () => { navigate(); toast('数据已刷新') }
  $('#cmdk-trigger').onclick = () => openCmdk()
  $('#avatar').onclick = () => openCmdk()

  // 徽标（待审批/未读告警）与平台更新提示
  void refreshBadges()
  void mountUpdateBadge()

  // 平台更新：30 分钟轮询一次徽标（自动检查的结果会在页面切换时自然刷新）
  clearInterval(window.__updatePoll)
  window.__updatePoll = setInterval(() => { if (session.token) void mountUpdateBadge() }, 30 * 60 * 1000)

  const content = $('#page-content')
  builder(content, params, { rerender: navigate })
}

async function refreshBadges() {
  try {
    const overview = await api.get('/api/overview')
    const targets = { approvals: overview.approvals?.pending ?? 0, alerts: overview.alerts?.unread ?? 0, skills: overview.skills?.pendingApproval ?? 0 }
    for (const section of NAV) {
      for (const item of section.items) {
        if (!item._badgeEl || !item.badge) continue
        const count = targets[item.badge] ?? 0
        item._badgeEl.textContent = String(count)
        item._badgeEl.classList.toggle('hidden', count === 0)
      }
    }
    const host = $('#alert-host')
    if (host && overview.alerts?.unread > 0) {
      host.innerHTML = `<button class="icon-btn" id="btn-alerts" title="${overview.alerts.unread} 条未读告警">${icon('bell')}<span class="dot"></span></button>`
      host.querySelector('#btn-alerts').onclick = () => { location.hash = '#/audit?tab=alerts' }
    } else if (host) {
      host.innerHTML = `<button class="icon-btn" title="暂无未读告警">${icon('bell')}</button>`
    }
  } catch { /* 静默 */ }
}

// 全局路由
window.addEventListener('hashchange', navigate)
navigate()

// ⌘K 快捷键
window.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault()
    if (session.token) openCmdk()
  }
})
