/** AI 应用本体：列表 + 详情（指标/编排拓扑/成本穿透/生命周期）。 */
import { api, session } from '../api.js'
import { icon } from '../icons.js'
import {
  h, $, $$, esc, toast, openDrawer, openModal, confirmDialog, copyText,
  statusBadge, renderTable, collectForm, field, inputField, selectField, textareaField,
  fmtNum, fmtPct, fmtCost, fmtTime, timeAgo, emptyState, lineChart, maybeShowConceptCard,
  multiSelectField, searchableSelectField, mountSearchableSelects,
} from '../ui.js'
import { buildAppOnboardingText, openOnboardingModal } from '../onboarding.js'
import {
  dataClassLabel, riskClass, riskLabel, typeLabel, stateLabel, actionLabel,
  miniStat, renderTopologyList, barChartSafe,
} from './agents.js'

const APP_TYPE = { web: ['Web 应用', 'globe'], h5: ['H5', 'app'], miniapp: ['小程序', 'app'], desktop: ['桌面端', 'server'], api: ['API 服务', 'plug'] }

const isIconUrl = (value) => /^https?:\/\//i.test(String(value ?? '').trim())

/** 头像 / 图标渲染：http(s) 图片地址渲染为 <img> 头像，其余按 emoji 文本展示（.res-icon 同尺寸）。 */
function appIconHtml(value) {
  if (isIconUrl(value)) {
    return `<img class="res-icon" src="${esc(String(value).trim())}" alt="" referrerpolicy="no-referrer" style="object-fit:cover;background:linear-gradient(135deg,#eef2ff,#e0e7ff)">`
  }
  return `<div class="res-icon" style="background:linear-gradient(135deg,#eef2ff,#e0e7ff);font-size:21px">${esc(String(value ?? '').trim() || '✨')}</div>`
}

/** 平台授权直达：签发一次性入场票据后带 #entry_ticket 打开应用（裸跳转已下线，与应用自有 OIDC 接入互不影响）。 */
async function openAppEntry(app) {
  try {
    const issued = await api.post(`/api/apps/${app.id}/entry-ticket`)
    window.open(`${app.attrs['url']}#entry_ticket=${encodeURIComponent(issued.ticket)}`, '_blank', 'noopener')
    toast(`已带平台身份打开（票据 ${issued.ttlSeconds}s 内有效，已留痕审计）`)
  } catch (error) { toast(error.message, 'error') }
}

export async function renderApps(content, params, ctx) {
  const data = await api.get('/api/apps')
  const apps = data.apps

  // 首次访问概念卡（易用性整改）
  maybeShowConceptCard(content, 'apps', {
    icon: 'app',
    title: 'AI 应用是什么？',
    subtitle: 'AI 应用 = 员工直接使用的智能应用入口（问答助手、文档助手等）。',
    points: [
      '形态多样：在 Agent 底座上扩展 Web / H5 / 小程序等访问入口。',
      '依赖可穿透：应用 → Agent → MCP/Skill 的调用链与成本一图归集。',
      '治理统一：谁能用、用了多少，走平台统一身份与审计。',
    ],
  })

  content.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">AI 应用本体管理</div>
        <div class="page-desc">在 Agent 底座上扩展应用形态与访问入口；应用 → Agent → MCP/Skill 依赖一图穿透，成本链路可归集。</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-primary" id="app-add">${icon('plus', 14)}注册应用</button>
      </div>
    </div>
    <div class="card-grid" id="app-cards"></div>`

  const holder = $('#app-cards')
  if (!apps.length) {
    holder.appendChild(emptyState({ title: '还没有 AI 应用', desc: '注册第一个应用，把 Agent 编排成产品', actionText: '注册应用', onAction: () => $('#app-add').click(), icon: 'app' }))
  }
  for (const app of apps) {
    const [typeLabel_, typeIcon] = APP_TYPE[app.attrs['appType']] ?? ['应用', 'app']
    const card = h(`
      <div class="res-card" data-id="${esc(app.id)}">
        <div class="res-card-top">
          ${appIconHtml(app.attrs['icon'])}
          <div class="grow">
            <div class="res-name">${esc(app.name)} ${statusBadge(app.status)}</div>
            <div class="res-slug">${esc(app.slug)} · ${esc(typeLabel_)}${app.attrs['publishVersion'] ? ' · ' + esc(app.attrs['publishVersion']) : ''}</div>
          </div>
        </div>
        <div class="res-desc">${esc(app.attrs['description'] ?? '')}</div>
        <div class="flex" style="gap:6px;flex-wrap:wrap">
          ${(Array.isArray(app.attrs['agentIds']) ? app.attrs['agentIds'] : []).length
            ? `<span class="badge badge-purple no-dot">编排 ${app.attrs['agentIds'].length} 个 Agent</span>` : '<span class="text-4 fs-12">未编排 Agent</span>'}
          ${(app.attrs['channels'] ?? []).map((ch) => `<span class="badge badge-muted no-dot">${esc(ch)}</span>`).join('')}
        </div>
        <div class="res-foot">
          <div class="res-foot-main">
            <span class="metric">${icon('eye', 13)}PV ${fmtNum(app.metrics.pv ?? 0)}</span>
            <span class="metric">${icon('users', 13)}UV ${fmtNum(app.metrics.uv ?? 0)}</span>
            <span class="metric">${icon('users', 13)}DAU ${fmtNum(app.metrics.dau)}</span>
            <span class="metric">${icon('activity', 13)}会话 ${fmtNum(app.metrics.sessions)}</span>
          </div>
          <div class="res-foot-side">
            ${app.attrs['url'] ? `<a class="btn btn-ghost btn-sm" data-entry href="javascript:void(0)">${icon('external', 13)}打开</a>` : ''}
            ${app.attrs['developerName'] ? `<span class="text-4">开发者 · ${esc(app.attrs['developerName'])}</span>` : ''}
          </div>
        </div>
      </div>`)
    const entryBtn = card.querySelector('[data-entry]')
    if (entryBtn) entryBtn.onclick = (e) => { e.stopPropagation(); void openAppEntry(app) }
    card.onclick = () => openAppDetail(app.id, ctx)
    holder.appendChild(card)
  }

  $('#app-add').onclick = () => openAppCreate(data.schema, ctx)
  if (params.get('action') === 'create') openAppCreate(data.schema, ctx)
  if (params.get('focus')) void openAppDetail(params.get('focus'), ctx)
}

async function openAppDetail(id, ctx) {
  const app = await api.get(`/api/apps/${id}`)
  const titleIcon = isIconUrl(app.attrs['icon'])
    ? `<img src="${esc(String(app.attrs['icon']).trim())}" alt="" referrerpolicy="no-referrer" style="width:22px;height:22px;border-radius:6px;object-fit:cover;vertical-align:-4px;margin-right:6px">`
    : esc(app.attrs['icon'] ?? '✨')
  const drawer = openDrawer({
    title: `${titleIcon} ${esc(app.name)}`,
    sub: `${app.slug} · ${app.attrs['url'] ?? '未登记访问地址'}`,
    wide: true,
    body: `
      <div class="flex mb-14" style="gap:8px;flex-wrap:wrap">
        ${statusBadge(app.status)}
        <span class="badge ${riskClass(app.attrs['riskLevel'])} no-dot">风险：${riskLabel(app.attrs['riskLevel'])}</span>
        <span class="badge badge-info no-dot">密级：${dataClassLabel(app.attrs['dataClass'])}</span>
        ${app.attrs['developerName'] ? `<span class="badge badge-muted no-dot">${icon('user', 12)} 开发者：${esc(app.attrs['developerName'])}</span>` : ''}
        ${(app.attrs['channels'] ?? []).map((ch) => `<span class="badge badge-muted no-dot">${esc(ch)}</span>`).join('')}
        ${app.attrs['url'] ? `<button class="btn btn-default btn-sm" id="app-open-entry">${icon('external', 13)}带平台身份打开应用</button>` : '<span class="text-4 fs-12">未登记访问地址</span>'}
      </div>

      <div class="stat-grid mb-20" style="grid-template-columns:repeat(6,1fr)">
        ${miniStat('eye', '今日 PV', fmtNum(app.metrics.pv ?? 0))}
        ${miniStat('users', '今日 UV', fmtNum(app.metrics.uv ?? 0))}
        ${miniStat('users', '今日 DAU', fmtNum(app.metrics.dau))}
        ${miniStat('activity', '累计会话', fmtNum(app.metrics.sessions))}
        ${miniStat('zap', '会话深度', app.metrics.avgDepth + ' 轮')}
        ${miniStat('trending', '7 日留存', fmtPct(app.metrics.retention7))}
      </div>

      <div class="tabs" id="app-tabs">
        <div class="tab active" data-tab="topology">编排拓扑</div>
        <div class="tab" data-tab="metrics">应用指标</div>
        <div class="tab" data-tab="cost">成本穿透</div>
        <div class="tab" data-tab="lifecycle">生命周期</div>
        <div class="tab" data-tab="sso">${icon('key', 13)} SSO 配置${app.sso ? (app.sso.status === 'active' ? '' : ' ⚠') : ''}</div>
      </div>
      <div id="app-tab-body"></div>`,
    foot: (app.availableTransitions.map((t) => {
      const isL4 = t.action === 'online' || t.action === 'offline'
      return `<button class="btn ${isL4 ? 'btn-primary' : 'btn-default'}" data-action="${esc(t.action)}">${icon(t.action === 'online' ? 'play' : t.action === 'offline' ? 'alert' : 'chevronRight', 14)}${esc(t.label)}</button>`
    }).join('') || '<button class="btn btn-default" disabled>终态</button>')
      + `<button class="btn btn-default" id="app-onboard">${icon('book', 14)}生成接入提示词</button>`
      + `<button class="btn btn-default" id="app-edit">${icon('edit', 14)}编辑资料</button>`
      + (['draft', 'archived'].includes(app.status) ? `<button class="btn btn-danger-ghost" id="app-delete">${icon('trash', 14)}删除</button>` : ''),
  })

  const tabBody = drawer.body.querySelector('#app-tab-body')
  const openEntryBtn = drawer.body.querySelector('#app-open-entry')
  if (openEntryBtn) openEntryBtn.onclick = () => void openAppEntry(app)
  const renderTab = (tab) => {
    if (tab === 'topology') {
      tabBody.innerHTML = `
        <div class="card card-pad mb-14">
          <div class="card-title mb-14">${icon('gitBranch', 14)} 依赖拓扑（应用 → Agent → MCP/Skill）</div>
          ${topologySvg(app.topology)}
          <div class="form-hint mt-8">异常节点标红；一图穿透到底层能力，出问题可快速定位层级。</div>
        </div>
        <div class="card card-pad">
          <div class="card-title mb-8">结构化视图</div>
          ${renderTopologyList(app.topology)}
        </div>
        ${app.impact.length ? `
          <div class="card card-pad mt-14" style="border-color:var(--warn-border);background:var(--warn-bg)">
            <div class="card-title mb-8">${icon('alert', 14)} 影响面（若下架）</div>
            ${app.impact.map((i) => `<div class="fs-13" style="padding:3px 0">· ${esc(i.name)}（${typeLabel(i.type)}）</div>`).join('')}
          </div>` : ''}`
    }
    if (tab === 'metrics') {
      tabBody.innerHTML = `
        <div class="card card-pad mb-14">
          <div class="card-title mb-8">近 14 天 UV / DAU（日去重口径）</div>
          ${lineChart([app.metrics.series.map((s) => s.uv ?? 0), app.metrics.series.map((s) => s.dau)], { width: 640, height: 150, colors: ['#10b981', '#4f6ef7'], labels: ['UV', 'DAU'] })}
        </div>
        <div class="card card-pad mb-14">
          <div class="card-title mb-8">近 14 天 PV（页面浏览量）</div>
          ${barChartSafe(app.metrics.series.map((s) => ({ label: s.date, value: s.pv ?? 0 })), 640, 150)}
        </div>
        <div class="card card-pad">
          <div class="card-title mb-8">近 14 天会话数</div>
          ${barChartSafe(app.metrics.series.map((s) => ({ label: s.date, value: s.sessions })), 640, 150)}
        </div>`
    }
    if (tab === 'cost') {
      const total = app.cost.reduce((s, row) => s + row.costYuan, 0)
      tabBody.innerHTML = `
        <div class="flex-between mb-14">
          <div><span class="fs-12 text-3">累计成本</span><div style="font-size:22px;font-weight:700">${fmtCost(total)}</div></div>
          <span class="fs-12 text-3">应用 → Agent → MCP/模型 穿透归集</span>
        </div>
        ${app.cost.map((row) => `
          <div class="flex" style="padding:10px 0;border-bottom:1px solid var(--border)">
            <span class="badge badge-purple no-dot">Agent</span>
            <span class="fs-13 grow">${esc(row.agentName)}</span>
            <span class="fs-12 text-3" style="margin-right:14px">Token ${fmtNum(row.llmTokens)} · 调用 ${fmtNum(row.toolCalls)}</span>
            <span style="font-weight:600">${fmtCost(row.costYuan)}</span>
          </div>`).join('') || '<span class="text-4 fs-12">暂无成本数据</span>'}`
    }
    if (tab === 'lifecycle') {
      tabBody.innerHTML = `
        <div class="timeline">
          ${app.lifecycleHistory.map((entry, index) => `
            <div class="timeline-item ${index === app.lifecycleHistory.length - 1 ? 'current' : 'ok'}">
              <div class="timeline-dot"></div>
              <div class="timeline-title">${esc(entry.action === 'create' ? '注册创建' : actionLabel(entry.action))} → ${esc(stateLabel(entry.to))}</div>
              <div class="timeline-time">${timeAgo(entry.at)} · 操作人 ${esc(entry.actor)}</div>
              ${entry.note ? `<div class="timeline-body">${esc(entry.note)}</div>` : ''}
            </div>`).join('')}
        </div>`
    }
    if (tab === 'sso') renderSsoTab(tabBody, app, ctx)
  }
  drawer.body.querySelectorAll('#app-tabs .tab').forEach((el) => {
    el.onclick = () => {
      drawer.body.querySelectorAll('#app-tabs .tab').forEach((t) => t.classList.remove('active'))
      el.classList.add('active')
      renderTab(el.dataset.tab)
    }
  })
  renderTab('topology')

  for (const transition of app.availableTransitions) {
    const btn = drawer.el.querySelector(`[data-action="${transition.action}"]`)
    if (!btn) continue
    btn.onclick = async () => {
      if (transition.action === 'online' || transition.action === 'offline') {
        const isOnline = transition.action === 'online'
        const result = await confirmDialog({
          title: isOnline ? '应用发布上线（L4）' : '应用下架（L4）',
          requireReason: !isOnline,
          danger: !isOnline,
          confirmText: '提交审批',
          message: isOnline
            ? `发布 <b>${esc(app.name)}</b> 需要另一管理员审批确认。`
            : `下架 <b>${esc(app.name)}</b> 后终端用户立即无法访问，机器凭证同步吊销。`,
        })
        if (!result) return
        try {
          await api.post(`/api/apps/${app.id}/transition`, { action: transition.action, note: result.reason ?? '发布申请' })
          toast('已创建审批单'); drawer.close(); ctx.rerender()
        } catch (error) { toast(error.message, 'error') }
      } else {
        try {
          await api.post(`/api/apps/${app.id}/transition`, { action: transition.action })
          toast('状态已更新'); drawer.close(); ctx.rerender()
        } catch (error) { toast(error.message, 'error') }
      }
    }
  }

  const editBtn = drawer.el.querySelector('#app-edit')
  if (editBtn) editBtn.onclick = () => openAppEdit(app, ctx)

  const onboardBtn = drawer.el.querySelector('#app-onboard')
  if (onboardBtn) onboardBtn.onclick = () => openAppOnboardPrompt(app)

  const deleteBtn = drawer.el.querySelector('#app-delete')
  if (deleteBtn) deleteBtn.onclick = async () => {
    const result = await confirmDialog({
      title: `删除应用 · ${app.name}`, requireReason: true, danger: true, confirmText: '确认删除',
      message: `将永久删除 <b>${esc(app.name)}</b>：清除编排依赖、禁用 SSO 客户端与机器凭证，操作不可恢复；指标与审计数据保留。`,
    })
    if (!result) return
    try {
      await api.delete(`/api/apps/${app.id}`)
      toast('已删除'); drawer.close(); ctx.rerender()
    } catch (error) { toast(error.message, 'error') }
  }
}

/** SSO 配置 tab：未签发 → 签发引导；已签发 → 回调管理 / 轮换 / 启停 / discovery；两态均附「平台直达」卡片。 */
function renderSsoTab(holder, app, ctx) {
  const sso = app.sso
  const enforced = (app.ssoEnforceTypes ?? []).includes(app.attrs['appType'])
  if (!sso) {
    holder.innerHTML = `
      <div class="card card-pad">
        <div class="card-title mb-8">${icon('key', 14)} 应用身份纳管（SSO）</div>
        <div class="fs-13 text-2 mb-8" style="line-height:1.9">
          签发 OIDC 客户端后，应用即可按标准协议接入平台统一身份：
          <div class="muted-box mt-8" style="font-size:12.5px">
            ① 授权码模式跳转 <code class="mono">${esc(app.sso?.discovery?.authorization_endpoint ?? '/oauth/authorize')}</code>（强制 PKCE S256）<br>
            ② <code class="mono">code</code> 换 <code class="mono">id_token / access_token</code>（Basic 或 Post 认证）<br>
            ③ <code class="mono">access_token</code> 调 <code class="mono">/oauth/userinfo</code> 取用户身份（sub / org / roles / tenant），业务权限应用内自理
          </div>
        </div>
        ${enforced ? `<div class="muted-box mb-14" style="display:flex;gap:8px;border-color:var(--warn-border);background:var(--warn-bg)">${icon('alert', 15)}<span><b>${esc(app.attrs['appType'])} 形态应用上线门禁</b>：未完成 SSO 签发前，上线审批将被拒绝。</span></div>` : ''}
        <button class="btn btn-primary" id="sso-issue">${icon('key', 14)}签发 SSO 客户端</button>
        <a class="btn btn-default" href="https://github.com/01men/ybkk-AIOS/blob/main/docs/app-sso-integration.md" target="_blank" style="margin-left:8px">接入文档</a>
      </div>
      ${entryDirectCardHtml(app)}`
    holder.querySelector('#sso-issue').onclick = () => openIssueSsoModal(app, ctx)
    wireEntryDirectCard(holder, app)
    return
  }
  const active = sso.status === 'active'
  holder.innerHTML = `
    <div class="card card-pad mb-14">
      <div class="flex-between mb-8">
        <div class="card-title">${icon('key', 14)} 已签发客户端 ${statusBadge(active ? 'active' : 'frozen', active ? '使用中' : '已禁用')}</div>
        <span class="badge ${sso.clientType === 'public' ? 'badge-purple' : 'badge-info'} no-dot">${sso.clientType === 'public' ? 'public（免 secret · 强制 PKCE）' : 'confidential'}</span>
      </div>
      <div class="desc-grid mb-14">
        <div class="desc-item"><span class="k">client_id</span><span class="v mono">${esc(sso.clientId)} <button class="btn btn-ghost btn-sm" id="sso-copy-id">复制</button></span></div>
        <div class="desc-item"><span class="k">关联应用</span><span class="v">${esc(sso.refAppName ?? app.name)}</span></div>
        <div class="desc-item"><span class="k">签发时间</span><span class="v">${fmtTime(sso.createdAt)}</span></div>
      </div>
      <div class="form-item">
        <label class="form-label">回调地址（redirect_uris，每行一个；https://，或 http:// 内网/本机地址）</label>
        <textarea class="form-control mono" id="sso-redirects" rows="2">${esc(sso.redirectUris.join('\n'))}</textarea>
      </div>
      <div class="form-item">
        <label class="form-label">登出回跳白名单（post_logout_redirect_uris，每行一个，可空）</label>
        <textarea class="form-control mono" id="sso-postlogouts" rows="2">${esc((sso.postLogoutUris ?? []).join('\n'))}</textarea>
      </div>
      <label class="flex" style="gap:8px;font-size:13px;margin:6px 0 12px;cursor:pointer">
        <input type="checkbox" id="sso-consent" ${sso.consentRequired ? 'checked' : ''} style="accent-color:var(--brand-500)">
        <span>授权页要求用户显式勾选同意（对外部应用建议开启）</span>
      </label>
      <div class="flex" style="gap:8px;flex-wrap:wrap">
        <button class="btn btn-primary" id="sso-save">${icon('check', 14)}保存配置</button>
        ${sso.clientType !== 'public' ? `<button class="btn btn-default" id="sso-rotate">${icon('refresh', 14)}轮换 secret</button>` : ''}
        ${active
          ? '<button class="btn btn-danger-ghost" id="sso-disable">禁用客户端</button>'
          : '<button class="btn btn-primary" id="sso-enable">启用客户端</button>'}
      </div>
      ${!active && enforced ? `<div class="muted-box mt-8" style="display:flex;gap:8px;border-color:var(--warn-border);background:var(--warn-bg)">${icon('alert', 15)}<span>客户端处于禁用状态：${esc(app.attrs['appType'])} 形态应用的上线门禁将被阻断。</span></div>` : ''}
    </div>
    <div class="card card-pad">
      <div class="card-title mb-8">${icon('plug', 14)} 接入端点（discovery）</div>
      <div class="desc-grid">
        <div class="desc-item"><span class="k">issuer</span><span class="v mono">${esc(sso.discovery.issuer)}</span></div>
        <div class="desc-item"><span class="k">authorize</span><span class="v mono">${esc(sso.discovery.authorization_endpoint)}</span></div>
        <div class="desc-item"><span class="k">token</span><span class="v mono">${esc(sso.discovery.token_endpoint)}</span></div>
        <div class="desc-item"><span class="k">userinfo</span><span class="v mono">${esc(sso.discovery.userinfo_endpoint)}</span></div>
      </div>
      <div class="flex mt-8" style="gap:8px">
        <button class="btn btn-default btn-sm" id="sso-copy-discovery">复制 discovery 地址</button>
        <a class="btn btn-default btn-sm" href="https://github.com/01men/ybkk-AIOS/blob/main/docs/app-sso-integration.md" target="_blank">接入文档</a>
      </div>
      <div class="form-hint mt-8">应用侧按 OIDC 标准接入（openid-client / oidc-client-ts 一行 discovery 驱动）；id_token 验签公钥见 JWKS：<code class="mono">${esc(sso.discovery.issuer)}/.well-known/jwks.json</code></div>
    </div>
    ${entryDirectCardHtml(app)}`
  holder.querySelector('#sso-copy-id').onclick = () => void copyText(sso.clientId)
  holder.querySelector('#sso-copy-discovery').onclick = () => void copyText(`${sso.discovery.issuer}/.well-known/openid-configuration`)
  wireEntryDirectCard(holder, app)
  holder.querySelector('#sso-save').onclick = async () => {
    const redirectUris = holder.querySelector('#sso-redirects').value.split('\n').map((s) => s.trim()).filter(Boolean)
    const postLogoutUris = holder.querySelector('#sso-postlogouts').value.split('\n').map((s) => s.trim()).filter(Boolean)
    try {
      await api.patch(`/api/apps/${app.id}/sso-client`, { redirectUris, postLogoutUris, consentRequired: holder.querySelector('#sso-consent').checked })
      toast('SSO 配置已保存'); openAppDetail(app.id, ctx)
    } catch (error) { toast(error.message, 'error') }
  }
  const rotateBtn = holder.querySelector('#sso-rotate')
  if (rotateBtn) rotateBtn.onclick = async () => {
    const result = await confirmDialog({
      title: '轮换 client_secret', danger: true, confirmText: '确认轮换',
      message: '旧 secret <b>立即失效</b>，应用侧需同步更新。新 secret 仅展示一次。',
    })
    if (!result) return
    try {
      const rotated = await api.post(`/api/apps/${app.id}/sso-client/rotate`)
      showSsoSecret(rotated)
    } catch (error) { toast(error.message, 'error') }
  }
  const disableBtn = holder.querySelector('#sso-disable')
  if (disableBtn) disableBtn.onclick = async () => {
    const result = await confirmDialog({
      title: '禁用 SSO 客户端', requireReason: true, danger: true, confirmText: '立即禁用',
      message: '禁用后该应用的登录跳转与令牌刷新立即失败（refresh 链一并吊销）。',
    })
    if (!result) return
    try {
      await api.post(`/api/apps/${app.id}/sso-client/disable`, { reason: result.reason })
      toast('客户端已禁用'); openAppDetail(app.id, ctx)
    } catch (error) { toast(error.message, 'error') }
  }
  const enableBtn = holder.querySelector('#sso-enable')
  if (enableBtn) enableBtn.onclick = async () => {
    try {
      await api.post(`/api/apps/${app.id}/sso-client/enable`)
      toast('客户端已启用'); openAppDetail(app.id, ctx)
    } catch (error) { toast(error.message, 'error') }
  }
}

/** 平台直达（entry-ticket）卡片：与应用自有 OIDC 接入互补，未签发 SSO 客户端也可用。 */
function entryDirectCardHtml(app) {
  if (!app.attrs['url']) {
    return `
      <div class="card card-pad mt-14">
        <div class="card-title mb-8">${icon('external', 14)} 平台直达（entry-ticket）</div>
        <div class="form-hint">未登记访问地址（attrs.url）——登记后控制台即可带平台身份直达应用。</div>
      </div>`
  }
  return `
    <div class="card card-pad mt-14">
      <div class="flex-between mb-8">
        <div class="card-title">${icon('external', 14)} 平台直达（entry-ticket）</div>
        <span class="badge badge-ok no-dot">已启用</span>
      </div>
      <div class="desc-grid mb-14">
        <div class="desc-item"><span class="k">访问地址</span><span class="v mono">${esc(app.attrs['url'])}</span></div>
        <div class="desc-item"><span class="k">兑换端点</span><span class="v mono">POST /api/authn/entry-tickets/redeem</span></div>
        <div class="desc-item"><span class="k">票据时效</span><span class="v">一次性 · 短时（默认 120s）</span></div>
      </div>
      <div class="flex" style="gap:8px">
        <button class="btn btn-primary" id="sso-entry-open">${icon('external', 14)}带平台身份打开应用</button>
      </div>
      <div class="form-hint mt-8">「打开应用」按钮已升级为带平台身份直达：签发一次性票据后以 <code class="mono">#entry_ticket=…</code> 打开，应用前端兑换平台身份；与上方标准 OIDC 授权码接入互不影响。</div>
    </div>`
}

function wireEntryDirectCard(holder, app) {
  const btn = holder.querySelector('#sso-entry-open')
  if (btn) btn.onclick = () => void openAppEntry(app)
}

/** 签发 SSO 客户端弹窗（redirectUris / 类型 / 同意策略）。 */
function openIssueSsoModal(app, ctx) {
  const modal = openModal({
    title: `签发 SSO 客户端 · ${app.name}`, wide: true,
    body: `
      <div class="muted-box mb-14" style="display:flex;gap:8px">${icon('info', 15)}<span>client_secret 仅签发后展示一次；应用按 OIDC 授权码模式接入（强制 PKCE S256）。</span></div>
      <div class="form-grid">
        ${field('回调地址 redirect_uris（每行一个）', `
          <textarea class="form-control mono" name="redirectUris" rows="2" placeholder="https://app.example.com/auth/cb&#10;http://192.168.0.7:8080/auth/cb（内网）&#10;http://localhost:3000/cb（本机调试）"></textarea>`, { required: true, full: true, hint: 'https:// 任意主机；http:// 仅限内网（localhost / 127.0.0.1 / 10.x / 172.16-31.x / 192.168.x）' })}
        ${field('客户端类型', selectField('clientType', [
          { value: 'confidential', label: 'confidential —— 有后端，持有 secret（推荐）' },
          { value: 'public', label: 'public —— 纯前端 SPA，免 secret（强制 PKCE、不发 refresh）' },
        ]), { full: true })}
        <label class="flex" style="gap:8px;font-size:13px;cursor:pointer">
          <input type="checkbox" name="consentRequired" style="accent-color:var(--brand-500)">
          <span>授权页要求用户显式勾选同意（对外部应用建议开启）</span>
        </label>
      </div>`,
    foot: '<button class="btn btn-default" data-cancel>取消</button><button class="btn btn-primary" data-ok>签发</button>',
  })
  modal.el.querySelector('[data-cancel]').onclick = () => modal.close()
  modal.el.querySelector('[data-ok]').onclick = async () => {
    const data = collectForm(modal.body)
    const redirectUris = (modal.body.querySelector('[name=redirectUris]').value).split('\n').map((s) => s.trim()).filter(Boolean)
    try {
      const created = await api.post(`/api/apps/${app.id}/sso-client`, {
        redirectUris,
        clientType: data.clientType,
        consentRequired: data.consentRequired === true,
      })
      modal.close()
      showSsoSecret(created)
      openAppDetail(app.id, ctx)
    } catch (error) { toast(error.message, 'error') }
  }
}

/** 一次性 secret 展示弹窗（签发 / 轮换共用）。 */
function showSsoSecret({ clientId, clientSecret, note }) {
  openModal({
    title: 'SSO 凭据（仅此一次展示）',
    body: `
      <div class="form-hint" style="margin-bottom:10px;color:var(--danger)">请立即复制保存，关闭后无法再次查看 client_secret。</div>
      <div class="code-block">client_id:     ${esc(clientId)}
${clientSecret ? `client_secret: ${esc(clientSecret)}` : '（public 客户端无 secret，凭 PKCE 保护）'}</div>
      <div class="form-hint mt-8">${esc(note ?? '')}</div>`,
    foot: '<button class="btn btn-primary" data-ok>已保存</button>',
  })
}

/** SVG 树形拓扑图（手工布局，节点分列排布）。 */
function topologySvg(root) {
  const layers = []
  const collect = (node, depth) => {
    if (!layers[depth]) layers[depth] = []
    layers[depth].push(node)
    for (const child of node.children) collect(child, depth + 1)
  }
  collect(root, 0)
  const NODE_W = 148, NODE_H = 54, GAP_X = 26, GAP_Y = 18
  const width = Math.max(...layers.map((l) => l.length)) * (NODE_W + GAP_X) - GAP_X
  const height = layers.length * (NODE_H + GAP_Y) + 20
  const posOf = new Map()
  layers.forEach((layer, depth) => {
    const layerWidth = layer.length * (NODE_W + GAP_X) - GAP_X
    const startX = (width - layerWidth) / 2
    layer.forEach((node, index) => {
      posOf.set(node, { x: startX + index * (NODE_W + GAP_X), y: 16 + depth * (NODE_H + GAP_Y) })
    })
  })
  const colorOf = (node) => {
    if (node.status === 'unhealthy') return { border: '#ef4444', bg: '#fef2f2', text: '#b91c1c' }
    if (node.type === 'app') return { border: '#4f6ef7', bg: '#eef2ff', text: '#2f49c1' }
    if (node.type === 'agent') return { border: '#8b5cf6', bg: '#f5f3ff', text: '#6d28d9' }
    if (node.type === 'skill') return { border: '#10b981', bg: '#ecfdf5', text: '#047857' }
    return { border: '#d4d6dd', bg: '#f8f9fb', text: '#4b5059' }
  }
  const nodeIcon = (node) => ({ app: 'app', agent: 'bot', skill: 'sparkles' }[node.type] ?? 'box')
  let edges = ''
  let nodes = ''
  const walkEdges = (node) => {
    for (const child of node.children) {
      const from = posOf.get(node), to = posOf.get(child)
      const x1 = from.x + NODE_W / 2, y1 = from.y + NODE_H
      const x2 = to.x + NODE_W / 2, y2 = to.y
      edges += `<path d="M${x1},${y1} C${x1},${y1 + 14} ${x2},${y2 - 14} ${x2},${y2}" fill="none" stroke="#c9ccd4" stroke-width="1.6"/>`
      walkEdges(child)
    }
  }
  walkEdges(root)
  for (const [node, pos] of posOf) {
    const c = colorOf(node)
    nodes += `
      <g transform="translate(${pos.x},${pos.y})" style="cursor:default">
        <rect width="${NODE_W}" height="${NODE_H}" rx="10" fill="${c.bg}" stroke="${c.border}" stroke-width="1.4"/>
        <g transform="translate(10,14)" stroke="${c.text}" fill="none" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${iconPathsRaw(nodeIcon(node))}</g>
        <text x="34" y="24" font-size="12" font-weight="600" fill="${c.text}">${esc(clip(node.name, 11))}</text>
        <text x="34" y="40" font-size="10" fill="#8a8f99">${esc(node.statusLabel)}</text>
      </g>`
  }
  return `
    <div style="overflow-x:auto">
      <svg width="${Math.max(width, 320)}" height="${height}" viewBox="0 0 ${Math.max(width, 320)} ${height}">
        ${edges}${nodes}
      </svg>
    </div>`
}
function iconPathsRaw(name) {
  return ICON_PATH_CACHE[name] ?? ''
}
import { PATHS as ICON_PATH_CACHE } from '../icons.js'
function clip(text, max) {
  return text.length > max ? text.slice(0, max) + '…' : text
}

/** 编辑应用资料（头像/开发者/描述/访问地址）：与注册白名单同源，PATCH attrs；开发者空选表示清除。 */
function openAppEdit(app, ctx) {
  void api.get('/api/apps/developer-options').catch(() => ({ options: [] })).then((devData) => {
    const devOptions = (devData.options ?? []).map((u) => ({ value: u.id, label: `${u.name}（@${u.username}）`, group: u.orgName || '未分组' }))
    const modal = openModal({
      title: `编辑应用资料 · ${app.name}`, wide: true,
      body: `
        <div class="form-grid">
          ${field('头像 / 图标', inputField('icon', { value: String(app.attrs['icon'] ?? '✨'), placeholder: 'emoji 或图片 URL（https://…）' }), { hint: '填图片 http(s) 地址即显示为头像' })}
          ${field('开发者', searchableSelectField('developerId', devOptions, {
            value: app.attrs['developerId'] ?? '',
            placeholder: '搜索姓名 / 账号选择开发者',
            emptyLabel: '（不指定开发者）',
          }))}
          ${field('访问地址', inputField('url', { value: String(app.attrs['url'] ?? ''), placeholder: 'https://…' }), { full: true })}
          ${field('描述', textareaField('description', { rows: 2, value: app.attrs['description'] ?? '' }), { required: true, full: true })}
        </div>`,
      foot: '<button class="btn btn-default" data-cancel>取消</button><button class="btn btn-primary" data-ok>保存</button>',
    })
    modal.el.querySelector('[data-cancel]').onclick = () => modal.close()
    mountSearchableSelects(modal.el)
    modal.el.querySelector('[data-ok]').onclick = async () => {
      const data = collectForm(modal.body)
      const attrs = { developerId: data.developerId ?? '' }
      if (String(data.icon ?? '').trim()) attrs.icon = String(data.icon).trim()
      if (String(data.url ?? '').trim()) attrs.url = String(data.url).trim()
      if (String(data.description ?? '').trim()) attrs.description = String(data.description).trim()
      try {
        await api.patch(`/api/apps/${app.id}`, { attrs })
        toast('应用资料已更新'); modal.close(); openAppDetail(app.id, ctx)
      } catch (error) { toast(error.message, 'error') }
    }
  })
}

/** 生成接入提示词：注册同款模板由平台侧生成（单一事实源）；可选轮换机器凭证（旧 secret 失效）以携带完整凭证。 */
function openAppOnboardPrompt(app) {
  const modal = openModal({
    title: `生成接入提示词 · ${app.name}`,
    body: `
      <div class="muted-box mb-14" style="display:flex;gap:8px;line-height:1.8">${icon('info', 15)}<span>按<b>注册同款模板</b>生成全文（换牌 → 接入验证 → SSO 打通 → 计量）。<br>
      <b>重新生成密钥并生成</b>：提示词携带完整 client_secret，<b>旧 secret 立即失效</b>——首次接入或密钥丢失时选这个；<br>
      <b>仅生成（不轮换）</b>：仅含 client_id，secret 部分为占位，适合只想重看接入步骤的场景。</span></div>`,
    foot: `
      <button class="btn btn-default" data-cancel>取消</button>
      <button class="btn btn-default" data-plain>仅生成（不轮换）</button>
      <button class="btn btn-primary" data-rotate>重新生成密钥并生成</button>`,
  })
  const generate = async (rotate) => {
    try {
      const result = await api.post(`/api/apps/${app.id}/onboarding-prompt`, { rotate })
      modal.close()
      openOnboardingModal({
        title: `接入提示词 · ${app.name}${rotate ? '（密钥已重新生成）' : ''}`,
        resourceLabel: 'AI 应用',
        resource: app,
        credential: result.credential,
        metaRows: [
          ['应用 ID', app.id],
          ['client_id', result.credential.clientId],
          ...(result.credential.clientSecret ? [['client_secret', result.credential.clientSecret]] : []),
        ],
        guideText: result.prompt,
      })
    } catch (error) { toast(error.message, 'error') }
  }
  modal.el.querySelector('[data-cancel]').onclick = () => modal.close()
  modal.el.querySelector('[data-plain]').onclick = () => void generate(false)
  modal.el.querySelector('[data-rotate]').onclick = () => void generate(true)
}

function openAppCreate(schema, ctx) {
  void Promise.all([
    api.get('/api/agents'),
    api.get('/api/apps/developer-options').catch(() => ({ options: [] })),
  ]).then(([agentData, devData]) => {
    const onlineAgents = agentData.agents.filter((a) => a.status === 'online' || a.status === 'trial')
    const modal = openModal({
      title: '注册 AI 应用', wide: true,
      body: `
        <div class="form-grid">
          ${field('应用名称', inputField('name'), { required: true })}
          ${field('应用标识', inputField('slug', { placeholder: '小写字母与中划线' }))}
          ${field('应用类型', selectField('appType', [
            { value: 'web', label: 'Web 应用' }, { value: 'h5', label: 'H5' }, { value: 'miniapp', label: '小程序' },
            { value: 'desktop', label: '桌面端' }, { value: 'api', label: 'API 服务' },
          ]), { required: true })}
          ${field('头像 / 图标', inputField('icon', { value: '✨', placeholder: 'emoji 或图片 URL（https://…）' }), { hint: '填图片 http(s) 地址即显示为头像，否则按 emoji 展示' })}
          ${field('访问地址', inputField('url', { placeholder: 'https://…' }), { full: true, hint: '上线（发布）前必须登记' })}
          ${field('描述', textareaField('description', { rows: 2 }), { required: true, full: true })}
        </div>
        <div class="card-title mb-8" style="margin-top:8px">归属与编排</div>
        ${field('开发者', searchableSelectField('developerId', (devData.options ?? []).map((u) => ({
          value: u.id,
          label: `${u.name}（@${u.username}）`,
          group: u.orgName || '未分组',
        })), { placeholder: '搜索姓名 / 账号选择开发者', emptyLabel: '（不指定，默认注册人）' }), { full: true, hint: '从平台在编用户中选择；不选则默认注册人' })}
        <div class="card-title mb-8" style="margin-top:8px">编排 Agent（依赖拓扑数据源）</div>
        ${onlineAgents.length
          ? field('选择编排 Agent（可多选）', multiSelectField('agentIds', onlineAgents.map((a) => ({
              value: a.id,
              label: `${a.attrs['avatar'] ?? '🤖'} ${a.name}（${a.slug}）`,
            })), { placeholder: '搜索并选择编排 Agent，可多选；留空表示暂无依赖' }))
          : '<div class="form-hint mb-8">没有在线 Agent 可编排（Agent 需先上线）</div>'}
        <div class="form-grid">
          ${field('风险等级', selectField('riskLevel', [{ value: 'low', label: '低' }, { value: 'medium', label: '中' }, { value: 'high', label: '高' }]), { required: true })}
          ${field('数据密级', selectField('dataClass', [{ value: 'internal', label: '内部' }, { value: 'public', label: '公开' }, { value: 'confidential', label: '机密' }]), { required: true })}
        </div>`,
      foot: '<button class="btn btn-default" data-cancel>取消</button><button class="btn btn-primary" data-ok>注册应用</button>',
    })
    modal.el.querySelector('[data-cancel]').onclick = () => modal.close()
    mountSearchableSelects(modal.el)
    modal.el.querySelector('[data-ok]').onclick = async () => {
      const data = collectForm(modal.body)
      const agentIds = (data.agentIds ?? '').split(',').filter(Boolean)
      try {
        const result = await api.post('/api/apps', {
          name: data.name, slug: data.slug || undefined,
          attrs: {
            appType: data.appType, icon: data.icon, url: data.url, description: data.description,
            riskLevel: data.riskLevel, dataClass: data.dataClass, agentIds,
            ...(data.developerId ? { developerId: data.developerId } : {}),
          },
          agentIds,
        })
        modal.close()
        if (result.credential) {
          openOnboardingModal({
            title: '注册成功 · 接入指引与应用凭证（仅此一次展示）',
            resourceLabel: 'AI 应用',
            resource: result.app,
            credential: result.credential,
            metaRows: [
              ['应用 ID', result.app.id],
              ['标识', result.app.slug],
              ['client_id', result.credential.clientId],
              ['client_secret', result.credential.clientSecret],
            ],
            guideText: buildAppOnboardingText(result.app, result.credential),
          })
        }
        ctx.rerender()
      } catch (error) { toast(error.message, 'error') }
    }
  })
}
