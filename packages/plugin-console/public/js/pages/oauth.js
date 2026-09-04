/**
 * OAuth 协议页（平台作为身份源 IdP 的三个对外页面，独立于控制台外壳）：
 *   #/oauth/authorize?req=<id> —— 授权确认（无会话渲染登录面板：账号密码 + 钉钉整页跳转扫码授权，
 *                                  钉钉客户端内自动免登，mock 模式回退手动授权码；有会话按需 consent）
 *   #/oauth/error?error=…     —— 协议错误页（静态展示，error_description 一律转义）
 *   #/oauth/logout?…          —— RP 发起登出中转（清平台会话后带 state 跳回应用）
 * 说明：本页直连原始 fetch（不经 api.js 会话拦截），保证协议流不被控制台跳转劫持。
 */
import { session } from '../api.js'
import { icon } from '../icons.js'
import { esc } from '../ui.js'

const SCOPE_LABEL = {
  openid: '确认你的身份标识（sub，平台内稳定不变）',
  profile: '读取基础资料（用户名 / 姓名 / 组织 / 角色 / 租户）',
  email: '读取邮箱地址',
}

/** 原始 JSON 请求（不带 {ok,data} 包裹处理逻辑的平台内部约定由本页自行解析）。 */
async function rawJson(method, path, body) {
  const headers = { 'content-type': 'application/json' }
  if (session.token) headers.authorization = `Bearer ${session.token}`
  const response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  let payload = null
  try { payload = await response.json() } catch { /* ignore */ }
  return { status: response.status, payload }
}

function pageShell(inner) {
  return `
    <div class="oauth-page">
      <div class="oauth-card">
        <div class="oauth-brand">
          <img class="brand-mark brand-logo" src="/rongqi_ai.png" alt="榕器">
          <div>
            <div class="oauth-title">榕器|企业AI资源管理平台</div>
            <div class="oauth-sub">统一身份源 · OIDC 授权</div>
          </div>
        </div>
        ${inner}
      </div>
    </div>`
}

/** 错误码 → 中文说明（协议错误码保持原文透传）。 */
const ERROR_LABEL = {
  invalid_request: '授权请求参数不完整或非法',
  unauthorized_client: '客户端未登记或已被禁用',
  unsupported_response_type: '仅支持授权码模式（response_type=code）',
  invalid_scope: '申请的授权范围（scope）未获平台允许',
  access_denied: '授权被拒绝',
}

// -- 授权确认页 -------------------------------------------------------------

export async function renderOauthAuthorize(app, params) {
  const reqId = params.get('req') ?? ''
  if (!reqId) {
    renderOauthError(app, new URLSearchParams({ error: 'invalid_request', error_description: '缺少 req 参数（授权请求无效）' }))
    return
  }
  app.innerHTML = pageShell('<div class="oauth-sub">正在加载授权请求…</div>')
  let info
  try {
    const result = await rawJson('GET', `/api/authn/oidc/auth-requests/${encodeURIComponent(reqId)}`)
    if (result.status !== 200 || !result.payload?.clientName) throw new Error(result.payload?.error_description ?? '授权请求无效、已使用或已过期')
    info = result.payload
  } catch (error) {
    renderOauthError(app, new URLSearchParams({ error: 'invalid_request', error_description: error.message }))
    return
  }
  // 无平台会话：先渲染登录面板（登录成功后回到授权确认）
  if (!session.token) {
    renderLoginPanel(app, reqId, info)
    return
  }
  renderConsent(app, reqId, info)
}

function renderLoginPanel(app, reqId, info) {
  app.innerHTML = pageShell(`
    <div class="oauth-sub" style="margin-bottom:14px">登录平台账号后继续授权给 <b>${esc(info.clientName)}</b></div>
    <div class="segmented" style="margin-bottom:18px" id="oauth-login-tabs">
      <span class="segmented-item" data-tab="dingtalk">钉钉扫码</span>
      <span class="segmented-item active" data-tab="password">账号密码</span>
    </div>
    <form id="oauth-login-form">
      <div class="form-item">
        <label class="form-label">用户名</label>
        <input class="input input-lg" id="oauth-login-user" placeholder="平台用户名" autocomplete="username">
      </div>
      <div class="form-item">
        <label class="form-label">密码</label>
        <input class="input input-lg" id="oauth-login-pass" type="password" placeholder="密码" autocomplete="current-password">
      </div>
      <button class="btn btn-primary btn-lg btn-block" id="oauth-login-submit" type="submit">登录并继续</button>
    </form>
    <div id="oauth-login-dingtalk" style="display:none">
      <div id="oauth-ding-step-authorize">
        <div id="oauth-ding-oauth-list">
          <button class="btn btn-primary btn-lg btn-block" id="oauth-ding-oauth-go" type="button">使用钉钉扫码 / 点击头像登录</button>
        </div>
        <div class="form-hint" style="margin:8px 0 4px">整页跳转钉钉授权：已登录钉钉点击头像即可完成，未登录则出二维码扫码；在钉钉客户端内打开会自动识别登录状态发起免登。</div>
        <details id="oauth-ding-manual" style="margin-top:12px">
          <summary class="form-hint" style="cursor:pointer">手动输入授权码（演示/mock 备用）</summary>
          <div style="text-align:center;padding:10px 0 6px">
            <div style="width:148px;height:148px;margin:0 auto;border-radius:14px;background:
              radial-gradient(100px 100px at 30% 25%, #e0e7ff, transparent),
              radial-gradient(100px 100px at 75% 80%, #ede9fe, transparent), #f8f9fb;
              border:1px solid var(--border);display:grid;place-items:center;position:relative">
              <div style="color:var(--brand-500)">${icon('fingerprint', 52)}</div>
              <div style="position:absolute;bottom:10px;font-size:11px;color:var(--text-3)">使用钉钉扫码授权登录</div>
            </div>
          </div>
          <div class="form-item" style="margin-top:14px">
            <label class="form-label">钉钉授权码</label>
            <input class="input input-lg" id="oauth-ding-code" placeholder="请输入钉钉扫码授权码">
          </div>
          <div id="oauth-ding-actions">
            <button class="btn btn-primary btn-lg btn-block" id="oauth-ding-submit">免密登录并继续</button>
          </div>
        </details>
      </div>
      <div id="oauth-ding-step-pending" style="display:none">
        <div class="muted-box" style="display:flex;gap:8px;margin-bottom:14px">
          ${icon('info', 15)}<span>首次使用该钉钉身份（<b id="oauth-ding-pending-name"></b>）。按「一人一号」原则，请绑定已有平台账号，或注册新账号。</span>
        </div>
        <div class="tabs" style="margin-bottom:14px">
          <div class="tab active" data-ptab="bind">绑定已有账号</div>
          <div class="tab" data-ptab="register">注册新账号</div>
        </div>
        <div id="oauth-ding-bind-panel">
          <div class="form-item"><label class="form-label">平台用户名</label><input class="input input-lg" id="oauth-ding-bind-username" placeholder="平台账号用户名"></div>
          <div class="form-item"><label class="form-label">密码</label><input class="input input-lg" id="oauth-ding-bind-password" type="password" placeholder="平台账号密码"></div>
          <button class="btn btn-primary btn-lg btn-block" id="oauth-ding-bind-submit">验证并绑定</button>
        </div>
        <div id="oauth-ding-register-panel" style="display:none">
          <div class="form-hint" style="margin-bottom:12px">将以三方身份自动注册平台账号（默认进入首个组织），并建立身份链接。</div>
          <button class="btn btn-primary btn-lg btn-block" id="oauth-ding-register-submit">注册并继续</button>
        </div>
        <button class="btn btn-ghost btn-block" style="margin-top:8px" id="oauth-ding-pending-back">返回重试</button>
      </div>
      <div class="form-hint" id="oauth-ding-tip" style="margin-top:10px"></div>
    </div>`)
  // 三方登录入口按平台连接器配置显隐（与主登录页同一探测端点与规则）：探测在下方入口渲染函数定义后执行
  const tabPassword = app.querySelector('#oauth-login-form')
  const tabDingtalk = app.querySelector('#oauth-login-dingtalk')
  // 用户是否手动切过标签：自动选中钉钉默认标签时不覆盖用户选择
  let tabTouched = false
  const switchTab = (name) => {
    app.querySelectorAll('#oauth-login-tabs .segmented-item').forEach((item) => item.classList.toggle('active', item.dataset.tab === name))
    const isPassword = name === 'password'
    tabPassword.style.display = isPassword ? '' : 'none'
    tabDingtalk.style.display = isPassword ? 'none' : ''
  }
  app.querySelectorAll('#oauth-login-tabs .segmented-item').forEach((el) => {
    el.onclick = () => {
      tabTouched = true
      switchTab(el.dataset.tab)
    }
  })

  const form = app.querySelector('#oauth-login-form')
  form.onsubmit = async (event) => {
    event.preventDefault()
    const btn = app.querySelector('#oauth-login-submit')
    btn.classList.add('btn-loading')
    try {
      const result = await rawJson('POST', '/api/auth/login', {
        username: app.querySelector('#oauth-login-user').value.trim(),
        password: app.querySelector('#oauth-login-pass').value,
      })
      if (result.status !== 200 || !result.payload?.ok) throw new Error(result.payload?.error?.message ?? '登录失败')
      session.save(result.payload.data.token, result.payload.data.user)
      if (result.payload.data.refreshToken) session.saveRefresh(result.payload.data.refreshToken)
      renderConsent(app, reqId, info)
    } catch (error) {
      btn.classList.remove('btn-loading')
      const tip = app.querySelector('#oauth-login-tip')
      if (tip) tip.textContent = error.message
      else form.insertAdjacentHTML('beforeend', `<div class="form-hint" id="oauth-login-tip" style="color:var(--danger);margin-top:10px">${esc(error.message)}</div>`)
    }
  }

  // 钉钉免密登录（与主登录页同一端点链：authorize 签发 state → code 换会话 → 首次身份走绑定/注册）
  let dingTicket = ''
  const dingTip = (text) => { app.querySelector('#oauth-ding-tip').textContent = text }
  const finishSsoLogin = (data) => {
    session.save(data.token, data.user)
    if (data.refreshToken) session.saveRefresh(data.refreshToken)
    // 本页内完成登录：清理可能残留的 OIDC 回跳暂存（consent 在本页继续，无需回跳）
    try { localStorage.removeItem(OIDC_REQ_KEY) } catch { /* 忽略 */ }
    renderConsent(app, reqId, info)
  }
  const unwrap = (result, fallback) => {
    if (result.status !== 200 || !result.payload?.ok) throw new Error(result.payload?.error?.message ?? fallback)
    return result.payload.data
  }
  // 钉钉免密登录提交：多主体接入时按按钮携带的主体（configId）发起 authorize
  const submitDingCode = async (btn, configId) => {
    btn.classList.add('btn-loading')
    try {
      const code = app.querySelector('#oauth-ding-code').value.trim()
      if (!code) throw new Error('请输入钉钉授权码（演示环境为工号，如 DD0002）')
      dingTip('')
      const auth = unwrap(await rawJson('POST', '/api/auth/sso/authorize', { provider: 'dingtalk', scene: 'web_qr', ...(configId ? { configId } : {}) }), '钉钉登录暂不可用')
      const data = unwrap(await rawJson('POST', '/api/auth/sso', { provider: 'dingtalk', code, state: auth.state }), '钉钉登录失败')
      if (data.kind === 'pending') {
        dingTicket = data.pendingTicket
        app.querySelector('#oauth-ding-pending-name').textContent = data.profileName
        app.querySelector('#oauth-ding-step-authorize').style.display = 'none'
        app.querySelector('#oauth-ding-step-pending').style.display = ''
        return
      }
      finishSsoLogin(data)
    } catch (error) {
      dingTip(error.message)
    } finally {
      btn.classList.remove('btn-loading')
    }
  }
  app.querySelector('#oauth-ding-submit').onclick = (e) => void submitDingCode(e.currentTarget)

  // 整页跳转钉钉统一授权（与主登录页同链路）：跳转前暂存本页授权请求 id（与授权请求同为 5 分钟有效），
  // SSO 回调登录成功后据此回到本页继续 consent，AI 应用的授权流才不会断在登录环节
  const OIDC_REQ_KEY = 'heng_ops_sso_oidc_req'
  // 上次使用的接入主体（多主体部署时保持入口视觉一致；身份归属最终以钉钉组织选择为准）
  let preferredConfigId = ''
  try { preferredConfigId = localStorage.getItem('heng_ops_last_sso_config') ?? '' } catch { /* 忽略 */ }
  const showManualFallback = (message) => {
    const manual = app.querySelector('#oauth-ding-manual')
    if (manual) manual.open = true
    if (message) dingTip(message)
  }
  const startDingOauth = async (btn, configId, auto) => {
    btn.classList.add('btn-loading')
    try {
      const auth = unwrap(await rawJson('POST', '/api/auth/sso/authorize', { provider: 'dingtalk', scene: 'web_qr', ...(configId ? { configId } : {}) }), '钉钉登录暂不可用')
      if (!auth.authorizeUrl) throw new Error('身份源未返回授权地址（可能为 mock 模式），请手动输入授权码')
      try { localStorage.setItem(OIDC_REQ_KEY, JSON.stringify({ req: reqId, ts: Date.now() })) } catch { /* 忽略 */ }
      try { localStorage.setItem('heng_ops_last_sso_config', configId ?? '') } catch { /* 忽略 */ }
      // 必须整页跳转：弹窗/iframe 会被第三方 Cookie 策略拦截导致授权失败
      window.location.href = auth.authorizeUrl
    } catch (error) {
      btn.classList.remove('btn-loading')
      // 自动免登失败（如 mock 模式）静默降级到手动授权码兜底，不打断页面
      if (auto) showManualFallback(error.message)
      else dingTip(error.message)
    }
  }
  // 多主体接入时保持与主登录页一致的入口形态：主按钮直达钉钉授权页，其余主体降级为次要链接
  const renderDingtalkEntry = (providers) => {
    const holder = app.querySelector('#oauth-ding-oauth-list')
    if (!providers.some((item) => (item.configId ?? '') === preferredConfigId)) {
      preferredConfigId = providers[0]?.configId ?? ''
    }
    if (providers.length < 2) {
      holder.querySelector('#oauth-ding-oauth-go').onclick = (e) => void startDingOauth(e.currentTarget, preferredConfigId || undefined)
      return
    }
    const others = providers.filter((item) => (item.configId ?? '') !== preferredConfigId)
    holder.innerHTML = `
      <button class="btn btn-primary btn-lg btn-block" id="oauth-ding-oauth-go" type="button">使用钉钉扫码 / 点击头像登录</button>
      ${others.length ? `<div class="form-hint" style="margin-top:8px;text-align:center">其他已接入主体：${others.map((item, index) => `
        <a class="fs-12" style="color:var(--brand-500);cursor:pointer;margin-left:${index ? 8 : 0}px" data-config-id="${esc(item.configId ?? '')}">${esc(item.name || item.corpId || '未命名主体')}</a>`).join('')}</div>` : ''}`
    holder.querySelector('#oauth-ding-oauth-go').onclick = (e) => void startDingOauth(e.currentTarget, preferredConfigId || undefined)
    holder.querySelectorAll('[data-config-id]').forEach((el) => {
      el.onclick = () => void startDingOauth(holder.querySelector('#oauth-ding-oauth-go'), el.dataset.configId || undefined)
    })
  }
  // 三方登录入口按平台连接器配置显隐（与主登录页同一探测端点与规则）
  void rawJson('GET', '/api/auth/providers').then((result) => {
    const dingtalkProviders = (result.payload?.data?.providers ?? []).filter((item) => item.provider === 'dingtalk')
    if (!dingtalkProviders.length) {
      app.querySelector('#oauth-login-tabs').style.display = 'none'
      return
    }
    // 钉钉扫码为平台默认登录方式：连接器可用即默认选中（用户已手动切换则不覆盖）
    if (!tabTouched) switchTab('dingtalk')
    renderDingtalkEntry(dingtalkProviders)
    // 钉钉客户端内（工作台打开 AI 应用 → 跳转本授权页）自动识别登录态：直接发起授权免登
    if (/DingTalk/i.test(navigator.userAgent)) {
      const go = app.querySelector('#oauth-ding-oauth-go')
      if (go) void startDingOauth(go, preferredConfigId || undefined, true)
    }
  }).catch(() => { /* 查询失败时保持默认展示 */ })
  app.querySelectorAll('#oauth-login-dingtalk .tab[data-ptab]').forEach((el) => {
    el.onclick = () => {
      app.querySelectorAll('#oauth-login-dingtalk .tab[data-ptab]').forEach((t) => t.classList.remove('active'))
      el.classList.add('active')
      app.querySelector('#oauth-ding-bind-panel').style.display = el.dataset.ptab === 'bind' ? '' : 'none'
      app.querySelector('#oauth-ding-register-panel').style.display = el.dataset.ptab === 'register' ? '' : 'none'
    }
  })
  app.querySelector('#oauth-ding-bind-submit').onclick = async () => {
    const btn = app.querySelector('#oauth-ding-bind-submit')
    btn.classList.add('btn-loading')
    try {
      dingTip('')
      const data = unwrap(await rawJson('POST', '/api/auth/sso/bind', {
        pendingTicket: dingTicket,
        username: app.querySelector('#oauth-ding-bind-username').value.trim(),
        password: app.querySelector('#oauth-ding-bind-password').value,
      }), '绑定失败')
      finishSsoLogin(data)
    } catch (error) {
      dingTip(error.message)
    } finally {
      btn.classList.remove('btn-loading')
    }
  }
  app.querySelector('#oauth-ding-register-submit').onclick = async () => {
    const btn = app.querySelector('#oauth-ding-register-submit')
    btn.classList.add('btn-loading')
    try {
      dingTip('')
      const data = unwrap(await rawJson('POST', '/api/auth/sso/register', { pendingTicket: dingTicket }), '注册失败')
      finishSsoLogin(data)
    } catch (error) {
      dingTip(error.message)
    } finally {
      btn.classList.remove('btn-loading')
    }
  }
  app.querySelector('#oauth-ding-pending-back').onclick = () => {
    dingTip('')
    app.querySelector('#oauth-ding-step-pending').style.display = 'none'
    app.querySelector('#oauth-ding-step-authorize').style.display = ''
  }
}

function renderConsent(app, reqId, info) {
  const user = session.user
  const scopes = String(info.scope ?? '').split(/\s+/).filter(Boolean)
  app.innerHTML = pageShell(`
    <div class="oauth-sub">应用请求获得以下授权：</div>
    <div class="oauth-app">
      <div class="oauth-app-ic">${info.appRef ? '✨' : '🔗'}</div>
      <div>
        <b>${esc(info.clientName)}</b>
        <span>${info.appRef ? `平台登记应用 · ${esc(info.appRef.name)}` : '外部登记客户端'}</span>
      </div>
    </div>
    <div class="oauth-scopes">
      ${scopes.map((scope) => `
        <div class="oauth-scope">${icon('check', 15)}<span><b>${esc(scope)}</b> · ${esc(SCOPE_LABEL[scope] ?? '自定义授权范围')}</span></div>`).join('')}
    </div>
    <div class="oauth-user">
      <div class="avatar sm">${esc((user?.displayName ?? '?').slice(0, 1))}</div>
      <span>将以 <b>${esc(user?.displayName ?? '当前用户')}</b> 身份授权${info.consentRequired ? '，授权后应用可在此后静默获取你的身份信息' : ''}</span>
    </div>
    ${info.consentRequired ? `
    <label class="flex" style="gap:8px;font-size:13px;margin-bottom:14px;cursor:pointer">
      <input type="checkbox" id="oauth-consent-check" style="accent-color:var(--brand-500)">
      <span>我已了解并同意向该应用提供上述信息</span>
    </label>` : ''}
    <div class="oauth-actions">
      ${info.consentRequired ? '<button class="btn btn-default" id="oauth-deny">拒绝</button>' : ''}
      <button class="btn btn-primary" id="oauth-approve">${info.consentRequired ? '同意并授权' : '确认授权'}</button>
    </div>
    <div class="form-hint" id="oauth-consent-tip" style="margin-top:12px"></div>`)
  const approve = app.querySelector('#oauth-approve')
  const deny = app.querySelector('#oauth-deny')
  const submit = async (consent) => {
    approve.classList.add('btn-loading')
    try {
      const result = await rawJson('POST', '/api/authn/oidc/authorize', { reqId, consent })
      if (result.status !== 200 || !result.payload?.location) {
        if (result.status === 401) {
          session.clear()
          renderLoginPanel(app, reqId, info)
          return
        }
        throw new Error(result.payload?.error_description ?? '授权失败，请从应用重新发起')
      }
      approve.textContent = consent ? '已授权，正在跳转…' : '已拒绝，正在跳转…'
      window.location.href = result.payload.location
    } catch (error) {
      approve.classList.remove('btn-loading')
      app.querySelector('#oauth-consent-tip').textContent = error.message
    }
  }
  approve.onclick = () => {
    if (info.consentRequired && !app.querySelector('#oauth-consent-check')?.checked) {
      app.querySelector('#oauth-consent-tip').textContent = '请先勾选同意后再授权'
      return
    }
    void submit(true)
  }
  if (deny) deny.onclick = () => void submit(false)
  // 无需显式同意的客户端（平台登记应用默认形态）：登录即静默完成授权跳转
  if (!info.consentRequired) void submit(true)
}

// -- 错误页 -------------------------------------------------------------------

export function renderOauthError(app, params) {
  const error = params.get('error') ?? 'invalid_request'
  // error_description 来源可能是任意外部输入，展示前必须转义（不自动跳转）
  const description = params.get('error_description') ?? ''
  const known = ERROR_LABEL[error]
  app.innerHTML = pageShell(`
    <div class="oauth-error-ic" style="color:#dc2626">${icon('alert', 24)}</div>
    <div class="oauth-title" style="margin-bottom:8px">授权无法完成</div>
    <div class="oauth-sub">
      错误码：<code class="mono">${esc(error)}</code>
      ${known && typeof known === 'string' ? `<br>${esc(known)}` : ''}
      ${description ? `<div class="muted-box" style="margin-top:10px;font-size:12.5px">${esc(description)}</div>` : ''}
    </div>
    <div class="oauth-actions" style="margin-top:20px">
      <a class="btn btn-default" href="#/dashboard" style="text-align:center">返回平台</a>
    </div>
    <div class="form-hint" style="margin-top:12px">请回到发起授权的应用重试；若反复出现，请联系应用负责人或平台管理员。</div>`)
}

// -- RP 发起登出中转页 ----------------------------------------------------------

export async function renderOauthLogout(app, params) {
  const postLogoutUri = params.get('post_logout_redirect_uri') ?? ''
  const state = params.get('state') ?? ''
  const clientName = params.get('client') ?? '应用'
  app.innerHTML = pageShell(`
    <div class="oauth-title" style="margin-bottom:8px">正在退出平台会话…</div>
    <div class="oauth-sub"><b>${esc(clientName)}</b> 发起了登出请求。平台会话清除后将${postLogoutUri ? '跳回应用地址' : '停留在平台'}。</div>
    <div class="form-hint" id="oauth-logout-state" style="margin-top:14px">处理中…</div>`)
  const mark = (text) => { const el = app.querySelector('#oauth-logout-state'); if (el) el.textContent = text }
  try {
    if (session.token) {
      const result = await rawJson('POST', '/api/auth/logout', { refreshToken: session.refreshToken || undefined })
      void result
    }
  } catch { /* 会话本就失效也继续完成登出跳转 */ }
  session.clear()
  mark('平台会话已清除。')
  if (postLogoutUri) {
    setTimeout(() => {
      try {
        const url = new URL(postLogoutUri)
        if (state) url.searchParams.set('state', state)
        window.location.href = url.toString()
      } catch {
        mark('回跳地址非法，已阻止跳转。')
      }
    }, 600)
  } else {
    mark('平台会话已清除。可重新登录平台。')
    setTimeout(() => { window.location.hash = '#/login' }, 1200)
  }
}
