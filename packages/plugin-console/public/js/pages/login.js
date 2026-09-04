/** 登录页：账号密码 / 三方扫码（按平台连接器配置显隐）。 */
import { api, session } from '../api.js'
import { icon } from '../icons.js'
import { h, $, esc, toast } from '../ui.js'

export function renderLogin(app) {
  app.innerHTML = `
    <div class="login-page">
      <div class="login-hero">
        <div class="login-hero-inner">
          <div style="display:flex;align-items:center;gap:14px">
            <img class="brand-mark brand-logo" src="/rongqi_ai.png" alt="榕器" style="width:46px;height:46px;border-radius:12px">
            <div style="font-size:19px;font-weight:600;letter-spacing:2px">榕器 · 企业AI资源管理平台</div>
          </div>
          <h1>让团队一起用 AI<br>把每一份资源都管起来</h1>
          <p>组织账号、MCP 服务、Skill 市场、Agent 本体、AI 应用——五类资源一套身份、一套权限、一套审计。一个工作台，撑起企业的全部 AI 资产。</p>

          <div class="login-hero-grid">
            <div class="login-hero-card">
              <div class="login-hero-card-ic">${icon('puzzle')}</div>
              <div class="login-hero-card-title">一切皆插件</div>
              <div class="login-hero-card-desc">基于 DeepSeek Harness 插件架构，九大业务域即插即用，按团队需要随用随上。</div>
            </div>
            <div class="login-hero-card">
              <div class="login-hero-card-ic">${icon('shieldCheck')}</div>
              <div class="login-hero-card-title">注册即治理</div>
              <div class="login-hero-card-desc">双轨身份 + RBAC + 令牌网关，从接入到调用全链路留痕，企业合规一次到位。</div>
            </div>
            <div class="login-hero-card">
              <div class="login-hero-card-ic">${icon('gitBranch')}</div>
              <div class="login-hero-card-title">依赖可穿透</div>
              <div class="login-hero-card-desc">应用 → Agent → MCP/Skill 拓扑一图可视，谁依赖谁、影响多大，先知再改。</div>
            </div>
            <div class="login-hero-card">
              <div class="login-hero-card-ic">${icon('zap')}</div>
              <div class="login-hero-card-title">开箱即协作</div>
              <div class="login-hero-card-desc">一份资源全员共享，权限随角色流转，团队从第一天就在同一套资产上工作。</div>
            </div>
          </div>

          <div class="login-hero-strip">
            <div class="login-hero-stat"><span class="num">9</span><span class="lab">业务域即插即用</span></div>
            <div class="login-hero-stat"><span class="num">5</span><span class="lab">类资源统一纳管</span></div>
            <div class="login-hero-stat"><span class="num">1</span><span class="lab">套身份与审计</span></div>
          </div>
        </div>
        <div class="login-hero-footer">© 2026 元冰可 · 基于 DeepSeek Harness 构建</div>
      </div>
      <div class="login-panel">
        <h2 id="login-title">登录控制台</h2>
        <div class="sub" id="login-sub">使用钉钉扫码或平台账号登录</div>
        <div class="segmented" style="margin-bottom:24px" id="login-tabs">
          <span class="segmented-item" data-tab="dingtalk">钉钉扫码</span>
          <span class="segmented-item active" data-tab="password">账号密码</span>
        </div>

        <form class="login-form" id="login-form-password">
          <div class="form-item">
            <label class="form-label">用户名</label>
            <input class="input input-lg" id="login-username" placeholder="请输入用户名" autocomplete="username">
          </div>
          <div class="form-item">
            <label class="form-label">密码</label>
            <input class="input input-lg" id="login-password" type="password" placeholder="请输入密码" autocomplete="current-password">
          </div>
          <button class="btn btn-primary btn-lg btn-block" id="login-submit" type="submit">登 录</button>
        </form>

        <form class="login-form" id="login-form-dingtalk" style="display:none">
          <div id="ding-step-authorize">
            <div id="ding-oauth-list">
              <button class="btn btn-primary btn-lg btn-block" id="ding-oauth-go" type="button">使用钉钉扫码 / 点击头像登录</button>
            </div>
            <div class="form-hint" style="margin:8px 0 4px">整页跳转钉钉授权：已登录钉钉点击头像即可完成，未登录则出二维码扫码；组织归属只需在钉钉「选择你加入的组织」页选定一次。授权过的浏览器会自动回跳。</div>
            <details style="margin-top:12px">
              <summary class="form-hint" style="cursor:pointer">手动输入授权码（演示/mock 备用）</summary>
              <div style="text-align:center;padding:10px 0 6px">
                <div style="width:180px;height:180px;margin:0 auto;border-radius:16px;background:
                  radial-gradient(120px 120px at 30% 25%, #e0e7ff, transparent),
                  radial-gradient(120px 120px at 75% 80%, #ede9fe, transparent), #f8f9fb;
                  border:1px solid var(--border);display:grid;place-items:center;position:relative">
                  <div style="color:var(--brand-500)">${icon('fingerprint', 64)}</div>
                  <div style="position:absolute;bottom:12px;font-size:12px;color:var(--text-3)">使用钉钉扫码授权登录</div>
                </div>
              </div>
              <div class="form-item" style="margin-top:16px">
                <label class="form-label">钉钉授权码</label>
                <input class="input input-lg" id="login-ding-code" placeholder="请输入钉钉扫码授权码">
                <div class="form-hint">走完整 OAuth2 链路：authorize 签发 state → code 换令牌 → unionId 归一化。code 5 分钟内仅可消费一次。</div>
              </div>
              <button class="btn btn-primary btn-lg btn-block" id="login-ding-submit" type="submit">免密登录</button>
            </details>
          </div>
          <div id="ding-step-pending" style="display:none">
            <div class="muted-box mb-14" style="display:flex;gap:8px;border-color:var(--brand-200);background:var(--brand-50)">
              ${icon('info', 15)}<span>首次使用该钉钉身份（<b id="ding-pending-name"></b>）。按「一人一号」原则，请绑定已有平台账号，或注册新账号。</span>
            </div>
            <div class="tabs" style="margin-bottom:16px">
              <div class="tab active" data-ptab="bind">绑定已有账号</div>
              <div class="tab" data-ptab="register">注册新账号</div>
            </div>
            <div id="ding-bind-panel">
              <div class="form-item"><label class="form-label">平台用户名</label><input class="input input-lg" id="ding-bind-username" placeholder="如 dev"></div>
              <div class="form-item"><label class="form-label">密码</label><input class="input input-lg" id="ding-bind-password" type="password" placeholder="平台账号密码"></div>
              <button class="btn btn-primary btn-lg btn-block" id="ding-bind-submit">验证并绑定</button>
            </div>
            <div id="ding-register-panel" style="display:none">
              <div class="form-hint" style="margin-bottom:12px">将以三方身份自动注册平台账号（默认进入首个组织），并建立身份链接。</div>
              <button class="btn btn-primary btn-lg btn-block" id="ding-register-submit">注册并登录</button>
            </div>
            <button class="btn btn-ghost btn-block mt-8" id="ding-pending-back">返回重试</button>
          </div>
        </form>
      </div>
    </div>`

  const tabPassword = $('#login-form-password')
  const tabDing = $('#login-form-dingtalk')
  // 上次使用的接入主体（多主体部署时保持入口视觉一致；身份归属最终以钉钉组织选择为准）
  const LAST_SSO_CONFIG_KEY = 'heng_ops_last_sso_config'
  let preferredConfigId = ''
  try { preferredConfigId = localStorage.getItem(LAST_SSO_CONFIG_KEY) ?? '' } catch { /* 忽略 */ }
  // 发起整页跳转授权：单一主入口，不再要求在平台侧预选企业主体
  const startDingOauth = async (btn, configId) => {
    btn.classList.add('btn-loading')
    try {
      const auth = await api.post('/api/auth/sso/authorize', { provider: 'dingtalk', scene: 'web_qr', ...(configId ? { configId } : {}) })
      if (!auth.authorizeUrl) throw new Error('身份源未返回授权地址（可能为 mock 模式），请改用手动输入授权码')
      try { localStorage.setItem(LAST_SSO_CONFIG_KEY, configId ?? '') } catch { /* 忽略 */ }
      // 必须整页跳转：弹窗/iframe 会被第三方 Cookie 策略拦截导致授权失败
      window.location.href = auth.authorizeUrl
    } catch (error) {
      toast(error.message, 'error')
      btn.classList.remove('btn-loading')
    }
  }
  // 登录入口渲染：一个主按钮直达钉钉授权页；其余已接入主体降级为次要链接，不作为必选步骤
  const renderDingtalkEntry = (providers) => {
    if (!providers.some((item) => (item.configId ?? '') === preferredConfigId)) {
      preferredConfigId = providers[0]?.configId ?? ''
    }
    const others = providers.filter((item) => (item.configId ?? '') !== preferredConfigId)
    const holder = $('#ding-oauth-list')
    holder.innerHTML = `
      <button class="btn btn-primary btn-lg btn-block" id="ding-oauth-go" type="button">使用钉钉扫码 / 点击头像登录</button>
      ${others.length ? `<div class="form-hint" style="margin-top:8px;text-align:center">其他已接入主体：${others.map((item, index) => `
        <a class="fs-12" style="color:var(--brand-500);cursor:pointer;margin-left:${index ? 8 : 0}px" data-config-id="${esc(item.configId ?? '')}">${esc(item.name || item.corpId || '未命名主体')}</a>`).join('')}</div>` : ''}`
    $('#ding-oauth-go').onclick = (e) => void startDingOauth(e.currentTarget, preferredConfigId || undefined)
    holder.querySelectorAll('[data-config-id]').forEach((el) => {
      el.onclick = () => void startDingOauth($('#ding-oauth-go'), el.dataset.configId || undefined)
    })
  }
  // 三方登录入口按平台配置显隐：未启用任何登录连接器时仅展示账号密码
  // 钉钉扫码为平台默认登录方式：连接器可用即默认选中（用户已手动切换则不覆盖）
  let loginTabTouched = false
  const switchLoginTab = (name) => {
    app.querySelectorAll('#login-tabs .segmented-item').forEach((item) => item.classList.toggle('active', item.dataset.tab === name))
    const isPassword = name === 'password'
    tabPassword.style.display = isPassword ? '' : 'none'
    tabDing.style.display = isPassword ? 'none' : ''
  }
  void api.get('/api/auth/providers').then((data) => {
    const dingtalkProviders = (data?.providers ?? []).filter((item) => item.provider === 'dingtalk')
    if (!dingtalkProviders.length) {
      $('#login-tabs').style.display = 'none'
      $('#login-sub').textContent = '使用平台账号登录'
      return
    }
    if (!loginTabTouched) switchLoginTab('dingtalk')
    renderDingtalkEntry(dingtalkProviders)
  }).catch(() => { /* 查询失败时保持默认展示 */ })
  app.querySelectorAll('#login-tabs .segmented-item').forEach((el) => {
    el.onclick = () => {
      loginTabTouched = true
      switchLoginTab(el.dataset.tab)
    }
  })

  const doLogin = async (payload, path) => {
    const btn = $(path === '/api/auth/login' ? '#login-submit' : '#login-ding-submit')
    btn.classList.add('btn-loading')
    try {
      const result = await api.post(path, payload)
      session.save(result.token, result.user)
      if (result.refreshToken) session.saveRefresh(result.refreshToken)
      toast(`欢迎回来，${result.user.displayName}`)
      location.hash = '#/dashboard'
    } catch (error) {
      toast(error.message, 'error')
    } finally {
      btn.classList.remove('btn-loading')
    }
  }

  tabPassword.onsubmit = (e) => {
    e.preventDefault()
    void doLogin({ username: $('#login-username').value.trim(), password: $('#login-password').value }, '/api/auth/login')
  }
  $('#ding-oauth-go').onclick = (e) => void startDingOauth(e.currentTarget)

  let dingTicket = ''
  // 承接扫码回跳：callback 页把「首次使用三方身份」的待绑定票据暂存 localStorage
  try {
    const pendingRaw = localStorage.getItem('heng_ops_sso_pending')
    if (pendingRaw) {
      localStorage.removeItem('heng_ops_sso_pending')
      const pending = JSON.parse(pendingRaw)
      dingTicket = pending.pendingTicket ?? ''
      if (dingTicket) {
        document.querySelector('#login-tabs .segmented-item[data-tab="dingtalk"]')?.click()
        $('#ding-pending-name').textContent = pending.profileName ?? ''
        $('#ding-step-authorize').style.display = 'none'
        $('#ding-step-pending').style.display = ''
      }
    }
  } catch { /* 票据损坏则忽略，走常规登录 */ }

  tabDing.onsubmit = async (e) => {
    e.preventDefault()
    const btn = $('#login-ding-submit')
    btn.classList.add('btn-loading')
    try {
      const code = $('#login-ding-code').value.trim()
      if (!code) return toast('请输入钉钉授权码（演示环境为工号，如 DD0002）', 'error')
      const auth = await api.post('/api/auth/sso/authorize', { provider: 'dingtalk', scene: 'web_qr' })
      const result = await api.post('/api/auth/sso', { provider: 'dingtalk', code, state: auth.state })
      if (result.kind === 'pending') {
        dingTicket = result.pendingTicket
        $('#ding-pending-name').textContent = result.profileName
        $('#ding-step-authorize').style.display = 'none'
        $('#ding-step-pending').style.display = ''
        return
      }
      finishLogin(result)
    } catch (error) {
      toast(error.message, 'error')
    } finally {
      btn.classList.remove('btn-loading')
    }
  }

  const finishLogin = (result) => {
    session.save(result.token, result.user)
    if (result.refreshToken) session.saveRefresh(result.refreshToken)
    toast(`欢迎回来，${result.user.displayName}`)
    // 承接回跳：从 OIDC 授权页发起的钉钉登录（含回调转本页完成首绑/注册的分支），
    // 登录后按暂存的授权请求（与授权请求同为 5 分钟有效）回授权页继续 consent，而非进控制台
    let resume = null
    try {
      resume = JSON.parse(localStorage.getItem('heng_ops_sso_oidc_req') ?? 'null')
      localStorage.removeItem('heng_ops_sso_oidc_req')
    } catch { /* 票据损坏则忽略，走常规入口 */ }
    if (resume && typeof resume.req === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(resume.req) && Date.now() - (resume.ts ?? 0) < 300_000) {
      location.hash = `#/oauth/authorize?req=${resume.req}`
      return
    }
    location.hash = '#/dashboard'
  }

  app.querySelectorAll('#login-form-dingtalk .tab[data-ptab]').forEach((el) => {
    el.onclick = () => {
      app.querySelectorAll('#login-form-dingtalk .tab[data-ptab]').forEach((t) => t.classList.remove('active'))
      el.classList.add('active')
      $('#ding-bind-panel').style.display = el.dataset.ptab === 'bind' ? '' : 'none'
      $('#ding-register-panel').style.display = el.dataset.ptab === 'register' ? '' : 'none'
    }
  })
  $('#ding-bind-submit').onclick = async () => {
    const btn = $('#ding-bind-submit')
    btn.classList.add('btn-loading')
    try {
      const result = await api.post('/api/auth/sso/bind', {
        pendingTicket: dingTicket,
        username: $('#ding-bind-username').value.trim(),
        password: $('#ding-bind-password').value,
      })
      finishLogin(result)
    } catch (error) { toast(error.message, 'error') } finally { btn.classList.remove('btn-loading') }
  }
  $('#ding-register-submit').onclick = async () => {
    const btn = $('#ding-register-submit')
    btn.classList.add('btn-loading')
    try {
      const result = await api.post('/api/auth/sso/register', { pendingTicket: dingTicket })
      finishLogin(result)
    } catch (error) { toast(error.message, 'error') } finally { btn.classList.remove('btn-loading') }
  }
  $('#ding-pending-back').onclick = () => {
    $('#ding-step-pending').style.display = 'none'
    $('#ding-step-authorize').style.display = ''
  }
}
