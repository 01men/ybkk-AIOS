/** Skill 市场：卡片市场 + 详情（版本历史/审批时间线/安装）+ 提交/审批流。 */
import { api, session } from '../api.js'
import { icon } from '../icons.js'
import {
  h, $, $$, esc, toast, openDrawer, openModal, confirmDialog,
  statusBadge, collectForm, field, inputField, selectField, textareaField,
  fmtNum, timeAgo, emptyState, maybeShowConceptCard,
  searchableSelectField, mountSearchableSelects,
} from '../ui.js'

const COVERS = ['linear-gradient(135deg,#4f6ef7,#7c5cf5)', 'linear-gradient(135deg,#10b981,#34d399)', 'linear-gradient(135deg,#f59e0b,#fbbf24)', 'linear-gradient(135deg,#8b5cf6,#a78bfa)', 'linear-gradient(135deg,#3b82f6,#60a5fa)', 'linear-gradient(135deg,#ef4444,#f87171)']
const COVER_ICONS = { '办公提效': 'file', '研发效能': 'terminal', '客户服务': 'ticket', '数据分析': 'chart', '人事行政': 'users', '市场情报': 'globe', '法务合规': 'shield', '通用': 'sparkles' }

export async function renderSkills(content, params, ctx) {
  const data = await api.get('/api/skills')
  // 首次访问概念卡（易用性整改：Skill 术语对业务成员有门槛）
  maybeShowConceptCard(content, 'skills', {
    icon: 'sparkles',
    title: 'Skill 是什么？',
    subtitle: 'Skill = 给 Agent 用的「专项技能包」，像手机装 App 一样即装即用。',
    points: [
      '能做什么：生成周报、读取合同要点、分析销售数据等专项任务。',
      '怎么上架：提交 → 自动安全扫描 → 两级审批 → 版本化上架，高风险需安全团队加签。',
      '怎么使用：按场景在市场挑选，下载安装即登记依赖，随时可停用。',
    ],
  })

  content.innerHTML = `
    <div class="page-head">
      <div>
        <div class="page-title">Skill 市场</div>
        <div class="page-desc">提交 → 静态扫描 → 两级审批 → 版本化上架。高风险 Skill 需安全团队加签，下载安装即登记依赖。</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" id="skill-storage">${icon('server', 14)}存储配置</button>
        <button class="btn btn-default" id="skill-mine">${icon('user', 14)}我的提交</button>
        ${session.can('skill.approve') ? `<button class="btn btn-default" id="skill-review">${icon('checkSquare', 14)}待审批<span class="badge badge-danger no-dot" id="skill-review-count" style="margin-left:6px;display:none">0</span></button>` : ''}
        <button class="btn btn-primary" id="skill-submit">${icon('plus', 14)}提交 Skill</button>
      </div>
    </div>
    <div id="skill-heatmap" class="mb-20"></div>
    <div class="filter-bar">
      <div class="search-input">${icon('search')}<input class="input" id="skill-q" placeholder="搜索名称 / 标签 / 简介"></div>
      <div class="chips" id="skill-cats">
        <span class="chip active" data-cat="">全部分类</span>
        ${(data.categories ?? []).map((cat) => `<span class="chip" data-cat="${esc(cat)}">${esc(cat)}</span>`).join('')}
      </div>
      <div class="segmented" style="margin-left:auto" id="skill-sort">
        <span class="segmented-item active" data-sort="downloads">按下载</span>
        <span class="segmented-item" data-sort="rating">按评分</span>
        <span class="segmented-item" data-sort="updated">按更新</span>
      </div>
    </div>
    <div class="card-grid" id="skill-cards"></div>`

  let state = { q: '', cat: '', sort: 'downloads', mode: 'market' }

  // 待审批徽标：在途项计数（驳回不算待办），让审批人在市场页第一眼看到待办
  const updateReviewBadge = async () => {
    const badge = $('#skill-review-count')
    if (!badge) return
    try {
      const result = await api.get('/api/skills' + api.qs({ pending: 1 }))
      const actionable = (result.skills ?? []).filter((s) => s.status !== 'rejected').length
      badge.textContent = String(actionable)
      badge.style.display = actionable > 0 ? '' : 'none'
    } catch { /* 静默 */ }
  }

  const refresh = async () => {
    const query = api.qs(state.mode === 'mine' ? { mine: 1 } : state.mode === 'review' ? { pending: 1 } : { q: state.q || undefined, category: state.cat || undefined, sort: state.sort })
    const result = await api.get('/api/skills' + query)
    renderCards(result.skills ?? [])
    void updateReviewBadge()
  }

  function renderCards(skills) {
    const holder = $('#skill-cards')
    holder.innerHTML = ''
    if (!skills.length) {
      holder.appendChild(emptyState({
        title: state.mode === 'review' ? '没有待审批的 Skill' : state.mode === 'mine' ? '你还没有提交过 Skill' : '没有匹配的 Skill',
        desc: state.mode === 'market' ? '换个关键字或分类试试' : '提交第一个 Skill 到市场，让能力复用起来',
        actionText: state.mode === 'market' ? undefined : '提交 Skill',
        onAction: () => $('#skill-submit').click(),
        icon: 'sparkles',
      }))
      return
    }
    for (const [index, skill] of skills.entries()) {
      const cover = COVERS[index % COVERS.length]
      const card = h(`
        <div class="res-card" data-id="${esc(skill.id)}">
          <div style="height:86px;border-radius:9px;background:${skill.status === 'deprecated' ? 'linear-gradient(135deg,#9ca3af,#d1d5db)' : cover};display:grid;place-items:center;color:#fff;position:relative">
            <span style="filter:drop-shadow(0 2px 6px rgba(0,0,0,.25))">${icon(COVER_ICONS[skill.category] ?? 'sparkles', 34)}</span>
            ${skill.riskLevel !== 'low' ? `<span class="badge ${skill.riskLevel === 'high' ? 'badge-danger' : 'badge-warn'} no-dot" style="position:absolute;top:8px;right:8px;background:rgba(255,255,255,.92)">${skill.riskLevel === 'high' ? '高风险' : '中风险'}</span>` : ''}
          </div>
          <div class="res-card-top" style="margin-top:2px">
            <div class="grow">
              <div class="res-name">${esc(skill.name)} ${statusBadge(skill.status)}</div>
              <div class="res-slug">v${esc(skill.currentVersion)} · ${esc(skill.category)}${skill.tags.length ? ' · ' + skill.tags.slice(0, 2).map(esc).join(' / ') : ''}</div>
            </div>
          </div>
          <div class="res-desc">${esc(skill.summary)}</div>
          <div class="res-foot">
            <span class="metric">${icon('user', 13)}${esc(skill.authorName)}</span>
            <span class="metric">${icon('download', 13)}${fmtNum(skill.stats.downloads)}</span>
            <span class="metric">${icon('star', 13)}${skill.stats.rating || '—'}</span>
            <span style="margin-left:auto" class="text-4">${timeAgo(skill.updatedAt)}</span>
          </div>
        </div>`)
      card.onclick = () => openSkillDetail(skill.id, ctx, refresh)
      holder.appendChild(card)
    }
  }

  $('#skill-q').oninput = debounce(() => { state.q = $('#skill-q').value.trim(); state.mode = 'market'; void refresh() }, 250)

  // 技能热力图：skill × 日 使用矩阵（usage 计量为主、历史下载流水回填）；无数据不占位
  api.get('/api/skills/usage-heatmap?days=30')
    .then((hm) => { if (hm.skills?.length) $('#skill-heatmap').innerHTML = heatCard(hm) })
    .catch(() => undefined)
  $$('#skill-cats .chip').forEach((chip) => {
    chip.onclick = () => {
      $$('#skill-cats .chip').forEach((c) => c.classList.remove('active'))
      chip.classList.add('active')
      state.cat = chip.dataset.cat
      state.mode = 'market'
      void refresh()
    }
  })
  $$('#skill-sort .segmented-item').forEach((el) => {
    el.onclick = () => {
      $$('#skill-sort .segmented-item').forEach((i) => i.classList.remove('active'))
      el.classList.add('active')
      state.sort = el.dataset.sort
      void refresh()
    }
  })
  $('#skill-mine').onclick = () => { state.mode = state.mode === 'mine' ? 'market' : 'mine'; void refresh() }
  $('#skill-storage').onclick = () => openStorageModal()
  const reviewBtn = $('#skill-review')
  if (reviewBtn) reviewBtn.onclick = () => { state.mode = state.mode === 'review' ? 'market' : 'review'; void refresh() }
  $('#skill-submit').onclick = () => openSubmitModal(ctx, refresh)

  await refresh()
  if (params.get('action') === 'submit') openSubmitModal(ctx, refresh)
  if (params.get('focus')) void openSkillDetail(params.get('focus'), ctx, refresh)
}

async function openSkillDetail(id, ctx, refresh) {
  const [skill, agentData] = await Promise.all([
    api.get(`/api/skills/${id}`),
    api.get('/api/agents').catch(() => ({ agents: [] })),
  ])
  const versions = [...skill.versions].reverse()
  const current = versions[0]

  const drawer = openDrawer({
    title: skill.name,
    sub: `${skill.category} · v${skill.currentVersion} · 作者 ${skill.authorName}`,
    wide: true,
    body: `
      <div class="flex mb-8" style="gap:8px;flex-wrap:wrap">
        ${statusBadge(skill.status)}
        <span class="badge ${skill.riskLevel === 'high' ? 'badge-danger' : skill.riskLevel === 'medium' ? 'badge-warn' : 'badge-ok'} no-dot">${skill.riskLevel === 'high' ? '高风险（需安全加签）' : skill.riskLevel === 'medium' ? '中风险' : '低风险'}</span>
        ${skill.tags.map((tag) => `<span class="badge badge-muted no-dot">${esc(tag)}</span>`).join('')}
      </div>
      <div class="fs-13 mt-14" style="line-height:1.7;color:var(--text-2)">${esc(skill.description || skill.summary)}</div>
      ${skill.deprecatedReason ? `
        <div class="muted-box mt-8" style="display:flex;gap:8px;border-color:var(--warn-border);background:var(--warn-bg)">
          ${icon('alert', 15)}<span><b>弃用原因</b>：${esc(skill.deprecatedReason)}${skill.deprecatedAt ? `（${timeAgo(skill.deprecatedAt)}）` : ''}</span>
        </div>` : ''}

      <div class="stat-grid mt-14 mb-20" style="grid-template-columns:repeat(4,1fr)">
        ${miniStat('download', '下载量', fmtNum(skill.stats.downloads))}
        ${miniStat('box', '安装量', fmtNum(skill.stats.installs))}
        ${miniStat('star', '评分', `${skill.stats.rating || '—'}（${skill.stats.ratingCount} 人）`)}
        ${miniStat('layers', '版本数', versions.length)}
      </div>

      <div class="tabs" id="sk-tabs">
        <div class="tab active" data-tab="readme">效果示例</div>
        <div class="tab" data-tab="versions">版本与审批</div>
      </div>
      <div id="sk-tab-body"></div>`,
    foot: `
      ${skill.status === 'published' ? `<button class="btn btn-default" id="sk-download">${icon('download', 14)}下载</button>` : ''}
      ${skill.status === 'published' && session.can('skill.install') ? `<button class="btn btn-primary" id="sk-install">${icon('plus', 14)}安装到 Agent</button>` : ''}
      ${canManage(skill) ? `<button class="btn btn-default" id="sk-edit">${icon('edit', 14)}编辑信息</button>` : ''}
      ${canManage(skill) && skill.versions.some((v) => v.status === 'published') ? `<button class="btn btn-default" id="sk-repkg">${icon('refresh', 14)}更新资源包</button>` : ''}
      ${session.can('skill.approve') && (current?.status === 'pending_domain' || current?.status === 'pending_security') ? `<button class="btn btn-primary" id="sk-approve">${icon('check', 14)}审批</button>` : ''}
      ${session.can('skill.approve') && current?.status === 'approved' && skill.status !== 'published' ? `<button class="btn btn-primary" id="sk-publish">${icon('send', 14)}上架</button>` : ''}
      ${session.can('skill.publish') && skill.status === 'published' ? `<button class="btn btn-danger-ghost" id="sk-deprecate">${icon('alert', 14)}弃用</button>` : ''}
      ${session.can('skill.publish') && ['deprecated', 'offline'].includes(skill.status) ? `<button class="btn btn-danger-ghost" id="sk-delete">${icon('trash', 14)}删除</button>` : ''}`,
  })

  const tabBody = drawer.body.querySelector('#sk-tab-body')
  const renderTab = (tab) => {
    if (tab === 'readme') {
      tabBody.innerHTML = `
        <div class="muted-box" style="display:flex;gap:8px;margin-bottom:12px">
          ${icon('info', 15)}<span>SKILL.md 由模型按需加载：何时使用 / 操作步骤 / 输出格式。适用模型：${skill.applicableModels.map(esc).join('、')}</span>
        </div>
        <div class="code-block">${esc(current?.content ?? '（暂无内容）')}</div>`
    }
    if (tab === 'versions') {
      tabBody.innerHTML = `
        <div class="timeline">
          ${versions.map((v) => `
            <div class="timeline-item ${v.status === 'published' ? 'ok' : v.status === 'rejected' ? 'danger' : 'current'}">
              <div class="timeline-dot"></div>
              <div class="timeline-title flex" style="gap:8px">v${esc(v.version)} ${statusBadge(versionStatus(v.status))}</div>
              <div class="timeline-time">提交于 ${timeAgo(v.submittedAt)}${v.publishedAt ? ' · 上架于 ' + timeAgo(v.publishedAt) : ''}</div>
              <div class="timeline-body">${esc(v.changelog)}</div>
              ${v.package ? `
                <div class="fs-12 mt-8" style="color:var(--text-3);display:flex;gap:6px;align-items:center;flex-wrap:wrap">
                  ${icon('server', 12)}<span>包存储：${v.package.storage === 'nas' ? `NAS（${esc(v.package.nasId ?? '')}）` : '平台本地'}</span>
                  ${v.package.path ? `<span class="mono text-4" style="word-break:break-all">${esc(v.package.path)}</span>` : ''}
                  ${v.package.sizeBytes !== undefined ? `<span>· ${fmtBytes(v.package.sizeBytes)}</span>` : ''}
                  ${v.package.uploadedAt ? `<span class="text-4">· ${timeAgo(v.package.uploadedAt)}</span>` : ''}
                </div>` : ''}
              ${v.findings?.length ? `
                <div class="mt-8">
                  ${v.findings.map((f) => `
                    <div class="flex" style="padding:3px 0">
                      <span style="color:var(--${f.level === 'block' ? 'danger' : f.level === 'warn' ? 'warn' : 'info'})">${icon(f.level === 'block' ? 'alert' : f.level === 'warn' ? 'alert' : 'info', 13)}</span>
                      <span class="fs-12">${esc(f.message)}<span class="mono text-4" style="margin-left:6px">${esc(f.rule)}</span></span>
                    </div>`).join('')}
                </div>` : ''}
              ${v.approvals?.length ? `
                <div class="mt-8">
                  ${v.approvals.map((a) => `
                    <div class="flex" style="padding:3px 0">
                      <span style="color:var(--ok)">${icon('check', 13)}</span>
                      <span class="fs-12">${a.level === 'domain' ? '领域审批' : '安全加签'}：${esc(a.approverName)} —— ${esc(a.opinion)}</span>
                    </div>`).join('')}
                </div>` : ''}
              ${v.rejectedReason ? `<div class="fs-12" style="color:var(--danger);padding:4px 0">驳回原因：${esc(v.rejectedReason)}</div>` : ''}
            </div>`).join('')}
        </div>`
    }
  }
  drawer.body.querySelectorAll('#sk-tabs .tab').forEach((el) => {
    el.onclick = () => {
      drawer.body.querySelectorAll('#sk-tabs .tab').forEach((t) => t.classList.remove('active'))
      el.classList.add('active')
      renderTab(el.dataset.tab)
    }
  })
  renderTab('readme')

  const downloadBtn = drawer.el.querySelector('#sk-download')
  if (downloadBtn) downloadBtn.onclick = async () => {
    try {
      // 先登记下载（审计可回溯谁下载了哪个版本），再拉 zip 触发浏览器保存
      await api.post(`/api/skills/${skill.id}/download`, {})
      const resp = await fetch(`/api/skills/${skill.id}/package?version=${encodeURIComponent(skill.currentVersion)}`, {
        headers: { authorization: `Bearer ${session.token}` },
      })
      if (!resp.ok) throw new Error(`skill.zip 下载失败（${resp.status}）`)
      const url = URL.createObjectURL(await resp.blob())
      const a = document.createElement('a')
      a.href = url
      a.download = `${skill.slug}-${skill.currentVersion}.zip`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      toast('已下载 skill.zip（下载已登记）')
    } catch (error) { toast(error.message, 'error') }
  }
  const installBtn = drawer.el.querySelector('#sk-install')
  if (installBtn) installBtn.onclick = () => {
    const modal = openModal({
      title: '安装到 Agent',
      body: `
        ${field('目标 Agent', searchableSelectField('agentId', agentData.agents.map((a) => ({ value: a.id, label: `${a.name}（${a.status}）` })), { placeholder: '点击选择目标 Agent，支持搜索' }), { required: true })}
        <div class="form-hint">安装后自动登记依赖关系，Agent 的「关联 Skill」属性同步回填。</div>`,
      foot: '<button class="btn btn-default" data-cancel>取消</button><button class="btn btn-primary" data-ok>安装</button>',
    })
    mountSearchableSelects(modal.el)
    modal.el.querySelector('[data-cancel]').onclick = () => modal.close()
    modal.el.querySelector('[data-ok]').onclick = async () => {
      try {
        await api.post(`/api/skills/${skill.id}/install`, { agentId: collectForm(modal.body).agentId, version: skill.currentVersion })
        toast('安装成功，依赖已登记'); modal.close(); drawer.close(); refresh?.()
      } catch (error) { toast(error.message, 'error') }
    }
  }
  const editBtn = drawer.el.querySelector('#sk-edit')
  if (editBtn) editBtn.onclick = () => openEditModal(skill, ctx, refresh)
  const repkgBtn = drawer.el.querySelector('#sk-repkg')
  if (repkgBtn) repkgBtn.onclick = () => openReplacePackageModal(skill, ctx, refresh)
  const approveBtn = drawer.el.querySelector('#sk-approve')
  if (approveBtn) approveBtn.onclick = () => {
    const needLevel = current?.status === 'pending_domain' ? 'domain' : 'security'
    const modal = openModal({
      title: `审批 · ${skill.name} v${current.version}`,
      body: `
        <div class="muted-box mb-14" style="display:flex;gap:8px">
          ${icon('info', 15)}
          <span>${needLevel === 'domain' ? '领域负责人审批：评估业务适用性与描述准确性。' : '安全团队加签：该 Skill 包含外联/写文件等高风险行为。'}${skill.riskLevel === 'high' ? '（高风险：两级审批均须通过）' : ''}</span>
        </div>
        ${field('审批意见', textareaField('opinion', { placeholder: '请说明审批依据…' }), { required: true })}`,
      foot: '<button class="btn btn-danger-ghost" data-reject>驳回</button><button class="btn btn-primary" data-ok>通过</button>',
    })
    modal.el.querySelector('[data-reject]').onclick = async () => {
      const opinion = collectForm(modal.body).opinion
      if (!opinion) return toast('请填写意见', 'error')
      try {
        await api.post(`/api/skills/${skill.id}/approve`, { decision: 'reject', level: needLevel, opinion })
        toast('已驳回'); modal.close(); drawer.close(); refresh?.()
      } catch (error) { toast(error.message, 'error') }
    }
    modal.el.querySelector('[data-ok]').onclick = async () => {
      const opinion = collectForm(modal.body).opinion
      if (!opinion) return toast('请填写意见', 'error')
      try {
        await api.post(`/api/skills/${skill.id}/approve`, { decision: 'approve', level: needLevel, opinion })
        toast('审批通过'); modal.close(); drawer.close(); refresh?.()
      } catch (error) { toast(error.message, 'error') }
    }
  }
  const publishBtn = drawer.el.querySelector('#sk-publish')
  if (publishBtn) publishBtn.onclick = async () => {
    try {
      await api.post(`/api/skills/${skill.id}/publish`, {})
      toast('已上架市场'); drawer.close(); refresh?.()
    } catch (error) { toast(error.message, 'error') }
  }
  const deprecateBtn = drawer.el.querySelector('#sk-deprecate')
  if (deprecateBtn) deprecateBtn.onclick = async () => {
    const result = await confirmDialog({
      title: '弃用 Skill', requireReason: true, danger: true, confirmText: '确认弃用',
      message: '弃用后市场不可安装；存量引用的 Agent 会收到迁移告警。旧版本保留可回滚。',
    })
    if (!result) return
    try {
      const response = await api.post(`/api/skills/${skill.id}/deprecate`, { reason: result.reason })
      if (response.referencingAgents?.length) {
        toast(`已弃用；${response.referencingAgents.length} 个 Agent 收到迁移告警`)
      } else {
        toast('已弃用')
      }
      drawer.close(); refresh?.()
    } catch (error) { toast(error.message, 'error') }
  }

  const deleteBtn = drawer.el.querySelector('#sk-delete')
  if (deleteBtn) deleteBtn.onclick = async () => {
    const result = await confirmDialog({
      title: `删除 Skill · ${skill.name}`, requireReason: true, danger: true, confirmText: '确认删除',
      message: '将永久删除该 Skill 记录（含全部版本与下载/安装登记），操作不可恢复；审计数据保留。',
    })
    if (!result) return
    try {
      await api.delete(`/api/skills/${skill.id}`)
      toast('已删除'); drawer.close(); refresh?.()
    } catch (error) { toast(error.message, 'error') }
  }
}

function openSubmitModal(ctx, refresh) {
  const modal = openModal({
    title: '提交 Skill 到市场', wide: true,
    body: `
      <div class="muted-box mb-14" style="display:flex;gap:8px">
        ${icon('zap', 15)}<span>提交后自动进入流水线：<b>静态扫描</b>（恶意代码 / 密钥泄露检测）→ <b>领域审批</b> → 高风险额外 <b>安全加签</b> → 上架。</span>
      </div>
      <div class="form-grid">
        ${field('名称', inputField('name'), { required: true })}
        ${field('分类', selectField('category', ['办公提效', '研发效能', '客户服务', '数据分析', '人事行政', '市场情报', '法务合规', '通用'].map((c) => ({ value: c, label: c }))))}
        ${field('一句话简介', inputField('summary'), { full: true })}
        ${field('版本号', inputField('version', { value: '1.0.0' }))}
        ${field('标签（逗号分隔）', inputField('tags', { placeholder: '文档,自动化' }))}
      </div>
      ${field('SKILL.md 内容', textareaField('content', { placeholder: '# Skill 名称\n\n## 何时使用\n…\n\n## 操作步骤\n1. …', rows: 8 }), { required: true, hint: '静态扫描将检测破坏性命令、动态执行、密钥泄露等风险模式' })}
      ${field('Skill 包（skill.zip，选填）', '<input class="input" type="file" id="skill-pkg" accept=".zip,application/zip">', { hint: '随版本保存：上架时按存储配置写入平台本地或 NAS（见「存储配置」）' })}`,
    foot: '<button class="btn btn-default" data-cancel>取消</button><button class="btn btn-primary" data-ok>提交（进入扫描）</button>',
  })
  modal.el.querySelector('[data-cancel]').onclick = () => modal.close()
  modal.el.querySelector('[data-ok]').onclick = async (e) => {
    const btn = e.currentTarget
    btn.classList.add('btn-loading')
    try {
      const data = collectForm(modal.body)
      const pkgFile = modal.body.querySelector('#skill-pkg')?.files?.[0]
      let packageBase64
      if (pkgFile) packageBase64 = await readFileBase64(pkgFile)
      const result = await api.post('/api/skills', {
        name: data.name, category: data.category, summary: data.summary, version: data.version,
        content: data.content,
        tags: data.tags ? data.tags.split(/[,，]/).map((s) => s.trim()).filter(Boolean) : [],
        ...(packageBase64 !== undefined ? { packageBase64 } : {}),
      })
      modal.close()
      if (result.status === 'rejected') {
        openModal({
          title: '静态扫描未通过（自动驳回）',
          body: `<div class="form-hint" style="margin-bottom:10px">检测到阻断级问题，请修复后重新提交：</div>
            ${result.findings.filter((f) => f.level === 'block').map((f) => `<div class="flex" style="padding:4px 0"><span style="color:var(--danger)">${icon('alert', 14)}</span><span class="fs-13">${esc(f.message)}</span></div>`).join('')}`,
          foot: '<button class="btn btn-primary" data-ok>知道了</button>',
        })
      } else {
        const warns = result.findings?.filter((f) => f.level === 'warn') ?? []
        openModal({
          title: '已提交，等待审批',
          body: warns.length
            ? `<div class="form-hint" style="margin-bottom:8px">扫描发现风险提示（将要求安全加签）：</div>${warns.map((f) => `<div class="flex" style="padding:3px 0"><span style="color:var(--warn)">${icon('alert', 14)}</span><span class="fs-13">${esc(f.message)}</span></div>`).join('')}`
            : `<div class="flex" style="gap:8px;padding:8px 0"><span style="color:var(--ok)">${icon('check', 16)}</span><span>扫描通过，进入领域审批环节。</span></div>`,
          foot: '<button class="btn btn-primary" data-ok>知道了</button>',
        })
      }
      refresh?.()
    } catch (error) {
      toast(error.message, 'error')
    } finally {
      btn.classList.remove('btn-loading')
    }
  }
}

/** 是否可管理该 Skill（编辑信息 / 更新资源包）：作者本人或平台管理员。 */
function canManage(skill) {
  return skill.authorId === session.user?.id || session.can('skill.publish')
}

/** 编辑已上架 Skill 的市场信息（名称/分类/标签/简介/描述/适用模型/依赖/可见性）；slug 保持不变。 */
function openEditModal(skill, ctx, refresh) {
  const CATEGORIES = ['办公提效', '研发效能', '客户服务', '数据分析', '人事行政', '市场情报', '法务合规', '通用']
  const modal = openModal({
    title: `编辑信息 · ${skill.name}`, wide: true,
    body: `
      <div class="muted-box mb-14" style="display:flex;gap:8px">
        ${icon('info', 15)}<span>直接更新市场展示信息，无需重新走审批；Skill 标识（slug）与已有版本保持不变。SKILL.md 内容变更请提交新版本。</span>
      </div>
      <div class="form-grid">
        ${field('名称', inputField('name', { value: skill.name }), { required: true })}
        ${field('分类', selectField('category', CATEGORIES.map((c) => ({ value: c, label: c })), { value: skill.category }))}
        ${field('作者 / 开发者名称', inputField('authorName', { value: skill.authorName }), { hint: '市场署名（列表与详情展示）；Skill 归属账号不变' })}
        ${field('一句话简介', inputField('summary', { value: skill.summary }), { full: true })}
        ${field('标签（逗号分隔）', inputField('tags', { value: (skill.tags ?? []).join(','), placeholder: '文档,自动化' }))}
        ${field('适用模型（逗号分隔）', inputField('applicableModels', { value: (skill.applicableModels ?? []).join(',') }))}
        ${field('依赖 Skill slug（逗号分隔）', inputField('deps', { value: (skill.deps ?? []).join(',') }), { hint: '安装该 Skill 时建议一并安装的前置 Skill' })}
        ${field('可见性', selectField('visibility', [
          { value: 'all', label: '全员可见' },
          { value: 'orgs', label: '指定组织可见' },
        ], { value: skill.visibility === 'orgs' ? 'orgs' : 'all' }))}
        ${field('目标组织 ID（逗号分隔）', inputField('targetOrgs', { value: (skill.targetOrgs ?? []).join(','), placeholder: 'org_xxx,org_yyy' }), { full: true, hint: '可见性为「指定组织」时必填；成员仅在其所属组织内可见该 Skill' })}
      </div>
      ${field('详细描述', textareaField('description', { value: skill.description || '', rows: 6, placeholder: '面向使用者的完整说明：能力边界、前置条件、使用示例…' }))}`,
    foot: '<button class="btn btn-default" data-cancel>取消</button><button class="btn btn-primary" data-ok>保存</button>',
  })
  const syncOrgVisibility = () => {
    const needOrg = modal.body.querySelector('[name="visibility"]')?.value === 'orgs'
    const orgItem = modal.body.querySelector('[name="targetOrgs"]')?.closest('.form-item')
    if (orgItem) orgItem.style.display = needOrg ? '' : 'none'
  }
  syncOrgVisibility()
  modal.body.querySelector('[name="visibility"]').onchange = syncOrgVisibility
  modal.el.querySelector('[data-cancel]').onclick = () => modal.close()
  modal.el.querySelector('[data-ok]').onclick = async (e) => {
    const btn = e.currentTarget
    btn.classList.add('btn-loading')
    try {
      const data = collectForm(modal.body)
      const toList = (value) => (value ?? '').split(/[,，]/).map((s) => s.trim()).filter(Boolean)
      if (data.visibility === 'orgs' && toList(data.targetOrgs).length === 0) {
        throw new Error('可见性为「指定组织」时须填写至少一个目标组织 ID')
      }
      await api.patch(`/api/skills/${skill.id}`, {
        name: data.name, category: data.category, summary: data.summary, description: data.description,
        tags: toList(data.tags), applicableModels: toList(data.applicableModels), deps: toList(data.deps),
        visibility: data.visibility, authorName: data.authorName,
        ...(data.visibility === 'orgs' ? { targetOrgs: toList(data.targetOrgs) } : {}),
      })
      toast('信息已更新'); modal.close(); drawer.close()
      openSkillDetail(skill.id, ctx, refresh)
      refresh?.()
    } catch (error) {
      toast(error.message, 'error')
    } finally {
      btn.classList.remove('btn-loading')
    }
  }
}

/** 重新手动上传当前已发布版本的 skill.zip 资源包（原地替换，版本号不变）。 */
function openReplacePackageModal(skill, ctx, refresh) {
  const published = [...skill.versions].reverse().find((v) => v.status === 'published')
  const pkg = published?.package
  const modal = openModal({
    title: `更新资源包 · v${published?.version ?? skill.currentVersion}`,
    body: `
      <div class="muted-box mb-14" style="display:flex;gap:8px">
        ${icon('info', 15)}<span>上传新的 skill.zip 原地替换当前已发布版本的资源包：<b>版本号不变</b>、不重走审批；下载/安装即刻取到新包。存储后端为 NAS 时会同步重传（失败则本次更新不生效）。</span>
      </div>
      ${pkg ? `
      <div class="desc-grid mb-14">
        <div class="desc-item"><span class="k">当前包</span><span class="v">${pkg.storage === 'nas' ? `NAS · ${esc(pkg.path ?? '')}` : '平台本地'}</span></div>
        ${pkg.sizeBytes !== undefined ? `<div class="desc-item"><span class="k">大小</span><span class="v">${fmtBytes(pkg.sizeBytes)}</span></div>` : ''}
        ${pkg.uploadedAt ? `<div class="desc-item"><span class="k">上传于</span><span class="v">${timeAgo(pkg.uploadedAt)}</span></div>` : ''}
      </div>` : ''}
      ${field('skill.zip 包', '<input class="input" type="file" id="skill-repkg" accept=".zip,application/zip">', { required: true, hint: '须为合法 ZIP（PK 魔数），base64 后上限 32MB' })}`,
    foot: '<button class="btn btn-default" data-cancel>取消</button><button class="btn btn-primary" data-ok>上传并替换</button>',
  })
  modal.el.querySelector('[data-cancel]').onclick = () => modal.close()
  modal.el.querySelector('[data-ok]').onclick = async (e) => {
    const btn = e.currentTarget
    const file = modal.body.querySelector('#skill-repkg')?.files?.[0]
    if (!file) return toast('请选择 skill.zip 文件', 'error')
    btn.classList.add('btn-loading')
    try {
      const packageBase64 = await readFileBase64(file)
      const result = await api.put(`/api/skills/${skill.id}/package`, { packageBase64 })
      toast(`资源包已更新（${fmtBytes(result.package?.sizeBytes ?? 0)}${result.package?.storage === 'nas' ? ' · 已上传 NAS' : ''}）`)
      modal.close(); drawer.close()
      openSkillDetail(skill.id, ctx, refresh)
      refresh?.()
    } catch (error) {
      toast(error.message, 'error')
    } finally {
      btn.classList.remove('btn-loading')
    }
  }
}

/** Skill 包存储配置（local / NAS）：写入口需 skill.storage.write，无权限降级只读。 */
async function openStorageModal() {
  let data
  try {
    data = await api.get('/api/skill-storage')
  } catch (error) {
    toast(error.message, 'error')
    return
  }
  const { config, nasOptions } = data
  const canWrite = session.can('skill.storage.write')
  const modal = openModal({
    title: 'Skill 包存储配置',
    body: `
      <div class="muted-box mb-14" style="display:flex;gap:8px">
        ${icon('info', 15)}<span>决定 Skill 上架时 skill.zip 包的存放位置：<b>平台本地</b>（内联存储）或 <b>NAS</b>（上架时上传到指定 NAS 资产的 basePath 下）。</span>
      </div>
      ${canWrite ? `
      <div class="form-item">
        <label class="form-label">存储模式</label>
        <div class="segmented" id="st-mode">
          <span class="segmented-item ${config.mode !== 'nas' ? 'active' : ''}" data-m="local">平台本地</span>
          <span class="segmented-item ${config.mode === 'nas' ? 'active' : ''}" data-m="nas">NAS</span>
        </div>
      </div>
      <div id="st-nas-fields" style="${config.mode === 'nas' ? '' : 'display:none'}">
        ${nasOptions.length ? `
          ${field('目标 NAS（仅已上线）', selectField('nasId', nasOptions.map((n) => ({ value: n.id, label: `${n.name}（${n.slug} · 根路径 ${n.rootPath ?? '/'}）` })), { value: config.nasId }), { required: true })}
          ${field('basePath', inputField('basePath', { value: config.basePath ?? '/skillhub', placeholder: '/skillhub' }), { required: true, hint: '以 / 开头的绝对路径（如 /共享名/skillhub），上架时按 Skill 归档' })}
        ` : '<div class="muted-box" style="color:var(--warn)">暂无「已上线」的 NAS 资产可选：请先在「NAS 存储」页纳管并上线。</div>'}
      </div>` : `
      <div class="desc-grid">
        <div class="desc-item"><span class="k">当前模式</span><span class="v">${config.mode === 'nas' ? 'NAS' : '平台本地'}</span></div>
        ${config.mode === 'nas' ? `
          <div class="desc-item"><span class="k">目标 NAS</span><span class="v mono">${esc(config.nasId ?? '—')}</span></div>
          <div class="desc-item"><span class="k">basePath</span><span class="v mono">${esc(config.basePath ?? '—')}</span></div>` : ''}
        <div class="desc-item"><span class="k">最近更新</span><span class="v">${config.updatedAt ? `${timeAgo(config.updatedAt)} · ${esc(config.updatedBy ?? '')}` : '—'}</span></div>
      </div>
      <div class="form-hint mt-8">你当前没有 skill.storage.write 权限，仅可查看。</div>`}`,
    foot: canWrite
      ? '<button class="btn btn-default" data-cancel>取消</button><button class="btn btn-primary" data-ok>保存</button>'
      : '<button class="btn btn-primary" data-ok>关闭</button>',
  })
  if (!canWrite) return
  let mode = config.mode === 'nas' ? 'nas' : 'local'
  modal.el.querySelector('[data-cancel]').onclick = () => modal.close()
  modal.body.querySelectorAll('#st-mode .segmented-item').forEach((el) => {
    el.onclick = () => {
      modal.body.querySelectorAll('#st-mode .segmented-item').forEach((i) => i.classList.remove('active'))
      el.classList.add('active')
      mode = el.dataset.m
      modal.body.querySelector('#st-nas-fields').style.display = mode === 'nas' ? '' : 'none'
    }
  })
  modal.el.querySelector('[data-ok]').onclick = async (e) => {
    const btn = e.currentTarget
    const form = collectForm(modal.body)
    if (mode === 'nas' && !nasOptions.length) return toast('暂无可用的已上线 NAS 资产', 'error')
    btn.classList.add('btn-loading')
    try {
      await api.put('/api/skill-storage', mode === 'nas'
        ? { mode, nasId: form.nasId, basePath: form.basePath }
        : { mode })
      toast('存储配置已保存'); modal.close()
    } catch (error) {
      toast(error.message, 'error')
    } finally {
      btn.classList.remove('btn-loading')
    }
  }
}

function readFileBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(new Error('读取本地文件失败'))
    reader.onload = () => resolve(String(reader.result).split(',')[1] ?? '')
    reader.readAsDataURL(file)
  })
}

function fmtBytes(value) {
  const n = Number(value)
  if (!Number.isFinite(n)) return '—'
  if (n >= 1 << 30) return (n / (1 << 30)).toFixed(1) + ' GB'
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + ' MB'
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + ' KB'
  return n + ' B'
}

function versionStatus(status) {
  const map = {
    published: 'published', approved: 'approved', rejected: 'rejected',
    pending_domain: 'pending_domain', pending_security: 'pending_security',
    scanning: 'scanning', deprecated: 'deprecated',
  }
  return map[status] ?? status
}

function miniStat(ic, label, value) {
  return `
    <div style="background:var(--surface-2);border-radius:10px;padding:12px 14px">
      <div style="color:var(--brand-500)">${icon(ic, 16)}</div>
      <div style="font-size:16px;font-weight:700;margin-top:6px">${value}</div>
      <div class="stat-label">${esc(label)}</div>
    </div>`
}

function debounce(fn, ms) {
  let timer
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms) }
}

/** 技能热力图卡片：行=skill、列=日、色深=使用次数（下载/安装计量口径）。 */
function heatCard({ days, skills, maxCell }) {
  const rows = skills.slice(0, 12)
  const cell = 15
  const gap = 3
  const labelW = 148
  const width = labelW + days.length * (cell + gap)
  const height = rows.length * (cell + gap) + 16
  const cells = rows.map((skill, r) => skill.cells.map((value, c) => {
    const opacity = value > 0 ? 0.1 + 0.9 * (value / maxCell) : 0.04
    return `<rect x="${labelW + c * (cell + gap)}" y="${r * (cell + gap)}" width="${cell}" height="${cell}" rx="3" fill="#4f6ef7" fill-opacity="${opacity.toFixed(2)}"><title>${esc(skill.name)} · ${esc(days[c])} · ${value} 次</title></rect>`
  }).join('')).join('')
  const rowLabels = rows.map((skill, r) =>
    `<text x="0" y="${r * (cell + gap) + 11}" font-size="11" fill="#6b7280">${esc(skill.name.length > 13 ? skill.name.slice(0, 12) + '…' : skill.name)}</text>`).join('')
  const dayTicks = days.map((day, c) => c % 7 === 6
    ? `<text x="${labelW + c * (cell + gap)}" y="${height - 3}" font-size="10" fill="#9ca3af">${esc(day.slice(5))}</text>` : '').join('')
  return `
    <div class="card">
      <div class="card-head"><span class="card-title">${icon('chart', 15)} 技能使用热力图</span><span class="card-sub">近 30 天 · 下载/安装计量（含历史流水回填）</span></div>
      <div class="card-body" style="padding-top:10px">
        <div style="overflow-x:auto">
          <svg width="${Math.max(width, 360)}" height="${height}" style="display:block">
            ${rowLabels}${cells}${dayTicks}
          </svg>
        </div>
        <div class="flex fs-11 text-4" style="justify-content:space-between;margin-top:4px">
          <span>Top ${rows.length}（按窗口使用次数）</span>
          <span>色深 = 当日使用次数（峰值 ${maxCell}）</span>
        </div>
      </div>
    </div>`
}
