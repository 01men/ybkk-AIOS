# 企业门户数据通道（plugin-portal）对接与运维文档

> 面向对象：门户方（前端）联调、平台运维、后续维护者。
> 对接依据：《AI 数字化门户 · 数据接口对接文档》v1.0（2026-09-02，即 api.md）。
> 本文档随服务发布，可直接访问 `http://192.168.0.7:7300/docs/portal-integration.md`。

---

## 一、定位与边界（先读）

门户（`http://192.168.0.4:8092`，纯前端静态站点）按**拉取（Pull）**策略主动来宿主平台取数：
**平台不需要调用门户任何接口**，只需提供 6 个只读 GET 端点；数据增删改全部发生在平台侧，
门户每次页面加载拉取最新数据（无通知、无推送、无回调）。

该能力为**外部系统对接，非平台核心功能**，实现上刻意保持（`packages/plugin-portal/`）：

| 设计点 | 说明 |
|--------|------|
| 单插件隔离 | 全部实现在 `packages/plugin-portal/`（端点 + CORS + 映射 + 留痕），摘除 = 删目录 + `boot-all.ts`/`cordis.yml` 各一行，不影响任何业务链路 |
| 一键停用 | 环境变量 `PORTAL_SYNC=off` 后重启即可；门户侧自动降级展示内置样板数据（契约 §5） |
| 只读直读 | 端点实时读 `resourceCore/skillHub/mcpRegistry`，无副本、无缓存 →「上线/下架 → 门户刷新即可见」 |
| 映射集中 | 门户字段契约只在 `src/mapping.ts` 一处映射；门户契约变化时改这一个文件 |
| 留痕可观测 | 应用/Agent 上下线 → 审计记录 `portal.feed.*`（拉取模式无外呼，留痕仅为运营可见性） |

### 与既有「AI 应用接入授权」能力的关系（非重复开发）

平台已有的对外通道均为**带鉴权的身份/访问/上报通道**，与门户数据通道解决的问题不同：

| 既有能力 | 面向 | 鉴权 | 与门户通道的区别 |
|----------|------|------|------------------|
| OIDC/SSO（plugin-authn） | 应用↔平台登录打通 | 协议级（PKCE） | 解决「用户是谁」，不含数据清单 |
| 入场票据 entry-ticket | 打开应用时身份直达 | 一次性票据 | 单次身份交付，非数据面 |
| 机器凭证 + `/api/apps` REST | 应用自身运维/提报 | Bearer + RBAC | 返回完整内部实体（ownerId/审计等），不适合全员门户公开 |
| 指标提报 / usage record | 应用 → 平台上报 | Bearer | 入站方向相反 |

门户契约要求**免鉴权 GET + 门户专用字段 + CORS**（api.md §3/§6），既有端点均不满足；
门户通道读取的访问地址即各应用登记的 `attrs.url`（与控制台「打开应用」、SSO 接入同一数据源），无平行数据。

### 门户侧访客指标上报（一行 beacon，可选）

门户作为平台在册应用（`app_mtjl5anjiupainet`），页面加载/路由切换时向平台公开埋点端点上报一次，
即可获得 PV/UV 统计（免鉴权、免 secret；SSO 打开/兑换已由平台自动折算 DAU，无需上报）：

```js
const vid = localStorage['rq:vid'] ??= crypto.randomUUID().replace(/-/g, '')
navigator.sendBeacon?.('http://192.168.0.7:7300/api/apps/beacon',
  new Blob([JSON.stringify({ app: 'app_mtjl5anjiupainet', vid })], { type: 'application/json' }))
```

详见 [app-sso-integration.md §十一](app-sso-integration.md#十一访客指标自动折算平台侧与-beacon-埋点应用侧)。

---

## 二、BASE URL 与端点（门户方回填 VITE_API_BASE 用）

```
BASE = http://192.168.0.7:7300/api/portal
```

门户构建时注入 `VITE_API_BASE=http://192.168.0.7:7300/api/portal` 并重新构建部署（门户侧操作）。

| 端点 | 内容 | 数据来源 |
|------|------|----------|
| `GET /api/portal` | 端点发现（联调自检入口） | — |
| `GET /api/portal/apps` | 已上线 AI 应用 | `resourceCore` app，**仅 `online`** |
| `GET /api/portal/employees` | 数字员工（已上线 Agent） | `resourceCore` agent，仅 `online` |
| `GET /api/portal/solutions` | 解决方案 | 暂无数据源 → `[]`（门户降级展示内置样板） |
| `GET /api/portal/tools` | AI 工具地图 | 暂无数据源 → `[]`（同上） |
| `GET /api/portal/skills` | 技能/提示词库 | `skillHub`，仅 `published` |
| `GET /api/portal/stats` | 首页统计 4 卡 | 平台实时计数 |

通用应答：`{code:0, message:"ok", data:[...]}`（`code` 0/200 为成功），`Content-Type: application/json; charset=utf-8`，
`Cache-Control: no-cache`；空值一律空串不返回 null；`launchDate` 为 `YYYY-MM-DD` 或空串（空串=未上线）。

`launchDate` 口径：应用/Agent 取生命周期最近一次进入 `online` 的日期；Skill 取最近一次版本 `publishedAt`。
应用 `tag` 优先取发布渠道 `channels[0]`，未登记渠道时用应用形态（Web/H5/小程序/桌面端/API）；
`accent` 为平台按 id 稳定生成的卡片主题色（#RRGGBB）；`dept` 取归属组织名（组织未命名时回退空串/作者名）。

`skills.downloadUrl`：已上架技能包的**登录下载端点绝对地址**（`<对外基址>/api/portal/skills/:id/download`，
zip 直出）。**api.md v1.1 起该端点必须携带门户登录令牌**：请求头 `Authorization: Bearer <token>`
（门户 OIDC 登录换取的 access_token 或平台会话令牌均可），未带/无效令牌返回 401 契约错误
（`{code:40100,...}`），登录后未上架/未知 id 返回 404。平台按解析出的登录用户登记下载计量与审计
（`portal.skill.download`：谁、时间、下载了什么、来源 IP）；仅 `published` 状态技能可下载。
配套 CORS：门户预检 `OPTIONS` 已放行 `authorization` 请求头（`Access-Control-Allow-Headers: authorization, content-type`）。

## 三、CORS（契约 §6，未放行则门户无法访问）

- 生产门户 `http://192.168.0.4:8092`：默认已放行；
- 门户本地/内网开发（`localhost`、内网 IP 的 `:8443`/`:8092`）：默认已放行；
- 其他来源：`PORTAL_CORS_ORIGINS` 环境变量逗号分隔追加；
- `OPTIONS` 预检统一 204；无凭证（不需要 `Access-Control-Allow-Credentials`）。

## 四、环境变量（可变适配点）

| 变量 | 默认 | 说明 |
|------|------|------|
| `PORTAL_SYNC` | `on` | `off` 停用整个数据通道（门户自动降级样板） |
| `PORTAL_API_PREFIX` | `/api/portal` | 端点前缀（变更后需同步告知门户方更新 VITE_API_BASE） |
| `PORTAL_PUBLIC_BASE` | `http://192.168.0.7:7300` | 平台对外基址——`downloadUrl` 等绝对地址字段的拼装基准（反代/换址时覆盖） |
| `PORTAL_CORS_ORIGINS` | （空） | 追加放行的门户来源，逗号分隔 |
| `PORTAL_HIDE_CONFIDENTIAL` | （关） | `1` 时机密级（dataClass=confidential）应用不出现在门户 |

systemd 部署（`/opt/ops-platform`）在 `ops-platform.service` 的 `Environment=` 行追加即可，改后 `systemctl restart ops-platform` 生效。

## 五、验收命令（api.md 附录口径）

```bash
BASE=http://192.168.0.7:7300/api/portal
for ep in apps employees solutions tools skills stats; do curl -s $BASE/$ep | head -c 500; echo; done

# CORS 放行验证（应看到 access-control-allow-origin: http://192.168.0.4:8092）
curl -s -i -H "Origin: http://192.168.0.4:8092" $BASE/stats | grep -i access-control
```

回归：`npm run selftest` 含「门户数据通道」专项断言（公开访问、契约包装、CORS、上线即可见、
未上线不可见、stats 口径一致、预检 204、只读 405 等）。

## 六、上线后运营口径

- 应用「发布上线」审批通过 → 即对门户可见（刷新页面即可，无需任何同步动作）；
- 应用「下架/归档」→ 门户清单即时消失；
- 每次上下线在「审计与告警」留下 `portal.feed.app.visible/hidden`（Agent 对应 `portal.feed.employee.*`）记录；
- 若门户方未来改为推送/回调模式：仅需在 `plugin-portal` 内新增出站适配器（事件总线已就绪），
  平台核心依旧不动。
