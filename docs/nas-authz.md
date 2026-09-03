# NAS 数据权限（组织位置 + 角色层级 RBAC）实施说明

> 落地版本：dev-plan-nas-authz v1.1（2026-08-29）· 判定引擎纯函数化 · 全链 fail-closed
> 本文是平台侧（ybkk-AIOS 仓库）的实施说明；网关/hermes 改造件见 `integrations/`。

## 一、架构落点

```
决策点 PDP：plugin-nas/src/authz.ts（NasAuthzService，服务键 nasAuthz）
判定引擎  ：plugin-nas/src/authz/engine.ts（纯函数，无容器/无 IO，selftest 直接单测）
数据源    ：IAM 组织树/负责人（leaderUserIds）/三方身份映射 identityLinks（单一事实源）
强制点①  ：网关 synology-filestation-mcp（integrations/synology-filestation-mcp，仅代码）
强制点②  ：hermes 本地直读 guard（integrations/hermes-patch，仅代码）
兜底层    ：DSM 原生权限（令牌绑定 NAS 账户，零代码，运维配置）
```

## 二、五步判定序（服务 B 语义移植）

1. 账号特殊规则：external 白名单只读 / suspended-review 全 deny 转人工 / 挂根非负责人 deny / 未落班组部门根只读 / **兼任子树只读**（主归属 primaryOrgId，缺省组织链最深者）；
2. 资源级显式 deny（nasId + 路径尾通配，可按人收敛）；
3. 资源级显式 allow（C 跨域白名单、临时授权，可设 expiresAt，过期即失效回落矩阵）；
4. 角色矩阵 × 作用域边界（映射表 `orgPathOverrides` 优先、名字推导默认；C 叠加跨域只读）；
5. 默认 deny。

**内置矩阵**（可经 rules.matrixOverrides 覆盖）：

| 角色 | read | download | write | modify | delete | share | admin |
|---|---|---|---|---|---|---|---|
| P 平台负责人 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| D 部门负责人 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ |
| T 班组负责人 | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| M 成员 | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| C 叠加 | 跨域 read/download 放行，写类全拒（白名单写需显式 allow） | | | | | | |

角色推导（无人员名单配置）：P/D/T = 组织链上负责人（深度 1/2/≥3），**多负责人全部推导（co-leader）**；M = 深度≥3 非负责人成员。负责人事实源 = `OrgRecord.leaderUserIds`（钉钉连接器同步 `dept_manager_userid_list`）。

**一人多身份（多主体/多部门/跨分支任职，2026-08-30 落地）**：

- **多主体**：同一人在聚杰/榕器创两个钉钉主体各有一条平台记录与身份链，互不合并、互不覆盖——hermes 按消息所属主体上报 userid，天然路由到对应身份；
- **双身份链**：同步为每人并存 unionId（SSO 登录匹配）与 userid（nasAuthz 身份反查、`dept_manager_userid_list` 负责人映射）两条 identityLinks；
- **主部门**：多部门用户主归属取钉钉 `dept_id_list[0]`（主部门），其余部门记挂靠（兼任子树只读，避免双写冲突）；
- **跨分支领导**：主归属链之外兼任的部门负责人身份独立保留（`leaderOfElsewhere`），按所领导部门子树套用该部门角色矩阵（全权限层）；主部门挂在下属班组的负责人，作用域锚提升到所领导的最高部门（角色与作用域对齐）；多身份作用域重叠时按 P>D>T 取最高档；主作用域未命中 NAS 锚点不提前拒绝（所领导部门在链上即放行）；
- 已知限制：引擎承载「主归属 + 1 挂靠 + N 跨分支领导」；同一部门内的双负责人用 co-leader 表达。
- **根目录只读列举（B 语义，2026-09-03）**：在本 NAS 有任一作用域（主/跨分支领导/兼任挂靠/C）的用户，放行对 NAS 根路径本身的 read/download（列目录/查元信息，理由 `org.root-listing`）；显式 deny 例外仍优先，写类与根下越界路径照常拒绝，无任何作用域用户全拒不变。

## 三、REST 端点（plugin-console，权限点见括号）

| 端点 | 说明 |
|---|---|
| `POST /api/nas/authz/check`（nas.authz.check） | `{nasId, userId, paths[], op[, override]}` → `{decision, role, cTag, scope, reasons[], perPath[], ruleId?}`；身份支持平台 userId / 钉钉 userId 反查 / `X-On-Behalf-User` 头 |
| `GET /api/nas/authz/scope`（同上） | 作用域 + 角色 + 矩阵快照（hermes/控制台收敛枚举；网关降级快照数据源） |
| `GET/PUT /api/nas/authz/rules`（nas.authz.read / write） | 规则读写；**PUT 携 `ifVersion` 乐观锁，冲突 409 VERSION_CONFLICT**；cGroups 支持按动态组名引用 |
| `POST /api/nas/authz/rules/import`（nas.authz.write） | 幂等导入 `packages/plugin-nas/seed/nas-authz-rules.json` |
| `POST /api/nas/authz/exceptions`（check / write 双模式） | `status=pending` = share 申请（审批人自动路由）；`effect` 直写例外 |
| `GET /api/nas/authz/decisions`（nas.authz.read） | 判定留痕（deny 全量 + delete/share/admin 高危；普通 90 天滚动、高危永久） |
| `POST /api/nas/authz/reconcile` / `leader-vacancy-scan`（nas.authz.read） | 组织↔目录对账 / 负责人悬空扫描（每日 job 自动执行） |

内置角色：`resource_admin` 经 `nas.*` 通配自动覆盖；`auditor` 迁移补 `nas.authz.read`。破窗：持 `nas.authz.write` 者可 `override=true` 走 P 判定并强制留痕（不越过特殊账号规则与显式 deny 例外）。

## 四、强制点与身份约束

- **身份一律走 `X-On-Behalf-User` 请求头，禁止进工具参数**（P0-2 教训）：平台 plugin-nas 调网关时经 `onBehalfHeaders` 注入（优先钉钉 userId）；nas_fs_* 工具身份改由 `exec.principal` 传递（schema 无身份参数，缺失 fail-closed）；网关/hermes 对非授信令牌携带该头直接拒绝（防伪造）。
- 网关三级降级：scope 快照（仅快照内读）→ readonly（灰度可配）→ deny（默认 fail-closed）；check 超时 ≤2s、连续 5 次超时熔断、恢复自动退出（`integrations/synology-filestation-mcp/test/authz-smoke.mjs` 23/23）。异步任务工具映射：`fs_task_status=read`、`fs_task_clear=delete`（G0 实测映射面外工具在 observeOnly 下也被 `op.unsupported` 硬拒后补齐，工具面 ↔ 映射表双向一致性已入 smoke 断言）。
- hermes guard hook 化 + hash 锚点校验（`integrations/hermes-patch`）。

## 五、事件与告警

`nas.authz.denied`（高频 deny 突发 → 告警规则 metric `nas_authz_denied`）、`nas.authz.leaderVacant`（负责人悬空）、`nas.authz.dirOrphan`（组织目录对账不匹配，组织改名提示登记 override）、`nas.authz.cGroupDrift`（C 关联动态组任何漂移 / 其余组超阈值，阈值缺省 5）。全部接平台告警中心。

## 六、灰度开关（rules 单例）

- `observeOnly`（缺省 true）：deny 只告警不拦截（G0，网关与 hermes 双通道同步观察）；
- `degradeAllToReadonly`：全量降级只读（G3 应急）；
- 网关侧 `AUTHZ_ENFORCE=off` 全局 kill-switch + 逐令牌 `enforce` 字段：任一阶段出问题秒级回退。

## 七、CLI（dshctl）

```
dshctl nas authz check --nas=<id> --user=<userId> --path=<路径> --op=<操作> [--override]
dshctl nas authz scope --nas=<id> --user=<userId>
dshctl nas authz rules get | set [--observe-only=on|off] [--degrade-readonly=on|off] [--c-groups=a,b] | import --file=<rules.json>
dshctl nas authz decisions [--decision=deny] [--limit=50]
```

## 八、测试

- `npm run selftest`：658 项断言全绿，其中 NAS 数据权限两分节（引擎纯函数 + API/审批闭环/对账 40+ 项）覆盖 §四 全部用例（35 格矩阵、co-leader、兼任、跨分支领导、负责人悬空、例外过期、C 叠加、改名不漂移、多 NAS 隔离、乐观锁 409、导入幂等、share 审批闭环含到期拒绝、C 组漂移告警、X-On-Behalf-User 透传与防伪）；
- `npm run lint:manifests`：70/70 通过；
- 网关 authz-smoke：24/24；hermes 补丁 `--selftest`：通过。
