/**
 * AI 应用本体属性表（方案 §6.1）：在 Agent 属性模型上扩展应用特有字段。
 */
import type { ResourceTypeSpec } from '../../platform-core/src/index.ts'

export const APP_TYPE_SPEC: ResourceTypeSpec = {
  type: 'app',
  label: 'AI 应用',
  plugin: 'app',
  idPrefix: 'app',
  schema: {
    groups: [
      { key: 'basic', label: '基本属性', description: '应用身份与归属' },
      { key: 'app', label: '应用属性', description: '形态、入口与编排' },
      { key: 'publish', label: '发布属性', description: '版本与发布渠道' },
      { key: 'governance', label: '治理属性', description: '风险与数据密级' },
    ],
    fields: [
      { key: 'description', label: '描述', type: 'text', group: 'basic', required: true },
      { key: 'icon', label: '头像 / 图标', type: 'string', group: 'basic', defaultValue: '✨', placeholder: 'emoji 或图片 URL（https://…）', hint: '一个 emoji，或一张图片的 http(s) 地址（控制台与卡片按 URL 渲染头像）' },
      { key: 'developerName', label: '开发者', type: 'string', group: 'basic', hint: '开发者姓名；传 developerId 时以平台账号 displayName 为准' },
      { key: 'developerId', label: '开发者 ID', type: 'string', group: 'basic', hint: '平台用户 ID；注册/更新时校验存在并回填开发者姓名' },
      { key: 'appType', label: '应用类型', type: 'enum', group: 'app', required: true, options: [
        { value: 'web', label: 'Web 应用' },
        { value: 'h5', label: 'H5' },
        { value: 'miniapp', label: '小程序' },
        { value: 'desktop', label: '桌面端' },
        { value: 'api', label: 'API 服务' },
      ] },
      { key: 'url', label: '访问地址', type: 'url', group: 'app', requiredForOnline: true, placeholder: 'https://…', hint: '上线前必须登记访问入口' },
      { key: 'agentIds', label: '编排 Agent', type: 'tags', group: 'app', defaultValue: [], requiredForOnline: true, hint: '一个应用可编排多个在线 Agent（依赖拓扑数据源）' },
      { key: 'channels', label: '发布渠道', type: 'tags', group: 'publish', defaultValue: [] },
      { key: 'publishVersion', label: '发布版本', type: 'string', group: 'publish', placeholder: '如 v2.4.0' },
      { key: 'riskLevel', label: '风险等级', type: 'enum', group: 'governance', required: true, options: [
        { value: 'low', label: '低' },
        { value: 'medium', label: '中' },
        { value: 'high', label: '高' },
      ] },
      { key: 'dataClass', label: '数据密级', type: 'enum', group: 'governance', requiredForOnline: true, options: [
        { value: 'public', label: '公开' },
        { value: 'internal', label: '内部' },
        { value: 'confidential', label: '机密' },
      ] },
    ],
  },
  lifecycle: {
    initial: 'draft',
    states: [
      { key: 'draft', label: '开发中', tone: 'muted' },
      { key: 'trial', label: '试运行', tone: 'info' },
      { key: 'online', label: '已发布', tone: 'ok' },
      { key: 'offline', label: '已下架', tone: 'warn' },
      { key: 'archived', label: '已归档', tone: 'muted', terminal: true },
    ],
    transitions: [
      { action: 'submit_trial', label: '进入试运行', from: ['draft'], to: 'trial' },
      { action: 'online', label: '发布上线', from: ['draft', 'trial'], to: 'online', approval: true },
      { action: 'offline', label: '下架', from: ['trial', 'online'], to: 'offline', approval: true },
      { action: 'retrial', label: '恢复试运行', from: ['offline'], to: 'trial' },
      { action: 'archive', label: '归档', from: ['offline'], to: 'archived' },
    ],
  },
}
