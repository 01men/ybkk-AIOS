// 临时语法校验（0904）：oauth.js / login.js 为浏览器 ES Module，用动态 import 触发解析。
// 解析阶段抛 SyntaxError 即语法错误；运行期缺少浏览器全局（ReferenceError 等）属预期，视为通过。
const base = 'file:///' + process.cwd().replace(/\\/g, '/') + '/packages/plugin-console/public/js/pages/'
for (const name of ['oauth.js', 'login.js']) {
  try {
    await import(base + name)
    console.log('[IMPORT_OK]', name)
  } catch (error) {
    if (error instanceof SyntaxError) {
      console.log('[SYNTAX_FAIL]', name, error.message)
      process.exitCode = 1
    } else {
      console.log('[PARSE_OK]', name, '-', error.constructor.name + ':', String(error.message).slice(0, 120))
    }
  }
}
