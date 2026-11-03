// End-to-end check of the stdio MCP server: spawn it, handshake, list tools,
// call one, and fail loudly on drift.
//
//   python3 dev/mock_sslmanager.py 8030 &
//   node dev/mcp-test.mjs
import { spawn } from 'node:child_process'

const child = spawn(process.execPath, ['mcp/server.mjs'], {
  env: { ...process.env, SSLMGR_BASE_URL: process.env.SSLMGR_BASE_URL || 'http://127.0.0.1:8030', SSLMGR_TOKEN: 'mock-token' },
  stdio: ['pipe', 'pipe', 'inherit'],
})

const pending = new Map()
let buffer = ''
let nextId = 1

child.stdout.setEncoding('utf8')
child.stdout.on('data', (chunk) => {
  buffer += chunk
  let index
  while ((index = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, index).trim()
    buffer = buffer.slice(index + 1)
    if (!line) continue
    const message = JSON.parse(line)
    const resolve = pending.get(message.id)
    if (resolve) {
      pending.delete(message.id)
      resolve(message)
    }
  }
})

function send(method, params) {
  const id = nextId++
  const promise = new Promise((resolve) => pending.set(id, resolve))
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`)
  return promise
}

const init = await send('initialize', { protocolVersion: '2024-11-05' })
const listed = await send('tools/list', {})
const names = listed.result.tools.map((tool) => tool.name).sort()
const call = await send('tools/call', { name: 'ssl_cert_list', arguments: { limit: 5 } })
const refused = await send('tools/call', {
  name: 'ssl_cert_apply',
  arguments: { domainName: 'example.com' },
})
const applied = await send('tools/call', {
  name: 'ssl_cert_apply',
  arguments: { domainName: 'example.com', confirm: true, reason: 'mcp smoke test' },
})

const failures = []
if (init.result?.serverInfo?.name !== 'sslmanager') failures.push('bad serverInfo')
if (names.length !== 11) failures.push(`expected 11 tools, got ${names.join(',')}`)
if (call.result?.isError) failures.push(`tool call failed: ${call.result.content?.[0]?.text}`)
if (refused.result?.isError !== true) failures.push('apply without confirm must be refused over MCP')
if (applied.result?.isError) failures.push(`confirmed apply failed: ${applied.result.content?.[0]?.text}`)
if (JSON.stringify([call.result, applied.result]).includes('BEGIN ')) failures.push('key material leaked')

console.log('tools:', names.join(', '))
console.log('call:', call.result?.content?.[0]?.text?.split('\n')[0])
console.log('refused:', refused.result?.content?.[0]?.text?.split('\n')[0])
console.log('applied:', applied.result?.content?.[0]?.text?.split('\n')[0])
console.log(failures.length ? `FAIL: ${failures.join('; ')}` : 'OK')
child.stdin.end()
process.exit(failures.length ? 1 : 0)
