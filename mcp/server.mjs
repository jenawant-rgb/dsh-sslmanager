#!/usr/bin/env node
/**
 * stdio MCP wrapper around the same read-only tool set the DSH plugin exposes.
 *
 * Codex (or any MCP client) can run it directly:
 *
 *   SSLMGR_BASE_URL=https://ssl.example.com SSLMGR_TOKEN=... node mcp/server.mjs
 *
 * Newline-delimited JSON-RPC 2.0 on stdin/stdout, per the MCP stdio transport.
 * Nothing is logged to stdout; diagnostics go to stderr.
 */
import { createTools } from '../index.js'

const serverInfo = { name: 'sslmanager', version: '0.1.0' }
const tools = createTools({}, {
  baseUrl: process.env.SSLMGR_BASE_URL || 'http://127.0.0.1:8030',
  tokenRef: 'SSLMGR_TOKEN',
})

const byName = new Map(tools.map((tool) => [tool.name, tool]))

function reply(id, result) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, result })}\n`)
}

function fail(id, code, message) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } })}\n`)
}

function text(value) {
  return [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }]
}

async function handle(message) {
  const { id, method, params } = message
  switch (method) {
    case 'initialize':
      return reply(id, {
        protocolVersion: params?.protocolVersion || '2024-11-05',
        capabilities: { tools: {} },
        serverInfo,
      })
    case 'notifications/initialized':
      return undefined
    case 'ping':
      return reply(id, {})
    case 'tools/list':
      return reply(id, {
        tools: tools.map((tool) => ({
          name: tool.name,
          description: tool.description,
          inputSchema: tool.parameters,
        })),
      })
    case 'tools/call': {
      const tool = byName.get(params?.name)
      if (!tool) return fail(id, -32602, `unknown tool: ${params?.name}`)
      try {
        const value = await tool.execute(params?.arguments || {}, {})
        return reply(id, { content: tool.output.render(params?.arguments || {}, value), isError: false })
      } catch (error) {
        return reply(id, { content: text(String(error?.message || error)), isError: true })
      }
    }
    default:
      if (id === undefined) return undefined
      return fail(id, -32601, `method not found: ${method}`)
  }
}

let buffer = ''
let queue = Promise.resolve()

function enqueue(line) {
  queue = queue
    .then(() => handle(JSON.parse(line)))
    .catch((error) => console.error('sslmanager-mcp:', error))
}

process.stdin.setEncoding('utf8')
process.stdin.on('data', (chunk) => {
  buffer += chunk
  let index
  while ((index = buffer.indexOf('\n')) >= 0) {
    const line = buffer.slice(0, index).trim()
    buffer = buffer.slice(index + 1)
    if (line) enqueue(line)
  }
})
process.stdin.on('end', () => {
  const tail = buffer.trim()
  if (tail) enqueue(tail)
  queue.finally(() => process.exit(0))
})
