// Drives the plugin's tools without a Harness: fake contexts capture the
// registrations, then every tool runs against the mock SSLManager API.
// The approval service is faked so both the "user approved" and "user
// rejected" paths, plus the no-approval (MCP) path, are exercised.
//
//   python3 dev/mock_sslmanager.py 8030 &
//   node dev/harness.mjs
import { createTools } from '../index.js'

const BASE_URL = process.env.SSLMGR_BASE_URL || 'http://127.0.0.1:8030'

function makeContext(approvalOutcome) {
  const tools = []
  const approvals = []
  const ctx = { tools: { register: (definition) => tools.push(definition) } }
  if (approvalOutcome) {
    ctx.approval = {
      request: async (request) => {
        approvals.push(request)
        return approvalOutcome
      },
    }
  }
  const agentExec = { agent: { session: {} }, signal: undefined }
  const definitions = createTools(ctx, { baseUrl: BASE_URL, token: 'mock-token' })
  return { tools: definitions, approvals, exec: { ...agentExec, ctx } }
}

const approved = makeContext('allowed-once')
const rejected = makeContext('rejected')
const headless = makeContext(null)

let failures = 0
const outputs = []

function check(condition, message) {
  if (!condition) {
    console.error(`FAIL: ${message}`)
    failures++
  }
}

async function run(context, name, args, { expectError = false } = {}) {
  const tool = context.tools.find((candidate) => candidate.name === name)
  if (!tool) {
    console.error(`MISSING TOOL ${name}`)
    failures++
    return undefined
  }
  try {
    const value = await tool.execute(args, context.exec)
    const rendered = tool.output.render(args, value).map((part) => part.text).join('\n')
    outputs.push(JSON.stringify(value))
    console.log(`\n=== ${name} ${JSON.stringify(args)} ===`)
    console.log(rendered)
    if (expectError) {
      console.error(`FAIL: ${name} should have been refused`)
      failures++
    }
    return value
  } catch (error) {
    if (!expectError) {
      console.error(`FAILED ${name}: ${error.message}`)
      failures++
    } else {
      console.log(`\n=== ${name} ${JSON.stringify(args)} ===`)
      console.log(`refused as expected: ${error.message}`)
    }
    return undefined
  }
}

// --- read-only -----------------------------------------------------------
await run(approved, 'ssl_cert_list', {})
await run(approved, 'ssl_cert_expiring', { days: 30 })
await run(approved, 'ssl_cert_get', { certId: 1 })
await run(approved, 'ssl_domain_list', {})
await run(approved, 'ssl_probe', { host: 'https://api.example.com/health' })
await run(approved, 'ssl_remote_list', {})

// --- write tools, approval granted --------------------------------------
const applied = await run(approved, 'ssl_cert_apply', { domainName: 'example.com', reason: 'expires in 9 days' })
check(applied?.accepted === true, 'apply should be accepted')
check(approved.approvals.length === 1, 'apply should ask the approval service exactly once')
check(approved.approvals[0]?.toolName === 'ssl_cert_apply', 'approval request should name the tool')

const status = await run(approved, 'ssl_cert_status', { domainName: 'example.com' })
check(status?.status === 'requested', `status should be requested, got ${status?.status}`)

const deployed = await run(approved, 'ssl_cert_deploy', { domainName: 'example.com', remoteId: 1, reason: 'new cert' })
check(deployed?.deployed === true, 'deploy should report success')
check(approved.approvals.length === 2, 'deploy should ask the approval service')

// --- revoke (after the deploy above) ------------------------------------
const revoked = await run(approved, 'ssl_cert_revoke', { domainName: 'old.example.com', reason: 'key exposed' })
check(revoked?.revoked === true, 'revoke should report success')

const revokedStatus = await run(approved, 'ssl_cert_status', { domainName: 'old.example.com' })
check(revokedStatus?.status === 'revoked', `status should be revoked, got ${revokedStatus?.status}`)

await run(rejected, 'ssl_cert_revoke', { domainName: 'api.example.com' }, { expectError: true })

// --- write tools, approval rejected -------------------------------------
await run(rejected, 'ssl_cert_apply', { domainName: 'api.example.com' }, { expectError: true })
check(rejected.approvals.length === 2, 'rejected path should still have asked for both writes')

// --- write tools, no approval service (MCP) -----------------------------
await run(headless, 'ssl_cert_apply', { domainName: 'api.example.com' }, { expectError: true })
const confirmed = await run(headless, 'ssl_cert_apply', {
  domainName: 'api.example.com',
  confirm: true,
  reason: 'MCP path',
})
check(confirmed?.authorization === 'confirmed', 'confirm:true should authorize without approval UI')

// --- never leak key material --------------------------------------------
for (const payload of outputs) {
  check(!payload.includes('BEGIN '), 'tool output must not contain PEM blocks')
  check(!payload.includes('key_content'), 'tool output must not contain key_content')
  check(!payload.includes('encrypted-not-returned'), 'tool output must not contain remote secrets')
}

console.log(`\n${failures === 0 ? 'OK' : `FAILURES: ${failures}`} (${approved.tools.length} tools registered)`)
process.exit(failures === 0 ? 0 : 1)
