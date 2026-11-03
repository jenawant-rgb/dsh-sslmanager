/**
 * SSLManager certificate tools (read-only MVP).
 *
 * Exposes certificate inventory, expiry, domain and live TLS probe data to the
 * model. Private keys never leave the SSLManager server: every tool here
 * returns metadata only, and key fields are dropped defensively even if the
 * API starts returning them.
 *
 * The module has no runtime imports on purpose: it must load both from a
 * profile-installed package and from a `link:`ed checkout, where Harness
 * packages are not resolvable from the plugin's real path. Tool definitions
 * are therefore plain registry definitions with standard JSON Schema.
 *
 * @module @sslmanager/dsh-sslmanager
 */

export const name = 'sslmanager'
export const inject = ['tools']

const DEFAULT_BASE_URL = 'http://127.0.0.1:8030'
const DAY_MS = 24 * 60 * 60 * 1000

/**
 * Build a registry-ready tool definition from JSON Schema parts.
 *
 * @param {object} options - Tool contract.
 * @param {string} options.name - Model-facing tool name.
 * @param {string} options.description - Model-facing description.
 * @param {Record<string, object>} options.parameters - Parameter schemas by name.
 * @param {string[]} [options.required] - Required parameter names.
 * @param {object} options.outputSchema - Canonical output schema.
 * @param {(args: object, value: object) => object[]} options.render - Content renderer.
 * @param {(args: object, exec: { signal?: AbortSignal }) => Promise<object>} options.execute - Body.
 */
function defineReadTool({ name: toolName, description, parameters, required = [], outputSchema, render, execute }) {
  return {
    name: toolName,
    description,
    parameters: {
      type: 'object',
      additionalProperties: false,
      properties: parameters,
      ...(required.length > 0 ? { required } : {}),
    },
    output: { schema: outputSchema, render },
    execute,
  }
}

/**
 * Look up an optional Cordis service without declaring it in `inject`.
 * Property access throws for undeclared services; `ctx.get` returns undefined
 * instead, and a test/MCP context has neither.
 */
function optionalService(ctx, name) {
  try {
    const viaGet = typeof ctx.get === 'function' ? ctx.get(name) : undefined
    if (viaGet) return viaGet
  } catch {
    // ignore and fall through
  }
  try {
    return ctx[name]
  } catch {
    return undefined
  }
}

/**
 * Build a small authenticated REST client for one plugin activation.
 *
 * Tokens resolve in this order: inline `config.token` (development only), the
 * credential store entry named by `config.tokenRef`, the environment variable
 * of the same name, then a username/password login against `/api/user/token`.
 *
 * @param {object} ctx - Cordis context of the activation.
 * @param {object} config - Row config from `cordis.patch.yml`.
 */
function createClient(ctx, config) {
  const baseUrl = String(config.baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, '')
  const tokenRef = String(config.tokenRef || 'SSLMGR_TOKEN')
  const usernameEnv = String(config.usernameEnv || 'SSLMGR_USERNAME')
  const passwordEnv = String(config.passwordEnv || 'SSLMGR_PASSWORD')

  let token = null
  let tokenExpiresAt = 0
  let domainCache = { at: 0, map: new Map(), list: [] }

  async function readSecret(ref) {
    try {
      const credentials = optionalService(ctx, 'credentials')
      const hit = await credentials?.resolve?.(ref)
      if (hit && typeof hit === 'object' && typeof hit.value === 'string' && hit.value) return hit.value
      if (typeof hit === 'string' && hit) return hit
    } catch {
      // Credential store unavailable (headless/test contexts); fall through.
    }
    return process.env[ref] || null
  }

  async function login() {
    const username = await readSecret(usernameEnv)
    const password = await readSecret(passwordEnv)
    if (!username || !password) {
      throw new Error(
        `SSLManager is not authenticated: set the credential "${tokenRef}" ` +
          `(or ${usernameEnv}/${passwordEnv}) and retry.`,
      )
    }
    const body = new URLSearchParams({ username, password, grant_type: 'password' })
    const response = await fetch(`${baseUrl}/api/user/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    })
    if (!response.ok) throw new Error(`SSLManager login failed: HTTP ${response.status}`)
    const payload = await response.json()
    token = payload.access_token
    const ttlSeconds = Number(payload.expired_in) || 600
    tokenExpiresAt = Date.now() + Math.max(30, ttlSeconds - 30) * 1000
    return token
  }

  async function getToken(force = false) {
    if (!force && token && Date.now() < tokenExpiresAt) return token
    if (config.token) {
      token = String(config.token)
      tokenExpiresAt = Date.now() + 10 * 60 * 1000
      return token
    }
    const stored = await readSecret(tokenRef)
    if (stored) {
      token = stored
      tokenExpiresAt = Date.now() + 10 * 60 * 1000
      return token
    }
    return login()
  }

  async function request(path, { params, signal, retry = true, method = 'GET', body } = {}) {
    const url = new URL(`${baseUrl}${path}`)
    for (const [key, value] of Object.entries(params || {})) {
      if (value !== undefined && value !== null && value !== '') url.searchParams.set(key, String(value))
    }
    const bearer = await getToken()
    const headers = { authorization: `Bearer ${bearer}`, accept: 'application/json' }
    if (body !== undefined) headers['content-type'] = 'application/json'
    const response = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    })
    if (response.status === 401 && retry) {
      token = null
      return request(path, { params, signal, retry: false, method, body })
    }
    if (!response.ok) {
      const detail = (await response.text().catch(() => '')).slice(0, 300)
      throw new Error(`SSLManager ${path} failed: HTTP ${response.status} ${detail}`)
    }
    return response.json()
  }

  async function domains() {
    if (Date.now() - domainCache.at < 60_000) return domainCache
    const list = await request('/api/domain/option')
    const map = new Map(list.map((domain) => [domain.domain_id, domain]))
    domainCache = { at: Date.now(), map, list }
    return domainCache
  }

  return { request, domains, baseUrl }
}

/**
 * Days until `not_valid_after`, rounded down, or null when unparseable.
 *
 * @param {string|null|undefined} value - ISO timestamp from the API.
 */
function daysLeft(value) {
  if (!value) return null
  const at = Date.parse(value.endsWith('Z') || value.includes('+') ? value : `${value}Z`)
  if (Number.isNaN(at)) return null
  return Math.floor((at - Date.now()) / DAY_MS)
}

/**
 * Project one certificate row into the model-facing shape.
 *
 * @param {object} cert - Raw certificate from `/api/certificate/option`.
 * @param {Map<number, object>} domainMap - domain_id to domain row.
 */
function toCertificate(cert, domainMap) {
  const domain = domainMap.get(cert.domain_id)
  return {
    certId: cert.cert_id,
    domain: domain ? domain.domain_name : null,
    domainId: cert.domain_id,
    status: String(cert.status),
    notValidAfter: cert.not_valid_after || null,
    daysLeft: daysLeft(cert.not_valid_after),
    deployed: Boolean(cert.deployed),
    updatedAt: cert.updated_at || null,
  }
}

const certificateProperties = {
  certId: { type: 'integer' },
  // Nullable on purpose: a requested certificate has no expiry yet, and a
  // certificate whose domain row is gone has no name. The registry rejects
  // `type` arrays, so nullability is spelled as an exact-one oneOf.
  domain: { oneOf: [{ type: 'string' }, { type: 'null' }] },
  domainId: { type: 'integer' },
  status: { type: 'string' },
  notValidAfter: { oneOf: [{ type: 'string' }, { type: 'null' }] },
  daysLeft: { oneOf: [{ type: 'integer' }, { type: 'null' }] },
  deployed: { type: 'boolean' },
  updatedAt: { oneOf: [{ type: 'string' }, { type: 'null' }] },
}

const certificateSchema = {
  type: 'object',
  additionalProperties: false,
  properties: certificateProperties,
  required: ['certId', 'domainId', 'status', 'deployed'],
}

const summaryRender = (label) => (_args, value) => {
  const rows = value.items.map(
    (item) =>
      `- ${item.domain || `cert#${item.certId}`}: ${item.status}` +
      (item.daysLeft === null ? '' : `, ${item.daysLeft} day(s) left`) +
      (item.deployed ? ', deployed' : ', not deployed'),
  )
  return [{ type: 'text', text: rows.length ? `${label} (${rows.length}):\n${rows.join('\n')}` : `${label}: none.` }]
}

/**
 * Reject an SSLManager action envelope that reports `success: false`.
 *
 * @param {object} result - Parsed JSON body.
 */
function unwrap(result) {
  if (result && result.success === false) {
    throw new Error(result.message || 'SSLManager rejected the request')
  }
  return result
}

/**
 * Gate a state-changing tool: ask the deployment's approval service when one
 * exists (the Harness), otherwise require an explicit `confirm: true`
 * (MCP clients such as Codex have no approval UI).
 *
 * @returns {Promise<'approved' | 'confirmed'>} How the action was authorized.
 */
async function authorize(ctx, exec, { toolName, summary, confirm }) {
  const approval = optionalService(ctx, 'approval')
  if (approval && typeof approval.request === 'function') {
    if (!exec?.agent) throw new Error(`${toolName} needs an agent session to request approval; nothing changed.`)
    const outcome = await approval.request({
      agent: exec.agent,
      toolName,
      reason: summary,
      displayReason: summary,
      signal: exec.signal,
    })
    if (outcome !== 'allowed-once') {
      throw new Error(`${toolName} was not approved (${outcome}); nothing changed.`)
    }
    return 'approved'
  }
  if (confirm !== true) {
    throw new Error(
      `${toolName} changes live infrastructure and no approval UI is available here. ` +
        'Review the plan, then re-run with confirm: true.',
    )
  }
  return 'confirmed'
}

/**
 * Register the SSLManager read-only tools.
 *
 * @param {object} ctx - Cordis context carrying `tools` and, optionally, `credentials`.
 * @param {object} config - Row config.
 */
export function createTools(ctx, config = {}) {
  const client = createClient(ctx, config)
  const tools = []

  async function listCertificates(args, exec) {
    const [certs, domains] = await Promise.all([
      client.request('/api/certificate/option', { signal: exec?.signal }),
      client.domains(),
    ])
    const limit = Math.max(1, Math.min(Number(args.limit) || 50, 200))
    const keyword = args.keyword ? String(args.keyword).toLowerCase() : null
    return certs
      .map((cert) => toCertificate(cert, domains.map))
      .filter((cert) => (args.status ? cert.status === args.status : true))
      .filter((cert) => (keyword ? (cert.domain || '').toLowerCase().includes(keyword) : true))
      .filter((cert) =>
        typeof args.expiringWithinDays === 'number'
          ? cert.daysLeft !== null && cert.daysLeft <= args.expiringWithinDays
          : true,
      )
      .sort((a, b) => (a.daysLeft ?? Number.MAX_SAFE_INTEGER) - (b.daysLeft ?? Number.MAX_SAFE_INTEGER))
      .slice(0, limit)
  }

  tools.push(
    defineReadTool({
      name: 'ssl_cert_list',
      description:
        'List SSL certificates managed by SSLManager, with domain, status, expiry and deployment state. ' +
        'Read-only. Filter by status, by domain keyword, or to certificates expiring within N days.',
      parameters: {
        status: {
          type: 'string',
          description: 'Certificate status filter, e.g. active, pending, expired (as stored by SSLManager).',
        },
        keyword: { type: 'string', description: 'Case-insensitive domain substring filter.' },
        expiringWithinDays: {
          type: 'number',
          description: 'Only return certificates whose remaining lifetime is at most this many days.',
        },
        limit: { type: 'number', description: 'Maximum rows to return (default 50, max 200).' },
      },
      outputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: { items: { type: 'array', items: certificateSchema } },
        required: ['items'],
      },
      render: summaryRender('SSLManager certificates'),
      async execute(args, exec) {
        return { items: await listCertificates(args, exec) }
      },
    }),
  )

  tools.push(
    defineReadTool({
      name: 'ssl_cert_expiring',
      description:
        'List SSL certificates that expire within the next N days, soonest first. Read-only; ' +
        'use it for renewal triage before issuing or deploying anything.',
      parameters: {
        days: { type: 'number', description: 'Look-ahead window in days, e.g. 30.' },
        includeExpired: { type: 'boolean', description: 'Also include certificates already past expiry.' },
      },
      required: ['days'],
      outputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          days: { type: 'integer' },
          items: { type: 'array', items: certificateSchema },
        },
        required: ['days', 'items'],
      },
      render: (_args, value) => summaryRender(`Certificates expiring within ${value.days} day(s)`)({}, value),
      async execute(args, exec) {
        const days = Math.max(0, Number(args.days) || 30)
        const items = await listCertificates({ expiringWithinDays: days, limit: 200 }, exec)
        const filtered = args.includeExpired
          ? items
          : items.filter((item) => item.daysLeft === null || item.daysLeft >= 0)
        return { days, items: filtered }
      },
    }),
  )

  tools.push(
    defineReadTool({
      name: 'ssl_cert_get',
      description:
        'Get metadata for one SSLManager certificate by id: domain, status, expiry, deployment state, ' +
        'and the certificate/key file paths on the server. Never returns key material.',
      parameters: {
        certId: { type: 'integer', description: 'SSLManager certificate id.' },
      },
      required: ['certId'],
      outputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ...certificateProperties,
          certPath: { type: 'string' },
          keyPath: { type: 'string' },
          fullChainPath: { type: 'string' },
          issueLog: { type: 'string' },
        },
        required: ['certId', 'domainId', 'status', 'deployed'],
      },
      render: (_args, value) => [
        {
          type: 'text',
          text:
            `Certificate #${value.certId} (${value.domain || 'unknown domain'}): ${value.status}\n` +
            `Expires: ${value.notValidAfter || 'unknown'}` +
            (value.daysLeft === null ? '' : ` (${value.daysLeft} day(s) left)`) +
            `\nDeployed: ${value.deployed ? 'yes' : 'no'}\n` +
            `Files: cert=${value.certPath || '-'}, key=${value.keyPath || '-'}, chain=${value.fullChainPath || '-'}`,
        },
      ],
      async execute(args, exec) {
        // Read from the list endpoint on purpose: /api/certificate/{id} also
        // returns cert_content and key_content, which must never reach this
        // process at all.
        const [certs, domains] = await Promise.all([
          client.request('/api/certificate/option', { signal: exec?.signal }),
          client.domains(),
        ])
        const cert = certs.find((candidate) => candidate.cert_id === args.certId)
        if (!cert) throw new Error(`Certificate #${args.certId} not found.`)
        const summary = toCertificate(cert, domains.map)
        return {
          ...summary,
          certPath: cert.cert_path || undefined,
          keyPath: cert.key_path || undefined,
          fullChainPath: cert.full_chain_path || undefined,
          issueLog: cert.issue_log || undefined,
        }
      },
    }),
  )

  tools.push(
    defineReadTool({
      name: 'ssl_domain_list',
      description:
        'List domains tracked by SSLManager with their verification, certificate and deployment status. Read-only.',
      parameters: {
        status: { type: 'string', description: 'Verification status filter (as stored by SSLManager).' },
        limit: { type: 'number', description: 'Maximum rows to return (default 50, max 200).' },
      },
      outputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          items: {
            type: 'array',
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                domainId: { type: 'integer' },
                domainName: { type: 'string' },
                status: { type: 'string' },
                certStatus: { type: 'string' },
                deployStatus: { type: 'string' },
                expiredAt: { type: 'string' },
                certCount: { type: 'integer' },
              },
              required: ['domainId', 'domainName'],
            },
          },
        },
        required: ['items'],
      },
      render: (_args, value) => [
        {
          type: 'text',
          text: value.items.length
            ? value.items
                .map(
                  (domain) =>
                    `- ${domain.domainName}: verify=${domain.status || '?'}, cert=${domain.certStatus || '-'}, ` +
                    `deploy=${domain.deployStatus || '-'}, certs=${domain.certCount ?? 0}`,
                )
                .join('\n')
            : 'No domains.',
        },
      ],
      async execute(args, exec) {
        const domains = await client.domains()
        const limit = Math.max(1, Math.min(Number(args.limit) || 50, 200))
        const items = domains.list
          .filter((domain) => (args.status ? String(domain.status) === args.status : true))
          .slice(0, limit)
          .map((domain) => ({
            domainId: domain.domain_id,
            domainName: domain.domain_name,
            status: String(domain.status),
            certStatus: domain.cert_status ? String(domain.cert_status) : undefined,
            deployStatus: domain.deploy_status ? String(domain.deploy_status) : undefined,
            expiredAt: domain.expired_at || undefined,
            certCount: domain.cert_count ?? 0,
          }))
        return { items }
      },
    }),
  )

  tools.push(
    defineReadTool({
      name: 'ssl_probe',
      description:
        'Probe a public host live over TLS: chain validity, issuer, expiry, SANs and whether it is self-signed. ' +
        'Read-only and safe to call before deciding to issue or deploy.',
      parameters: {
        host: { type: 'string', description: 'Public hostname, e.g. api.example.com.' },
      },
      required: ['host'],
      outputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string' },
          subject: { type: 'string' },
          issuer: { type: 'string' },
          notAfter: { type: 'string' },
          daysLeft: { type: 'integer' },
          sans: { type: 'array', items: { type: 'string' } },
          selfSigned: { type: 'boolean' },
          error: { type: 'string' },
        },
        required: ['host'],
      },
      render: (_args, value) =>
        value.error
          ? [{ type: 'text', text: `TLS probe for ${value.host} failed: ${value.error}` }]
          : [
              {
                type: 'text',
                text:
                  `${value.host}: issuer=${value.issuer || '?'}, subject=${value.subject || '?'}, ` +
                  `expires=${value.notAfter || '?'}` +
                  (value.daysLeft === null ? '' : ` (${value.daysLeft} day(s) left)`) +
                  `, selfSigned=${value.selfSigned ? 'yes' : 'no'}`,
              },
            ],
      async execute(args, exec) {
        const host = String(args.host).trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '')
        const result = await client.request('/api/tools/ssl-check', { params: { host }, signal: exec?.signal })
        return {
          host,
          subject: result.subject,
          issuer: result.issuer,
          notAfter: result.not_after || result.notAfter,
          daysLeft: daysLeft(result.not_after || result.notAfter),
          sans: Array.isArray(result.sans) ? result.sans : [],
          selfSigned: Boolean(result.self_signed ?? result.selfSigned),
          error: result.error,
        }
      },
    }),
  )

  tools.push(
    defineReadTool({
      name: 'ssl_remote_list',
      description:
        'List deployment targets (remotes) configured in SSLManager with their host and certificate paths. ' +
        'Read-only. Use the returned remoteId with ssl_cert_deploy. Credentials are never returned.',
      parameters: {},
      outputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          items: {
            type: 'array',
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                remoteId: { type: 'integer' },
                name: { type: 'string' },
                host: { type: 'string' },
                port: { type: 'integer' },
                username: { type: 'string' },
                remoteCertPath: { type: 'string' },
                restartCommand: { type: 'string' },
              },
              required: ['remoteId', 'name', 'host'],
            },
          },
        },
        required: ['items'],
      },
      render: (_args, value) => [
        {
          type: 'text',
          text: value.items.length
            ? value.items
                .map(
                  (remote) =>
                    `- #${remote.remoteId} ${remote.name}: ${remote.username || '?'}@${remote.host}:${remote.port ?? 22}, ` +
                    `cert=${remote.remoteCertPath || '-'}`,
                )
                .join('\n')
            : 'No deployment targets.',
        },
      ],
      async execute(_args, exec) {
        const remotes = await client.request('/api/remote/option', { signal: exec?.signal })
        const items = remotes.map((remote) => ({
          remoteId: remote.remote_id,
          name: remote.name,
          host: remote.host,
          port: remote.port,
          username: remote.username,
          remoteCertPath: remote.remote_cert_path,
          restartCommand: remote.restart_command || undefined,
        }))
        return { items }
      },
    }),
  )

  async function findDomain(name, exec) {
    const wanted = String(name || '').trim().toLowerCase()
    const { list } = await client.domains()
    const domain = list.find((candidate) => candidate.domain_name.toLowerCase() === wanted)
    if (!domain) {
      throw new Error(
        `Domain "${name}" is not tracked by SSLManager. Known domains: ` +
          `${list.map((candidate) => candidate.domain_name).join(', ') || '(none)'}.`,
      )
    }
    return domain
  }

  tools.push(
    defineReadTool({
      name: 'ssl_domain_check',
      description:
        'Re-run SSLManager DNS verification for a tracked domain (checks the _acme-challenge CNAME and updates ' +
        'its verify status). Safe and idempotent; run it before ssl_cert_apply when a domain is unverified.',
      parameters: {
        domainName: { type: 'string', description: 'Tracked domain name, e.g. example.com.' },
      },
      required: ['domainName'],
      outputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          domainName: { type: 'string' },
          verified: { type: 'boolean' },
          message: { type: 'string' },
        },
        required: ['domainName', 'verified'],
      },
      render: (_args, value) => [
        {
          type: 'text',
          text: `${value.domainName}: ${value.verified ? 'verified' : 'not verified'}${value.message ? ` (${value.message})` : ''}`,
        },
      ],
      async execute(args, exec) {
        const domain = await findDomain(args.domainName, exec)
        const result = await client.request('/api/domain/check', {
          method: 'POST',
          body: { domain_name: domain.domain_name },
          signal: exec?.signal,
        })
        return {
          domainName: domain.domain_name,
          verified: result.success !== false,
          message: result.message || undefined,
        }
      },
    }),
  )

  tools.push(
    defineReadTool({
      name: 'ssl_cert_apply',
      description:
        'Issue (or renew, which is a fresh issuance) an SSL certificate for a tracked domain through SSLManager/ACME. ' +
        'CHANGES STATE: it spends an issuance attempt, creates a certificate record and runs in the background. ' +
        'Requires approval; poll the result with ssl_cert_status.',
      parameters: {
        domainName: { type: 'string', description: 'Tracked, verified domain name, e.g. example.com.' },
        reason: { type: 'string', description: 'Why this issuance is needed; shown in the approval prompt.' },
        confirm: {
          type: 'boolean',
          description: 'Only for deployments without an approval UI (MCP): must be true to execute.',
        },
      },
      required: ['domainName'],
      outputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          domainName: { type: 'string' },
          domainId: { type: 'integer' },
          accepted: { type: 'boolean' },
          message: { type: 'string' },
          authorization: { type: 'string' },
        },
        required: ['domainName', 'domainId', 'accepted'],
      },
      render: (_args, value) => [
        {
          type: 'text',
          text:
            `Issuance started for ${value.domainName} (certificate record created). ` +
            `Poll with ssl_cert_status; ACME validation usually takes a minute or two.`,
        },
      ],
      async execute(args, exec) {
        const domain = await findDomain(args.domainName, exec)
        if (String(domain.status) !== 'verified') {
          throw new Error(
            `Domain ${domain.domain_name} is not verified (status: ${domain.status}). ` +
              'Run ssl_domain_check first and make sure the _acme-challenge CNAME is in place.',
          )
        }
        const summary =
          `Issue an SSL certificate for ${domain.domain_name} via ACME` +
          (args.reason ? ` — ${args.reason}` : '')
        const authorization = await authorize(ctx, exec, {
          toolName: 'ssl_cert_apply',
          summary,
          confirm: args.confirm,
        })
        const result = unwrap(
          await client.request('/api/certificate/apply', {
            method: 'POST',
            body: { domain_name: domain.domain_name },
            signal: exec?.signal,
          }),
        )
        return {
          domainName: domain.domain_name,
          domainId: domain.domain_id,
          accepted: result.success !== false,
          message: result.message || 'issuance queued',
          authorization,
        }
      },
    }),
  )

  tools.push(
    defineReadTool({
      name: 'ssl_cert_status',
      description:
        'Read the current issuance state for a domain (the certificate SSLManager attached to it). ' +
        'Read-only. Use it to poll after ssl_cert_apply; never returns key material.',
      parameters: {
        domainName: { type: 'string', description: 'Tracked domain name.' },
      },
      required: ['domainName'],
      outputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ...certificateProperties,
          issueLog: { type: 'string' },
        },
        required: ['certId', 'domainId', 'status', 'deployed'],
      },
      render: (_args, value) => [
        {
          type: 'text',
          text:
            `${value.domain || `cert#${value.certId}`}: ${value.status}` +
            (value.notValidAfter ? `, expires ${value.notValidAfter}` : '') +
            (value.daysLeft === null ? '' : ` (${value.daysLeft} day(s) left)`) +
            `, ${value.deployed ? 'deployed' : 'not deployed'}` +
            (value.issueLog ? `\nissue log: ${value.issueLog}` : ''),
        },
      ],
      async execute(args, exec) {
        const domain = await findDomain(args.domainName, exec)
        const result = await client.request('/api/certificate/status', {
          method: 'POST',
          body: { domain_name: domain.domain_name },
          signal: exec?.signal,
        })
        if (result.success === false) throw new Error(result.message || 'No certificate for this domain')
        const cert = result.data
        if (!cert) throw new Error(`No certificate has been issued for ${domain.domain_name} yet.`)
        const { map } = await client.domains()
        return { ...toCertificate(cert, map), issueLog: cert.issue_log || undefined }
      },
    }),
  )

  tools.push(
    defineReadTool({
      name: 'ssl_cert_deploy',
      description:
        'Deploy a domain\'s current certificate to a configured remote over SSH and run its reload command. ' +
        'CHANGES LIVE SERVERS: the call blocks until SSLManager finishes the deployment. Requires approval; ' +
        'check the target with ssl_remote_list first.',
      parameters: {
        domainName: { type: 'string', description: 'Tracked domain whose current certificate should be deployed.' },
        remoteId: { type: 'integer', description: 'Deployment target id from ssl_remote_list.' },
        reason: { type: 'string', description: 'Why this deployment is needed; shown in the approval prompt.' },
        confirm: {
          type: 'boolean',
          description: 'Only for deployments without an approval UI (MCP): must be true to execute.',
        },
      },
      required: ['domainName', 'remoteId'],
      outputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          domainName: { type: 'string' },
          remoteId: { type: 'integer' },
          remoteName: { type: 'string' },
          deployed: { type: 'boolean' },
          message: { type: 'string' },
          authorization: { type: 'string' },
        },
        required: ['domainName', 'remoteId', 'deployed'],
      },
      render: (_args, value) => [
        {
          type: 'text',
          text:
            `Deployment to ${value.remoteName || `remote #${value.remoteId}`} ` +
            `${value.deployed ? 'succeeded' : 'failed'}${value.message ? `: ${value.message}` : '.'}`,
        },
      ],
      async execute(args, exec) {
        const domain = await findDomain(args.domainName, exec)
        const remotes = await client.request('/api/remote/option', { signal: exec?.signal })
        const remote = remotes.find((candidate) => candidate.remote_id === args.remoteId)
        if (!remote) {
          throw new Error(
            `Remote #${args.remoteId} is not configured. Available targets: ` +
              `${remotes.map((candidate) => `#${candidate.remote_id} ${candidate.name}`).join(', ') || '(none)'}.`,
          )
        }
        const summary =
          `Deploy the ${domain.domain_name} certificate to ${remote.name} (${remote.host})` +
          (args.reason ? ` — ${args.reason}` : '')
        const authorization = await authorize(ctx, exec, {
          toolName: 'ssl_cert_deploy',
          summary,
          confirm: args.confirm,
        })
        const result = unwrap(
          await client.request('/api/certificate/deploy', {
            method: 'POST',
            body: { domain_name: domain.domain_name, remote_id: args.remoteId },
            signal: exec?.signal,
          }),
        )
        return {
          domainName: domain.domain_name,
          remoteId: args.remoteId,
          remoteName: remote.name,
          deployed: result.success !== false,
          message: result.message || undefined,
          authorization,
        }
      },
    }),
  )

  tools.push(
    defineReadTool({
      name: 'ssl_cert_revoke',
      description:
        'Revoke a domain\'s current certificate at the CA. IRREVERSIBLE: browsers will reject the certificate ' +
        'once the CA publishes the revocation, so only do this for a compromised or mis-issued certificate, ' +
        'and issue a replacement immediately after. Requires approval.',
      parameters: {
        domainName: { type: 'string', description: 'Tracked domain whose current certificate should be revoked.' },
        reason: { type: 'string', description: 'Why the certificate must be revoked; shown in the approval prompt.' },
        confirm: {
          type: 'boolean',
          description: 'Only for deployments without an approval UI (MCP): must be true to execute.',
        },
      },
      required: ['domainName'],
      outputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          domainName: { type: 'string' },
          revoked: { type: 'boolean' },
          message: { type: 'string' },
          authorization: { type: 'string' },
        },
        required: ['domainName', 'revoked'],
      },
      render: (_args, value) => [
        {
          type: 'text',
          text:
            `${value.domainName}: certificate ${value.revoked ? 'revoked' : 'was NOT revoked'}` +
            (value.message ? ` — ${value.message}` : '') +
            '. Issue a replacement certificate before serving traffic again.',
        },
      ],
      async execute(args, exec) {
        const domain = await findDomain(args.domainName, exec)
        const certs = await client.request('/api/certificate/option', { signal: exec?.signal })
        const latest = certs
          .filter((candidate) => candidate.domain_id === domain.domain_id)
          .pop()
        if (!latest) throw new Error(`No certificate has been issued for ${domain.domain_name}.`)
        if (String(latest.status) === 'revoked') {
          throw new Error(`The certificate for ${domain.domain_name} is already revoked.`)
        }
        const summary =
          `Revoke the certificate for ${domain.domain_name} at the CA (irreversible)` +
          (args.reason ? ` — ${args.reason}` : '')
        const authorization = await authorize(ctx, exec, {
          toolName: 'ssl_cert_revoke',
          summary,
          confirm: args.confirm,
        })
        const result = unwrap(
          await client.request('/api/certificate/revoke', {
            method: 'POST',
            body: { domain_name: domain.domain_name },
            signal: exec?.signal,
          }),
        )
        return {
          domainName: domain.domain_name,
          revoked: result.success !== false,
          message: result.message || undefined,
          authorization,
        }
      },
    }),
  )

  return tools
}

/**
 * Register the SSLManager read-only tools on a Cordis context.
 *
 * @param {object} ctx - Cordis context carrying `tools` and, optionally, `credentials`.
 * @param {object} config - Row config.
 */
export function apply(ctx, config = {}) {
  for (const tool of createTools(ctx, config)) ctx.tools.register(tool)

  // Dashboard feed for the Web Client panel. An exact route beats the /api
  // prefix, and connection.admit() applies the same browser-cookie check the
  // rest of the API bridge uses, so the endpoint is never public.
  ctx.inject(['webServer', 'connection'], (web) => {
    web.effect(
      () =>
        web.webServer.register({
          kind: 'exact',
          path: '/api/sslmanager/expiring',
          handler: async (request, response) => {
            const admission = web.connection.admit(request)
            if ('rejection' in admission) {
              response.writeHead(admission.rejection)
              response.end()
              return
            }
            if (request.method !== 'GET') {
              response.writeHead(405, { allow: 'GET' })
              response.end()
              return
            }
            try {
              const url = new URL(request.url || '/', 'http://localhost')
              const days = Math.max(1, Math.min(Number(url.searchParams.get('days')) || 45, 365))
              const client = createClient(ctx, config)
              const [certs, domains] = await Promise.all([
                client.request('/api/certificate/option'),
                client.domains(),
              ])
              const items = certs
                .map((cert) => toCertificate(cert, domains.map))
                .filter((cert) => cert.daysLeft !== null && cert.daysLeft <= days)
                .sort((a, b) => a.daysLeft - b.daysLeft)
                .slice(0, 50)
              response.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
              response.end(JSON.stringify({ generatedAt: new Date().toISOString(), days, items }))
            } catch (error) {
              response.writeHead(502, { 'content-type': 'application/json; charset=utf-8' })
              response.end(JSON.stringify({ error: String(error?.message || error) }))
            }
          },
        }),
      'sslmanager: expiring feed route',
    )
  })
}
