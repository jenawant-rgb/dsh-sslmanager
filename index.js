/**
 * DeepSeek Harness entry: registers the tools and the Web Client routes.
 *
 * @module @sslmanager/dsh-sslmanager
 */
import {
  DEFAULT_BASE_URL,
  createClient,
  createTools,
  optionalService,
  toCertificate,
} from './core.js'

export { createTools } from './core.js'

/**
 * Read a small JSON request body from a Node HTTP request.
 *
 * @param {object} request - node:http request.
 * @param {number} [limit] - maximum accepted bytes.
 */
function readJsonBody(request, limit = 8192) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    request.on('data', (chunk) => {
      size += chunk.length
      if (size > limit) {
        request.destroy()
        reject(new Error('request body too large'))
        return
      }
      chunks.push(chunk)
    })
    request.on('end', () => {
      try {
        resolve(chunks.length === 0 ? {} : JSON.parse(Buffer.concat(chunks).toString('utf8')))
      } catch {
        reject(new Error('invalid JSON body'))
      }
    })
    request.on('error', reject)
  })
}

/**
 * Register the Web Client routes: the expiry feed and the token setup form.
 *
 * Both are exact routes with the same browser-cookie admission as the rest of
 * the API bridge, so neither is publicly readable. The token route validates
 * the credential against SSLManager before storing it in the DSH credential
 * store, and never echoes it back.
 *
 * @param {object} ctx - Cordis context carrying `webServer`, `connection` and `credentials`.
 * @param {object} config - Row config.
 */
export function registerDashboardRoutes(ctx, config = {}) {
  ctx.inject(['webServer', 'connection'], (web) => {
    const baseUrl = String(config.baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, '')

    const admit = (request, response) => {
      const admission = web.connection.admit(request)
      if ('rejection' in admission) {
        response.writeHead(admission.rejection)
        response.end()
        return false
      }
      return true
    }

    const json = (response, status, payload) => {
      response.writeHead(status, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
      })
      response.end(JSON.stringify(payload))
    }

    web.effect(
      () =>
        web.webServer.register({
          kind: 'exact',
          path: '/api/sslmanager/expiring',
          handler: async (request, response) => {
            if (!admit(request, response)) return
            if (request.method !== 'GET') {
              response.writeHead(405, { allow: 'GET' })
              response.end()
              return
            }
            try {
              const url = new URL(request.url || '/', 'http://localhost')
              const days = Math.max(1, Math.min(Number(url.searchParams.get('days')) || 45, 365))
              const client = createClient(web, config)
              const [certs, domains] = await Promise.all([
                client.request('/api/certificate/option'),
                client.domains(),
              ])
              const items = certs
                .map((cert) => toCertificate(cert, domains.map))
                .filter((cert) => cert.daysLeft !== null && cert.daysLeft <= days)
                .sort((a, b) => a.daysLeft - b.daysLeft)
                .slice(0, 50)
              json(response, 200, { configured: true, generatedAt: new Date().toISOString(), days, items })
            } catch (error) {
              const message = String(error?.message || error)
              if (message.includes('not authenticated')) {
                json(response, 200, { configured: false, error: message, items: [], days: 45 })
                return
              }
              json(response, 502, { configured: true, error: message })
            }
          },
        }),
      'sslmanager: expiring feed route',
    )

    web.effect(
      () =>
        web.webServer.register({
          kind: 'exact',
          path: '/api/sslmanager/token',
          handler: async (request, response) => {
            if (!admit(request, response)) return
            if (request.method !== 'POST') {
              response.writeHead(405, { allow: 'POST' })
              response.end()
              return
            }
            let body
            try {
              body = await readJsonBody(request)
            } catch (error) {
              json(response, 400, { error: String(error.message || error) })
              return
            }
            const token = String(body.token || '').trim()
            if (!/^ssm_[A-Za-z0-9_-]{16,}$/.test(token)) {
              json(response, 400, { error: 'Invalid token format: expected an ssm_… personal access token' })
              return
            }

            try {
              const check = await fetch(`${baseUrl}/api/certificate/option`, {
                headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
              })
              if (check.status === 401) {
                json(response, 400, { error: 'The token was rejected: invalid, expired or revoked' })
                return
              }
              if (check.status === 403) {
                json(response, 400, { error: 'The token is valid but lacks the cert:read scope' })
                return
              }
              if (!check.ok) {
                json(response, 502, { error: `SSLManager answered HTTP ${check.status}` })
                return
              }

              const credentials = optionalService(web, 'credentials')
              if (!credentials || typeof credentials.set !== 'function') {
                json(response, 501, { error: 'The DSH credential store is not available in this profile' })
                return
              }
              await credentials.set(String(config.tokenRef || 'SSLMGR_TOKEN'), token)
              json(response, 200, { ok: true, baseUrl })
            } catch (error) {
              json(response, 502, { error: String(error?.message || error) })
            }
          },
        }),
      'sslmanager: token setup route',
    )
  })
}

/**
 * Register the SSLManager tools and the Web Client routes.
 *
 * @param {object} ctx - Cordis context.
 * @param {object} config - Row config.
 */
export function apply(ctx, config = {}) {
  for (const tool of createTools(ctx, config)) ctx.tools.register(tool)
  registerDashboardRoutes(ctx, config)
}
