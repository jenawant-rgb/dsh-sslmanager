// Exercises the two Web Client routes without a Harness: the fake web server
// captures the handlers, the fake connection admits every request, and the
// fake credential store records what the token route writes.
//
//   python3 dev/mock_sslmanager.py 8030 &
//   node dev/route-test.mjs
import { Readable } from 'node:stream'
import { registerDashboardRoutes } from '../index.js'

const routes = []
const written = []

const web = {
  webServer: {
    register: (route) => {
      routes.push(route)
      return () => {}
    },
  },
  connection: { admit: () => ({ peer: { id: 'test' } }) },
  credentials: {
    // Pretend a token is already stored so the feed renders the ready state.
    resolve: async (key) => (key === 'SSLMGR_TOKEN' ? { value: 'mock-token', source: 'file' } : undefined),
    set: async (key, value) => {
      written.push([key, value])
    },
  },
  effect: (fn) => {
    fn()
    return () => {}
  },
}

registerDashboardRoutes({ inject: (_names, cb) => cb(web) }, {
  baseUrl: process.env.SSLMGR_BASE_URL || 'http://127.0.0.1:8030',
  tokenRef: 'SSLMGR_TOKEN',
})

function call(path, { method = 'GET', body } = {}) {
  const route = routes.find((candidate) => candidate.path === path.split('?')[0])
  if (!route) throw new Error(`route ${path} not registered`)
  const request = Readable.from(body === undefined ? [] : [Buffer.from(JSON.stringify(body))])
  request.method = method
  request.url = path
  request.headers = { 'content-type': 'application/json' }
  request.destroy = () => {}
  return new Promise((resolve) => {
    const response = {
      status: 0,
      headers: {},
      payload: '',
      writeHead(status, headers) {
        this.status = status
        this.headers = headers || {}
      },
      end(chunk) {
        this.payload = chunk ? String(chunk) : ''
        resolve({ status: this.status, body: JSON.parse(this.payload || '{}') })
      },
    }
    route.handler(request, response)
  })
}

const failures = []
const check = (condition, message) => {
  if (!condition) failures.push(message)
}

const feed = await call('/api/sslmanager/expiring?days=45')
check(feed.status === 200, `feed status ${feed.status}`)
check(feed.body.configured === true, 'feed should report configured')
check(Array.isArray(feed.body.items), 'feed items should be an array')
console.log('feed:', feed.status, 'configured:', feed.body.configured, 'items:', feed.body.items.length)

const badFormat = await call('/api/sslmanager/token', { method: 'POST', body: { token: 'nope' } })
check(badFormat.status === 400, `bad format should be 400, got ${badFormat.status}`)
console.log('bad format:', badFormat.status, badFormat.body.error)

const good = await call('/api/sslmanager/token', {
  method: 'POST',
  body: { token: 'ssm_test_token_1234567890abcdef' },
})
check(good.status === 200, `valid token should be 200, got ${good.status} ${good.body.error || ''}`)
check(written.length === 1 && written[0][0] === 'SSLMGR_TOKEN', 'credential must be written once')
check(!JSON.stringify(good.body).includes('ssm_'), 'response must not echo the token')
console.log('save:', good.status, good.body.ok === true, 'stored key:', written[0]?.[0])

const wrongMethod = await call('/api/sslmanager/token', { method: 'GET' })
check(wrongMethod.status === 405, `GET should be 405, got ${wrongMethod.status}`)

console.log(failures.length ? `FAIL: ${failures.join('; ')}` : 'OK')
process.exit(failures.length ? 1 : 0)
