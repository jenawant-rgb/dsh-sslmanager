# dsh-sslmanager

**SSL certificates for your coding agent.** See what is about to expire, issue a
replacement, push it to every server, and revoke a leaked one — from the chat,
with every state-changing call gated by an approval prompt.

Backed by [SetHttps](https://sethttps.com): Let's Encrypt wildcard certificates
over DNS-01, deployed to your own servers.

[![Website](https://img.shields.io/badge/website-sethttps.com-22d3ee.svg)](https://sethttps.com)
[![DeepSeek Harness](https://img.shields.io/badge/DeepSeek%20Harness-plugin-8b5cf6.svg)](https://sethttps.com/guide.html)
[![MCP](https://img.shields.io/badge/MCP-stdio-34d399.svg)](https://modelcontextprotocol.io)
[![License](https://img.shields.io/badge/license-MIT-3b82f6.svg)](LICENSE)

One implementation, two entry points:

```
index.js            native DSH plugin — registers 11 tools on ctx.tools
client.js           Web Client dock panel: certificates expiring soon
mcp/server.mjs      stdio MCP server wrapping the same tool set
cordis.patch.yml    DSH bundle patch (the plugin row + config)
.codex-plugin/      Codex plugin manifest (skills + .mcp.json)
dev/                mock SSLManager API + harnesses, no network needed
```

## Why this exists

Certificate expiry is the one failure in a normal web stack that is **silent
until it is total**: nothing degrades, nothing warns, and then every browser
refuses to connect at once.

An agent that already reads your repo and your logs is a good place to notice
that. But noticing is not fixing — so this plugin also lets it write, to a CA and
to live servers, and nothing else:

- reads are free and safe
- writes always ask a human first
- no tool ever returns private key material or server credentials

## What it looks like

```
you ▸ what's expiring this month?

     ssl_cert_expiring(days: 30)
     ▸ api.example.com    9 days left   deployed
       shop.example.com  21 days left   deployed
       legacy.example.com 34 days       not deployed

you ▸ renew api.example.com and ship it to the sg node

     ssl_cert_apply(domainName: "api.example.com")
     ⏸ issue a certificate for api.example.com — current one expires in 9 days
       [approve] [reject]

     ssl_cert_deploy(domainName: "api.example.com", remoteId: 3)
     ⏸ deploy api.example.com to edge-sg-01 (203.0.113.10) and reload
       [approve] [reject]
     ▸ uploaded, reloaded, live certificate matches the new serial
```

## Install

### DeepSeek Harness (native plugin)

```bash
# from the repository
dsh plugin --profile <name> add github:jenawant-rgb/dsh-sslmanager
# or from a local checkout
dsh plugin --profile <name> add /path/to/dsh-sslmanager
# then select the bundle in the profile manifest:
#   dsh.profile.bundles += "@sslmanager/dsh-sslmanager"
```

The plugin panel accepts the same `github:` spec.

The row config lives in [`cordis.patch.yml`](cordis.patch.yml):

```yaml
- insert:
    - id: sslmanager
      name: '@sslmanager/dsh-sslmanager'
      config:
        baseUrl: https://sethttps.com     # or http://127.0.0.1:8030 for a local server
        tokenRef: SSLMGR_TOKEN
```

### Any MCP client (Codex, Claude Code, …)

```bash
cp -R dsh-sslmanager ~/codex-plugins/sslmanager
# ~/.codex/config.toml: [features] plugins = true
```

[`.mcp.json`](.mcp.json) launches `node ./mcp/server.mjs`. Export the
configuration in the environment the client runs in:

```bash
export SSLMGR_BASE_URL=https://sethttps.com
export SSLMGR_TOKEN=<your token>
```

## Configuration

| Key | Default | Meaning |
| --- | --- | --- |
| `baseUrl` | `http://127.0.0.1:8030` | SSLManager API root. Use `https://sethttps.com` for the hosted service |
| `tokenRef` | `SSLMGR_TOKEN` | Credential-store entry (or env var) holding the token |
| `usernameEnv` / `passwordEnv` | `SSLMGR_USERNAME` / `SSLMGR_PASSWORD` | Fallback login, only used when no token is present |

### Getting a token

Create a scoped personal access token on the console's **访问令牌** (`/token`)
page, or mint one from the API. The login endpoint is OAuth2 password form
encoded, not JSON:

```bash
# 1. log in once to get a short-lived token
LOGIN=$(curl -s -X POST https://sethttps.com/api/user/token \
  -d 'username=you@example.com' -d 'password=…' | jq -r .access_token)

# 2. create a scoped token for the agent
curl -s -X POST https://sethttps.com/api/token/ \
  -H "Authorization: Bearer $LOGIN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"dsh","scopes":["cert:read","cert:write","domain:read","deploy:read","deploy:write"],"expires_in_days":90}'
```

PATs are pinned to the routes and scopes the server allows: they cannot reach
`/api/user`, `/api/admin` or `/api/token`, and a write tool without its scope
fails with 403.

Resolution order, first hit wins:

1. `config.token` — development only, never commit it
2. the credential-store entry named by `config.tokenRef` (default `SSLMGR_TOKEN`)
3. that same name as an environment variable
4. username / password login against `/api/user/token` (read from `SSLMGR_USERNAME` / `SSLMGR_PASSWORD`)

A 401 invalidates the cached token and retries once.

### Entering the token

The dock panel above the composer is also the setup form: click **设置 → 填入令牌**
(or it opens by itself when no credential is stored), paste the `ssm_…` value and
save. The browser posts it to the Harness host, which validates it against
SSLManager and writes it to the credential store under `SSLMGR_TOKEN`; the value
is never echoed back or added to the conversation.

Editing `~/.dsh/.credentials.yaml` by hand still works:

```yaml
refs:
  SSLMGR_TOKEN: ssm_…
```

The panel only appears after a restart, because Web Client modules are composed
when the Harness boots. The tools are available immediately.

## Tools

**Read-only** — safe to call at any time:

| Tool | Purpose |
| --- | --- |
| `ssl_cert_list` | Certificates with domain, status, expiry, deployment state |
| `ssl_cert_expiring` | What expires within N days, soonest first |
| `ssl_cert_get` | One certificate's metadata and server-side file paths |
| `ssl_cert_status` | Current certificate for a domain (poll after apply) |
| `ssl_domain_list` | Tracked domains and their verify / cert / deploy status |
| `ssl_remote_list` | Deployment targets with host and certificate paths |
| `ssl_probe` | Live TLS probe of any host (issuer, expiry, SANs, self-signed) |

**State-changing** — always behind an approval:

| Tool | Effect | Endpoint |
| --- | --- | --- |
| `ssl_cert_apply` | Issue a certificate (renewal is a fresh issuance) | `POST /api/certificate/apply` |
| `ssl_cert_deploy` | Push the current certificate over SFTP + trigger reload | `POST /api/certificate/deploy` |
| `ssl_cert_revoke` | Revoke at the CA — irreversible | `POST /api/certificate/revoke` |
| `ssl_domain_check` | Re-run DNS (`_acme-challenge`) verification | `POST /api/domain/check` |

No tool returns `key_content`, `cert_content` or remote credentials; the
projections in `toCertificate()` and `ssl_remote_list` drop them defensively.

## Safety model

Every state-changing tool goes through `authorize()`:

1. **Harness (approval UI available)** — `ctx.approval.request()` with a one-line
   summary (`Issue an SSL certificate for example.com — expires in 9 days`).
   Only `allowed-once` proceeds; `rejected`, `cancelled` and `unavailable` abort
   before touching the API. Request and outcome land in the session audit log.
2. **MCP / headless (no approval UI)** — the call is refused unless it carries
   `confirm: true`. A model can still set that flag, but the refusal message makes
   the deliberate step visible in the transcript.

`ssl_cert_apply` pre-checks that the domain exists and is `verified`, and fails
with the list of known domains otherwise. `ssl_cert_deploy` checks the remote id
against `ssl_remote_list` before asking for approval.

## Web Client panel

`client.js` registers into `conversation.input.dock`: a compact strip above the
composer showing how many certificates expire within 45 days, expanding into a
list with per-certificate days left and deployment state. It refreshes every
10 minutes.

Data comes from an exact `GET /api/sslmanager/expiring` route registered by the
host plugin. The handler calls `connection.admit(request)` first, so the endpoint
uses the same browser-cookie authentication as the rest of the API bridge and is
never publicly readable.

## Local development

```bash
python3 dev/mock_sslmanager.py 8030 &   # fake API: certs, domains, remotes, writes
node dev/harness.mjs                     # all 11 tools, approval allow/reject/absent, leak checks
node dev/mcp-test.mjs                    # JSON-RPC handshake, read + confirm-gated write
```

The module intentionally imports nothing at runtime: a `link:`ed install resolves
from the checkout directory, where Harness packages such as `@deepseek-ai/dsh-tools`
are not visible. Tool definitions are plain registry definitions with standard
JSON Schema.

## Roadmap

- Audit trail of who called what, independent of the Harness session log
- Per-certificate severity in the client panel, not just a count
- `ssl_cert_deploy` is synchronous and can outlast a default tool timeout on a
  slow SSH target — move it to a job with progress
- The console page for tokens lives in the SSLManager front end (`/token`), not
  in this repository

## Links

| | |
| --- | --- |
| Hosted service | https://sethttps.com |
| Docs — quickstart, DNS, Nginx, panels | https://sethttps.com/guide.html |
| The script that runs on your server (open source) | https://github.com/jenawant-rgb/sethttps-agent |
| Free tools, no account | [SSL expiry check](https://sethttps.com/ssl-check.html) · [CNAME check](https://sethttps.com/cname-check.html) |

## License

MIT — see [LICENSE](LICENSE).

---

## 中文说明

**给编码助手用的 SSL 证书工具。** 在对话里查看哪些证书快到期、签发、推送到服务器、吊销泄露的证书，
所有写操作都会先弹审批。

数据来自 [SetHttps](https://sethttps.com)：Let's Encrypt 泛域名证书，一条 CNAME 过 DNS-01，
签发后自动分发到你自己的服务器，到期前自动续期。

- 读操作（7 个工具）随时可用：证书列表、到期筛选、单张详情、DNS 验证状态、部署节点、实时 TLS 探测
- 写操作（4 个工具）必须审批：签发、部署、吊销、重新验证
- 不返回私钥、不返回服务器密码；Token 只能访问证书相关路由

安装与配置见上方英文部分。本地调试不需要联网：

```bash
python3 dev/mock_sslmanager.py 8030 &
node dev/harness.mjs
```

文档：https://sethttps.com/guide.html ｜ 服务器端脚本（已开源）：https://github.com/jenawant-rgb/sethttps-agent
