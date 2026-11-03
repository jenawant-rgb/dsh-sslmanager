# SSLManager agent plugin

Certificate tools for the DeepSeek Harness (native plugin) and for any MCP
client such as Codex. One implementation, two entry points:

```
index.js            native DSH plugin — registers 10 tools on ctx.tools
mcp/server.mjs      stdio MCP server wrapping the same tool set
cordis.patch.yml    DSH bundle patch (the plugin row + config)
.codex-plugin/      Codex plugin manifest (skills + .mcp.json)
dev/                mock SSLManager API + harnesses, no network needed
```

## Tools

Read-only:

| Tool | Purpose |
|---|---|
| `ssl_cert_list` | Certificates with domain, status, expiry, deployment state |
| `ssl_cert_expiring` | What expires within N days, soonest first |
| `ssl_cert_get` | One certificate's metadata and server-side file paths |
| `ssl_cert_status` | Current certificate for a domain (poll after apply) |
| `ssl_domain_list` | Tracked domains and their verify/cert/deploy status |
| `ssl_remote_list` | Deployment targets with host and certificate paths |
| `ssl_probe` | Live TLS probe of a host (issuer, expiry, SANs, self-signed) |

State-changing:

| Tool | Effect | Endpoint |
|---|---|---|
| `ssl_cert_apply` | Issue a certificate (also how renewal works) | `POST /api/certificate/apply` |
| `ssl_cert_deploy` | Push the current certificate to a remote over SSH + reload | `POST /api/certificate/deploy` |
| `ssl_cert_revoke` | Revoke the certificate at the CA (irreversible) | `POST /api/certificate/revoke` |
| `ssl_domain_check` | Re-run DNS verification for a tracked domain | `POST /api/domain/check` |

No tool returns `key_content`/`cert_content` or remote credentials; the
projections in `toCertificate()` / `ssl_remote_list` drop them defensively.

## Approval model

Every state-changing tool goes through `authorize()`:

1. **Harness (approval UI available)** — calls `ctx.approval.request()` with a
   one-line summary (`Issue an SSL certificate for example.com — expires in 9
   days`). Only `allowed-once` proceeds; `rejected`, `cancelled` and
   `unavailable` abort without touching the API. The request and outcome are
   written to the session audit log.
2. **MCP / headless (no approval UI)** — the call is refused unless it carries
   `confirm: true`. A model can still set that flag, but the refusal message
   makes the deliberate step visible in the transcript.

`ssl_cert_apply` also pre-checks that the domain exists and is `verified`, and
fails with the list of known domains otherwise. `ssl_cert_deploy` checks the
remote id against `ssl_remote_list` before asking for approval.

## Authentication

Preferred: a scoped personal access token created in SSLManager
(`POST /api/token/`, scopes `cert:read cert:write domain:read deploy:read
deploy:write`). Resolved in this order:

1. `config.token` — development only, never commit.
2. The DSH credential store entry named by `config.tokenRef` (default `SSLMGR_TOKEN`).
3. The environment variable of the same name.
4. Username/password login against `/api/user/token`, reading
   `SSLMGR_USERNAME` / `SSLMGR_PASSWORD` (configurable through
   `usernameEnv` / `passwordEnv`).

A 401 invalidates the cached token and retries once. PATs are pinned to the
routes and scopes the server allows: they cannot reach `/api/user`,
`/api/admin` or `/api/token`, and a write tool without its scope fails 403.

## DSH install

```bash
dsh plugin --profile <name> add /path/to/agent/dsh-sslmanager
# then select the bundle in the profile manifest:
#   dsh.profile.bundles += "@sslmanager/dsh-sslmanager"
```

The row config lives in `cordis.patch.yml`:

```yaml
- insert:
    - id: sslmanager
      name: '@sslmanager/dsh-sslmanager'
      config:
        baseUrl: http://127.0.0.1:8030
        tokenRef: SSLMGR_TOKEN
```

The module intentionally imports nothing at runtime: a `link:`ed install
resolves from the checkout directory, where Harness packages such as
`@deepseek-ai/dsh-tools` are not visible. Tool definitions are plain registry
definitions with standard JSON Schema.

## Codex install

```bash
cp -R /path/to/agent/dsh-sslmanager ~/codex-plugins/sslmanager
# ~/.codex/config.toml: [features] plugins = true
```

`.mcp.json` launches `node ./mcp/server.mjs`; export `SSLMGR_BASE_URL` and
`SSLMGR_TOKEN` in the environment Codex runs in.

## Local development

```bash
python3 dev/mock_sslmanager.py 8030 &   # fake API: certs, domains, remotes, writes
node dev/harness.mjs                     # all 10 tools, approval allow/reject/absent, leak checks
node dev/mcp-test.mjs                    # JSON-RPC handshake, read + confirm-gated write
```

## Not done yet (next steps)

- Token management UI in the console (the API exists; curl/Settings today).
- Audit trail of who called what, independent of the Harness session log.
- DSH client panel: expiring certificates by severity.
- Scoped API tokens in SSLManager instead of username/password login.
- `ssl_cert_deploy` is synchronous and can outlast a default tool timeout on a
  slow SSH target.
