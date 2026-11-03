---
name: sslmanager
description: Use when asked about SSL/TLS certificates managed by SSLManager — inventory, expiry, domains, live TLS state, issuing a certificate, or deploying one to a server.
---

# SSLManager certificates

The `sslmanager` MCP server exposes read tools plus three state-changing tools
over the SSLManager API.

| Tool | Use it for |
|---|---|
| `ssl_cert_list` | Inventory with domain, status, expiry, deployment state |
| `ssl_cert_expiring` | Renewal triage: what expires within N days |
| `ssl_cert_get` | One certificate's metadata and file paths |
| `ssl_cert_status` | Current certificate for a domain; poll after `ssl_cert_apply` |
| `ssl_domain_list` | Domains with verification/certificate/deploy status |
| `ssl_remote_list` | Deployment targets (hosts, paths); never credentials |
| `ssl_probe` | Live TLS check: issuer, expiry, SANs, self-signed |
| `ssl_cert_apply` | **Writes**: issue/renew a certificate (needs `confirm: true`) |
| `ssl_cert_deploy` | **Writes**: deploy a domain's certificate to a remote (needs `confirm: true`) |
| `ssl_cert_revoke` | **Writes**: revoke at the CA, irreversible (needs `confirm: true`) |
| `ssl_domain_check` | Re-run DNS verification for a domain |

## Workflow

1. Gather evidence first: `ssl_cert_expiring`, `ssl_cert_status`, `ssl_probe`.
2. For issuance: confirm the domain is verified (`ssl_domain_list`), then call
   `ssl_cert_apply` with `confirm: true` and a `reason`. It returns immediately
   because issuance runs in the background; poll `ssl_cert_status` rather than
   re-applying.
3. For deployment: `ssl_remote_list` → `ssl_cert_deploy` with the chosen
   `remoteId`, `confirm: true`, and a `reason`. The call blocks until the SSH
   deployment and reload finish.

## Rules

- These tools never return private keys. Never ask for, print, or store key
  material; point at the server-side path instead.
- Every write is irreversible or externally visible. Before calling one, state
  the exact domain and target, and never batch several writes behind one user
  "yes".
- Over MCP there is no approval UI: the `confirm: true` flag is the only gate.
  Set it only after the user explicitly asked for that specific action.
- Revocation is irreversible and only for compromised or mis-issued certificates.
  After calling it, issue a replacement before serving traffic again.
- Quote certificate ids, domains and remote ids exactly as returned.
- If a call fails with "not authenticated", the server is missing `SSLMGR_TOKEN`
  (or `SSLMGR_USERNAME`/`SSLMGR_PASSWORD`); report that instead of retrying in a
  loop.
