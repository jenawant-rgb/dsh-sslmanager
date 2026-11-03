#!/usr/bin/env python3
"""Minimal SSLManager API stand-in for exercising the DSH plugin offline.

Implements the endpoints the plugin uses, read and write:

  POST /api/user/token
  GET  /api/certificate/option
  GET  /api/certificate/<id>
  GET  /api/domain/option
  GET  /api/remote/option
  GET  /api/tools/ssl-check
  POST /api/domain/check
  POST /api/certificate/apply
  POST /api/certificate/status
  POST /api/certificate/deploy

Write endpoints mutate in-memory state, so a harness run can observe the
effect of apply/deploy. Run:  python3 mock_sslmanager.py [port]
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

NOW = datetime.now(timezone.utc)


def iso(delta: timedelta) -> str:
    return (NOW + delta).strftime("%Y-%m-%dT%H:%M:%S")


DOMAINS = [
    {
        "domain_id": 1,
        "domain_name": "example.com",
        "cname_record": "example.com.cdn.example.net",
        "status": "verified",
        "cert_status": "active",
        "deploy_status": "deployed",
        "cert_count": 2,
        "expired_at": iso(timedelta(days=10)),
        "last_update": iso(timedelta(days=-355)),
        "last_cert_id": 1,
        "user_id": 1,
        "remote_id": 1,
        "created_at": iso(timedelta(days=-400)),
        "updated_at": iso(timedelta(days=-355)),
    },
    {
        "domain_id": 2,
        "domain_name": "api.example.com",
        "cname_record": "api.example.com.cdn.example.net",
        "status": "verified",
        "cert_status": "active",
        "deploy_status": "pending",
        "cert_count": 1,
        "expired_at": iso(timedelta(days=200)),
        "last_update": iso(timedelta(days=-160)),
        "last_cert_id": 2,
        "user_id": 1,
        "remote_id": 1,
        "created_at": iso(timedelta(days=-170)),
        "updated_at": iso(timedelta(days=-160)),
    },
    {
        "domain_id": 3,
        "domain_name": "old.example.com",
        "cname_record": "old.example.com.cdn.example.net",
        "status": "verified",
        "cert_status": "expired",
        "deploy_status": "failed",
        "cert_count": 1,
        "expired_at": iso(timedelta(days=-20)),
        "last_update": iso(timedelta(days=-400)),
        "last_cert_id": 3,
        "user_id": 1,
        "remote_id": 2,
        "created_at": iso(timedelta(days=-500)),
        "updated_at": iso(timedelta(days=-400)),
    },
]

CERTIFICATES = [
    {
        "cert_id": 1,
        "user_id": 1,
        "domain_id": 1,
        "status": "active",
        "cert_path": "/data/certs/example.com/fullchain.pem",
        "key_path": "/data/certs/example.com/privkey.pem",
        "full_chain_path": "/data/certs/example.com/fullchain.pem",
        "not_valid_after": iso(timedelta(days=10)),
        "issue_log": "issued via acme.sh (dns-01)",
        "deployed": True,
        "created_at": iso(timedelta(days=-355)),
        "updated_at": iso(timedelta(days=-355)),
    },
    {
        "cert_id": 2,
        "user_id": 1,
        "domain_id": 2,
        "status": "active",
        "cert_path": "/data/certs/api.example.com/fullchain.pem",
        "key_path": "/data/certs/api.example.com/privkey.pem",
        "full_chain_path": "/data/certs/api.example.com/fullchain.pem",
        "not_valid_after": iso(timedelta(days=200)),
        "issue_log": "issued via acme.sh (dns-01)",
        "deployed": False,
        "created_at": iso(timedelta(days=-160)),
        "updated_at": iso(timedelta(days=-160)),
    },
    {
        "cert_id": 3,
        "user_id": 1,
        "domain_id": 3,
        "status": "expired",
        "cert_path": "/data/certs/old.example.com/fullchain.pem",
        "key_path": "/data/certs/old.example.com/privkey.pem",
        "full_chain_path": "/data/certs/old.example.com/fullchain.pem",
        "not_valid_after": iso(timedelta(days=-20)),
        "issue_log": "renewal failed: dns propagation timeout",
        "deployed": False,
        "created_at": iso(timedelta(days=-400)),
        "updated_at": iso(timedelta(days=-400)),
    },
]

REMOTES = [
    {
        "remote_id": 1,
        "user_id": 1,
        "name": "web-1",
        "host": "10.0.0.11",
        "port": 22,
        "username": "deploy",
        "password": "encrypted-not-returned",
        "remote_cert_path": "/etc/nginx/ssl/example.com",
        "remote_full_chain_path": "/etc/nginx/ssl/example.com/fullchain.pem",
        "remote_key_path": "/etc/nginx/ssl/example.com/privkey.pem",
        "restart_command": "sudo nginx -s reload",
        "created_at": iso(timedelta(days=-400)),
        "updated_at": iso(timedelta(days=-400)),
    },
    {
        "remote_id": 2,
        "user_id": 1,
        "name": "web-2",
        "host": "10.0.0.12",
        "port": 22,
        "username": "deploy",
        "password": "encrypted-not-returned",
        "remote_cert_path": "/etc/nginx/ssl/old.example.com",
        "remote_full_chain_path": "/etc/nginx/ssl/old.example.com/fullchain.pem",
        "remote_key_path": "/etc/nginx/ssl/old.example.com/privkey.pem",
        "restart_command": None,
        "created_at": iso(timedelta(days=-400)),
        "updated_at": iso(timedelta(days=-400)),
    },
]

STATE = {"next_cert_id": 4}


def ssl_check(host: str) -> dict:
    if host in {"unknown.invalid", "nxdomain.example"}:
        return {"error": f"unable to resolve {host}", "host": host}
    return {
        "host": host,
        "subject": f"CN={host}",
        "issuer": "R11 (Let's Encrypt)",
        "not_after": iso(timedelta(days=47 if "api" in host else 10)),
        "sans": [host, f"www.{host}"],
        "self_signed": False,
        "serial": "3f7a1c9b",
    }


def find_domain(name: str):
    return next((d for d in DOMAINS if d["domain_name"] == name), None)


def latest_cert(domain_id: int):
    candidates = [c for c in CERTIFICATES if c["domain_id"] == domain_id]
    return candidates[-1] if candidates else None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:  # keep the harness output readable
        pass

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        return self.headers.get("authorization", "").startswith("Bearer ")

    def _body(self) -> dict:
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return {}

    def do_POST(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/api/user/token":
            self._body()
            self._send(200, {"access_token": "mock-token", "token_type": "bearer", "expired_in": "3600"})
            return
        if not self._authorized():
            self._send(401, {"detail": "unauthorized"})
            return
        body = self._body()
        if path == "/api/domain/check":
            domain = find_domain(body.get("domain_name", ""))
            if not domain:
                self._send(200, {"success": False, "message": "Invalid domain"})
                return
            self._send(200, {"success": True, "message": "Verified success"})
            return
        if path == "/api/certificate/apply":
            domain = find_domain(body.get("domain_name", ""))
            if not domain or domain["status"] != "verified":
                self._send(200, {"success": False, "message": "Domain not verified or not found."})
                return
            cert_id = STATE["next_cert_id"]
            STATE["next_cert_id"] += 1
            CERTIFICATES.append(
                {
                    "cert_id": cert_id,
                    "user_id": 1,
                    "domain_id": domain["domain_id"],
                    "status": "requested",
                    "cert_path": None,
                    "key_path": None,
                    "full_chain_path": None,
                    "not_valid_after": None,
                    "issue_log": "queued: issue_cert_task",
                    "deployed": False,
                    "created_at": iso(timedelta(0)),
                    "updated_at": iso(timedelta(0)),
                }
            )
            domain.update(cert_status="requested", deploy_status="pending", last_cert_id=cert_id, cert_count=domain["cert_count"] + 1)
            self._send(200, {"success": True, "message": "Certificate issuance started in background"})
            return
        if path == "/api/certificate/status":
            domain = find_domain(body.get("domain_name", ""))
            cert = latest_cert(domain["domain_id"]) if domain else None
            if not cert:
                self._send(200, {"success": False, "message": "Certificate not exist"})
                return
            self._send(200, {"success": True, "message": "Success", "data": cert})
            return
        if path == "/api/certificate/revoke":
            domain = find_domain(body.get("domain_name", ""))
            if not domain:
                self._send(200, {"success": False, "message": "Domain not verified or not found."})
                return
            cert = latest_cert(domain["domain_id"])
            if not cert:
                self._send(200, {"success": False, "message": "Certificate not exist"})
                return
            if cert["status"] == "revoked":
                self._send(200, {"success": False, "message": "Certificate is already revoked"})
                return
            cert["status"] = "revoked"
            cert["issue_log"] = "revoked via acme.sh"
            domain.update(cert_status="revoked")
            self._send(200, {"success": True, "message": "Certificate revoked"})
            return
        if path == "/api/certificate/deploy":
            domain = find_domain(body.get("domain_name", ""))
            remote = next((r for r in REMOTES if r["remote_id"] == body.get("remote_id")), None)
            if not domain or not remote:
                self._send(200, {"success": False, "message": "Domain or remote not found."})
                return
            cert = latest_cert(domain["domain_id"])
            if cert:
                cert["deployed"] = True
            domain.update(deploy_status="success", remote_id=remote["remote_id"])
            self._send(200, {"success": True, "message": f"Deployed to {remote['name']} and reloaded nginx"})
            return
        self._send(404, {"detail": "not found"})

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if not self._authorized():
            self._send(401, {"detail": "unauthorized"})
            return
        if path == "/api/certificate/option":
            self._send(200, CERTIFICATES)
            return
        if path.startswith("/api/certificate/"):
            cert_id = path.rsplit("/", 1)[-1]
            match = next((c for c in CERTIFICATES if str(c["cert_id"]) == cert_id), None)
            self._send(200, match) if match else self._send(404, {"detail": "not found"})
            return
        if path == "/api/domain/option":
            self._send(200, DOMAINS)
            return
        if path == "/api/remote/option":
            self._send(200, REMOTES)
            return
        if path == "/api/tools/ssl-check":
            host = parse_qs(parsed.query).get("host", [""])[0]
            self._send(200, ssl_check(host))
            return
        self._send(404, {"detail": "not found"})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8030
    print(f"mock SSLManager listening on http://127.0.0.1:{port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
