"""The finding taxonomy — passive detectors over captured HTTP exchanges.

Each detector reads one Exchange and yields zero or more Findings. Detectors are
pure and read-only: they never mutate the exchange and never emit traffic. The
tells encoded here are exactly the ones that surfaced 13 findings across ~13
microservices in one browsing pass of an authenticated O'Reilly enterprise
session (see ../poc/oreilly-enterprise-session.md).

Every Finding carries a `vdt_class` pointing into the VDT knowledge base so a
tell in traffic routes straight to the class page that explains + fixes it.
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

from .redact import redact


# ─────────────────────────── data model ───────────────────────────

@dataclass
class Exchange:
    """One request/response pair captured off the wire."""
    url: str
    method: str = "GET"
    request_headers: dict = field(default_factory=dict)
    status: int = 0
    response_headers: dict = field(default_factory=dict)
    body: str = ""

    @property
    def host(self) -> str:
        return urlparse(self.url).netloc.lower()

    @property
    def path(self) -> str:
        return urlparse(self.url).path


@dataclass
class Finding:
    detector: str
    title: str
    severity: str          # Critical | High | Medium | Low | Info
    vdt_class: str         # relative link into the VDT KB
    url: str
    evidence: str          # always passed through redact() before display

    def redacted(self) -> "Finding":
        return Finding(
            self.detector, self.title, self.severity, self.vdt_class,
            redact(self.url), redact(self.evidence),
        )


# ─────────────────────────── helpers ───────────────────────────

_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
_THIRD_PARTY_ANALYTICS = (
    "analytics.google.com", "google-analytics.com", "www.google-analytics.com",
    "api2.amplitude.com", "amplitude.com", "browser-intake-datadoghq.com",
    "stats.g.doubleclick.net", "px.ads.linkedin.com",
)
_ID_PARAM_HINTS = ("uid", "user_id", "userid", "up.org_id", "org_id",
                   "up.custom_user_id", "customer_id", "$user_id")


def _header(headers: dict, name: str):
    name = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == name:
            return v
    return None


def _decode_jwt_payload(tok: str):
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


# ─────────────────────────── detectors ───────────────────────────

def d_presigned_url_infra(ex: Exchange):
    hay = ex.url + " " + (ex.body or "")
    for cred_key, cloud in (("X-Goog-Credential", "GCS"), ("X-Amz-Credential", "S3")):
        m = re.search(re.escape(cred_key) + r"=([^&\s\"]+)", hay, re.I)
        if m:
            ident = m.group(1)
            yield Finding(
                "presigned-url-infra", f"{cloud} pre-signed URL leaks signer identity",
                "Low", "information-disclosure/presigned-url-infrastructure-disclosure.md",
                ex.url, f"{cred_key}={ident}  (bucket/host: {urlparse(ex.url).netloc})",
            )


def d_pii_to_third_party(ex: Exchange):
    if ex.host not in _THIRD_PARTY_ANALYTICS:
        return
    qs = parse_qs(urlparse(ex.url).query)
    leaked = {}
    for k, vals in qs.items():
        if k.lower() in _ID_PARAM_HINTS or any(_UUID.search(v) for v in vals):
            if any(_UUID.search(v) for v in vals):   # only real identifiers, not counters
                leaked[k] = vals[0]
    if leaked:
        sev = "Medium" if any("org" in k or k.lower() in ("uid", "user_id") for k in leaked) else "Low"
        yield Finding(
            "pii-to-third-party", f"Real account identifier(s) sent to {ex.host}",
            sev, "information-disclosure/",
            ex.url, "leaked params: " + ", ".join(f"{k}={v}" for k, v in leaked.items()),
        )


def d_wildcard_cors(ex: Exchange):
    acao = _header(ex.response_headers, "access-control-allow-origin")
    if acao == "*":
        creds = _header(ex.response_headers, "access-control-allow-credentials")
        sev = "Medium" if str(creds).lower() == "true" else "Low"
        note = "with Allow-Credentials:true (browser will still block, but a real risk if reflected)" \
            if str(creds).lower() == "true" else "no Allow-Credentials (self-limiting)"
        yield Finding(
            "wildcard-cors", "Wildcard CORS (Access-Control-Allow-Origin: *)",
            sev, "access-control/", ex.url, f"ACAO: *  ({note})",
        )


def d_wildcard_entitlement(ex: Exchange):
    # a privilege/scope field whose value contains a '*' wildcard
    for m in re.finditer(
        r'"(privileges|scope|scopes|perms|permissions|grants)"\s*:\s*"([^"]*\*[^"]*)"',
        ex.body or "", re.I,
    ):
        yield Finding(
            "wildcard-entitlement", f"Wildcard entitlement in `{m.group(1)}`",
            "High", "access-control/", ex.url,
            f'{m.group(1)} = "{m.group(2)}"  (grants over an entire class/tenant)',
        )


def d_jwt_exposure(ex: Exchange):
    blob = " ".join([
        str(_header(ex.request_headers, "authorization") or ""),
        str(_header(ex.request_headers, "cookie") or ""),
        ex.body or "",
    ])
    m = re.search(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}", blob)
    if not m:
        return
    payload = _decode_jwt_payload(m.group(0))
    if not payload:
        return
    perms = payload.get("perms") or payload.get("scope") or payload.get("permissions")
    exp = payload.get("exp")
    ev = f"sub={payload.get('sub','?')} exp={exp} perms={json.dumps(perms)[:160] if perms else 'n/a'}"
    # Info by default; the value is confirming what identity/authority is on the wire.
    yield Finding(
        "jwt-exposure", "JWT present on the wire (decode for authority)",
        "Info", "access-control/", ex.url, ev,
    )


def d_version_banner(ex: Exchange):
    for hname in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "orm-service"):
        val = _header(ex.response_headers, hname)
        if val and val.lower() not in ("istio-envoy", "cloudflare", "nginx"):
            # bare generic names are low-signal; a version or a service codename is the tell
            if any(c.isdigit() for c in val) or hname == "orm-service":
                yield Finding(
                    "version-banner", f"Backend fingerprint in `{hname}`",
                    "Info", "information-disclosure/version-banner-leakage.md",
                    ex.url, f"{hname}: {val}",
                )


def d_graphql_endpoint(ex: Exchange):
    if ex.path.rstrip("/").endswith("graphql") or "/graphql" in ex.path:
        yield Finding(
            "graphql-endpoint", "GraphQL endpoint (introspection / over-fetch candidate)",
            "Info", "information-disclosure/open-api-documentation.md",
            ex.url, f"{ex.method} {ex.path}",
        )


def d_idor_uuid_in_path(ex: Exchange):
    # an authenticated API path that carries a user/object identifier as a segment
    if not ex.path.startswith("/api"):
        return
    m = _UUID.search(ex.path)
    seg_id = None
    if m:
        seg_id = m.group(0)
    else:
        m2 = re.search(r"/(users?|accounts?|profiles?|orgs?)/(\d{3,})(/|$)", ex.path, re.I)
        if m2:
            seg_id = m2.group(2)
    if seg_id:
        yield Finding(
            "idor-uuid-in-path", "Object identifier in URL path (IDOR/BOLA candidate)",
            "Low", "access-control/", ex.url,
            f"{ex.method} {ex.path}  — swap `{seg_id}` for a neighbor's id and re-test authorization",
        )


def d_ai_reasoning_leak(ex: Exchange):
    body = ex.body or ""
    if not body:
        return
    tells = [t for t in ('"reasoning"', '"chain_of_thought"', '"tool_schema"',
                         '"thought"', 'create_answer_draft', 'ask_oreilly') if t in body]
    if tells:
        yield Finding(
            "ai-reasoning-leak", "AI agent reasoning / tool schema in response",
            "Medium", "information-disclosure/", ex.url,
            "leaked keys: " + ", ".join(tells),
        )


def d_public_client_token(ex: Exchange):
    m = re.search(r"(?:dd-api-key|api[_-]?key|token)=(pub[A-Za-z0-9]{8,})", ex.url, re.I)
    if m:
        yield Finding(
            "public-client-token", "Public client token in request URL",
            "Low", "information-disclosure/", ex.url,
            f"token={m.group(1)[:16]}…  (public by design; check domain-lock / ingest-abuse)",
        )


ALL_DETECTORS = [
    d_presigned_url_infra,
    d_pii_to_third_party,
    d_wildcard_cors,
    d_wildcard_entitlement,
    d_jwt_exposure,
    d_version_banner,
    d_graphql_endpoint,
    d_idor_uuid_in_path,
    d_ai_reasoning_leak,
    d_public_client_token,
]


def run_detectors(ex: Exchange, detectors=None):
    """Run every detector over one exchange; return a list of Findings."""
    out = []
    for det in (detectors or ALL_DETECTORS):
        try:
            out.extend(det(ex))
        except Exception:
            # a detector must never break the observer; skip and continue.
            continue
    return out
