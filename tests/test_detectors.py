"""Detector + redaction + ledger tests.

All fixtures are synthetic. No real credentials, tokens, or PII appear here —
the values are shaped like the real tells (right prefixes, right structure) but
are fabricated. This is the same discipline the tool enforces at runtime.
"""
import base64
import json

from overwatch.detectors import (
    Exchange, run_detectors,
    d_presigned_url_infra, d_pii_to_third_party, d_wildcard_cors,
    d_wildcard_entitlement, d_jwt_exposure, d_version_banner,
    d_graphql_endpoint, d_idor_uuid_in_path, d_ai_reasoning_leak,
    d_public_client_token,
)
from overwatch.ledger import Ledger
from overwatch.redact import redact


# ── helpers ───────────────────────────────────────────────────────

def _fake_jwt(payload: dict) -> str:
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{b64({'alg':'RS256'})}.{b64(payload)}.{'s' * 40}"


FAKE_UUID = "00000000-1111-2222-3333-444444444444"
FAKE_ORG = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


# ── presigned-url infra disclosure ───────────────────────────────

def test_presigned_gcs_leaks_signer():
    ex = Exchange(url=(
        "https://storage.googleapis.com/example-bucket/asset.zip"
        "?X-Goog-Credential=svc-account%40my-project.iam.gserviceaccount.com"
        "&X-Goog-Signature=deadbeef" + "0" * 40
    ))
    finds = list(d_presigned_url_infra(ex))
    assert len(finds) == 1
    assert "svc-account" in finds[0].evidence
    assert finds[0].severity == "Low"


def test_presigned_none_on_clean_url():
    ex = Exchange(url="https://cdn.example.com/logo.png")
    assert list(d_presigned_url_infra(ex)) == []


# ── PII to third-party analytics ─────────────────────────────────

def test_pii_uuid_to_ga_is_medium():
    ex = Exchange(url=(
        f"https://analytics.google.com/g/collect?tid=G-XXXX&uid={FAKE_UUID}"
        f"&up.org_id={FAKE_ORG}"
    ))
    finds = list(d_pii_to_third_party(ex))
    assert len(finds) == 1
    assert finds[0].severity == "Medium"      # uid/org present -> Medium
    assert "uid" in finds[0].evidence


def test_pii_ignores_first_party_and_counters():
    # first-party host: not flagged
    assert list(d_pii_to_third_party(
        Exchange(url=f"https://app.example.com/track?uid={FAKE_UUID}"))) == []
    # third-party but only opaque counters (no UUID): not flagged
    assert list(d_pii_to_third_party(
        Exchange(url="https://analytics.google.com/g/collect?tid=G-X&sid=12345&_p=99"))) == []


# ── wildcard CORS ─────────────────────────────────────────────────

def test_wildcard_cors_with_credentials_is_medium():
    ex = Exchange(url="https://api.example.com/x", response_headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })
    finds = list(d_wildcard_cors(ex))
    assert finds and finds[0].severity == "Medium"


def test_wildcard_cors_without_credentials_is_low():
    ex = Exchange(url="https://api.example.com/x", response_headers={
        "Access-Control-Allow-Origin": "*",
    })
    finds = list(d_wildcard_cors(ex))
    assert finds and finds[0].severity == "Low"


# ── wildcard entitlement ─────────────────────────────────────────

def test_wildcard_entitlement_is_high():
    ex = Exchange(url="https://api.example.com/session",
                  body='{"user":"x","privileges":"sview:*","other":1}')
    finds = list(d_wildcard_entitlement(ex))
    assert finds and finds[0].severity == "High"
    assert "sview:*" in finds[0].evidence


# ── JWT exposure ──────────────────────────────────────────────────

def test_jwt_exposure_decodes_authority():
    tok = _fake_jwt({"sub": FAKE_UUID, "exp": 9999999999, "perms": {"scnrio": "v"}})
    ex = Exchange(url="https://api.example.com/me",
                  request_headers={"Authorization": f"Bearer {tok}"})
    finds = list(d_jwt_exposure(ex))
    assert finds and finds[0].severity == "Info"
    assert FAKE_UUID in finds[0].evidence
    assert "scnrio" in finds[0].evidence


# ── version banner ────────────────────────────────────────────────

def test_version_banner_on_versioned_server():
    ex = Exchange(url="https://x/", response_headers={"Server": "nginx/1.21.6"})
    assert list(d_version_banner(ex))          # has a digit -> flagged


def test_version_banner_service_codename():
    ex = Exchange(url="https://x/", response_headers={"orm-service": "card_service"})
    finds = list(d_version_banner(ex))
    assert finds and "card_service" in finds[0].evidence


def test_version_banner_skips_bare_proxy():
    ex = Exchange(url="https://x/", response_headers={"Server": "istio-envoy"})
    assert list(d_version_banner(ex)) == []


# ── graphql / idor / ai-leak / public token ──────────────────────

def test_graphql_endpoint():
    assert list(d_graphql_endpoint(Exchange(url="https://api.example.com/graphql")))


def test_idor_uuid_in_api_path():
    ex = Exchange(url=f"https://api.example.com/api/v2/users/{FAKE_UUID}/profile")
    finds = list(d_idor_uuid_in_path(ex))
    assert finds and FAKE_UUID in finds[0].evidence


def test_idor_numeric_id():
    ex = Exchange(url="https://api.example.com/api/accounts/8675309/detail")
    finds = list(d_idor_uuid_in_path(ex))
    assert finds and "8675309" in finds[0].evidence


def test_ai_reasoning_leak():
    ex = Exchange(url="https://api.example.com/answers",
                  body='{"reasoning":"step 1...","answer":"42"}')
    finds = list(d_ai_reasoning_leak(ex))
    assert finds and finds[0].severity == "Medium"


def test_public_client_token():
    ex = Exchange(url="https://browser-intake-datadoghq.com/api/v2/rum?dd-api-key=pubABCDEFGH12345")
    finds = list(d_public_client_token(ex))
    assert finds and "pubABCDEFGH" in finds[0].evidence


# ── run_detectors aggregation ────────────────────────────────────

def test_run_detectors_multiple_tells_one_exchange():
    ex = Exchange(
        url=f"https://analytics.google.com/g/collect?uid={FAKE_UUID}",
        response_headers={"Server": "Apache/2.4.51"},
    )
    finds = run_detectors(ex)
    detectors = {f.detector for f in finds}
    assert "pii-to-third-party" in detectors
    assert "version-banner" in detectors


def test_detector_exception_does_not_break_run():
    # a detector that throws must be swallowed; run_detectors returns the rest
    def boom(ex):
        raise ValueError("boom")
    ex = Exchange(url="https://api.example.com/graphql")
    finds = run_detectors(ex, detectors=[boom, d_graphql_endpoint])
    assert any(f.detector == "graphql-endpoint" for f in finds)


# ── redaction ─────────────────────────────────────────────────────

def test_redact_truncates_jwt():
    tok = _fake_jwt({"sub": "x"})
    out = redact(f"Authorization: Bearer {tok}")
    assert "<redacted" in out
    assert tok not in out


def test_redact_truncates_gcs_signature():
    sig = "A" * 60
    out = redact(f"https://x?X-Goog-Signature={sig}")
    assert sig not in out
    assert "<redacted-sig>" in out


def test_redact_keeps_prefix_for_correlation():
    tok = "eyJhbGciOiJSUzI1NiJ9.PAYLOADPART.SIGNATUREPART"
    out = redact(tok, keep=6)
    assert out.startswith("eyJhbG")           # recognizable
    assert "PAYLOADPART" not in out           # but unusable


# ── ledger dedupe + severity sort ────────────────────────────────

def test_ledger_dedupes_same_finding():
    led = Ledger()
    ex = Exchange(url="https://api.example.com/x", response_headers={
        "Access-Control-Allow-Origin": "*"})
    assert led.add_all(run_detectors(ex)) == 1     # first time: new
    assert led.add_all(run_detectors(ex)) == 0     # second time: dupe
    assert len(led.findings()) == 1


def test_ledger_severity_sort():
    led = Ledger()
    led.add_all(run_detectors(Exchange(
        url="https://api.example.com/graphql")))                       # Info
    led.add_all(run_detectors(Exchange(
        url="https://api.example.com/s",
        body='{"privileges":"admin:*"}')))                             # High
    order = [f.severity for f in led.findings()]
    assert order.index("High") < order.index("Info")


def test_ledger_render_redacts():
    led = Ledger()
    tok = _fake_jwt({"sub": "secret"})
    led.add_all(run_detectors(Exchange(
        url="https://api.example.com/me",
        request_headers={"Authorization": f"Bearer {tok}"})))
    out = led.render()
    assert tok not in out
