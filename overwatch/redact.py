"""Credential redaction — the restraint ethic, in code.

Overwatch reports the *claim* (a wildcard privilege, an IDOR-shaped URL), never
the *secret*. Every string that reaches output passes through redact() so live
JWTs, signing signatures, bearer tokens, and session cookies are truncated to a
recognizable-but-unusable stub.
"""
import re

# A JWT: three base64url segments separated by dots, starting with the classic
# {"alg":...} header prefix `eyJ`.
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")

# Cloud pre-signed URL signatures (GCS / S3) and generic Signature= params.
_SIG = re.compile(
    r"((?:X-Goog-Signature|X-Amz-Signature|Signature)=)([A-Za-z0-9%/+_-]{16,})",
    re.IGNORECASE,
)

# Authorization: Bearer <token>
_BEARER = re.compile(r"(Bearer\s+)([A-Za-z0-9._-]{16,})", re.IGNORECASE)

# Long opaque session-ish cookie/token values (key=value where value is long).
_SESSIONISH = re.compile(
    r"((?:orm-jwt|groot_sessionid|session|sessionid|_dd_s|bm_s|token)=)"
    r"([A-Za-z0-9._%/+-]{20,})",
    re.IGNORECASE,
)


def redact(text: str, keep: int = 12) -> str:
    """Truncate every live-credential-looking substring, keeping a short prefix.

    keep = number of leading chars retained so a value stays *recognizable*
    (for correlation across a report) but *unusable* (can't be replayed).
    """
    if not text:
        return text
    text = _JWT.sub(lambda m: m.group(0)[:keep] + "…<redacted-jwt>", text)
    text = _SIG.sub(lambda m: m.group(1) + m.group(2)[:keep] + "…<redacted-sig>", text)
    text = _BEARER.sub(lambda m: m.group(1) + m.group(2)[:keep] + "…<redacted-token>", text)
    text = _SESSIONISH.sub(lambda m: m.group(1) + m.group(2)[:keep] + "…<redacted>", text)
    return text
