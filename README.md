# Overwatch

**A passive web-application security assessment tool.**

Overwatch watches the traffic a browser already sends and receives, and reports
security findings from it. It connects to Chrome over the Chrome DevTools
Protocol (CDP) and **sends no requests of its own** — to the server you look like
a normal user.

You log in, use the app, and Overwatch reads each request and response and runs a
set of detectors over it. In **live mode** it runs alongside Claude Code, which
reasons over the traffic and calls out findings as you browse.

> Authorized testing only. It leaves no scanner trace, so scope is on you. Watch
> only apps you own or are cleared to test.

## Install

```bash
pip install .          # core + offline HAR scanning, zero dependencies
pip install '.[live]'  # add live watch (needs a WebSocket client)
```

Python 3.10+. The offline path uses only the standard library.

## Use

```bash
# 1. start Chrome with the debugging port, then log in
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/ow-profile

# 2. list tabs
overwatch tabs

# 3. watch one tab for a bounded window (passive only)
overwatch watch --tab oreilly --seconds 120
#   [+] [High]   Wildcard entitlement in `privileges`
#   [+] [Medium] Real account identifier(s) sent to analytics.google.com
#   [+] [Low]    GCS pre-signed URL leaks signer identity

# 4. or scan a saved capture offline
overwatch scan-har session.har --json
```

For live mode, point a Claude Code session at `http://127.0.0.1:9222` (the
`chrome-devtools` MCP) and tell it: *"watch this session and call out any
vulnerabilities as I browse."*

## What it looks like

Four frames from one authorized session on an enterprise O'Reilly Learning
account. Credentials and the account UUID are boxed out in the first frame.

![Capturing a response body over CDP](docs/img/01-cdp-capture.png)
![Findings surfaced from the AI Answers endpoint](docs/img/02-answers-ai-findings.png)
![Verify-only discipline and the positive controls](docs/img/03-entitlement-and-verify-only.png)
![Critical: client-controlled royalty attribution](docs/img/04-critical-royalty-attribution.png)

## Detectors

Each finding is a candidate — **surface open ≠ access exercised**. Confirming one
means sending a request deliberately, which the passive pass never does.

| Detector | Tell on the wire | Severity |
|---|---|---|
| `wildcard-entitlement` | a scope value with a `*` (`"privileges":"sview:*"`) | High |
| `ai-reasoning-leak` | `"reasoning"` / `"tool_schema"` in a response | Medium |
| `pii-to-third-party` | real account/org UUID in an analytics beacon | Medium / Low |
| `wildcard-cors` | `Access-Control-Allow-Origin: *` (+creds → Medium) | Medium / Low |
| `presigned-url-infra` | `X-Goog-Credential` / `X-Amz-Credential` names the signer | Low |
| `idor-uuid-in-path` | an object UUID/id as an `/api/...` path segment | Low |
| `public-client-token` | a `pub...` client token in a URL | Low |
| `version-banner` | `Server:` version or a service codename | Info |
| `graphql-endpoint` | a `/graphql` path | Info |
| `jwt-exposure` | a JWT on the wire, decoded to `sub` / `perms` / `exp` | Info |

Add one by writing a `(Exchange) -> Iterable[Finding]` function in
`overwatch/detectors.py`. It must not modify the exchange or send traffic.

## Restraint

- **Passive only.** The only CDP commands used are `Network.enable` and
  `getResponseBody`.
- **Credentials truncated.** Every output string passes through
  `overwatch.redact`; JWTs, signatures, tokens, and cookies become unusable
  stubs. The report shows the finding, not the secret.
- **Names, not exfiltration.** Identifiers (a service-account email, your own
  account UUID) are the finding and are shown; the credential that would let you
  replay is redacted.
- **Captures stay out.** `.gitignore` blocks `*.har` and `*.network-*`.

## More

- [`poc/oreilly-enterprise-session.md`](poc/oreilly-enterprise-session.md) — the
  real run that produced this taxonomy: 13 findings, all metadata, all
  credentials redacted.
- [VDT-INFO-LEARN](../VDT-INFO-LEARN/tools/overwatch.md) — where the method
  started.
