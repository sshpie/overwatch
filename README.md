# Overwatch

**A passive web application security assessment tool.**

Overwatch observes the network traffic between a web browser and a web server. It
does not send any network requests of its own. It only reads the requests and
responses that the browser already sends and receives.

Overwatch connects to a running Chrome or Chromium browser through the Chrome
DevTools Protocol (CDP). CDP is an interface that Chrome exposes on a local TCP
port when the browser is started with the `--remote-debugging-port` flag.
Overwatch uses exactly two CDP commands: `Network.enable`, which tells Chrome to
report network activity, and `Network.getResponseBody`, which retrieves the body
of a specific response. It sends no other commands.

To use Overwatch, you log in to the target web application in the browser and use
the application normally. As you use it, the browser sends requests and receives
responses. Overwatch reads each request and response and passes it to a set of
detectors. A detector is a function that checks one specific condition and
reports a finding when that condition is true.

Overwatch has two modes:

1. **Live mode with Claude Code.** A Claude Code session connects to the same
   browser through CDP, reads the traffic, and reports findings as they occur.
   Examples of findings: a permission scope that contains a wildcard character;
   an account identifier sent to a third-party domain; a pre-signed cloud storage
   URL that contains the identity of the account that signed it; a JSON Web Token
   (JWT) that grants more permission than required.
2. **Command-line mode.** The `overwatch` command performs the same detection
   without Claude Code.

Because Overwatch sends no requests of its own, the web server receives exactly
the same traffic it would receive from the user alone. There is no additional
traffic, no modified requests, and no additional endpoints contacted.

> Overwatch is for authorized security testing only. Because it sends no traffic
> of its own, it produces no signal that a defender could detect. Therefore the
> person using it is responsible for staying within an authorized scope. Observe
> only sessions on applications that you own or that you have explicit written
> permission to test.

---

## How it works

Overwatch does not interact with the web application. The user interacts with the
application. Overwatch reads the resulting traffic and reports findings. There are
two ways to run it.

**Live mode.** The screenshots below show this mode. The steps are:

1. Start Chrome or Chromium with the remote debugging port open.
2. Log in to an application you are authorized to test.
3. A Claude Code session connects to the browser through CDP, using the
   `chrome-devtools` MCP, and reads the traffic.
4. You use the application: open a page, run a search, ask the built-in AI a
   question.
5. For each request and response, the session reads the message, parses the JSON
   body, and checks it against the detectors. It reports each finding.

Examples of what a detector reports: a wildcard character in a permission scope;
an account identifier sent to a third-party domain; a pre-signed URL that contains
the signer identity; a token that grants more permission than required. No traffic
is sent to the server. The server receives only the user's own requests.

**Command-line mode.** The `overwatch` command runs the same detection loop
without Claude Code. It connects to the same debugging port, reads the same
traffic, runs the same detectors, and prints a report. The report is deduplicated
and sorted by severity. Use live mode when you want a Claude Code session to
interpret the traffic. Use the command when you want a repeatable, scriptable run.

### An example session

The following four screenshots are from one authorized session on an enterprise
O'Reilly Learning account. The session was ordinary use: asking the built-in AI a
question and reading a book. A Claude Code session observed the traffic. In the
first screenshot, the live cookies and the account UUID are covered with opaque
rectangles, because they are credentials. Overwatch applies the same redaction to
its own screenshots that it applies to its reports.

**Screenshot 1. Reading a response the browser already received.** The session
retrieves one response body from the browser's DevTools cache using
`get_network_request`. No new request is sent. The response shows that the AI
Answers endpoint accepts a search query supplied by the client (the browser),
rather than constructing the query on the server.

![Overwatch capturing a response body over CDP and flagging a client-supplied RAG query](docs/img/01-cdp-capture.png)

**Screenshot 2. Two findings from that endpoint.** Both are severity Medium.
First: the response includes the AI agent's internal reasoning text and its tool
schema (the function names `ask_oreilly_books` and `create_answer_draft`), and
these are sent to the browser. Second: the client supplies the raw Solr filter
query, and the search backend uses it without constructing it on the server.

![Passive findings: agent chain-of-thought and tool schema leaked to the client, client-dictated RAG query](docs/img/02-answers-ai-findings.png)

**Screenshot 3. Recording only what was observed, and recording correct
controls.** The entitlement-gate finding and the filter-injection finding are
recorded with the status "surface open, access not exercised." This status means
the condition was observed in traffic but not tested with a crafted request,
because sending a crafted request is outside passive scope. The session also
records controls that were implemented correctly, because the absence of a
vulnerability is useful information.

![Content-extraction table, verify-only entitlement question, and the positive controls](docs/img/03-entitlement-and-verify-only.png)

**Screenshot 4. The highest-severity finding.** The usage-event request exposes
the royalty-attribution system. The browser sends the per-book payout weights in
the request body, in a field named `attribution_map`, and the values sum to
100.00. This means the values used for financial attribution are supplied by the
client. Combined with the client-supplied search query from screenshot 2, this
allows a user to control which books receive royalty attribution. This finding is
recorded as severity Critical, with status "access not exercised."

![Critical finding: client-submitted royalty/attribution accounting in the usage-event POST](docs/img/04-critical-royalty-attribution.png)

### Running live mode

1. Start the browser with the remote debugging port open, then log in to an
   application you are authorized to test:
   ```bash
   google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/ow-profile
   ```
2. Connect a Claude Code session to the browser. The `chrome-devtools` MCP
   connects to `http://127.0.0.1:9222`. Instruct the session: *"watch this session
   and call out any vulnerabilities as I browse."*
3. Use the application. The session reads each request and response as it occurs
   and reports findings.

---

## Install

There are two installation options. The core functionality has no dependencies.
Live mode requires one additional package.

```bash
# core taxonomy + offline HAR scanning — ZERO dependencies
pip install .

# live watch also needs a WebSocket client
pip install '.[live]'
```

Overwatch requires Python 3.10 or later. The offline functionality (all
detectors, the ledger, and the `scan-har` command) uses only the Python standard
library and requires no additional packages.

---

## Use

### 1. Start Chrome with the debugging port

```bash
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/ow-profile
# then log into the app you're authorized to assess, as you normally would
```

### 2. List the open tabs

```bash
overwatch tabs
#   8A3F...  O'Reilly — Cassandra Sandbox        https://learning.oreilly.com/...
```

### 3. Watch one tab for a set duration

```bash
overwatch watch --tab oreilly --seconds 120
# passive only — 120s budget, 5000 exchange cap
#   [+] [High]   Wildcard entitlement in `privileges`  — https://.../session
#   [+] [Medium] Real account identifier(s) sent to analytics.google.com  — ...
#   [+] [Low]    GCS pre-signed URL leaks signer identity  — ...
```

Use the application during this period. Overwatch reports the requests and
responses it observed. The report is sorted by severity, deduplicated, and every
live credential is truncated.

### 4. Scan a saved capture file

```bash
overwatch scan-har session.har --json
```

This runs the same detectors on a HAR (HTTP Archive) file. You can produce a HAR
file using "Save all as HAR" in Chrome DevTools, or from a proxy. No live browser
is required. This is useful for a capture file provided by another person, or a
session recorded earlier.

---

## The finding taxonomy

Each condition that a detector checks corresponds to a page in the VDT knowledge
base that explains the condition and how to fix it. The detectors are
intentionally conservative. Each detector reports a candidate, not a confirmed
vulnerability, and Overwatch states this. **Surface open does not mean access
exercised.** To confirm a vulnerability, such as an IDOR (Insecure Direct Object
Reference) or the full scope of a wildcard permission, you must send a request
deliberately. The passive pass does not do this.

| Detector | Tell on the wire | Default severity | VDT class |
|---|---|---|---|
| `wildcard-entitlement` | `"privileges":"sview:*"` — a scope value with a `*` | High | access-control |
| `ai-reasoning-leak` | `"reasoning"` / `"tool_schema"` in a response body | Medium | information-disclosure |
| `pii-to-third-party` | real account/org UUID in an analytics beacon URL | Medium / Low | information-disclosure |
| `wildcard-cors` | `Access-Control-Allow-Origin: *` (+creds → Medium) | Medium / Low | hardening/cors |
| `presigned-url-infra` | `X-Goog-Credential` / `X-Amz-Credential` names the signer SA | Low | [presigned-url-infrastructure-disclosure](../VDT-INFO-LEARN/information-disclosure/presigned-url-infrastructure-disclosure.md) |
| `idor-uuid-in-path` | an object UUID/numeric id as an `/api/...` path segment | Low | access-control |
| `public-client-token` | a `pub...` client token in a request URL | Low | information-disclosure |
| `version-banner` | `Server: nginx/1.21.6`, a service codename in `orm-service` | Info | version-banner-leakage |
| `graphql-endpoint` | a `/graphql` path (introspection / over-fetch candidate) | Info | open-api-documentation |
| `jwt-exposure` | a JWT on the wire — decoded to show `sub` / `perms` / `exp` | Info | access-control |

To add a detector, write one function with the signature
`(Exchange) -> Iterable[Finding]` in `overwatch/detectors.py` and add it to the
`ALL_DETECTORS` list. The function must not modify the exchange and must not send
any traffic.

---

## The restraint ethic

- **Passive only.** No detector and no command-line option sends a crafted
  request. The only CDP commands used are `Network.enable` and `getResponseBody`.
- **Truncate live credentials.** Every string in the output passes through the
  `overwatch.redact` function. JWTs, cloud signatures, bearer tokens, and session
  cookies are replaced with truncated stubs that are readable but cannot be used.
  The report contains the description of the finding, not the credential itself.
- **Report identifiers; do not exfiltrate data.** A finding consists of metadata:
  the structure of a message, a header, or an identifier. An identifier, such as
  a service-account email address or the operator's own account UUID, is the
  finding and is shown. A credential, such as the signature that would allow
  replaying a request, is redacted. Identifiers are shown; credentials are
  removed.
- **Capture files are excluded from the repository.** The `.gitignore` file
  excludes `*.har` and `*.network-*` files. Redaction protects reports. Raw
  capture files contain real credentials, so they are excluded entirely.
- **Scope is the operator's responsibility.** The tool cannot determine whether a
  session is authorized. Only the operator can. Observe only sessions on
  applications you own or are authorized to test.

---

## Proof of concept

[`poc/oreilly-enterprise-session.md`](poc/oreilly-enterprise-session.md)
documents a real run on an authorized, authenticated enterprise O'Reilly Learning
session. One session of ordinary use produced 13 findings across approximately 13
microservices. All findings are metadata only. All credentials are redacted. This
session is the source of the finding taxonomy.

---

## Origin

Overwatch began as a method description in the
[VDT-INFO-LEARN](../VDT-INFO-LEARN/tools/overwatch.md) knowledge base, documented
as a technique for VDT training. It became a separate tool because the technique —
connect to an authorized session and read the traffic the application already
produces — is useful on its own. As a tool, the restraint rules are enforced in
the code rather than only described in documentation.
