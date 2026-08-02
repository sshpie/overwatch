# Overwatch

**A passive tool for testing web applications. It watches. It does not touch.**

Overwatch joins a real Chrome session over the Chrome DevTools Protocol (CDP).
You log in. You click around the target like any other user. Overwatch watches
the traffic you make. It sends nothing of its own. It takes what it sees and
gives it to the detectors.

In live mode it runs beside Claude Code. Claude reads the traffic as it comes
and says what is wrong. A permission too wide. An account name where it should
not be. A signed cloud URL that names the signer. A weak token. Small things, on
the wire, that add up.

It never knocks. To the server you are one user and nothing more. No noise. No
payload. No new door.

> **This is a tool for work you are allowed to do.** A quiet watcher leaves no
> mark, so the line is yours to hold. Watch only the sessions you own or are
> cleared to watch. Hold the scope before the first byte.

---

## How it works

The plumbing is not the point. You use the app. Something reads the traffic and
names the trouble as it goes past. There are two ways to do it.

**The live way.** This is what the pictures show. You open Chrome with the
debugging port open. You log in. A Claude Code session joins the browser over the
DevTools Protocol (the `chrome-devtools` MCP) and watches. You open a page. You
run a search. You ask the built-in AI a question. Every request and every answer
goes past the session. It reads each one. It opens the JSON. It marks what is
wrong: a wildcard, your account ID sent to a stranger, a signed URL that names
its own account, a token that grants too much. You browse. It finds. Nothing
more goes to the server. From the app's side there is only you.

**The packaged way.** The `overwatch` command is the same loop, alone. It joins
the same port. It watches the same traffic. It runs the same detectors. It prints
a clean report, sorted by weight. No AI needed. Use the live way when you want a
mind on it. Use the command when you want the same pass, again and again.

### A real session

Four frames. One allowed pass over an **enterprise O'Reilly Learning** account.
An ordinary session. Ask the AI. Read a book. Claude watches. In the first frame
the live cookies and the account UUID are boxed out. The tool redacts its own
pictures the way it redacts its reports.

**1 — Reading what the app already sent.** The session takes one response body
from the browser cache. It sends no request. It sees at once that the AI Answers
endpoint lets the client write the search query.

![Overwatch capturing a response body over CDP and flagging a client-supplied RAG query](docs/img/01-cdp-capture.png)

**2 — The findings come.** Two mediums fall out of that one endpoint. The answer
ships the agent's own reasoning and its tool schema (`ask_oreilly_books`,
`create_answer_draft`) down to the browser. And the client writes the raw Solr
filter the search trusts.

![Passive findings: agent chain-of-thought and tool schema leaked to the client, client-dictated RAG query](docs/img/02-answers-ai-findings.png)

**3 — Say only what you saw.** The entitlement gate and the filter lead go down
as *"surface open, access not exercised."* To prove them you would have to send
something, and that is past the line. The session also writes down what was done
right. A finding can be an absence.

![Content-extraction table, verify-only entitlement question, and the positive controls](docs/img/03-entitlement-and-verify-only.png)

**4 — The one that mattered.** The usage beacon shows the royalty engine. The
browser posts the payout weights itself, an `attribution_map` that sums to
100.00. The money inputs come from the client. Join that to the client-written
search from frame two and you have a way to farm royalties. Logged Critical. Not
exercised.

![Critical finding: client-submitted royalty/attribution accounting in the usage-event POST](docs/img/04-critical-royalty-attribution.png)

### Do it yourself

1. Open the browser with the port open and log in to an app you are allowed to test:
   ```bash
   google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/ow-profile
   ```
2. Point a Claude Code session at it. The `chrome-devtools` MCP talks to `http://127.0.0.1:9222`. Tell it plain: *"watch this session and call out any vulnerabilities as I browse."*
3. Use the app. The session reads each request and each answer as it comes and names the findings. You drive. It watches.

---

## Install

The core needs nothing. Live watching needs one more thing.

```bash
# core taxonomy + offline HAR scanning — ZERO dependencies
pip install .

# live watch also needs a WebSocket client
pip install '.[live]'
```

Python 3.10 or better. The offline path runs on the standard library alone.
Every detector. The ledger. `scan-har`. Good for a locked-down box.

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

### 3. Watch one tab for a while

```bash
overwatch watch --tab oreilly --seconds 120
# passive only — 120s budget, 5000 exchange cap
#   [+] [High]   Wildcard entitlement in `privileges`  — https://.../session
#   [+] [Medium] Real account identifier(s) sent to analytics.google.com  — ...
#   [+] [Low]    GCS pre-signed URL leaks signer identity  — ...
```

Now use the app for those two minutes. Overwatch reports what went past. Sorted
by weight. Deduped. Every live credential cut short.

### 4. Or read a saved capture

```bash
overwatch scan-har session.har --json
```

It runs the same detectors on a HAR export. "Save all as HAR" in DevTools, or a
proxy dump. No browser needed. Good for a capture handed to you, or one made
earlier.

---

## The finding taxonomy

Every tell on the wire points to a VDT page that explains it and fixes it. The
detectors are careful. A tell is a candidate, and Overwatch says so. **Surface
open is not access exercised.** To prove an IDOR, or how far a wildcard reaches,
you go back and do it on purpose. The passive pass does not.

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

A detector is one function, `(Exchange) -> Iterable[Finding]`, in
`overwatch/detectors.py`, added to `ALL_DETECTORS`. It does not change the
exchange. It does not send traffic.

---

## The restraint ethic

- **Passive only.** No detector and no command ever sends a crafted request. The
  watcher knows two words: `Network.enable` and `getResponseBody`.
- **Cut the credentials short.** Every string that reaches the output goes
  through `overwatch.redact`. JWTs, cloud signatures, bearer tokens, session
  cookies. All become stubs you can read but not use. The report shows the claim,
  not the secret.
- **Names, not theft.** A finding is metadata. A shape. A header. A name. A name
  is the finding, and you show it — a service-account email, your own account
  UUID. A credential you hide — the signature that would let you replay. Name the
  infrastructure. Hide the key.
- **Captures stay out.** `.gitignore` blocks `*.har` and `*.network-*`. Redaction
  guards the reports. The raw captures hold real credentials, so they never come
  in at all.
- **The scope is yours.** The tool cannot tell an allowed session from one that
  is not. Only you can. Watch only what you own or are cleared to watch.

---

## Proof of concept

[`poc/oreilly-enterprise-session.md`](poc/oreilly-enterprise-session.md) — a real
run on an allowed, logged-in **enterprise** O'Reilly Learning session. One
ordinary pass turned up 13 findings across some 13 services. All metadata. All
credentials cut short. This is the run that made the taxonomy.

---

## Origin

Overwatch started as a note in the
[VDT-INFO-LEARN](../VDT-INFO-LEARN/tools/overwatch.md) knowledge base. A way of
working, written down to teach. It became its own tool because the idea is worth
keeping alone: ride the real session, and read what the app already tells you.
Now the restraint lives in the code, not only in the note.
