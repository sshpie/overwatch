# PoC — O'Reilly Learning (enterprise), authenticated session

**What this is.** A real Overwatch run: a human logged into an **authorized,
enterprise** O'Reilly Learning account, opened an interactive lab, and used the
platform normally for a couple of minutes while Overwatch rode the session over
CDP. One ordinary browsing pass surfaced **13 findings across ~13 microservices**
— none from a crafted request, all from traffic the app generated on its own.

**Redaction note (read first).** This case study applies Overwatch's own
restraint ethic *to itself*. Two classes of value appear differently:

- **Vendor infrastructure identifiers are shown** — they *are* the findings, and
  they describe O'Reilly / Katacoda infrastructure, not a person: the Katacoda
  GCP service account and bucket, the GA4 measurement ID (embedded in every page
  O'Reilly serves), the internal microservice codenames.
- **The operator's personal identifiers are masked** — the real profile UUID,
  org/account UUID, and live session tokens observed on the wire are replaced
  with `<profile-uuid>` / `<org-uuid>` / `st__<redacted>`. They were present and
  are the substance of findings 3 and 5, but publishing a case study is a
  different context than an operator reading a report about their own session.
  The finding is stated in full; the live identifier is not shipped to a public
  repo.

This is exactly the identifier-vs-credential line the tool enforces in
`overwatch/redact.py` — extended, for a *published* artifact, to also mask the
operator's own account identifiers.

---

## The environment

O'Reilly's interactive labs run on **acquired Katacoda infrastructure**. The tells
made the acquisition legible from the outside:

```
learner browser ──► learning.oreilly.com ──► istio-envoy service mesh
                                              ├─ interactive_lab_content   (orm-service hdr)
                                              ├─ interactive_chronicles    (activity events)
                                              ├─ card_service              (content cards)
                                              ├─ coot                      (usage metering)
                                              ├─ loon
                                              └─ miso_answers_relay_service (AI Q&A)
                                                       │
   lab backend ◄── socket.io term.js ──────────────────┘
   ubuntu:22.04 container, ~60-min lifetime, {{execute}} command protocol
   assets ◄── GCS pre-signed URLs ── bucket: inka-lab-assets
                                     project: katacoda-core-infrastructure
```

---

## The 13 findings

Severity is Overwatch's default per detector; `(candidate)` marks a tell that is
a *lead*, not a confirmed exploit — **surface open ≠ access exercised**.

| # | Finding | Detector | Severity | VDT class |
|---|---|---|---|---|
| 1 | Kaltura session grants `sview:*` — a wildcard entitlement over the whole partner catalog, not just the entitled asset | `wildcard-entitlement` | **High** | access-control |
| 2 | Interactive-lab backend gives the learner a **root-controlled Docker daemon**; container-escape / isolation boundary untested (candidate) | manual | **Medium** | hardening / container-isolation |
| 3 | Real account UUID + org UUID + `e_learning_account_type=enterprise` shipped **in plaintext to Google Analytics** (`G-4WZYL59WMV`) | `pii-to-third-party` | **Medium** | information-disclosure |
| 4 | AI answer-relay (`miso_answers_relay_service`) surface — model Q&A roster reachable from the session (reasoning-leak candidate) | `ai-reasoning-leak` | **Medium** | information-disclosure |
| 5 | GCS pre-signed asset URLs name the **signer SA, project, and bucket** (`katacoda-editor@katacoda-core-infrastructure.iam.gserviceaccount.com`, `inka-lab-assets`) | `presigned-url-infra` | **Low** | [presigned-url-infrastructure-disclosure](../../VDT-INFO-LEARN/information-disclosure/presigned-url-infrastructure-disclosure.md) |
| 6 | Datadog RUM **public client token** (`pub…`) in the browser telemetry request | `public-client-token` | **Low** | information-disclosure |
| 7 | Scenario IDs are sequential (`urn:orm:scenario:9781098119232`) — question-bank / scenario **IDOR candidate** | `idor-uuid-in-path` | **Low** | access-control |
| 8 | `orm-jwt` (RS256) on the wire — claims decode to profile UUID, org UUID, `individual:false`, `perms` incl. `scnrio:v` | `jwt-exposure` | Info | access-control |
| 9 | Katacoda session token `st__<redacted>` present in client-visible request bodies | manual | Info | information-disclosure |
| 10 | Internal **microservice codenames** leaked via the `orm-service` response header (`interactive_lab_content`, `card_service`, `coot`, `loon`, …) | `version-banner` | Info | version-banner-leakage |
| 11 | `istio-envoy` service-mesh fingerprint on responses — confirms the mesh + sidecar topology | `version-banner` | Info | version-banner-leakage |
| 12 | Backend container image + lifetime disclosed (`ubuntu:22.04`, ~60-min TTL) via lab-content metadata | manual | Info | information-disclosure |
| 13 | **Meta-finding:** GA4 gets the *real* account UUID while Datadog gets a *pseudonymized* `anonymous_id` — the inconsistency is the tell that #3 is an oversight, not policy | correlation | Info | information-disclosure |

---

## The three that matter, in detail

### #1 — Kaltura `sview:*` wildcard entitlement (High)

The video player's session response carried a privileges field shaped like
`"privileges":"sview:*"`. The `*` is the whole finding: a session entitled to
*one* video presents an entitlement string that names *view on any asset in the
partner account*. Overwatch flags any scope/privilege value containing a
wildcard as **High** because the blast radius is an entire class, not one object.

- **What:** over-broad entitlement wildcard in a per-asset session token.
- **Why it matters:** if the player trusts the client-presented scope, a user
  entitled to one asset can address the partner's whole catalog.
- **Verification discipline:** Overwatch *observed* the wildcard; it did **not**
  exercise it against a second asset. Reported as "surface open, access not
  exercised." Confirming reach is a deliberate follow-up, not the passive pass.
- **Fix:** issue per-asset scopes (`sview:<assetId>`); never a class wildcard to
  a client-held token.

### #3 — Real account UUID + enterprise flag to Google Analytics (Medium)

On page analytics beacons, the GA4 collect URL
(`analytics.google.com/g/collect?tid=G-4WZYL59WMV…`) carried:

```
uid          = <profile-uuid>        ← real, stable account identifier
up.org_id    = <org-uuid>            ← the enterprise org
e_learning_account_type = enterprise ← account tier
```

The same session's **Datadog** telemetry, by contrast, used a pseudonymized
`anonymous_id` — so the org *has* a de-identification pattern; GA4 just didn't
get it. That inconsistency (finding #13) is what turns "PII in analytics" from a
maybe into a confirmed oversight.

- **Why it matters:** a stable, real customer + org identifier and their
  enterprise status land in a third-party analytics property in plaintext,
  correlatable across every page and outside the org's data boundary.
- **Fix:** send GA4 the same pseudonymized surrogate Datadog already gets; never
  ship the raw account/org UUID or tier to a third party.

### #5 — GCS pre-signed URL names its signer (Low)

Lab assets loaded from `storage.googleapis.com/inka-lab-assets/…` via pre-signed
URLs. The signing parameters are self-describing:

```
X-Goog-Credential = katacoda-editor@katacoda-core-infrastructure.iam.gserviceaccount.com
                    └ signer SA ──────┘ └ GCP project ─────────────┘
bucket            = inka-lab-assets
X-Goog-Signature  = AAAA…<redacted-sig>   ← the actual secret — truncated
```

- **Why it matters:** free cloud recon. The URL alone yields the signing service
  account, the GCP project (`katacoda-core-infrastructure` — a legible fossil of
  the Katacoda acquisition), and the asset bucket — a starting map for bucket-ACL
  enumeration or an IAM pivot, with no auth and no noise.
- **Restraint in the output:** the SA email and bucket **are shown** (they're the
  finding), the `X-Goog-Signature` **is redacted** (it's the secret that would
  authorize a download). Name the infra, redact the key.
- **Fix:** front assets with a CDN / signed-cookie scheme so the object URL never
  exposes the signer identity; or use a dedicated, least-privilege signer whose
  name reveals nothing about project topology.

Full class writeup:
[`../../VDT-INFO-LEARN/information-disclosure/presigned-url-infrastructure-disclosure.md`](../../VDT-INFO-LEARN/information-disclosure/presigned-url-infrastructure-disclosure.md).

---

## Positive controls (what was done *right*)

A passive pass reports the clean signals too — absence of a finding is a finding:

- **`interactive_chronicles` CORS was correctly scoped** — not a wildcard;
  `wildcard-cors` did **not** fire on it. A deliberate, narrow origin allowlist.
- **Sandbox usage-events carried no `attribution_map`** — the client relays the
  event; the *server* computes attribution. The sensitive mapping never reached
  client JS. Correct trust placement.
- **Datadog telemetry was pseudonymized** — the `anonymous_id` pattern shows the
  org knows how to de-identify; it's what makes the GA4 leak (#3) legibly an
  oversight rather than an accepted policy.

---

## What the run demonstrates about the method

- **One human session, ~2 minutes, zero crafted requests → 13 findings.** The app
  volunteers its own attack surface in normal use; Overwatch just reads it.
- **The tells map cleanly to VDT classes.** Every row above routes to a knowledge-
  base page that explains and fixes the class — the taxonomy is the point, not
  the individual bug.
- **Restraint held throughout.** Wildcard observed, not exercised (#1). IDOR
  shape noted, not walked (#7). Signature redacted, signer named (#5). Operator's
  own account UUIDs masked for publication (#3, #5, #8). The report carries the
  *claims*; it carries none of the *secrets*.
