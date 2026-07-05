# ORKS
Open standard API Spec - ORKS (Open Revocable Key Standard)


# Open Revocable Key Standard (ORKS)
 
**Draft v0.1 — Discussion Document**
Status: Pre-standard sketch, seeking feedback
Requirement keywords (MUST, SHOULD, MAY) per RFC 2119.
 
---
 
## 1. Abstract
 
ORKS defines an open convention for issuing API keys that are (a) attributable to their issuer by inspection, (b) revocable by anyone in possession of them via a discoverable endpoint, and (c) optionally subject to a **quarantine delay** that protects key owners from malicious or accidental revocation while still neutralizing leaked credentials quickly.
 
The goal: when a key is found in a public repo, paste site, or log file, any party — the owner, a scanner, or a good-samaritan researcher — can neutralize it in seconds, with zero human back-and-forth, without knowing anything about the issuer in advance.
 
## 2. Motivation
 
- OAuth 2.0 has RFC 7009 (token revocation) and OIDC Discovery. Plain API keys — the most commonly leaked credential class — have no equivalent.
- Today's leak response is manual: identify the provider, find a security contact, email, wait. Hours-to-days of exposure.
- GitHub's Secret Scanning Partner Program proves the model works (provider-registered patterns + revocation webhooks) but is proprietary, centralized, and invite-only. ORKS decentralizes it.
## 3. Key Format
 
### 3.1 Structure
 
```
orks_{issuer}_{secret}_{check}
```
 
| Segment | Description |
|---|---|
| `orks` | Fixed literal prefix identifying an ORKS-conformant key. Issuers MAY append a vendor tag (e.g. `orks-live`, `orks-test`). |
| `issuer` | The issuer's domain, base32-encoded (lowercase, no padding). Enables offline attribution. |
| `secret` | ≥ 128 bits of CSPRNG entropy, base62-encoded. |
| `check` | CRC32 of the preceding segments, base62-encoded. Eliminates scanner false positives; carries no security value. |
 
### 3.2 ABNF (informal)
 
```
orks-key   = "orks" [vendor-tag] "_" issuer "_" secret "_" check
vendor-tag = "-" 1*8(ALPHA / DIGIT)
issuer     = 1*64(base32-lower)
secret     = 22*86(base62)
check      = 6(base62)
```
 
### 3.3 Properties
 
- A scanner that finds a matching string can: validate the checksum offline, decode the issuer domain, fetch the issuer's discovery document, and act — all without a registry.
- The checksum MUST NOT be treated as authentication. Possession of the full key string is the only credential.
## 4. Discovery
 
Issuers MUST serve a JSON document at:
 
```
https://{issuer}/.well-known/api-key-config
```
 
Example:
 
```json
{
  "orks_version": "0.1",
  "issuer": "api.example.com",
  "revocation_endpoint": "https://api.example.com/orks/revoke",
  "introspection_endpoint": "https://api.example.com/orks/introspect",
  "security_contact": "mailto:security@example.com",
  "revocation_modes": ["immediate", "quarantine"],
  "quarantine_delay_seconds": 86400,
  "quarantine_restrictions": ["read_only", "rate_limited"],
  "supported_constraints": ["ip_allowlist", "expiry", "scopes", "mtls"],
  "documentation": "https://example.com/docs/api-keys"
}
```
 
Requirements:
 
- MUST be served over TLS with `Content-Type: application/json`.
- SHOULD be cacheable (`Cache-Control`) for at least 1 hour.
- The `security_contact` field gives responders a fallback channel, mirroring RFC 9116 (security.txt).
## 5. Revocation Endpoint
 
### 5.1 Request
 
```
POST /orks/revoke
Content-Type: application/json
 
{
  "key": "orks_nfxgg...._abc123",
  "mode": "quarantine",
  "reason": "found_in_public_repository",
  "evidence_url": "https://github.com/acme/app/blob/main/config.js#L14",
  "reporter_contact": "mailto:researcher@example.org"
}
```
 
- `key` (REQUIRED): the complete key string. Partial keys MUST be rejected — requiring the full secret means only parties who could already abuse the key can revoke it ("possession implies revocation right").
- `mode` (OPTIONAL): `immediate` or `quarantine`. If omitted, the issuer applies its advertised default. Issuers MAY ignore a requested `immediate` from unauthenticated callers and downgrade to `quarantine` (see §6).
- `reason`, `evidence_url`, `reporter_contact` (OPTIONAL): forwarded to the key owner in the notification.
### 5.2 Response
 
```
HTTP/1.1 200 OK
 
{ "status": "accepted", "mode_applied": "quarantine", "hard_revoke_at": "2026-07-04T18:00:00Z" }
```
 
- Issuers MUST return `200` with `"status": "accepted"` for both valid-and-processed keys **and** unknown/already-revoked keys, to prevent the endpoint from being used as a key-validity oracle. (`mode_applied` and `hard_revoke_at` MAY be synthesized for unknown keys.)
- The endpoint MUST NOT require authentication.
- Issuers MUST rate-limit aggressively (per-IP and global) and SHOULD require the checksum to validate before doing any database lookup, making bulk-guess attacks computationally useless.
## 6. Quarantine Delay (Optional Mode)
 
The quarantine mode addresses the primary objection to unauthenticated revocation: **a leaked key becomes a griefing vector** — an attacker who finds (or is given) a key could instantly break production. Quarantine converts "instant outage" into "supervised wind-down."
 
### 6.1 State Machine
 
```
ACTIVE ──(revoke: immediate)──────────────► REVOKED
ACTIVE ──(revoke: quarantine)──► QUARANTINED ──(timer expires)──► REVOKED
                                     │
                                     ├──(owner cancels + acknowledges)──► ACTIVE
                                     └──(owner expedites)──► REVOKED
```
 
### 6.2 Behavior in QUARANTINED state
 
On entering quarantine, the issuer:
 
1. **MUST notify the key owner immediately** via all registered channels (email, webhook, dashboard alert), including the `reason`, `evidence_url`, and time of hard revocation.
2. **SHOULD apply immediate restrictions** while the timer runs, chosen from its advertised `quarantine_restrictions` — e.g. force read-only scopes, drop rate limits to a trickle, block destructive/financial operations, log all usage with source IPs. This narrows the attacker's window even though the key still "works."
3. **MUST hard-revoke** when `quarantine_delay_seconds` elapses (advertised in discovery; RECOMMENDED default 24h, MUST NOT exceed 72h).
### 6.3 Owner controls
 
- **Cancel**: The owner MAY cancel quarantine through an authenticated channel (dashboard/API). Cancellation MUST require explicit acknowledgment of the leak evidence, and the issuer SHOULD strongly prompt rotation — canceling on a genuinely leaked key is almost always the wrong call, and the UI should say so.
- **Expedite**: The owner MAY convert quarantine to immediate revocation at any time.
- Repeated cancel-after-report cycles on the same key SHOULD trigger escalation (e.g. account security review).
### 6.4 Choosing a default mode
 
- Issuers SHOULD default third-party (unauthenticated) revocations to `quarantine`.
- Issuers SHOULD honor `immediate` when the request arrives through an authenticated owner channel.
- High-risk key classes (payment, admin) MAY be configured for immediate revocation always — the discovery document's `revocation_modes` communicates this.
### 6.5 Self-Revocation and Task-Scoped Keys
 
Autonomous holders — AI agents especially — often need a credential only for the duration of a task. ORKS supports treating revocation as the natural end of a key's life, not just an emergency response:
 
- Holders SHOULD revoke their own keys upon task completion by POSTing to the revocation endpoint with `"reason": "task_complete"`.
- Because the issuer cannot distinguish a legitimate holder from an attacker at the revocation endpoint, `task_complete` alone MUST NOT bypass the issuer's default quarantine policy. Instead, owners MAY opt in **at issuance** by minting the key with a `self_revoke: "immediate"` policy. Keys of this class are hard-revoked instantly on any possession-based revocation request — the owner has pre-declared that this credential is disposable and that availability-griefing is a non-concern for it.
- Issuers supporting this SHOULD advertise `"issuance_policies": ["self_revoke_immediate"]` in the discovery document.
- Orchestration frameworks SHOULD issue task-scoped keys with both `self_revoke: "immediate"` and a short `expiry`, so revoke-on-completion is the fast path and TTL is the backstop when an agent crashes before cleanup.
This gives agents least-privilege in the time dimension: a key found in a log after its task finished is already dead, and the revocation call itself doubles as an auditable "task released its credentials" event.
 
## 7. Introspection Endpoint (Optional)
 
```
POST /orks/introspect
{ "key": "orks_...." }
```
 
Returns minimal, non-sensitive state: `{"state": "active" | "quarantined" | "revoked" | "unknown"}` plus `hard_revoke_at` when quarantined. The full key MUST be required (anti-enumeration). Issuers MAY omit this endpoint entirely; scanners use it to prioritize findings.
 
## 8. Constraint Declarations
 
`supported_constraints` advertises which bindings the issuer can attach to keys at creation:
 
| Constraint | Meaning |
|---|---|
| `ip_allowlist` | Key valid only from declared CIDRs |
| `expiry` | Mandatory max TTL supported |
| `scopes` | Fine-grained permission subsets |
| `mtls` | Key bound to a client certificate |
| `referrer` | Browser-context origin restriction |
 
This turns key hygiene into an auditable procurement question: "does this vendor support IP-pinned keys?" is answerable with one GET.
 
## 9. Security Considerations
 
- **Revocation DoS / griefing**: mitigated by quarantine delay (§6), rate limiting, and full-key requirement. Vault/OpenBao chose to authenticate their proof-of-possession revocation endpoint for exactly this reason; ORKS instead keeps the endpoint open (so strangers can act on leaks) and absorbs the risk with delay + restriction.
- **Enumeration**: uniform `200 accepted` responses, full-key requirement, checksum-first validation.
- **Attacker-visible prefixes**: self-identifying keys are also easier for attackers to grep. This trade is accepted: attackers already fingerprint keys by entropy and context; identifiability primarily accelerates defenders and automated scanners.
- **Delay window is attacker window**: if the leak is real, quarantine leaves a restricted-but-live key for up to the delay period. §6.2's restriction requirement exists to shrink this; issuers with low tolerance should advertise and use `immediate`.
- **Notification channel compromise**: if the attacker controls the owner's email, they could cancel quarantine. Cancellation therefore requires the authenticated dashboard, not an email link.
## 10. Prior Art
 
RFC 7009 (OAuth token revocation), RFC 8615 (well-known URIs), RFC 9116 (security.txt), OIDC Discovery, GitHub Secret Scanning Partner Program, GitHub token prefixes + CRC32 checksums, Stripe key prefixes, Vault/OpenBao PoP certificate revocation.
 
## 11. Open Questions and Proposed Resolutions
 
### 11.1 Issuer segment: raw domain vs. base32
 
**Proposed: raw lowercase domain.** Base32 was solving a charset problem domains don't actually have — DNS labels are already lowercase alphanumerics, hyphens, and dots, all of which are safe in header values and shell strings, and none of which collide with the `_` delimiter (underscores never appear in hostnames). Raw domains make keys human-attributable at a glance (`orks_api.stripe.com_...`), which matters during incident response when a responder is staring at a log line, not running a decoder. Internationalized domains MUST be encoded as punycode (their on-the-wire DNS form). The checksum segment already covers integrity. Resolution: v0.2 drops base32; the `issuer` segment is the raw punycode-normalized domain.
 
### 11.2 Quarantine event webhooks
 
**Proposed: adopt Shared Signals, don't invent one.** v0.1 deliberately requires notification without specifying transport. For v0.2, rather than defining a bespoke webhook format, ORKS should profile the OpenID Shared Signals Framework (SSF) and CAEP, which already standardize signed Security Event Tokens for exactly this class of signal — CAEP's credential-change event maps almost directly onto quarantine/revoke transitions. Issuers advertise an SSF transmitter in the discovery document (`"event_stream": "https://..."`); SIEMs and agent orchestrators subscribe with existing SSF receivers instead of custom integrations. Plain HTTPS webhook delivery remains a MAY for issuers that don't want the SSF machinery, but the event payload schema is shared either way.
 
### 11.3 Signed key variant (offline constraint verification)
 
**Proposed: out of scope; keep as a future optional profile.** A JWT/PASETO-style key would let gateways verify constraints without calling introspection, but it triples key size, invites the classic mistake of treating key contents as trusted policy after revocation, and — most importantly — breaks the "thirty seconds to integrate" property that explains why plain keys dominate in the first place. ORKS's core value is a kill switch for the keys the world actually uses; constraint enforcement stays issuer-side. If demand materializes, a separate `orksj_` profile can be layered on later without touching the base spec. Resolution: rejected for core; parked as an extension.
 
### 11.4 Registry vs. convention for `reason` codes and constraint names
 
**Proposed: a lightweight public registry with an escape hatch.** Pure convention guarantees collisions ("does `ip_allowlist` mean CIDRs or exact IPs?"); a full IANA registry is too heavy for a v0.x spec and would stall momentum. Middle path: a registry file in the spec's public repository, amended by pull request under expert review — the same lightweight model that has kept the well-known URI and security.txt ecosystems coherent. Unregistered experimental values MUST use an `x-` prefix (`x-vendor_geo_fence`) so parsers can distinguish standard from private semantics. If ORKS later goes through the IETF, the repo registry migrates to IANA wholesale. Resolution: repo-based registry seeded with the §5.1 reason codes and §8 constraint names.
