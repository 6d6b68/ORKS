# ORKS — Research Notes

Working notes behind the spec. Newest first. Each entry: what was found, why it matters to ORKS, where it landed in the README.

---

## 2026-11-06 — Landscape review since v0.1 (Sept 2026)

**Bottom line:** no competing open standard for API-key revocation discovery has appeared; no IETF draft in this space. The field is empty, but the ecosystem is now shipping *ad-hoc* versions of the interfaces ORKS specifies (Truffle's program, GitHub partner forwarding). The risk is a proprietary scanner-side interface becoming de facto before an open issuer-side one exists.

### Truffle Security — Secrets Revocation Program (announced 2026-11-04)
- Free, early access, for any credential issuer. Two integration modes: (1) issuer exposes a revocation endpoint Truffle calls directly; (2) Truffle webhooks the issuer with live keys + discovery locations, issuer must revoke or explain within **14 days**.
- 16 issuers at launch incl. Hugging Face, Notion, Vercel, Resend, RubyGems, Twilio. ~1.4M verified live leaked credentials in scope; 43,699 held for issuers not yet enrolled.
- Data: 81% of keys reported in 2025 still live 6 months later. Aug 2026 re-check of 64,024 leaked AWS keys: 88% still active, median age ~5 yrs, 768 full-admin, **929 already under AWS compromised-key quarantine (some 3+ yrs)**.
- No published payload schema, auth model, or discovery mechanism. Scanner-centric: issuers integrate with Truffle, not with "anyone holding the key."
- → README §11.7 (report tier), §9 (quarantine ≠ safe state), §11.11, §10.
- Action: reach out — they are the natural first adopters, and ORKS's `/revoke` + `report_endpoint` is a drop-in for both of their modes.
- Links: https://joho-todai.com/en/truffle-security-14-million-leaked-api-keys-revoked/ · https://windowsforum.com/news/truffle-security-launches-free-api-key-revocation-program-as-1-4-million-leaked-keys-remain-live.451103/ · trufflesecurity.com/blog/launching-the-secrets-revocation-program

### Demir, Vekaria, Smaragdakis, Durumeric — "Keys on Doormats: Exposed API Credentials on the Web" (CCS 2026)
- Sept 2025 HTTP Archive crawl, 11.9M hostnames. ~2M regex candidates, **1,748 verified live** (0.09%) across 14 services. Most FPs from GitHub's broad pattern.
- 84% in first-party JS, 62% of those in build bundles (webpack env-var baking). Operators often thought the key was safe to expose.
- Exposure persists ~12 months avg. Notification (9,746 emails via security.txt / role addresses): removals −50% by day 14, **revocations only −26%**.
- Distinctive formats verify far better (Telegram 85%).
- Issuer recommendations: minimal default perms, short-lived/per-env keys, auto-rotation, **distinct client-side keys** (scoped, rate-limited, origin-bound, easy to revoke).
- → §11.9 (publishable class), §11.11, §10.
- Link: https://arxiv.org/pdf/2603.12498

### Apache Software Foundation — Scannable Secret Token Standard (draft, 2026)
- Format `^asf_([a-z]{3,6})_([0-9A-Za-z]{27})([0-4][0-9A-Za-z]{5})$`. 27×base62 entropy (~160.76 bits), 6×base62 CRC-32 suffix, underscores so double-click selects the whole token, token68-compatible for DPoP (RFC 9449).
- Checksum fully specified: CRC-32 over the **ASCII text** of the entropy chars, poly `0xEDB88320`, init/xor `0xFFFFFFFF`, base62 MSB-first, left-pad `0` to 6. Max encodes to `4gfFC3` → first checksum char is `0-4`. Test vector: 27×`0` → `2MvMGi` (verified locally with `zlib.crc32`).
- Internal-only scope (ASF-built apps), no revocation/discovery/reporting. Component = issuer namespace from an approved list (URL placeholder, unfilled).
- → §11.6. ORKS adopts the algorithm verbatim so one validator serves both; ORKS vector `orks_api.example.com_4Zq9mLpX2vR7tK1sB8nW3cD6fH0jY5aE` → `15KzgI`.
- Link: https://tooling.apache.org/draft-asf-token-standard

### OpenID — CAEP Interoperability Profile 1.0, draft 01 (2026-07-21)
- Conformance = at least one of: session-revoked, **credential-change**, device-compliance-change. `credential-change` receivers must handle all `change_type`/`credential_type` values; transmitters must populate non-empty `reason_admin`.
- Subject IDs (RFC 9493): `email` and `iss_sub` required; `opaque` only for verification events. Neither fits a bearer API key.
- Transport: SSF push (RFC 8935) / poll (RFC 8936), RS256 ≥2048-bit, one event per SET, OAuth client-credentials or auth-code for stream mgmt, access tokens ≤60 min, scopes `ssf.read`/`ssf.manage`.
- Does **not** address API keys / non-human credentials; `credential_type` values not enumerated in the profile.
- → §11.8 resolves §11.2 with a mapping table. Two gaps to file with the SSF WG: `credential_type: api_key`, and an `opaque` subject = SHA-256(full key).
- Links: https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html · https://openid.net/specs/openid-caep-1_0.html

### GitHub secret scanning changes (Oct 2026)
- 2026-10-13: `anthropic_service_api_key` / `anthropic_user_api_key` blocked by push protection by default; Salesforce joins partner program; partner secrets found in public repos are forwarded to the provider to "revoke or rotate before it can be abused." Mechanism and SLA unpublished.
- 2026-10-28: push protection now blocks secrets with **no predefined pattern** via a context-aware classifier (built with Microsoft Applied Sciences); public preview, opt-in, consumes AI credits; more than doubled catches. Agents must obtain authorization before bypassing a block.
- 2026-10-07: purpose-built model for leaked-secret detection.
- → §9 reframing (prefix = attribution/routing, not detection); §11.10 (agents must not self-cancel quarantine, by analogy).
- Links: https://github.blog/changelog/2026-10-13-secret-scanning-blocks-anthropic-keys-by-default-adds-salesforce · https://github.blog/changelog/2026-10-28-push-protection-beyond-predefined-secret-patterns · https://github.blog/changelog/2026-10-07-purpose-built-model-for-leaked-secret-detection

### Agent identity / credentials literature (2026)
- MCP authorization (OAuth 2.1 + PKCE), delegated scopes, short TTLs, workload identity — all about **issuance**. Nothing on **release** of credentials at task end. §6.5's "revoke-on-completion doubles as an audit event" has no competitor; keep it.
- IETF `draft-illyes-webbotauth-jafar-01` (Oct 2026) is only a JSON format for publishing crawler IP ranges — not auth, not relevant despite the name.
- Links: https://blog.gitguardian.com/ai-agents-authentication-how-autonomous-systems-prove-identity/ · https://aembit.io/blog/mcp-oauth-2-1-pkce-and-the-future-of-ai-authorization/ · https://datatracker.ietf.org/doc/draft-illyes-webbotauth-jafar/

### Other
- Gitee exposure (Oct 2026): 26,400 valid cloud + AI credentials in public repos, incl. OpenAI and DeepSeek. More motivation data. https://thehackernews.com/2026/10/26400-valid-cloud-and-ai-credentials.html
- Coverage of ORKS v0.1: SecurityWeek (2026-09-09), Polish/Dutch trade press, news4hackers, Offseq radar. No substantive public critique found yet.

### Open items
- [ ] Contact Truffle Security re: ORKS as the open interface for both of their integration modes.
- [ ] File `credential_type: api_key` + opaque-SHA-256 subject proposal with the OpenID Shared Signals WG.
- [ ] Decide whether §11.7 `report_endpoint` is a v0.2 MUST-advertise-one-of (`report_endpoint` | `revocation_endpoint`) or stays optional.
- [ ] Reference implementation: a ~50-line validator (regex + CRC-32) scanners can vendor; publish test vectors alongside.
- [ ] Fold §11.1 (raw domain) and §11.6 (checksum) into §3 for the v0.2 draft rather than leaving them as resolved open questions.
