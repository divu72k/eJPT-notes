# JWT Testing Notes — Offensive Security Reference

Working notes for testing JSON Web Token implementations during authorized web/API application assessments. Structured as: primer → recon → vulnerability classes → tooling → checklist → reporting language.

---

## 1. JWT Structure Primer

A JWT is three base64url-encoded segments joined by dots: `header.payload.signature`

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

- **Header** — declares `alg` (signing algorithm) and `typ`. May also carry `kid` (key ID), `jku` (JWK Set URL), `jwk` (embedded public key), `x5u`/`x5c` (X.509 cert references).
- **Payload** — claims. Standard ones: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`. Everything else is application-defined and frequently where sensitive data or authorization decisions leak into the token.
- **Signature** — proves integrity/authenticity, computed over `base64url(header) + "." + base64url(payload)` using the algorithm in the header.

**Core testing mindset:** the client can read and rewrite all three segments trivially. Every security property of a JWT depends entirely on the server correctly and rigidly validating the signature against a fixed, expected algorithm and key. Almost every JWT vuln class is a variation of "the server trusted something it shouldn't have."

---

## 2. Recon Before Attacking

- Decode header + payload (CyberChef, `jwt_tool -T`, or Burp's built-in JWT decoder in the Inspector panel).
- Note the `alg` value — RS256/ES256 (asymmetric) vs HS256 (symmetric) changes the entire attack surface.
- Check for `kid`, `jku`, `jwk`, `x5u`, `x5c` in the header — each is a potential injection point.
- Identify what claims drive authorization (role, tenant ID, user ID, scope) vs. what's just informational.
- Check token lifetime (`exp` vs `iat`) — is it long-lived? Is there a refresh token, and is *that* also a JWT?
- Determine where the token is transmitted/stored: `Authorization: Bearer`, cookie, `localStorage`? (Storage location matters for impact — XSS-stealable tokens escalate severity of everything else.)
- Grab two tokens from two different accounts/roles if possible — makes structural comparison and forgery testing much faster.
- Find the public key if RS/ES algorithm is used — often published at a `/.well-known/jwks.json` or similar endpoint. Save it; you'll need it for algorithm confusion.

---

## 3. Vulnerability Classes

### 3.1 `alg: none`
**Root cause:** some JWT libraries, if not explicitly configured otherwise, will accept a token with `"alg": "none"` and an empty signature segment as valid, since "none" is technically part of the JWS spec for unsecured JWTs.

**Test:** Take a valid token, change the header to `{"alg":"none","typ":"JWT"}`, modify payload claims as desired (e.g., `"role":"admin"`), base64url-encode both, and submit with an **empty** third segment (trailing dot, nothing after it): `header.payload.`

**Variants to try if the exact string is filtered:** `None`, `NONE`, `nOnE` — some parsers do case-sensitive matching only against `"none"` and miss variants.

**Detection of the flaw without full exploitation:** if the server returns a *different* error for a garbage signature vs. a well-formed-but-empty one, that's a signal the alg-none path is handled separately in code — worth pushing further.

**Impact:** complete authentication/authorization bypass — forge any claim, any user, any role.

---

### 3.2 Algorithm Confusion (RS256 → HS256)
**Root cause:** when a server is configured to expect RS256 (asymmetric — sign with private key, verify with public key) but the verification library doesn't pin/enforce the expected algorithm, an attacker can craft a token with `alg: HS256` and sign it using the **public key** (readable, often published) as the HMAC secret. The server, verifying with what it thinks is "the key" using whatever algorithm the *token* claims, ends up computing `HMAC-SHA256(data, public_key)` — which the attacker can compute too, since the public key is, by definition, public.

**Steps:**
1. Obtain the server's RSA public key (JWKS endpoint, TLS cert, config leak, or a `jku`/`x5u` you control).
2. Normalize the key's exact byte representation — PEM formatting (line endings, header/footer, trailing newline) must match exactly what the server would use internally, or the HMAC won't match.
3. Change header `alg` to `HS256`.
4. Modify payload claims.
5. Sign with `HMAC-SHA256(base64url(header) + "." + base64url(payload), public_key_bytes)`.
6. Submit.

**Tooling:** `jwt_tool -X k` automates this end to end once you supply the public key file.

**Why it works conceptually:** the vulnerability isn't cryptographic weakness, it's a validation-logic bug — the server's verify function is algorithm-agnostic when it should be pinned to exactly one algorithm and one key type.

---

### 3.3 Weak / Brute-Forceable HMAC Secret
**Root cause:** HS256 secrets are sometimes short, default, or dictionary words (`secret`, `changeme`, company name, framework default).

**Test:** Extract the signing input (`header.payload`) and signature, run offline cracking:
```
hashcat -a 0 -m 16500 jwt.txt rockyou.txt
```
or `jwt_tool -C -d wordlist.txt` for a more targeted JWT-aware brute force including common secret patterns (`{app_name}_secret`, etc.).

**Impact:** once cracked, you can forge arbitrary tokens exactly as with `alg:none`, just properly signed — likely to survive more scrutiny/logging than an alg:none attempt.

---

### 3.4 `kid` (Key ID) Header Injection
**Root cause:** servers often use the `kid` header value to look up which key to verify against — e.g., a filename, a database row, or a cache key. If that lookup isn't sanitized, `kid` becomes an injection point.

**Variants to test:**
- **Path traversal:** `"kid": "../../../../dev/null"` — if the app reads the key from a file path and `/dev/null` is readable-but-empty, the "key" becomes an empty string, which you can then sign with (`HMAC-SHA256(data, "")`).
- **SQL injection:** `"kid": "nonexistent' UNION SELECT 'attacker_known_value'--"` if `kid` feeds a DB query for the key, potentially letting you set the key to a value you already know.
- **Command/SSRF injection:** if `kid` is used to fetch a key from a URL or shell out, standard SSRF/command injection testing applies.

**Process:** always test `kid` like any other user-controlled input funneling into a file path, DB query, or URL fetch — the fact that it's inside a JWT header doesn't exempt it from standard injection methodology.

---

### 3.5 `jwk` / `jku` / `x5u` Header Abuse
**Root cause:** these headers let the token *declare where its own verification key lives* — `jwk` embeds the public key directly in the header; `jku` points to a URL hosting a JWK Set; `x5u` points to an X.509 cert chain. If the server blindly trusts and fetches/uses whatever the token specifies, the attacker controls both the token *and* the key used to validate it.

**`jwk` embedded key attack:**
1. Generate your own RSA keypair.
2. Set the header's `jwk` field to your **public** key.
3. Sign the token with your **private** key.
4. If the server extracts the key from the `jwk` header instead of using its own trusted key store, it will successfully "verify" a token you fully control.

**`jku` attack:**
1. Host a JWKS file containing your own public key at a URL you control.
2. Set `jku` to that URL.
3. Sign the token with your matching private key.
4. If the server fetches whatever `jku` points to without validating it against an allowlist of trusted key-hosting domains, it trusts your key.

**What to check server-side behavior for:** does the app validate `jku`'s domain against an allowlist? Does it require HTTPS + pinned host? Does it cache keys rather than re-fetching per request (re-fetching = live SSRF primitive as a bonus)?

---

### 3.6 Missing / Incomplete Signature Verification
**Root cause:** occasionally the server decodes the JWT (to read claims) but never actually calls the verify function, or calls decode-only library methods in test/debug code that made it to production.

**Test:** submit a token where the payload is modified but the signature is left completely unchanged/invalid (don't bother crafting a valid one). If the server still honors the modified claims, verification isn't happening at all — this is rarer but devastating when found, and easy to miss if you only test "clever" attacks and skip the dumb one.

---

### 3.7 Missing `exp` / No Revocation / Long-Lived Tokens
**Root cause:** tokens with no `exp`, an absurdly long `exp`, or no server-side revocation/blocklist mechanism remain valid indefinitely — a stolen token (via XSS, log leakage, MITM) is a permanent credential.

**Test:** decode `exp` vs `iat`, calculate lifetime. Log out / change password / trigger a "revoke sessions" feature, then replay the *old* token — if it still works post-logout or post-password-change, that's a finding: stateless JWTs without a server-side revocation list or short-lived tokens + refresh rotation can't actually be invalidated.

---

### 3.8 Missing `aud` / `iss` Validation (Token Confusion Across Services)
**Root cause:** in microservice or multi-tenant environments, a token minted for Service A or Tenant A may be accepted by Service B or Tenant B if the verifying service doesn't check `aud` (intended audience) or `iss` (issuer) matches itself.

**Test:** if you can obtain a valid token from one service/tenant/environment (e.g., a lower-privilege internal API, or a different customer's tenant in a multi-tenant SaaS), try replaying it against a different service or tenant boundary. Cross-tenant token acceptance in SaaS platforms is a critical/high finding — full tenant isolation break.

---

### 3.9 Sensitive Data Exposure in Payload
**Root cause:** base64url is *encoding*, not encryption — anyone holding the token can read every claim. Developers sometimes stuff PII, internal IDs, permission flags, or even secrets into the payload assuming it's opaque.

**Test:** decode every token you encounter throughout the app (access tokens, refresh tokens, password-reset tokens, invite tokens, "remember me" tokens) and flag any claim containing PII, internal system identifiers, or anything that shouldn't be client-visible even if it can't be *modified* usefully.

---

### 3.10 Claim Tampering Where Signature Validation IS Correct
Even with airtight crypto, check the **authorization logic** built on top of valid claims:
- Can you request a token as a low-privilege user, then find an unrelated endpoint that trusts a claim (e.g., `tenant_id`) without cross-checking it against the resource being accessed? (This shades into IDOR territory but the entry point is the token claim.)
- Role/permission claims baked into the token at login time — if roles change server-side (e.g., admin revokes your access) but your token isn't invalidated, you retain the *old* privileges until natural expiry.

---

## 4. Tooling

| Tool | Use |
|---|---|
| **jwt_tool** (ticarpi) | Swiss-army knife: `-M` mode scans for common misconfigs automatically, `-X` for exploit modes (alg:none, key confusion, etc.), `-T` for interactive tamper mode |
| **Burp Suite JWT Editor extension** | Decode/edit/re-sign in-proxy; supports generating attacker keypairs and embedding `jwk` headers directly in Repeater |
| **hashcat** (mode 16500) / **john** | Offline HMAC secret brute-forcing |
| **CyberChef** | Quick manual decode/recipe-building for header & payload |
| **c-jwt-cracker** | Fast C-based brute forcer for short/simple secrets |

---

## 5. Testing Checklist (Quick Pass)

- [ ] Decode header + payload — note `alg`, `kid`, `jku`/`jwk`/`x5u` presence
- [ ] Try `alg: none` (and case variants) with empty signature
- [ ] If RS/ES algorithm: attempt HS256 confusion using the public key as HMAC secret
- [ ] Attempt offline HMAC secret cracking (wordlist + rules)
- [ ] Test `kid` for path traversal / SQLi / SSRF if present
- [ ] Test `jwk` header injection (self-signed key embedded in token)
- [ ] Test `jku`/`x5u` pointing to attacker-controlled host (check for domain allowlisting)
- [ ] Submit token with tampered payload + deliberately broken signature (verify verification is actually happening)
- [ ] Check `exp` presence and reasonableness; test token validity after logout/password change
- [ ] Check `aud`/`iss` enforcement — replay across services/tenants if multiple are in scope
- [ ] Decode every JWT-shaped token in the app (not just the main access token) for sensitive data
- [ ] Confirm token storage location (cookie flags: `HttpOnly`/`Secure`/`SameSite`, vs. `localStorage` exposure to XSS)
- [ ] Re-test all of the above against the refresh token flow if refresh tokens are also JWTs

---

## 6. Severity / CVSS Notes

- **`alg:none` bypass, algorithm confusion, missing verification, `jwk`/`jku` key injection** → typically Critical (CVSS ~9.x): full authentication bypass, Privileges Required: None, Confidentiality/Integrity/Availability: High.
- **Weak secret crackable offline** → High, scaled by how trivially crackable (a 4-char secret cracked in seconds vs. a secret that survives rockyou but might fall to a targeted wordlist).
- **Missing `exp`/no revocation** → Medium–High depending on token scope and how the token is likely to leak (XSS-exposed storage pushes this up).
- **Sensitive data in payload** → Medium, scaled by data sensitivity (PII/financial pushes toward High).
- **Missing `aud`/`iss` in single-tenant, single-service context** → often Low/informational; in multi-tenant SaaS → Critical (tenant isolation failure).

Always tie severity to demonstrated impact, not just theoretical weakness — a forged-admin-token PoC that actually returns another user's data lands far better with clients than "the algorithm isn't pinned."

---

## 7. Sample Reporting Language

**Finding title:** JWT Signature Verification Bypass via Algorithm Confusion (RS256/HS256)

**Description (technical):** The application's JWT verification logic does not enforce a fixed signing algorithm. During testing, a token was crafted using the `HS256` algorithm and signed using the application's publicly available RSA public key (retrieved from `<endpoint>`) as the HMAC secret. The application accepted this forged token as valid, allowing full control over token claims including `role` and `sub`.

**Impact:** An attacker with access to the application's public key — which is inherently public by design — can forge authentication tokens for any user, including privileged accounts, resulting in complete authentication and authorization bypass.

**Recommendation:** Explicitly pin the expected signing algorithm(s) in the verification configuration and reject any token whose header `alg` does not match. Do not derive the verification algorithm from the token itself. Prefer libraries/configurations that require the expected algorithm to be passed explicitly at verify-time rather than inferred from the token.

---

*Notes assume all testing is performed under written authorization within a defined engagement scope. Always confirm rules of engagement before testing token forgery/replay against production systems, and coordinate with the client on any findings involving live credential or session material.*
