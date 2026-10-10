# JavaScript Bundle Analysis for Web Application Security
### A Practical Study Guide for Authorized Penetration Testing and Bug Bounty Hunting

> **Scope note:** Everything in this guide assumes you have explicit, documented authorization to test the target (a bug bounty program's in-scope assets, a client engagement with signed rules of engagement, or your own lab environment). Running these techniques against systems you are not authorized to test is illegal in most jurisdictions.

---

## Table of Contents

1. [Fundamentals of JavaScript Bundles](#1-fundamentals-of-javascript-bundles)
2. [JavaScript Reconnaissance Methodology](#2-javascript-reconnaissance-methodology)
3. [Understanding and Reading Minified JavaScript](#3-understanding-and-reading-minified-javascript)
4. [Automated Extraction and Analysis Tools](#4-automated-extraction-and-analysis-tools)
5. [API Endpoint and Attack-Surface Discovery](#5-api-endpoint-and-attack-surface-discovery)
6. [Authentication and Authorization Analysis](#6-authentication-and-authorization-analysis)
7. [Secret and Sensitive-Information Discovery](#7-secret-and-sensitive-information-discovery)
8. [Client-Side Vulnerability Discovery](#8-client-side-vulnerability-discovery)
9. [A Repeatable Bug Bounty Workflow](#9-a-repeatable-bug-bounty-workflow)
10. [Practical Labs and Worked Examples](#10-practical-labs-and-worked-examples)
11. [Advanced Analysis](#11-advanced-analysis)
12. [Common Mistakes and Researcher Mindset](#12-common-mistakes-and-researcher-mindset)
13. [Reference Checklist and Findings Template](#13-reference-checklist-and-findings-template)
14. [Further Reading](#14-further-reading)

---

## 1. Fundamentals of JavaScript Bundles

### 1.1 What is a "bundle" and why does it exist?

Modern web apps are written as dozens or hundreds of small source files (components, utilities, API clients, state management). Browsers don't want to make hundreds of separate HTTP requests to load them all, and raw developer source code is often not directly browser-compatible (it may use new syntax, module systems, or frameworks like React/Vue/Angular that need compiling).

A **bundler** (Webpack, Vite, Rollup, esbuild, Parcel) solves this by:
- Walking the dependency graph starting from an entry file (e.g., `index.js`).
- Combining all imported modules into one or a few output files.
- Transforming non-standard syntax (JSX, TypeScript, newer ES features) into code browsers can run — this is **transpilation**.
- Optionally shrinking the output — **minification**.

**Analogy:** Think of source code as a chef's full recipe book with notes, substitutions, and commentary. The bundle is the single index card of condensed steps handed to the kitchen staff (the browser) — functionally complete, but stripped of the authorial context.

### 1.2 How browsers load, execute, and cache JavaScript

1. The browser parses HTML and encounters `<script>` tags (or dynamically injected ones).
2. It fetches the script (unless `defer`/`async` changes timing) over HTTP(S).
3. The JavaScript engine (e.g., V8 in Chrome) parses and executes the script top-to-bottom.
4. Scripts are cached according to HTTP caching headers (`Cache-Control`, `ETag`) and are frequently **content-hashed** in the filename (e.g., `main.8f3a1c2.js`) so a new deployment produces a new URL and busts old caches.

For you as a tester, this means: **the exact bundle you're looking at today may differ from what existed last week.** Always note the hash/version of files you analyze.

### 1.3 Source vs. bundled vs. minified vs. obfuscated vs. transpiled

| Term | What happened to the code | Readability |
|---|---|---|
| **Source code** | Original, as written by developers | High |
| **Transpiled code** | Modern syntax (JSX, TS, ES2022) converted to broadly-compatible JS | Medium-high |
| **Bundled code** | Many modules concatenated into one file, wrapped in module-loader boilerplate | Medium |
| **Minified code** | Whitespace removed, variable names shortened (`function getUserProfile(userId)` → `function a(b)`) | Low |
| **Obfuscated code** | Deliberately transformed to resist analysis (string encoding, control-flow flattening, dead code injection, VM-based packers) | Very low |

Minification is a side effect of wanting smaller file sizes; it's not intended as a security control. Obfuscation, by contrast, is sometimes deliberately added by anti-piracy or anti-bot vendors specifically to slow down reverse engineers — you'll encounter it more in bot-protection scripts (e.g., PerimeterX/HUMAN, Akamai Bot Manager, DataDome) than in ordinary application logic.

### 1.4 How Webpack, Vite, Rollup, and esbuild shape what you see

- **Webpack**: Wraps modules in numbered arrays/objects and a runtime loader (`__webpack_require__`). Look for `webpackJsonp`, `__webpack_modules__`, or numeric module IDs as a fingerprint.
- **Vite** (dev mode): Serves largely unbundled ES modules over HTTP — great for recon, since you often see near-source code. Production Vite builds use Rollup under the hood and look more like standard minified ESM.
- **Rollup**: Tends to produce flatter, more readable ES-module output with fewer wrapper layers than Webpack.
- **esbuild**: Extremely fast, output resembles Rollup's but with its own comment markers (e.g., `// node_modules/...` banner comments if `--metafile`/`--sourcemap` options were used).

Knowing which bundler produced a file helps you predict its structure and guess where to find manifest/chunk-mapping files.

### 1.5 Lazy loading, dynamic imports, chunks, and code splitting

Instead of shipping one giant file, apps often split code so users only download what they need:

```js
// A dynamic import — this becomes a separate "chunk" file
button.addEventListener("click", async () => {
  const { openAdminPanel } = await import("./admin-panel.js");
  openAdminPanel();
});
```

This produces a separate file (e.g., `admin-panel.3f8a1b.chunk.js`) that only loads when the button is clicked. **This matters a lot for recon**: a chunk that's never triggered during normal browsing (e.g., an admin-only chunk) might never appear in your Network tab unless you know to look for it — which is exactly why hunting for chunk manifests (Section 2) is valuable.

### 1.6 Source maps: what they are and what they expose

A **source map** (`*.js.map`) is a JSON file that maps positions in the minified/bundled output back to the original source file names, line numbers, and even original variable names. It exists so developers can debug production code in original form.

```json
{
  "version": 3,
  "sources": ["webpack:///./src/api/auth.js"],
  "sourcesContent": ["export function login(username, password) { ... }"],
  "names": ["login", "username", "password"],
  "mappings": "AAAA,SAASA..."
}
```

If `sourcesContent` is present, you effectively get the **original, unminified source code** — comments, original variable names, file structure, and all. This is the single highest-value artifact you can find in JS recon, because it instantly undoes all minification.

**Important nuance:** a source map existing is not itself a vulnerability — it's a (common, often intentional or accidental) convenience. Whether it's a *finding* depends on program policy and what it exposes (see Section 12).

### 1.7 Client-side vs. server-side code

Client-side JS executes in the user's browser and is, by definition, delivered to and readable by that user. Server-side code (the API backend, business logic enforcing permissions) never reaches the browser — you only see its *effects* (HTTP responses). **Any logic implemented only in the client — validation, role checks, feature gating — can be bypassed**, because the attacker fully controls their own browser execution environment (DevTools, proxies, modified requests).

### 1.8 Why frontend code must be treated as fully accessible

There is no technical control that prevents a user from reading, modifying, or replaying their own browser's JavaScript. Minification and obfuscation raise the *effort* required, not the *possibility*. Treat every byte shipped to the browser as public.

### 1.9 What you can and cannot reliably infer from a bundle

**You CAN often infer:**
- API endpoint paths and HTTP methods the frontend is built to call.
- Expected request/response shapes (fields, types).
- Feature flags and their names.
- Client-side logic for showing/hiding UI based on roles.
- Internal naming conventions, sometimes internal hostnames.

**You CANNOT reliably infer:**
- Whether the backend actually enforces authorization on a given endpoint (you must test this).
- Whether an endpoint referenced in code is actually deployed/reachable.
- The real sensitivity of a value without further investigation (a "key" might be a public analytics ID).
- Full business logic — client code often represents only a thin UI layer over a more complex backend.

---

## 2. JavaScript Reconnaissance Methodology

### 2.1 Goals of this phase

Build a complete, organized inventory of every JS asset in scope, before you start deep analysis. Recon that isn't organized leads to duplicated effort and missed chunks.

### 2.2 Browser DevTools: Network and Sources tabs

- **Network tab**: Filter by `JS`. Reload the page with "Disable cache" checked and "Preserve log" on, then navigate through the app's main flows (login, dashboard, settings, admin areas if your account has access) to trigger lazy-loaded chunks.
- **Sources tab**: Shows the full tree of loaded scripts, and if source maps are available, an expandable "original sources" tree appears automatically — this is often the fastest way to confirm source maps exist.

**Tip:** Use the Network tab's "Filter" box with a regex like `\.js(\?|$)` to catch versioned script URLs with query strings (e.g., `app.js?v=123`).

### 2.3 Identifying dynamically loaded chunks

Look in already-downloaded bundles for chunk-loading patterns:

```js
// Webpack-style chunk loader call — the array are chunk IDs
__webpack_require__.e(4821).then(__webpack_require__.bind(__webpack_require__, 7734))
```

Searching bundles for `.e(` (Webpack chunk loader), `import(` (native dynamic import), or a `webpackJsonp`/`webpackChunk` array assignment reveals chunk IDs you may not have triggered by clicking through the UI.

### 2.4 Extracting script references from HTML

```bash
curl -s https://target.example/ | grep -oE '<script[^>]+src="[^"]+"' 
```

This pulls every `<script src="...">` tag from the raw HTML. It won't catch scripts injected by other scripts at runtime — for that, you need the Network tab or a headless browser crawl (Section 4).

### 2.5 Script URLs, CDN assets, and hashed filenames

Filenames like `main.8f3a1c2.js` embed a content hash. If you see the same hash across two testing sessions, the file hasn't changed — useful for deciding whether to re-analyze. First-party scripts are usually served from the app's own domain or a dedicated asset subdomain (`static.target.example`); third-party scripts (analytics, ads, chat widgets) come from external domains and are **generally lower priority** unless the engagement scope explicitly includes supply-chain analysis.

### 2.6 Downloading and organizing bundles locally

```bash
mkdir -p recon/target.example/js
cd recon/target.example/js
curl -s -o main.js "https://target.example/static/js/main.8f3a1c2.js"
```

Organize by domain → by date/version → by file. Keep a simple manifest (CSV or Markdown table) recording: URL, SHA256 hash, date collected, whether a source map was found, and a one-line note on what the file appears to contain.

```bash
sha256sum main.js >> ../manifest.txt
```

### 2.7 Checking for source maps safely

A source map is often referenced at the bottom of its JS file:

```js
//# sourceMappingURL=main.8f3a1c2.js.map
```

```bash
tail -c 200 main.js   # check the last bytes for a sourceMappingURL comment
curl -s -o main.js.map "https://target.example/static/js/main.8f3a1c2.js.map"
```

If the comment is absent, some apps still expose the map at the predictable `<filename>.map` path even without the comment (a common misconfiguration) — it's reasonable recon practice to simply try fetching it.

### 2.8 Handling large applications with hundreds of JS files

- Automate the download loop (Section 4) rather than fetching by hand.
- De-duplicate by content hash — many "different" filenames across pages are actually the same shared vendor chunk.
- Prioritize by likely relevance: files named `auth`, `admin`, `account`, `api`, `payments` before generic vendor/polyfill bundles.

### 2.9 Keeping track of progress

A simple Markdown tracking table works well:

```markdown
| File | Hash (short) | Source map? | Reviewed? | Notable findings |
|---|---|---|---|---|
| main.8f3a1c2.js | 8f3a1c2 | No | Yes | /api/v2/admin/* referenced |
| vendor.a1b2c3.js | a1b2c3 | No | Skipped (known library) | — |
```

---

## 3. Understanding and Reading Minified JavaScript

### 3.1 Pretty-printing

Minified code is syntactically valid but has no meaningful line breaks. Reformatting it (re-inserting whitespace/indentation based on brace/paren nesting) makes it navigable without changing its logic.

- **Chrome DevTools**: Click the `{}` ("Pretty print") icon at the bottom of the Sources panel viewer.
- **CLI**: `npx js-beautify main.js > main.pretty.js` (js-beautify is a widely used formatter; verify current usage via its own docs before relying on specific flags).

### 3.2 Navigating large bundles

- Use your editor's symbol search / "Go to Definition" where possible.
- Search for string literals first (endpoint paths, error messages) — these survive minification unchanged and are strong anchors for where to start reading.
- Work outward from a distinctive string, like `"/api/v1/users/"`, to find the surrounding function.

### 3.3 Identifying modules, functions, classes, and exports

**Before (original):**
```js
export class AuthClient {
  async login(username, password) {
    return fetch("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });
  }
}
```

**After (minified, typical of production output):**
```js
class a{async b(c,d){return fetch("/api/v1/auth/login",{method:"POST",body:JSON.stringify({username:c,password:d})})}}
```

Note what *survives* minification: the string literal `/api/v1/auth/login`, the object key names (`username`, `password`, `method`) — because changing those would break behavior (they're protocol-level identifiers, not just internal names). This is why **string and object-key search is usually more productive than trying to read renamed variables.**

### 3.4 Recognizing API clients and request wrappers

Look for repeated patterns centered on `fetch(`, `XMLHttpRequest`, or a wrapped HTTP client (`axios.create(...)`, a custom `apiRequest()` helper). Once you find the wrapper, every call site that uses it becomes a predictable shape, making the rest of the bundle much faster to scan.

### 3.5 Tracing a function to its caller

In DevTools Sources panel, right-click inside a function and choose **"Show references"** (Chrome) or use **"Go to definition"**/**"Find all references"** style navigation if you've imported the file into an IDE. This lets you walk backward from a sensitive sink to everywhere it's invoked.

### 3.6 Following data from user input to an HTTP request

This is **source-to-sink tracing**, covered in depth in Section 8. At a basic level: find the DOM event handler or form submission, follow the variable through any transformation functions, and see what request body/URL it ends up in.

### 3.7 Using source maps to recover structure

Tools:
- **DevTools** auto-detects and displays original source trees when maps are available.
- **`source-map-explorer`** or manual parsing of the map's `sources`/`sourcesContent`/`mappings` fields to reconstruct original files programmatically (see Section 4/11 for scripted extraction).

### 3.8 Approaching a bundle with fully shortened names

When no source map exists and names are single letters:
1. Anchor on strings and object keys (survive minification).
2. Anchor on well-known library signatures (React, Redux, Axios have recognizable boilerplate even minified).
3. Use runtime behavior (breakpoints, Section 3.9) rather than purely static reading — watching actual values flow is often faster than naming archaeology.

### 3.9 Using breakpoints to confirm findings

Static analysis gives you *hypotheses* ("this function seems to check a role flag"). Setting a breakpoint (DevTools → Sources → click the line number) and triggering the code path (e.g., clicking the relevant button) lets you inspect real variable values at runtime — confirming or refuting your static read. This is a critical habit: **never report a finding based purely on a guess about what minified code does.**

---

## 4. Automated Extraction and Analysis Tools

For each tool below: problem solved → when to use → setup → basic usage → example → pitfalls.

### 4.1 Chrome DevTools
1. **Problem solved**: Live inspection, breakpoints, network capture, source map resolution — your primary interactive environment.
2. **When**: Constantly, throughout recon and validation.
3. **Setup**: Built into Chrome/Edge/Brave.
4. **Usage**: `F12` or right-click → Inspect. Sources tab for code, Network tab for traffic.
5. **Pitfall**: DevTools performance can choke on very large (multi-MB) single-line files — pretty-print first, or use a CLI tool for huge files.

### 4.2 Burp Suite
1. **Problem solved**: Intercepting, modifying, and replaying HTTP(S) traffic; correlating what the JS *says* it will request with what actually happens on the wire.
2. **When**: Throughout — especially Section 5 (endpoint correlation) and Section 6 (auth testing).
3. **Setup**: Configure your browser to proxy through Burp (default `127.0.0.1:8080`), install Burp's CA certificate for HTTPS interception.
4. **Usage**: Browse the target through the proxy; findings accumulate in **Proxy → HTTP History** and **Target → Site map**. Use **Burp's built-in JS/link extraction** features in Site Map (right-click → "Engagement tools" → "Find scripts" / "Analyze target") to catch endpoints Burp's own passive scanner notices in JS files it has seen.
5. **Pitfall**: Passive JS parsing in Burp is heuristic — always manually confirm paths it reports.

### 4.3 JSLuice
1. **Problem solved**: Purpose-built static extraction of URLs, paths, and secrets from JavaScript, using AST parsing (more reliable than regex alone) rather than naive text matching.
2. **When**: Bulk, first-pass extraction across many downloaded files.
3. **Setup**: A Go-based CLI tool; install per its official README (`go install github.com/BishopFox/jsluice/cmd/jsluice@latest` — verify the current install command from the project's GitHub page, since install paths for Go tools can change).
4. **Usage**:
   ```bash
   jsluice urls main.js
   jsluice secrets main.js
   ```
5. **Example output** (illustrative):
   ```json
   {"url": "/api/v2/admin/users/{id}", "method": "GET"}
   ```
6. **Common mistakes**: Treating every extracted URL as confirmed-live; JSLuice reports what's *referenced in code*, not what's reachable or authorized.
7. **Interpretation**: Use output as a candidate list to feed into manual/Burp-based verification (Section 5), not as a final report.

### 4.4 LinkFinder
1. **Problem solved**: Regex-based extraction of endpoint-like strings from JS — an earlier, widely used tool predating AST-based approaches.
2. **When**: Fast first pass, especially on single large files; useful as a cross-check against JSLuice's AST-based results.
3. **Setup**: Python tool, install per its official repository instructions (clone + `pip install -r requirements.txt`).
4. **Usage**:
   ```bash
   python linkfinder.py -i https://target.example/static/js/main.js -o cli
   ```
5. **Pitfall**: Regex-only extraction produces more false positives than AST tools (e.g., matching CSS class name strings that look path-like). Manually verify hits.

### 4.5 ripgrep (`rg`)
1. **Problem solved**: Extremely fast recursive text search across many files — your workhorse for pattern hunting once you have files downloaded locally.
2. **When**: Any time you need to search many bundles for a pattern (endpoint prefixes, keywords like `admin`, `role`, `isAdmin`, `token`).
3. **Setup**: `apt install ripgrep` / `brew install ripgrep`.
4. **Usage**:
   ```bash
   rg -o '"/api/[a-zA-Z0-9/_-]+"' recon/target.example/js/
   rg -i 'isadmin|hasrole|permission' recon/target.example/js/
   ```
5. **Pitfall**: `-o` prints only the matched portion, losing context — drop `-o` (or add `-C 2`) when you need surrounding code to interpret a hit.

### 4.6 grep, curl, and shell basics
- `grep -rE "pattern" dir/` — classic recursive search, slower than `rg` on large trees but universally available.
- `curl -s -o out.js URL` — download a file silently.
- Combine with `xargs` for bulk downloads from a URL list:
  ```bash
  cat urls.txt | xargs -n1 -P4 -I{} curl -s -O {}
  ```

### 4.7 JavaScript AST-based analysis (overview — detailed in Section 11)
Tools like **Babel's parser** (`@babel/parser`) or **esprima**/**acorn** let you parse JS into an Abstract Syntax Tree and programmatically walk it — far more reliable than regex for things like "find every call to `fetch` and extract its first argument," because it understands code structure rather than just matching text.

### 4.8 What to extract, and how reliability differs

| Target | Best tool(s) | Reliability |
|---|---|---|
| URLs / API paths | JSLuice, LinkFinder, `rg` on string literals | Heuristic — confirm each one |
| GraphQL operation names | `rg -o '"operationName":"[^"]+"'`, or search for `.graphql`/`gql\`` template literals | Heuristic |
| Auth-related functions | `rg -i 'login|logout|refreshtoken|verifytoken'` | Heuristic, needs manual read |
| Role/permission checks | `rg -i 'isadmin|haspermission|role ==='` | Heuristic |
| Resource IDs | Manual tracing from UI to request | Needs confirmation |
| Config/secrets | JSLuice `secrets`, `rg` for `key|secret|token` near `=` | High false-positive rate — see Section 7 |
| DOM sources/sinks | AST search for `innerHTML`, `document.write`, `eval`, `location.href` assignment | Reliable to *locate*, not reliable proof of exploitability |
| Feature flags/hidden routes | `rg` for `featureFlag|flags\[|/route`, router config objects | Heuristic |

**Reliable extraction** = the tool correctly found a literal string in the code. **Heuristic matching** = the tool's guess about what that string *means* (e.g., "this looks like an endpoint"). **Vulnerability confirmation** = you tested it against the live system and observed an actual security failure. Keep these three categories separate in your notes at all times.

---

## 5. API Endpoint and Attack-Surface Discovery

### 5.1 Categories to map

- **REST endpoints**: paths, HTTP methods inferred from surrounding code (`method: "POST"`, `.get(`, `.put(`).
- **GraphQL**: a single endpoint (often `/graphql`) with many **operation names** — search for `query ` / `mutation ` keywords inside template literals, or a `.graphql` bundle of persisted queries.
- **API versions**: `/v1/`, `/v2/` paths — deprecated versions sometimes have weaker validation; compare behavior across versions if multiple are referenced.
- **Internal-looking paths**: `/internal/`, `/debug/`, `/_admin/`, staff-only naming conventions.
- **Upload/export/import/reporting operations**: often under-tested because they're less central to normal QA flows.
- **Tenant/org/account management**: endpoints taking an `orgId`/`tenantId`/`accountId` parameter are prime candidates for **IDOR** (Insecure Direct Object Reference) testing (see Section 6).

### 5.2 Correlating bundle findings with real traffic

Workflow:
1. Extract a candidate endpoint from the bundle (e.g., `/api/v2/orgs/{orgId}/invoices`).
2. Trigger the matching UI action while proxying through Burp.
3. Find the real request in **Burp Proxy → HTTP History**; note actual headers, cookies, and body shape used in practice (which may differ from what a quick static read suggested — e.g., extra headers added by an interceptor).
4. Send it to **Burp Repeater** for controlled, manual follow-up testing.

### 5.3 Prioritizing endpoints, not just collecting them

A list of 400 URLs is not a finding. Prioritize by:
- **Sensitivity of the operation** (financial, PII, account takeover potential > read-only public data).
- **Trust boundary crossed** (does it take an ID belonging to another user/tenant?).
- **State-changing vs. read-only** (`POST`/`PUT`/`DELETE` generally higher impact than `GET`).
- **Evidence of weak gating** (e.g., referenced only in an admin chunk, suggesting the backend *might* be relying on "security through obscurity" rather than real server-side checks — this is a hypothesis to test, not a conclusion).

---

## 6. Authentication and Authorization Analysis

For each topic: JS patterns to look for → what they might indicate → what they do NOT prove → a hypothesis → a safe validation procedure → evidence needed → common false positives.

### 6.1 JWTs (creation, decoding, verification, expiry)

**Patterns:** `jwt-decode` library usage, manual `atob(token.split('.')[1])`, checks like `payload.exp < Date.now()`.

- **Might indicate**: the frontend reads claims out of the token to decide what UI to show.
- **Does NOT prove**: the backend performs equivalent checks. Client-side expiry checks are a UX nicety, not a security boundary.
- **Hypothesis**: "The UI hides admin features based on a `role` claim in the JWT — does the backend independently verify `role` on each admin API call, or does it trust a client-supplied value?"
- **Validation**: With proper authorization, decode your own JWT, note claim names, then test whether backend endpoints behave differently when that claim is altered (where you have legitimate means to do so, e.g., a lower-privileged test account) vs. simply modifying client state.
- **Evidence needed**: A reproducible request showing the server granting access/data it shouldn't based on a claim/role it should be validating independently.
- **False positive**: Many apps correctly treat the JWT as merely a UI hint while performing real authorization via a separate, server-side session/permission lookup — the presence of a claim in a JWT proves nothing about backend enforcement either way.

### 6.2 Access and refresh tokens

Look for where tokens are stored (`localStorage.setItem("access_token", ...)` vs. an httpOnly cookie you can't read from JS) and how refresh is triggered. Tokens in `localStorage` are readable by any JS running on the page — relevant context for XSS impact assessment (Section 8), not a vulnerability by itself.

### 6.3 Client-side role checks

**Pattern:**
```js
{user.role === "admin" && <AdminPanel />}
```

- **Might indicate**: UI-only gating.
- **Does NOT prove**: lack of server enforcement — you must test the underlying API directly.
- **Validation**: Identify the API call `<AdminPanel>` makes, then attempt that same call directly (correct auth, your own account) and observe the server's actual authorization decision.

### 6.4 Tenant/org identifiers and user-controlled resource IDs

**Pattern:** `/api/orgs/${currentOrgId}/settings` where `currentOrgId` comes from client state.

- **Hypothesis**: IDOR — can you substitute a different, non-owned `orgId` and still get a valid response?
- **Validation**: With your own authorized test accounts across two different tenants/orgs (never a third party's real data), swap the ID in Repeater and compare responses.
- **Evidence**: A response containing data/actions belonging to the other tenant, obtained with the "wrong" account's credentials.

### 6.5 Permission flags / feature gating

Similar reasoning to 6.3 — a `features.canExport` flag disabling a button is a UI nicety unless the export API independently checks entitlement server-side.

### 6.6 General principle

> **Frontend restrictions are UX, not security boundaries.** A suspicious-looking client check is a *lead*, never a *finding*, until you've reproduced the underlying server-side behavior with controlled, authorized requests and captured evidence.

---

## 7. Secret and Sensitive-Information Discovery

### 7.1 What to search for

```bash
rg -i 'api[_-]?key|secret|token|password|aws_access_key|private_key' recon/target.example/js/
```

### 7.2 Classifying what you find

| Found value | Likely classification | Why |
|---|---|---|
| `GOOGLE_MAPS_API_KEY = "AIza..."` restricted to a domain | Often intentionally public | Many client-side API keys are *designed* to be exposed and restricted by referrer/domain instead |
| Stripe key starting `pk_live_...` | Intentionally public (publishable key) | Stripe's publishable keys are meant for client-side use |
| Stripe key starting `sk_live_...` | **Likely a real secret if present client-side** | Secret keys should never ship to browsers — high-value, verify carefully before reporting |
| `internal-api.corp.target.local` hostname | Informational, not usually a standalone vuln | Internal naming disclosure; may have mild recon value, rarely a vulnerability by itself per most program policies |
| `DEBUG = true` flag | Informational | Check if it changes real backend behavior; often it's purely cosmetic/logging |
| A hardcoded JWT in test/demo code paths | Needs careful handling | If it grants real access, treat it as a live credential: do not use it beyond confirming validity, report immediately |

### 7.3 Distinguishing public identifiers from real secrets

Ask: **"Was this value designed to be shipped to a browser?"** Publishable keys, public client IDs (OAuth `client_id` for public clients using PKCE), and analytics IDs are normal. Keys that are meant to authenticate a *server* to another service (database credentials, private signing keys, server-only API secrets) are not.

### 7.4 Assessing impact responsibly

- Do not use a discovered credential to access systems beyond what's needed to **confirm** it's live and understand its scope — and only if your program's rules permit this kind of validation. Many programs prefer you report the exposure immediately without testing it further.
- Document exactly where you found it (file, line, commit/build hash if determinable) so the vendor can rotate it precisely.

---

## 8. Client-Side Vulnerability Discovery

### 8.1 Source-to-sink analysis in depth

A **source** is anywhere attacker-influenceable data enters the application (URL, URL fragment, `postMessage`, form input, `document.referrer`, response from an API). A **sink** is a place where that data is used in a way that can cause harm if unsanitized (`innerHTML`, `eval`, `document.write`, dynamic script injection, `location.href` assignment, unsafely constructed SQL/HTML on the server if data round-trips there).

**Method:**
1. Enumerate sinks first (search for `innerHTML =`, `dangerouslySetInnerHTML`, `document.write(`, `eval(`, `new Function(`, `location.href =`, `window.open(`, `.src =` assignments on script/img tags).
2. For each sink, trace backward: what variable feeds it? Where did that variable's value originate?
3. Check whether any sanitization/encoding happens between source and sink.
4. If the path is unbroken and unsanitized, you have a hypothesis to validate with an actual payload in a safe/authorized way.

### 8.2 DOM-based XSS

**Vulnerable:**
```js
const name = new URLSearchParams(location.search).get("name");
document.getElementById("greeting").innerHTML = "Hello, " + name;
```

**Corrected:**
```js
const name = new URLSearchParams(location.search).get("name");
document.getElementById("greeting").textContent = "Hello, " + name; // textContent, not innerHTML
```

### 8.3 Unsafe HTML rendering

React's `dangerouslySetInnerHTML`, Vue's `v-html`, or Angular's `[innerHTML]` bypass each framework's normal auto-escaping. Finding these directives is a strong, fast heuristic for where to start a source-to-sink trace.

### 8.4 URL / fragment-based injection

URL fragments (`#...`) are never sent to the server, so **server-side logs/WAFs won't see fragment-based payloads** — code reading `location.hash` directly into a sink is a classic DOM XSS pattern worth prioritizing.

### 8.5 postMessage origin-validation issues

**Vulnerable:**
```js
window.addEventListener("message", (event) => {
  document.getElementById("content").innerHTML = event.data.html; // no origin check!
});
```

**Corrected:**
```js
window.addEventListener("message", (event) => {
  if (event.origin !== "https://trusted.target.example") return;
  document.getElementById("content").textContent = event.data.html;
});
```
Search bundles for `addEventListener("message"` and check whether `event.origin` is validated before use.

### 8.6 Unsafe redirects

```js
location.href = new URLSearchParams(location.search).get("next"); // open redirect if "next" isn't validated against an allowlist
```

### 8.7 Client-side prototype pollution

Look for recursive merge/clone utilities (`_.merge`, hand-rolled deep-assign functions) applied to attacker-influenceable objects (query strings parsed into nested objects, JSON bodies) without guarding against `__proto__`/`constructor`/`prototype` keys.

### 8.8 Insecure storage and trust assumptions

Sensitive data (tokens, PII) in `localStorage`/`sessionStorage` is readable by any script on the page — this *amplifies* the impact of any XSS you find elsewhere, which is why it's worth noting even when it's not independently reportable.

### 8.9 Business-logic weaknesses visible client-side

E.g., price calculations, discount logic, or quantity limits computed in JS and merely *sent* to the server for recording rather than re-validated server-side. Confirm by altering the client-computed value and observing whether the server accepts it.

---

## 9. A Repeatable Bug Bounty Workflow

**Hypothesis → Test → Result → Next hypothesis** — run this cycle at every stage below.

1. **Scope and authorization verification** — Record program scope, in-scope domains, excluded assets, and testing restrictions *before* touching anything. Screenshot/save the policy page with a date.
2. **JS file collection** — Section 2's methodology; build your manifest.
3. **Source-map discovery** — Attempt `.map` fetches for every collected file; note which succeed.
4. **Automated extraction** — Run JSLuice/LinkFinder/`rg` sweeps; dump raw candidate lists to files.
5. **Manual code review** — Read the highest-priority files (auth, admin, payments) in full; everything else, skim with targeted search.
6. **Endpoint and feature mapping** — Correlate candidates with real Burp traffic; build an endpoint inventory with method, purpose, and auth requirement observed.
7. **Vulnerability hypothesis generation** — For each suspicious pattern, write one sentence: *"I believe X because Y; I will test by Z."*
8. **Controlled validation** — Execute the minimal test needed to confirm or refute — using only your own authorized test accounts/data.
9. **Evidence collection** — Screenshots, raw HTTP requests/responses (redact others' data), timestamps.
10. **Impact assessment** — What's the realistic worst case? Who is affected? Map to a severity framework your program uses (often CVSS).
11. **Report preparation** — Clear reproduction steps, impact statement, suggested remediation, and the exact evidence from step 9.

**What to record at each stage:** file hashes, timestamps, exact commands run, and — critically — which category each finding sits in (reliable extraction / heuristic / confirmed vulnerability) so you never accidentally escalate a guess into a report.

**Avoiding time sinks:** Set a cap (e.g., 15–20 minutes) on investigating any single string match before deciding "confirm, deprioritize, or discard." Most `admin`/`token`/`secret` keyword hits are discardable within minutes once you understand the context (Section 12).

---

## 10. Practical Labs and Worked Examples

> All labs use self-contained, fictional code — no live third-party target required.

### Lab 1 — Extracting API Endpoints From a Bundle

**Scenario:** You've downloaded `app.bundle.js` from a fictional SaaS, "Nimbus CRM."

```js
// app.bundle.js (excerpt)
const a=class{constructor(t){this.base=t}async b(t){return fetch(this.base+"/api/v1/contacts",{headers:{Authorization:"Bearer "+t}})}async c(t,n){return fetch(this.base+"/api/v1/contacts/"+t+"/notes",{method:"POST",headers:{Authorization:"Bearer "+n},body:JSON.stringify({text:"x"})})}async d(t){return fetch(this.base+"/api/v2/admin/export?format=csv",{headers:{Authorization:"Bearer "+t}})}};
```

**Questions before reading the solution:**
- How many distinct endpoints are present, and what HTTP methods do they use?
- Which one looks highest-priority to investigate first, and why?

**Solution:** Three endpoints: `GET /api/v1/contacts`, `POST /api/v1/contacts/{id}/notes`, `GET /api/v2/admin/export?format=csv`. The export endpoint is highest priority — it's admin-named, exports bulk data (CSV), and is a `GET` (meaning it might be reachable just by navigating a URL if auth is weak), making it worth checking first whether it's reachable by a non-admin test account.

**Command:**
```bash
rg -o '"/api/[a-zA-Z0-9/_-]+' app.bundle.js
```

**Lesson:** HTTP methods often aren't adjacent to the path string — you have to read the surrounding object (`method: "POST"`) rather than relying on regex alone for method detection.

---

### Lab 2 — Understanding a Minified Authentication Flow

```js
function l(e,t){return fetch("/api/v1/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({u:e,p:t})}).then(e=>e.json()).then(e=>{if(e.ok)return localStorage.setItem("tok",e.token),e.token;throw new Error("bad creds")})}
```

**Questions:** Where is the token stored after login? What does that imply if an XSS is later found elsewhere on the same origin?

**Solution:** Token is stored in `localStorage` under key `"tok"`. Since `localStorage` is readable by any JS on the page, a DOM XSS anywhere on this origin would allow full token theft (session hijack) — an important severity-amplifying fact to note even though storage choice alone isn't independently a vulnerability on most programs' policies.

**Lesson:** Always note *where* credentials land, not just *that* login succeeds — it directly affects the impact rating of any XSS you find later.

---

### Lab 3 — Identifying a Suspicious Authorization Check

```js
function canDelete(e){return e.role==="owner"||localStorage.getItem("debugAdmin")==="true"}
```

**Questions:** Is this exploitable? What would you need to confirm before reporting?

**Solution:** This is a strong *lead*: a debug flag in `localStorage` appears to grant elevated client-side permission. But — critically — this only changes what the **UI** allows the user to click. You must test whether the actual delete API independently enforces `role === "owner"` server-side. If the server performs its own check and rejects the request regardless of this flag, there is no vulnerability (the backend is correctly not trusting the client). If the server accepts the delete request because the client simply calls the same endpoint real owners use, and the server doesn't re-verify role, that's a real authorization bypass.

**Validation:** Set `localStorage.debugAdmin = "true"` on your own authorized test account (non-owner role), click delete on a resource you own, and inspect in Burp whether the server-side response actually performs the deletion for a non-owner identity, or returns a 403 despite the client allowing the click.

**Lesson:** This is the single most common beginner mistake — stopping at "I found a flag that unlocks a button" instead of testing the backend.

---

### Lab 4 — Tracing a Potentially Unsafe DOM Data Flow

```js
function renderSearchBanner(){const e=new URLSearchParams(location.search).get("q");document.getElementById("banner").innerHTML="Results for: "+e}
```

**Questions:** Identify the source, the sink, and whether any sanitization occurs between them.

**Solution:**
- **Source**: `location.search` query parameter `q` (fully attacker-controlled via a crafted link).
- **Sink**: `.innerHTML` assignment.
- **Sanitization**: None — the value is concatenated directly into HTML.
- **Hypothesis**: Reflected DOM XSS via `?q=<img src=x onerror=...>`.
- **Validation (in an authorized lab/your own test instance only)**: Navigate to the crafted URL and confirm script execution in a controlled, non-production-impacting way; capture a screenshot/PoC.

**Lesson:** `innerHTML` + unsanitized URL parameter is one of the highest-signal, lowest-effort patterns to search for across an entire bundle set (`rg 'innerHTML\s*='`).

---

### Lab 5 — Investigating a Source Map and Producing a Defensible Finding

You find `https://target.example/static/js/main.8f3a1c2.js.map` returns `200 OK` and contains a `sourcesContent` array including a file `src/internal/feature-flags-admin.js` with comments describing an unreleased internal tool and a hardcoded staging API hostname.

**Questions:** Is the presence of the source map itself the finding? What would make this report strong vs. weak?

**Solution:** The source map being present is **not automatically a vulnerability** — plenty of programs consider this low/informational, or explicitly out of scope, depending on policy. What strengthens a report is: (a) checking the program's policy on source map disclosure, (b) identifying *concrete* sensitive content inside it (real internal hostnames you can further investigate, logic revealing an authorization flaw you can reproduce, or literal credentials — see Section 7), and (c) demonstrating impact (e.g., "the exposed staging hostname is reachable and has no authentication, exposing X") rather than just "a source map exists."

**Lesson:** Separate the *observation* ("source map is public") from the *finding* ("the source map discloses reachable, unauthenticated internal infrastructure") — only the latter, with evidence, is reportable as a vulnerability in most programs.

---

## 11. Advanced Analysis

*(Defer this section until comfortable with Sections 1–10.)*

### 11.1 JavaScript AST analysis

Parse with Babel's parser and walk the tree to find all `fetch`/`axios` calls programmatically:

```js
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const fs = require("fs");

const code = fs.readFileSync("main.js", "utf8");
const ast = parser.parse(code, { sourceType: "unambiguous" });

traverse(ast, {
  CallExpression(path) {
    const callee = path.node.callee;
    if (callee.name === "fetch" || (callee.property && callee.property.name === "get")) {
      console.log(path.node.arguments[0]);
    }
  }
});
```

This is far more robust than regex because it understands scoping and won't be fooled by a URL-like string sitting inside a comment or unrelated object.

### 11.2 Module and dependency mapping

For Webpack bundles, the module registry (often an object/array keyed by numeric or hashed module IDs) can be walked to reconstruct an approximate dependency graph — useful for understanding which "module" a given function lives in before source maps are available.

### 11.3 Data-flow analysis

Beyond single-function tracing (Section 8), full data-flow analysis tracks a value across function boundaries, closures, and async boundaries (Promises, `await`). This is where custom tooling (AST + manual graph building) outperforms manual reading for large codebases.

### 11.4 Custom extraction scripts in Python

```python
import re, sys, json

def extract_endpoints(path):
    text = open(path, encoding="utf-8", errors="ignore").read()
    return sorted(set(re.findall(r'"(/api/[a-zA-Z0-9/_\-{}]+)"', text)))

if __name__ == "__main__":
    for ep in extract_endpoints(sys.argv[1]):
        print(ep)
```

### 11.5 Reducing duplicate results across many bundles

Hash extracted strings (not whole files) and store in a set; many "unique" hits across 50 files are the same shared vendor/polyfill code repeated. De-duplicating at the string level, grouped by the *originating module/source file* when maps exist, keeps your findings list honest.

### 11.6 Comparing bundle versions

```bash
diff <(rg -o '"/api/[a-zA-Z0-9/_-]+"' old/main.js | sort -u) \
     <(rg -o '"/api/[a-zA-Z0-9/_-]+"' new/main.js | sort -u)
```

Newly added endpoints after a deployment are high-value — they haven't been battle-tested by other researchers yet.

### 11.7 Recognizing obfuscation and knowing when to stop

Signs of deliberate obfuscation (vs. ordinary minification): string arrays decoded via an index-lookup function, control-flow flattened into a single `switch` dispatcher, self-modifying/anti-debug checks (`debugger` statement loops, timing checks). Heavily obfuscated bot-protection or DRM scripts are rarely where application-logic vulnerabilities live, and reversing them is time-intensive with low payoff for typical bug bounty scope — know when to deprioritize and move to higher-value targets.

### 11.8 Automating recon without losing interpretability

Pipelines are useful for *collection* (Sections 2–4), but every hypothesis that becomes a report must be traced back to a human-reviewed, validated test (Section 6, 8). Automation should widen your funnel, not replace judgment at the narrow end of it.

---

## 12. Common Mistakes and Researcher Mindset

- **Endpoint discovery ≠ vulnerability.** Finding a URL string proves the frontend *references* it — nothing about its actual security posture.
- **"admin"/"token"/"secret" keyword matches are usually noise.** Variable names, CSS classes, and comments frequently contain these words harmlessly.
- **A `200 OK` does not prove unauthorized access.** Confirm the *content* of the response actually reflects privileged/other-user data — some apps return `200` with an empty or generic body for unauthorized requests.
- **Source maps are not automatically vulnerabilities.** Check program policy; look for concrete sensitive disclosure, not just presence.
- **Avoid duplicate/low-impact reports.** Search the program's public disclosure history (if available) before submitting; ask whether your finding changes real-world risk or is purely theoretical.
- **Distinguish a lead from a confirmed finding at every step** — maintain this distinction explicitly in your notes, not just in your head.
- **Prioritize by trust boundaries and impact**, not by how many strings you can extract. A short, well-validated report beats a long list of unconfirmed URLs.

---

## 13. Reference Checklist and Findings Template

### Recon checklist

```markdown
- [ ] Scope/authorization confirmed and saved with date
- [ ] All first-party JS files collected and hashed
- [ ] Source maps attempted for every file
- [ ] Automated extraction run (JSLuice/LinkFinder/rg) and output saved
- [ ] High-priority files (auth/admin/payments) manually reviewed
- [ ] Endpoint inventory correlated against real Burp traffic
- [ ] Each hypothesis has a one-line "I believe X because Y; test by Z"
- [ ] Each validated finding has evidence (requests/responses, screenshots)
- [ ] Each finding classified as: reliable extraction / heuristic / confirmed vulnerability
```

### Findings template

```markdown
## Finding: <short title>

**Category:** [DOM XSS / IDOR / Auth bypass / Information disclosure / Other]
**Status:** [Hypothesis / Validated / Confirmed vulnerability]

### Summary
One or two sentences.

### Location
- File / endpoint: 
- URL: 

### Reproduction steps
1. 
2. 
3. 

### Evidence
(Request/response pairs, screenshots — redact any third-party data)

### Impact
Who is affected, what can an attacker do, realistic worst case.

### Suggested remediation


### Notes / false positives considered
```

---

## 14. Further Reading

- OWASP Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- OWASP DOM-based XSS Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy — DOM-based vulnerabilities: https://portswigger.net/web-security/dom-based
- PortSwigger Web Security Academy — Access control vulnerabilities: https://portswigger.net/web-security/access-control
- PortSwigger Web Security Academy — JWT attacks: https://portswigger.net/web-security/jwt
- Source map spec (for reference on structure): https://github.com/mozilla/source-map
- JSLuice (BishopFox): https://github.com/BishopFox/jsluice
- LinkFinder: https://github.com/GerbenJavado/LinkFinder
- Burp Suite documentation: https://portswigger.net/burp/documentation

---

*End of guide. Recommended next step: work through Labs 1–5 (Section 10) hands-on before applying this methodology to an in-scope target.*
