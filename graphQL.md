# GraphQL API Pentesting — Notes

## 1. Why GraphQL Is Different
- Single endpoint (almost always `/graphql`, but also check `/api`, `/api/graphql`, `/graphql/v1`, `/gql`, `/query`, `/v1/graphql`) handles every operation — the query itself decides what data comes back.
- No REST-style URL structure to fuzz; the attack surface is the *schema* (types, fields, resolvers) rather than endpoints.
- Every resolver can theoretically have its own auth logic, so access control bugs live at the field/resolver level, not just the route level. A single missed check on one resolver = a vuln that's invisible from the outside unless you specifically probe that field.
- Three operation types to test separately: **Query** (read), **Mutation** (write), **Subscription** (websocket/real-time — often overlooked).

## 2. Recon & Endpoint Discovery
- Common paths to brute force: `/graphql`, `/graphiql`, `/api/graphql`, `/v1/graphql`, `/console/graphql`, `/graphql-explorer`, `/playground`.
- Check for exposed dev tools that ship with GraphQL servers: **GraphiQL**, **Apollo Sandbox/Studio Explorer**, **GraphQL Playground**, **Altair** — these often sit unauthenticated on staging/dev subdomains.
- Send a harmless probe query and look at the error format — a JSON body with `"errors": [...]` and a `message` field is a strong GraphQL fingerprint even without introspection.
- For subdomain-wide discovery, tools like **Goctopus** crawl/brute-force to find every GraphQL endpoint across an org and flag whether introspection/suggestions are on.
- Check both the web app's JS bundle (for hardcoded query/endpoint strings) and any mobile app APK/IPA — client code frequently embeds full queries you can replay directly, including ones not reachable from the UI.

## 3. Introspection

### 3.1 Standard introspection
- The default introspection query (`__schema { types { name fields { name args { name type { name } } } } } }`, full version in tools below) dumps the entire schema: every type, field, argument, and mutation — effectively free API documentation.
- Tools to run it and browse the results:
  - **InQL** (Burp Suite extension, BApp Store) — generates a query/mutation list from introspection, builds a searchable schema doc, and can bulk-send generated queries.
  - **GraphQL Voyager** — visual schema graph.
  - **Altair GraphQL Client / Postman / GraphiQL** — manual exploration and autocomplete against the live schema.
  - **graphql-path-enum** — enumerates all possible query paths from a schema.

### 3.2 When introspection is disabled
Try these, roughly in order:

1. **Method switching** — some servers only enforce the introspection block on `POST`; the same query sent as `GET` (with the query in the querystring) or as `POST` with a different `Content-Type` (e.g. `application/graphql` or `x-www-form-urlencoded`) can slip past the check.
2. **Regex-bypass via ignorable characters** — if the block is implemented as a naive regex/WAF rule matching the literal string `__schema`, insert characters GraphQL itself ignores but a sloppy regex won't expect: spaces, newlines, tabs, or a stray comma immediately after `__schema` (e.g. `__schema\n{`, `__schema,{`, `__schema {`). GraphQL's lexer treats commas and whitespace as insignificant, so the query still parses correctly while dodging the filter.
3. **Alternate introspection field names / older spec fields** — some implementations only filter `__schema` but leave `__type` queryable, or don't block introspection on a *second* endpoint (many apps run separate public/internal GraphQL servers).
4. **Field-suggestion / "did you mean" schema reconstruction** — even with introspection fully off, most GraphQL engines (Apollo, Graphene, Hot Chocolate, gqlgen, etc.) still return typo-correction hints by default:
   ```
   { "errors": [{ "message": "Cannot query field 'ussr' on type 'Query'. Did you mean 'user'?" }] }
   ```
   Send deliberately-misspelled field/argument names and harvest the suggestions. This is **field fuzzing** and can rebuild large portions of a schema one field at a time.
   - **Clairvoyance** (`nikitastupin/clairvoyance`, and the more robust fork `clairvoyancex`) automates this: it brute-forces field names from a wordlist, parses the suggestion errors, and reconstructs a usable JSON schema (importable into InQL/Voyager). Best results come from combining a general English wordlist, a GraphQL-specific wordlist (e.g. Escape Technologies' lists), and a target-specific list pulled from the app's own JS/traffic.
   - Defensively this is fixed independently of disabling introspection (e.g. Apollo Server v4's `hideSchemaDetailsFromClientErrors`, or **GraphQL Armor**'s block-suggestions plugin) — so always test both introspection *and* suggestions separately; one being off doesn't mean the other is.

## 4. Authorization & Access Control (BOLA/IDOR)
- This is the #1 real-world GraphQL bug class: object-level authorization has to be re-implemented in *every resolver*, and it's easy to secure the top-level query gate while leaving nested/related resolvers unchecked.
- Method: authenticate as User A, capture a query that returns User B's data by substituting an ID/argument (order ID, user ID, account ID) anywhere it appears in the query — not just the obvious top-level argument, but also nested field arguments and mutation inputs.
- Pay special attention to fields reachable only through relationships (e.g. `user { organization { billingInfo } }`) — the outer field may be authorized while the inner one isn't.
- Also test **field-level authorization**: can a low-privileged user query an admin-only field that simply wasn't hidden from the schema, even if the corresponding UI never exposes it?

## 5. Injection
- GraphQL is just a query layer in front of whatever the resolver does — classic injection still applies wherever a variable reaches a datastore or shell command:
  - SQL/NoSQL injection via query variables and mutation input objects.
  - Command injection where a resolver shells out.
  - XSS/stored payloads where GraphQL is the write path into content later rendered elsewhere.
- Fuzz every scalar argument (String/Int/ID) with standard injection payloads, oversized strings, and format-breaking characters (quotes, backslashes, unicode). GraphQL's type system doesn't sanitize for injection — it only validates *shape*, not *content*.

## 6. Denial of Service / Resource Exhaustion
- **Batching attacks** — many servers accept a JSON *array* of query objects in one HTTP request. This lets you bundle thousands of operations (e.g. thousands of login attempts) behind a single request that per-request rate limiters never see as more than "one request."
- **Aliases** — GraphQL lets you invoke the same field/mutation multiple times in one operation under different names:
  ```graphql
  { a: login(user:"a",pass:"1"){ok} b: login(user:"a",pass:"2"){ok} c: login(user:"a",pass:"3"){ok} }
  ```
  This is an effective brute-force/rate-limit bypass technique — a limiter counting HTTP requests, or a WAF signature looking for repeated mutation names, misses aliased duplicates entirely.
- **Deep/nested queries** — GraphQL allows arbitrary nesting through relationships. A query nested 8–10 levels deep against one-to-many relationships can fan out into an enormous number of resolver/database calls from a single small request (classic "billion laughs"-style amplification for APIs). Test by nesting a self-referential or circular relationship as deep as the server allows.
- **Field duplication / query complexity** — requesting the same expensive field hundreds of times in one query to multiply cost without tripping depth limits.
- Defensively these map to: batching limits, depth limiting, query cost/complexity analysis, and per-operation (not per-HTTP-request) rate limiting — worth noting in your report even if you're only testing offense.

## 7. CSRF
- If the server accepts GraphQL queries over `GET` (with the query in the URL) or over `POST` with `Content-Type: text/plain` / `application/x-www-form-urlencoded` (simple-request types that don't trigger a CORS preflight), a state-changing mutation can potentially be triggered cross-site with just a crafted link/auto-submitting form — same as classic CSRF, but easy to miss because people assume "it's JSON, it's safe."
- Check whether mutations require a custom header (many GraphQL clients set one) — if not, and cookies are the only auth, CSRF is in play.

## 8. SSRF
- Any resolver that accepts a URL/URI-like argument (avatar-from-URL, webhook registration, "import from link," image proxy, etc.) is a candidate for classic SSRF — same test approach as REST, just delivered through a mutation input instead of a form field.

## 9. Subscriptions (WebSockets) — don't skip these
- Subscriptions run over a separate WS connection/protocol (`graphql-ws` or the older `subscriptions-transport-ws`) and often have weaker or entirely missing auth checks compared to the HTTP query/mutation path, since they're easy to forget when access control is bolted on.
- Check: does the subscription handshake require the same auth token as queries? Can you subscribe to another user's event stream by supplying their ID as a subscription argument?

## 10. Tooling Summary
| Tool | Purpose |
|---|---|
| **InQL** (Burp extension) | Introspection → generates browsable query/mutation list, bulk scanning |
| **GraphQL Voyager** | Visual schema graph |
| **Altair / GraphiQL / Apollo Sandbox** | Manual query building against live schema |
| **Clairvoyance / clairvoyancex** | Blind schema reconstruction via field-suggestion fuzzing when introspection is off |
| **GraphQL Cop** | Automated GraphQL-specific vuln scanner (introspection, batching, CSRF, etc.) |
| **graphql-path-enum** | Enumerate all valid query paths from a schema |
| **Goctopus** | Org-wide GraphQL endpoint discovery |
| **Burp Suite** (repeater/intruder) | Manual manipulation, batching/alias fuzzing |
| **GraphQL Armor** (defensive) | Reference for what a hardened server blocks (suggestions, depth, cost, batching) — useful to know what you're up against |

## 11. Testing Methodology / Checklist
1. Discover endpoint(s) — common paths, JS bundle, mobile app, subdomains.
2. Fingerprint via error response shape.
3. Attempt standard introspection query.
4. If blocked: try GET vs POST, content-type swaps, ignorable-character regex bypass (`__schema ,\n`), alternate endpoints.
5. If still blocked: field-suggestion fuzzing (manual typos, then Clairvoyance for full reconstruction).
6. Map queries/mutations/subscriptions → load into InQL/Voyager.
7. Auth-test every resolver with cross-user IDs (BOLA/IDOR), not just the top-level query.
8. Check field-level auth — enumerate admin/internal-looking fields from the schema and query them as a low-priv user.
9. Fuzz scalar args for injection (SQLi/NoSQLi/command/XSS).
10. Test batching (array of operations in one request) for rate-limit/brute-force bypass.
11. Test alias abuse for the same purpose.
12. Test deep nesting / circular relationships for DoS.
13. Check GET-based queries and simple-request content types for CSRF exposure on mutations.
14. Check any URL-accepting resolver for SSRF.
15. Test subscription auth independently of query/mutation auth.
16. Note information disclosure even where no "hard" vuln exists — an exposed full schema on a public API is itself a finding if it reveals internal/unreleased functionality.

## 12. Quick Defensive Notes (for the report)
- Disable introspection **and** field suggestions independently — one without the other still leaks the schema.
- Enforce authorization inside every resolver, not just at the top-level query/mutation gate.
- Add query cost analysis + depth limiting, not just a flat rate limiter on HTTP requests.
- Rate-limit/monitor at the *operation* level so batching and aliasing can't bypass request-count-based limits.
- Require CSRF tokens or restrict to `POST` + `application/json` with a custom header to kill GET/simple-request CSRF paths.
- Apply the same auth checks to subscriptions as to queries/mutations.
