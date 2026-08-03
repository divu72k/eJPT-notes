# IDOR / BOLA Deep Dive — Offensive Security Reference

## 1. Root Cause
IDOR (Insecure Direct Object Reference) — called BOLA (Broken Object Level Authorization) in the OWASP API Top 10 — happens when an application uses a client-supplied identifier to fetch or act on a resource, and checks that the *user is authenticated* but never checks that the user is *authorized for that specific object*. It's consistently one of the most common high-impact findings in real assessments precisely because it's easy to introduce (authorization logic has to be re-implemented correctly on every single endpoint) and easy to miss in code review (the endpoint "works correctly" for the legitimate case being tested).

## 2. Where to Look
Any endpoint taking an identifier referencing a specific resource:
- Path parameters — `/api/orders/{id}`, `/users/{id}/profile`
- Query parameters — `?invoice_id=1042`
- Body parameters in POST/PUT/PATCH/DELETE requests
- Identifiers hidden in nested JSON structures, not just top-level fields
- File/document references — `/download?file=report_1042.pdf`
- WebSocket messages and GraphQL query variables (same vulnerability, different transport)

## 3. Testing Methodology

**Step 1 — Two-account setup.** Always test with two accounts of the same privilege level (Account A, Account B) plus, if available, one lower-privileged account testing against higher-privileged data.

**Step 2 — Map every ID-bearing request** made by Account A during normal app usage (Burp's site map / proxy history after a full walkthrough).

**Step 3 — Cross-substitute.** For each captured request, replace Account A's resource ID with one belonging to Account B, while keeping Account A's session/token. Do this for:
- Read operations (GET) — data disclosure
- Write operations (PUT/PATCH) — unauthorized modification
- Delete operations (DELETE) — unauthorized deletion, often the most severe and most overlooked since testers focus on read access

**Step 4 — Test both direct and indirect references.** Direct: numeric/sequential IDs, trivially enumerable. Indirect: UUIDs, hashes, or opaque tokens — these are *not* automatically safe. If a UUID can be harvested from another response (e.g., appears in a shared-link, webhook payload, or another user's publicly-listed content), the "unguessable" property is defeated. Always ask: where else in the app might this identifier leak?

**Step 5 — Test the full CRUD surface per object type**, not just the one endpoint you happened to notice — an app might correctly authorize `GET /orders/{id}` but forget the same check on `GET /orders/{id}/export` or `GET /orders/{id}/history`.

## 4. Common Variants

- **Sequential ID enumeration** — trivial once one authorization gap is found; script iteration across the ID space to demonstrate scale (e.g., "accessed 500 other customers' invoices in under a minute") for report impact.
- **Parameter pollution bypass** — some apps check authorization against one instance of a duplicated parameter but use another for the actual query (`?id=own_id&id=victim_id`).
- **Nested/indirect object references** — object B is only reachable through object A (`/projects/{project_id}/tasks/{task_id}`); check whether `task_id` authorization is actually scoped to the specific `project_id` in the path, or whether any valid `task_id` works regardless of the project segment.
- **Cross-tenant BOLA** — in multi-tenant SaaS, the "object" is effectively the entire tenant's dataset; a tenant-scoping bypass here is a full isolation failure, typically Critical severity.
- **Function-chaining BOLA** — an endpoint correctly scopes access on the primary action but a secondary action triggered by it (e.g., a "resend invoice" action that emails a PDF) doesn't re-check ownership.
- **Batch/bulk endpoint BOLA** — bulk-action endpoints (`/api/orders/bulk-export`) that accept an array of IDs sometimes authorize the *request* but not each *individual ID* in the array.

## 5. Distinguishing Real Findings from Non-Issues
Not every ID-swap "success" is a vulnerability — verify actual impact:
- Does the response actually contain *different* data belonging to a different user/object, or does it just return a generic/empty response regardless of ID?
- Is the object genuinely private, or intentionally public-by-design (e.g., a public product catalog ID)?
- Confirm with a clean before/after diff — Account A's own data vs. the swapped-in victim data — as your PoC evidence.

## 6. Tools
| Tool | Use |
|---|---|
| **Burp Suite (Autorize / AuthMatrix extensions)** | Automates replaying captured requests under a second session/role to flag authorization differences at scale |
| **Burp Intruder** | Sequential ID enumeration to demonstrate scale of exposure |
| **Custom scripts (Python + requests)** | For bulk/batch endpoint testing and complex multi-step object chains |

## 7. Checklist
- [ ] Full CRUD surface enumerated for every distinct object type in the app
- [ ] Cross-account substitution tested on read, write, and delete operations
- [ ] Both sequential/direct and UUID/opaque identifiers tested
- [ ] Nested object references tested for parent-scope enforcement, not just child-ID validity
- [ ] Bulk/batch endpoints tested for per-item authorization, not just request-level
- [ ] Cross-tenant boundary tested if the app is multi-tenant
- [ ] Secondary/chained actions triggered by an authorized primary action re-checked for their own authorization
- [ ] Scale of exposure demonstrated (how many objects are enumerable) for report impact, where appropriate

## 8. Severity Notes
Cross-tenant data exposure or write/delete access on another user's data → Critical–High. Read-only exposure of non-sensitive metadata → Medium. Always weight severity by data sensitivity, scale of enumerability, and whether write/delete actions (not just reads) are affected.

## 9. Sample Reporting Language
**Finding title:** Broken Object Level Authorization on `DELETE /api/v1/documents/{id}`

**Description:** The document deletion endpoint validates that the requester is authenticated but does not verify that the requester owns or is a collaborator on the specified document. An authenticated Account A was able to delete documents belonging to Account B by substituting Account B's document ID into an otherwise-normal delete request signed with Account A's session token.

**Impact:** Any authenticated user can delete any other user's documents, resulting in unauthorized data loss across the platform without requiring any special privilege or prior access to the target document.

**Recommendation:** Implement a server-side authorization check on every object-level operation (read, write, delete) that verifies the requesting user's relationship to the specific object — ownership, team membership, or explicit sharing grant — rather than authentication alone. Apply this check consistently across the full CRUD surface for every object type, including secondary and bulk-action endpoints.

---
*Assumes testing under written authorization with test accounts provisioned for cross-account testing. Delete-operation testing should be scoped carefully — confirm with the client whether destructive testing is permitted or should be limited to read/write PoCs.*
