# Race Condition Testing Notes — Offensive Security Reference

## 1. Root Cause
A race condition (in this context, usually a TOCTOU — time-of-check-to-time-of-use — flaw) occurs when an application checks a condition (balance sufficient, coupon unused, item in stock) and then acts on it in a way that isn't atomic, leaving a window where concurrent requests can both pass the check before either has updated the state. Send enough requests fast enough within that window, and an action meant to happen once happens multiple times.

## 2. High-Value Targets
Anywhere an action is meant to be limited — once per user, once per code, bounded by a finite resource:
- Coupon/discount code redemption (single-use codes applied multiple times)
- Fund withdrawal / balance transfer (withdraw more than the account balance by racing concurrent withdrawal requests)
- Inventory/stock decrement (purchase more of a limited-stock item than actually exists)
- Referral bonus / sign-up bonus claiming (claim a one-time bonus multiple times across concurrent requests)
- Rate-limit or attempt-counter bypass (racing requests to process more attempts than the limit before the counter updates)
- Account/resource creation with uniqueness constraints (creating two accounts with the same "unique" identifier by racing the creation requests before the first commit)
- Voting/rating systems (casting more than the allowed number of votes)
- Multi-currency or multi-step financial transactions where each leg is validated independently

## 3. Testing Methodology

**Step 1 — Identify a limited/single-use action** with a clear "should only work once" semantic.

**Step 2 — Establish a baseline** by performing the action normally once, confirming expected single-success behavior.

**Step 3 — Send the request concurrently**, not sequentially. This is the critical technical detail: sequential rapid-fire requests (even scripted) usually still land far enough apart in server processing that the check-then-act window has already closed. True race condition testing requires requests to arrive at the server as close to simultaneously as possible.

**Tooling for true concurrency:**
- **Burp Suite's Turbo Intruder** — the standard tool for this; use the `race` attack template, which opens all connections and holds them, then releases the final byte of each request simultaneously (the "last-byte sync" technique) to land requests within microseconds of each other server-side, defeating network jitter that would otherwise desynchronize naively-scripted concurrent requests.
- **Custom async scripts** (Python `asyncio`/`aiohttp`, or Go) as an alternative if Turbo Intruder isn't available, though achieving true last-byte synchronization is harder to replicate manually.

**Step 4 — Scale up gradually.** Start with 2 concurrent requests to confirm the race exists at all, then scale to 10–50+ to demonstrate real-world exploitability and quantify impact (e.g., "a single-use $10 coupon was successfully applied 47 times in one batch, resulting in a $470 discount").

**Step 5 — Test across different HTTP/1.1 vs HTTP/2 behavior** if applicable — HTTP/2's multiplexing over a single connection can make achieving true request synchronization easier/more reliable than HTTP/1.1's connection-per-request model in some setups; Turbo Intruder supports both.

## 4. Related Sub-Classes

- **Single-endpoint races** — the classic case: one endpoint, one check, called concurrently.
- **Multi-endpoint / multi-step races** — the race window spans multiple different endpoints in a workflow (e.g., a "reserve item" and "confirm payment" endpoint pair where the reservation isn't atomically locked against the confirmation).
- **Partial construction races** — exploiting the window during multi-step object creation where an object exists in an incomplete/default-privilege state briefly before being fully initialized (e.g., a newly created account briefly has default/elevated permissions before role assignment completes).

## 5. Tools
| Tool | Use |
|---|---|
| **Burp Suite Turbo Intruder** | Purpose-built last-byte-sync race condition testing |
| **race-the-web** | Standalone tool for basic concurrent request race testing |
| **Custom asyncio/aiohttp or Go scripts** | Fallback for environments without Burp Pro access |

## 6. Checklist
- [ ] Every single-use/limited action identified across the app (coupons, withdrawals, inventory, bonuses, votes)
- [ ] True concurrent (not just rapid sequential) requests tested using last-byte-sync technique
- [ ] Race scaled up from 2 to higher concurrency to quantify real-world impact
- [ ] Multi-step/multi-endpoint workflows tested for races spanning the full workflow, not just single endpoints
- [ ] Object-creation flows tested for partial-construction privilege windows
- [ ] Financial/balance-affecting races prioritized for report impact given direct monetary consequence

## 7. Severity Notes
Financial-impact races (fund withdrawal beyond balance, unlimited coupon redemption) → Critical–High, direct monetary loss potential at scale. Non-financial limit bypasses (vote count, rate-limit bypass) → Medium, scaled by what the limit was protecting against.

## 8. Sample Reporting Language
**Finding title:** Race Condition in Coupon Redemption Allows Multiple Uses of Single-Use Discount Code

**Description:** The `/api/cart/apply-coupon` endpoint validates that a coupon code has not been previously used before applying its discount and marking it as redeemed. Using Burp Suite's Turbo Intruder with a last-byte synchronization race attack, 20 concurrent requests were sent using a single-use coupon code. 17 of the 20 requests successfully applied the discount, confirming that the "already used" check and the "mark as used" update are not performed atomically.

**Impact:** An attacker can apply a single-use discount code an effectively unlimited number of times by sending sufficiently concurrent requests, resulting in direct financial loss scaled to the discount value and the degree of concurrency achievable.

**Recommendation:** Enforce atomicity on the check-and-update operation using database-level constructs such as row-level locking (`SELECT ... FOR UPDATE`), atomic increment/compare-and-swap operations, or a unique database constraint on (coupon_code, user_id) that causes concurrent duplicate redemption attempts to fail at the database layer rather than relying on an application-level check performed before the update.

---
*Assumes testing under written authorization. Race condition testing against financial/inventory systems can cause real data inconsistency in production — coordinate scope and cleanup expectations with the client before testing, and prefer staging environments where available.*
