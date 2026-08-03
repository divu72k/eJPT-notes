# Business Logic Flaws Testing Notes — Offensive Security Reference

## 1. Why This Category Is Different
Business logic flaws don't violate any technical security control — no injection, no broken crypto, no missing auth check. They exploit the *assumptions* the application makes about how it will be used. No scanner catches these; they require understanding what the application is actually *for* and then asking "what happens if I don't follow the intended path?" This makes them consistently under-reported by automated tooling and correspondingly high-value in manual assessments.

## 2. Core Testing Mindset
For every multi-step process, form, or workflow in the app, ask:
- What does the app *assume* about the order operations happen in?
- What does it assume about values being positive, within range, or internally consistent?
- What does it assume the client will and won't do, that a legitimate client (browser/app) enforces but the server doesn't re-verify?
- Can this action be repeated, when it should only happen once?
- Can this action be skipped, when it should be mandatory?

## 3. Common Categories & Test Approaches

### 3.1 Workflow / State Machine Bypass
Multi-step processes (checkout, KYC/identity verification, loan approval, multi-stage signup) are often implemented as independently-callable endpoints per step. Test calling a later step directly without completing earlier ones — e.g., can you hit the "order confirmed, ship now" endpoint without ever completing the "payment processed" step? Can you access a "verified" account state by directly calling the verification-complete endpoint rather than actually completing verification?

### 3.2 Price / Quantity / Parameter Manipulation
- Negative quantities (`quantity: -5`) that might result in a credit rather than a charge
- Decimal quantities where integers are expected, potentially causing rounding-based value extraction
- Client-supplied price/total fields that should be server-calculated — intercept and modify the price parameter in a checkout request to see if the server trusts it rather than recalculating server-side
- Currency confusion — switching currency mid-transaction where conversion isn't re-validated
- Coupon/discount stacking beyond intended limits — applying multiple discount codes when only one should be allowed, or reapplying a single-use code multiple times in parallel requests

### 3.3 Race Conditions in Business-Critical Actions
(See dedicated Race Conditions notes for full technical methodology — this is the business-logic framing of the same class.) Coupon redemption, fund withdrawal, inventory decrement, and "claim this limited offer" actions are classic targets — fire the same request concurrently and see if server-side locking actually prevents double-application.

### 3.4 Replay of One-Time Actions/Tokens
Password reset tokens, email verification links, payment confirmation callbacks, and referral/invite codes — test whether they're genuinely single-use and expire, or just conventionally treated as one-time by a well-behaved client.

### 3.5 Insufficient Anti-Automation
Account creation, coupon generation, review/rating submission, referral bonus claiming — anywhere a per-account or per-action limit exists, test whether it's enforced server-side or only through UI friction (rate limiting, CAPTCHA) that can be bypassed by direct API calls.

### 3.6 Trust Boundary Violations Between Client and Server
Anywhere the client calculates something and sends the *result* rather than the server recalculating independently — totals, permissions, feature flags, subscription tier/entitlement checks. Test by modifying the client-supplied value directly and observing whether the server blindly trusts it.

### 3.7 Feature Interaction Flaws
Flaws that only appear when two legitimate features are combined in an unintended way — e.g., using a "gift this subscription" feature combined with an account-merge feature to duplicate a paid entitlement, or using an export feature in combination with a sharing feature to exfiltrate data that neither feature alone would expose. These require actually exploring the app broadly rather than testing endpoints in isolation.

### 3.8 Insufficient Validation of Real-World Constraints
Booking systems allowing overlapping reservations of the same resource, negative account balances where none should be possible, exceeding stated capacity/quota limits (e.g., adding more seats to an event than physically exist) — these map real-world business rules onto the system and test whether the system actually enforces them.

## 4. Methodology for Finding These
1. **Map every workflow fully** — walk each multi-step process end-to-end as a legitimate user first, capturing every request.
2. **Identify every trust assumption** — for each step, note what the server is implicitly trusting the client to have already done or to send correctly.
3. **Break one assumption at a time** — reorder steps, skip steps, replay steps, manipulate values, run steps concurrently.
4. **Think like the business, not just like a technical tester** — read the terms of service, pricing page, and stated limits; each stated rule/limit is a hypothesis to test against the actual implementation.
5. **Combine features** — deliberately try unusual combinations of legitimate features rather than testing each in isolation.

## 5. Tools
Largely manual/methodological rather than tool-driven. Burp Repeater (step reordering/replay) and Turbo Intruder (concurrency/race testing) are the main technical aids; the actual finding process is analytical, not automated.

## 6. Checklist
- [ ] Every multi-step workflow mapped and tested for step-skipping/reordering
- [ ] All client-supplied values that should be server-derived (price, total, permissions) tested for server-side trust
- [ ] One-time tokens/actions tested for actual single-use enforcement
- [ ] Per-account/per-action limits tested via direct API calls bypassing UI friction
- [ ] Concurrent request testing applied to any balance-affecting or limited-quantity action
- [ ] Stated business rules/limits (from ToS, pricing page, help docs) tested against actual enforcement
- [ ] Legitimate feature combinations explored for unintended interaction effects

## 7. Severity Notes
Severity here maps to direct business/financial impact more than to a technical CVSS-style score — free access to paid features, financial fraud potential (negative pricing, discount stacking), or unauthorized workflow completion (e.g., bypassing identity verification) are typically High–Critical given direct monetary or compliance impact, even though no traditional "vulnerability" (injection, auth bypass) is technically present.

## 8. Sample Reporting Language
**Finding title:** Checkout Workflow Allows Order Completion Without Payment Step

**Description:** The checkout process consists of independently-callable API endpoints for cart review, payment processing, and order confirmation. Testing confirmed that the order-confirmation endpoint (`POST /api/checkout/confirm`) does not verify that a corresponding successful payment record exists for the session before marking an order as paid and triggering fulfillment, allowing the payment step to be skipped entirely.

**Impact:** An attacker can obtain paid products or services without completing payment by directly calling the confirmation endpoint after adding items to cart, bypassing the payment step entirely — resulting in direct financial loss at scale if automated.

**Recommendation:** Implement server-side state validation at each workflow step that verifies the required prior step(s) were genuinely completed (e.g., confirming a valid, matching payment gateway transaction record exists) before allowing progression, rather than trusting that the client called the endpoints in the intended order.

---
*Assumes testing under written authorization. Testing that involves real payment processing, financial transactions, or production inventory/booking systems should be explicitly scoped and coordinated with the client to avoid unintended real-world financial or operational impact.*
