# SSRF (Server-Side Request Forgery) Testing Notes — Offensive Security Reference

## 1. Root Cause
SSRF occurs when an application takes a user-influenced URL, hostname, or IP and has the *server* make a request to it, without adequately restricting where that request can go. The server effectively becomes a proxy the attacker can direct — often into internal networks the attacker could never reach directly.

## 2. Where to Look
Any feature where the server fetches something on the client's behalf:
- Webhook registration / callback URLs
- "Import from URL" or "fetch avatar/image from URL" features
- PDF/screenshot generation services that render a given URL
- File upload-by-URL, or document/image processing pipelines that accept a remote source
- XML parsers (XXE-to-SSRF via external entities — see the XXE notes)
- PDF generators or link-preview features that fetch metadata (Open Graph tags) from a submitted URL
- Any "test connection" or integration-setup feature (Slack/webhook integrations, custom API connectors)
- Redirect/URL-shortener style endpoints
- Server-side rendering of user-supplied SVG (`<image href=...>` can trigger a fetch)

## 3. Testing Methodology

**Step 1 — Confirm the server is making the request, not the client.** Point the target parameter at a domain/endpoint you control and monitor for an inbound hit (Burp Collaborator, `interactsh`, or a simple netcat listener + DNS you control). A hit confirms basic SSRF; response timing differences (fast fail vs. slow timeout) can also indicate blind SSRF even without a callback if outbound traffic is fully egress-filtered.

**Step 2 — Determine response visibility.**
- **In-band/full SSRF** — the response from the fetched URL is reflected back to you (e.g., an "import from URL" feature that displays the fetched content). Highest impact — direct internal data read.
- **Blind SSRF** — no response content returned, but you can infer success via timing, DNS interaction, or side effects (email sent, webhook triggered elsewhere).

**Step 3 — Target internal/restricted ranges once basic SSRF is confirmed:**
- Loopback: `127.0.0.1`, `localhost`, `0.0.0.0`
- RFC1918 internal ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- **Cloud metadata endpoints — highest priority target:** `169.254.169.254` (AWS/Azure/GCP IMDS). A successful hit here can leak IAM role credentials (AWS `latest/meta-data/iam/security-credentials/`), service account tokens (GCP), or managed identity tokens (Azure), turning an SSRF into full cloud account compromise. Always test both IMDSv1 (simple GET) and check whether IMDSv2 (token-required, harder to SSRF into) is enforced — IMDSv1 availability is itself a finding.
- Internal service discovery — try common internal ports/services on discovered internal IPs (Redis on 6379, internal admin panels, Kubernetes API on 6443/10250) once you have any internal network read primitive.

## 4. Filter Bypass Techniques
Naive SSRF filters (regex/blocklist-based) are common and usually bypassable:
- **Alternate IP encodings** — decimal (`2130706433` = `127.0.0.1`), octal (`0177.0.0.1`), hex (`0x7f.0.0.1`), IPv6-mapped (`::ffff:127.0.0.1`), or shorthand (`127.1`)
- **DNS rebinding** — register a domain that resolves to a public IP on first lookup (passing validation) and an internal IP on a subsequent lookup at request time
- **Open redirect chaining** — if the target validates the initial URL but then follows redirects, host a redirect on an allowed domain that 302s to the internal target
- **URL parser inconsistencies** — exploit differences between the validation library's URL parsing and the actual HTTP client's parsing, e.g., `http://allowed-domain.com@169.254.169.254/` (userinfo confusion) or `http://169.254.169.254#@allowed-domain.com`
- **Alternate schemes** — `file://`, `gopher://`, `dict://` where the fetching library supports them, each with different exploitation potential (gopher can be used to smuggle raw TCP payloads to internal services like Redis)

## 5. Escalation Paths
- **Cloud metadata → credential theft → full cloud pivot** (the single highest-value SSRF outcome, always prioritize testing this)
- **Internal service interaction** — reaching internal admin panels, databases, or message queues with no auth exposed internally
- **Port scanning via response timing** — even blind SSRF can be used to fingerprint internal open ports by measuring connect-vs-timeout response differences
- **Gopher-based protocol smuggling** — crafting raw request bytes via `gopher://` to speak to internal services (Redis `SET`/`CONFIG` commands for RCE via module load, internal SMTP for relay abuse) where the HTTP client supports the gopher scheme

## 6. Tools
| Tool | Use |
|---|---|
| **Burp Collaborator / interactsh** | Out-of-band confirmation for blind SSRF |
| **SSRFmap** | Automated SSRF exploitation against common targets (AWS metadata, Redis, etc.) once a vector is confirmed |
| **Gopherus** | Generates gopher:// payloads for internal service exploitation |

## 7. Checklist
- [ ] Every URL/hostname-accepting parameter identified and tested with an OOB callback domain
- [ ] Response visibility determined (in-band vs. blind)
- [ ] Cloud metadata endpoint (`169.254.169.254`) tested as top priority if app runs in a cloud environment
- [ ] Internal RFC1918 ranges tested where metadata endpoint isn't reachable/applicable
- [ ] Alternate IP encodings tested against any naive blocklist filter
- [ ] Redirect-chaining bypass tested if the fetcher follows redirects
- [ ] Alternate URL schemes (`file://`, `gopher://`) tested if the underlying HTTP client might support them
- [ ] DNS rebinding considered for time-of-check/time-of-use validation gaps

## 8. Severity Notes
Cloud metadata credential theft → Critical, near-always full cloud environment compromise potential. Internal network read access to sensitive internal services → High–Critical depending on what's reachable. Blind SSRF with no clear internal target reachable → Medium, but still worth reporting as it indicates a control gap even without demonstrated internal impact.

## 9. Sample Reporting Language
**Finding title:** Server-Side Request Forgery via `webhookUrl` Parameter Leading to Cloud Metadata Exposure

**Description:** The `webhookUrl` parameter on the integration setup endpoint is used by the server to make an outbound HTTP request without validating the destination against an allowlist of expected external domains. Setting this parameter to `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` returned valid temporary AWS IAM credentials for the instance's attached role in the application's response.

**Impact:** An attacker can obtain valid cloud IAM credentials for the hosting environment's role, potentially enabling access to other cloud resources (S3 buckets, databases, additional compute) scoped to that role's permissions — a full pivot from application-layer access to cloud infrastructure compromise.

**Recommendation:** Implement strict allowlisting of permitted destination domains for any server-initiated outbound request feature. Additionally, enforce IMDSv2 (token-required metadata requests) at the infrastructure level to prevent simple SSRF from directly retrieving metadata credentials, and apply network-level egress controls preventing application servers from reaching the metadata endpoint unless explicitly required.

---
*Assumes testing under written authorization. Internal network and metadata endpoint testing can have infrastructure-wide impact — confirm cloud environment details and scope boundaries with the client before testing.*
