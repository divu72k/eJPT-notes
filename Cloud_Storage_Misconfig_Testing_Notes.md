# Cloud Storage Misconfiguration Testing Notes (S3 / Azure Blob) — Offensive Security Reference

## 1. Root Cause
Cloud object storage (S3 buckets, Azure Blob containers, GCS buckets) defaults vary by provider and have shifted over time toward safer defaults, but misconfiguration remains extremely common because permissions are frequently set broadly during development ("just make it public so it works") and never tightened, or because bucket policies/ACLs and account-level public-access-block settings interact in ways that are easy to get wrong.

## 2. Discovery / Enumeration

**Finding buckets belonging to a target:**
- Naming convention guessing — `{company}-backup`, `{company}-assets`, `{company}-prod`, `{company}-dev`, `{company}-logs`, `{company}-static`, combined with common suffixes/prefixes
- JS/HTML source mining — bucket URLs frequently appear directly in frontend asset references (`<img src="https://company-assets.s3.amazonaws.com/...">`)
- Certificate transparency logs and DNS records — CNAME records pointing at bucket-backed custom domains
- GitHub/GitLab code search for hardcoded bucket names or ARNs in committed code, CI configs, or Terraform/CloudFormation files
- Tools: **S3Scanner**, **GrayhatWarfare** (search engine indexing publicly known open buckets — useful for scoping/verification, not blind discovery), **cloud_enum**, **Bucket Finder**, **MicroBurst** (Azure-specific enumeration)

## 3. S3-Specific Testing

**Access level testing (test each independently — they're not mutually exclusive):**
```bash
aws s3 ls s3://target-bucket --no-sign-request        # anonymous list
aws s3 cp s3://target-bucket/somefile . --no-sign-request   # anonymous read
echo "test" > test.txt && aws s3 cp test.txt s3://target-bucket/ --no-sign-request  # anonymous write
```
- **Public listing** — reveals full bucket contents/structure even if individual objects aren't directly downloadable, itself a disclosure issue (internal file naming, structure, potentially sensitive filenames alone).
- **Public read** — direct data exposure; check for backups, database dumps, config files with embedded credentials, source code, PII exports, employee documents.
- **Public write** — check if you can upload/overwrite objects; if the bucket serves a website or is referenced by application code (e.g., serving JS assets), public write can lead directly to stored XSS or supply-chain-style compromise of anyone loading content from that bucket.
- **ACL vs. bucket policy vs. account-level Block Public Access** — all three layers matter; a bucket policy might grant public access even with a restrictive ACL, or vice versa, and account-level Block Public Access settings can override both if enabled (test whether it's actually enabled, since it's opt-in-by-default only for accounts/buckets created after the setting became default).
- **Bucket policy misconfig via wildcard principal** — `"Principal": "*"` combined with insufficiently scoped `Condition` blocks.
- **Cross-account access misconfiguration** — buckets that grant access to "any authenticated AWS user" (`"Principal": {"AWS": "*"}` with `aws:PrincipalIsAWSAccount` checks missing) rather than specifically trusted accounts — exploitable by anyone with any AWS account, not just the public.

**Signed URL / pre-signed URL testing:**
- Check expiration enforcement — does an expired pre-signed URL actually get rejected, or does clock skew / caching allow reuse past intended expiry?
- Check scope — does a pre-signed URL intended for one specific object grant broader access than intended due to overly permissive underlying IAM policy?

## 4. Azure Blob Storage-Specific Testing

- **Container-level public access** — Azure containers have three explicit states: Private, Blob (anonymous read of blobs, not listing), and Container (anonymous read + listing). Test both direct blob access and container listing separately since they're independently configurable.
```bash
az storage blob list --container-name target --account-name targetaccount --auth-mode login
# or unauthenticated:
curl https://targetaccount.blob.core.windows.net/target?restype=container&comp=list
```
- **SAS token issues** — Shared Access Signature tokens with overly broad permissions (write/delete when only read was intended), excessively long expiry, or tokens accidentally leaked in client-side code/logs/URLs.
- **Storage account key exposure** — if a full storage account key (not just a SAS token) leaks (in a mobile app binary, JS bundle, or public repo), it grants full read/write/delete across *every* container in the account, not just one — always check the scope of any leaked credential type before rating severity.

## 5. Escalation Once Access Is Confirmed
- Grep retrieved contents for embedded credentials (DB connection strings, API keys, other cloud credentials) — bucket compromise frequently chains directly into broader infrastructure compromise via secrets stored in "just a backup file."
- Check for Terraform state files (`.tfstate`) — these routinely contain plaintext secrets and full infrastructure topology.
- Check for source code / CI artifacts revealing internal architecture, other internal endpoints, or additional attack surface.

## 6. Tools
| Tool | Use |
|---|---|
| **AWS CLI (`--no-sign-request`)** | Manual anonymous access testing against S3 |
| **S3Scanner / Bucket Finder** | Bulk bucket discovery and permission testing |
| **cloud_enum** | Multi-cloud (AWS/Azure/GCP) enumeration |
| **MicroBurst** | Azure-specific enumeration and exploitation toolkit |
| **ScoutSuite / Prowler** | Broader cloud security posture assessment beyond just storage, useful if cloud config review is in scope |

## 7. Checklist
- [ ] Bucket/container names enumerated via naming conventions, source mining, and cert transparency
- [ ] Anonymous list access tested independently from anonymous read access
- [ ] Anonymous write access tested (higher-severity than read-only exposure)
- [ ] All three permission layers checked where applicable (ACL, bucket/container policy, account-level public access block)
- [ ] Retrieved content reviewed for embedded credentials/secrets enabling further pivot
- [ ] Pre-signed URL / SAS token expiry and scope tested
- [ ] Cross-account principal misconfiguration tested (not just "public," but "any AWS/Azure account")
- [ ] Full storage account key exposure checked for and scope-tested if found (grants account-wide access, not container-scoped)

## 8. Severity Notes
Public write access on a bucket serving live application content → Critical (supply-chain/stored-XSS potential). Public read exposing PII, credentials, or financial data → Critical–High depending on data volume/sensitivity. Public listing only, no readable sensitive content → Low–Medium (information disclosure of structure/naming). Leaked full account key vs. scoped SAS/pre-signed URL → treat account-key leaks as significantly higher severity given the broader blast radius.

## 9. Sample Reporting Language
**Finding title:** Publicly Readable and Writable S3 Bucket Exposing Customer Data Backups

**Description:** The S3 bucket `company-prod-backups` was found to permit both anonymous listing and anonymous read access via its bucket policy, which granted `s3:GetObject` and `s3:ListBucket` to principal `*` without any IP or account restriction. The bucket contained daily database export files including customer PII and unhashed API credentials for third-party integrations. Anonymous write access was also confirmed via a test file upload.

**Impact:** Any unauthenticated internet user can read the full contents of customer data backups, including PII and embedded third-party credentials, and can upload or overwrite objects in the bucket, potentially enabling further compromise if bucket contents are referenced by production systems.

**Recommendation:** Remove the wildcard principal from the bucket policy and restrict access to specifically authorized IAM roles/accounts only. Enable S3 Block Public Access at the account level as a defense-in-depth control. Rotate any credentials found within exposed backup files immediately, and review CloudTrail logs for evidence of prior unauthorized access to this bucket.

---
*Assumes testing under written authorization. Confirm with the client before performing any write/upload testing against production storage, and avoid downloading/retaining more data than necessary to demonstrate impact — reference specific filenames/record counts in the report rather than exfiltrating full datasets.*
