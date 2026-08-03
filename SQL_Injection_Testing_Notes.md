# SQL Injection Testing Notes — Offensive Security Reference

## 1. Root Cause
SQLi occurs when user-controlled input is concatenated into a SQL query string rather than passed as a parameterized bind variable, allowing an attacker to alter the query's logic or structure. It shows up anywhere input reaches a database call: form fields, URL parameters, JSON/XML bodies, HTTP headers (`User-Agent`, `X-Forwarded-For`, cookies), and even file names or sort/filter parameters that get built into `ORDER BY` clauses.

## 2. Detection Methodology

**Manual probing (do this before tooling — understand the injection context):**
- Single quote `'` — look for SQL syntax errors in the response (500 error, stack trace, generic "database error" page).
- Boolean pairs — `' AND 1=1--` vs `' AND 1=2--`; compare response length/content/status.
- Numeric context — if the parameter is unquoted (e.g., `?id=5`), test `5 AND 1=1` vs `5 AND 1=2` without quotes.
- Time-based — `' AND SLEEP(5)--` (MySQL), `'; WAITFOR DELAY '0:0:5'--` (MSSQL), `' AND pg_sleep(5)--` (Postgres). Use when there's zero observable output difference (true blind).
- Error-based — force verbose DB errors to leak data directly: `' AND extractvalue(1,concat(0x7e,(SELECT version())))--` (MySQL/XML error trick).

**Identify the DBMS and injection context first** — string vs numeric, single vs double quote, comment syntax (`--`, `#`, `/**/`), and whether stacked queries (`;`) are permitted, since all of this changes payload construction.

## 3. Exploitation Paths

- **UNION-based** — once you know the column count (`ORDER BY n--` incrementing until error) and which columns render in the response, use `UNION SELECT` to pull arbitrary data: `' UNION SELECT username, password FROM users--`.
- **Boolean-blind** — binary search character-by-character extraction: `' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--`, iterating position and character.
- **Time-blind** — same binary search, but infer true/false from response delay instead of content, for cases with zero observable diff.
- **Out-of-band (OOB)** — when both in-band and blind channels are unusable/too slow: trigger DNS/HTTP callbacks to exfiltrate data, e.g., MSSQL `xp_dirtree`, Oracle UTL_HTTP, or MySQL `LOAD_FILE` combined with a UNC path to a listener you control (Burp Collaborator or similar).
- **Stacked queries** — `'; DROP TABLE logs--` or `'; EXEC xp_cmdshell('whoami')--` (MSSQL) if the driver allows multiple statements per call — high-severity since this can reach OS command execution.
- **Second-order SQLi** — payload is stored benignly (e.g., in a "display name" field) and only triggers injection later when a *different* function pulls that stored value into a query unsanitized. Easy to miss because the injection point and the trigger point are different requests entirely.

## 4. WAF/Filter Evasion (only within authorized scope)
Case manipulation (`SeLeCt`), inline comments (`SEL/**/ECT`), whitespace alternatives (`%0a`, `/**/`, `+`), encoding (URL/double-URL/Unicode), and alternate equivalent syntax (`OR 'a'='a'` vs `OR 1=1` vs `OR true`).

## 5. Tools
| Tool | Use |
|---|---|
| **sqlmap** | Automated detection + exploitation across DBMS types; `--risk`/`--level` tuning, `--os-shell` for command exec via stacked queries where supported |
| **Burp Suite** | Manual testing via Repeater/Intruder; Collaborator for OOB confirmation |
| **NoSQLMap** | NoSQL equivalent for Mongo-style injection |

## 6. Checklist
- [ ] Every parameter tested (URL, body, JSON, headers, cookies) — not just obvious search/login fields
- [ ] DBMS fingerprinted before crafting payloads
- [ ] Boolean, time-based, and error-based channels all attempted
- [ ] OOB exfiltration attempted if in-band/blind channels are blocked
- [ ] Second-order injection considered — trace where stored input is later reused in queries
- [ ] Stacked query support tested (higher-severity command execution potential)
- [ ] WAF presence identified and evasion attempted only within scope

## 7. Severity Notes
Data-extraction SQLi on sensitive tables → Critical. Blind SQLi with confirmed extraction capability → High–Critical depending on data sensitivity. Stacked-query RCE via `xp_cmdshell` or similar → Critical, full host compromise potential.

## 8. Sample Reporting Language
**Finding title:** SQL Injection in `search` Parameter (`/api/products/search`)

**Description:** The `search` parameter is concatenated directly into a backend SQL query without parameterization. A time-based blind payload (`' AND SLEEP(5)--`) produced a consistent 5-second response delay, confirming injectability. Boolean-based extraction confirmed access to the underlying `users` table, including password hash values.

**Impact:** An unauthenticated/low-privileged attacker can extract, and potentially modify or delete, arbitrary data from the application database, including credentials and any other sensitive data stored in the backend.

**Recommendation:** Use parameterized queries / prepared statements exclusively for all database access. Do not rely on input sanitization or WAF rules as the primary control — they are bypassable and should be treated as defense-in-depth only.

---
*Assumes testing under written authorization. Time-based and stacked-query testing can cause production load or data loss — confirm scope and get explicit sign-off before using destructive payloads (DROP/UPDATE/DELETE) even in a PoC.*
