# Mobile API / App Testing Notes — Offensive Security Reference

## 1. Scope of This Category
Mobile app testing splits into two overlapping surfaces: the **client** (the iOS/Android binary itself — local storage, code-level flaws, reverse engineering) and the **API** it talks to (usually the highest-value target, since that's where the real data/logic lives — see the API Pentesting Walkthrough for the backend-side methodology in depth). This document focuses on the mobile-specific setup and client-side techniques needed to get traffic visibility and extract useful intel to feed into that backend testing.

## 2. Environment Setup

- **Android:** rooted device or emulator (Genymotion, or AVD with root via Magisk) — needed to install a proxy CA cert as a trusted system cert and to run Frida.
- **iOS:** jailbroken device (Frida works far better with jailbreak access) or use of tools like `objection` for limited testing on non-jailbroken devices via app repackaging.
- **Proxy setup:** Burp Suite or mitmproxy configured as the device's network proxy, with the proxy's CA certificate installed and trusted on the device — this is step one for any traffic visibility at all.

## 3. Certificate Pinning Bypass
Most production apps implement cert/public-key pinning specifically to defeat proxy-based traffic inspection — expect to need a bypass before any traffic analysis is possible.

- **Frida** — the standard tool. Use published bypass scripts (e.g., `frida-multiple-unpinning` or SSL-kill-switch equivalents) that hook the app's certificate validation functions (`X509TrustManager` on Android, `SecTrustEvaluate`/`NSURLSession` delegate methods on iOS) and force them to accept the proxy's certificate.
- **Objection** — wraps common Frida bypass scripts into simpler CLI commands (`android sslpinning disable`, `ios sslpinning disable`) for faster setup without writing custom hooks.
- **Static bypass (APK patching)** — for Android, decompile with `apktool`, locate and patch the pinning validation logic or `network_security_config.xml`, then rebuild and resign the APK — useful when dynamic Frida hooking is blocked by anti-tampering/root detection.
- **Native/library-level pinning** — some apps implement pinning in native code (JNI/C++) or via third-party networking libraries rather than the OS-standard APIs; this requires identifying the specific pinning implementation (often via static analysis of the binary) before an appropriate Frida hook can target it.

## 4. Root/Jailbreak Detection Bypass
Apps performing security-sensitive operations often detect root/jailbreak and refuse to run or restrict functionality. Common bypass approaches:
- Frida hooks targeting known detection methods (checking for `su` binary presence, checking build tags, checking for Magisk-specific files/packages)
- Magisk Hide / Zygisk modules on Android specifically designed to hide root from detection checks
- For simple checks, static patching of the detection logic directly in the decompiled APK

## 5. Static Analysis
- **Android:** decompile the APK with `jadx` or `apktool` for readable Java/Smali source. Review `AndroidManifest.xml` for exported components (activities/services/broadcast receivers marked `exported="true"` without proper permission checks — these can be launched by *any* other app on the device, a common privilege/data-exposure issue). Grep decompiled source for hardcoded API keys, secrets, internal endpoint URLs, and debug/test endpoints left in production builds.
- **iOS:** use `class-dump` or Hopper/Ghidra on the decrypted binary (requires jailbroken device or decrypted IPA) to review Objective-C/Swift class structure and string tables for the same category of hardcoded secrets and endpoint references.
- **Both platforms:** review any bundled config files, `.plist` (iOS) or `.xml`/`.properties` (Android) resource files for embedded credentials or environment-specific (dev/staging) endpoint URLs that might have weaker security controls than production.

## 6. Local Data Storage Review
- **Android:** check `/data/data/{package}/` for shared preferences (often stored as plaintext XML), SQLite databases, and cache files — look for tokens, session data, PII, or credentials stored without encryption.
- **iOS:** check the app sandbox (`Documents/`, `Library/`) for plist files, SQLite/Core Data stores, and keychain usage — verify whether sensitive data uses Keychain (with appropriate accessibility class, e.g., not `kSecAttrAccessibleAlways`) versus being dropped into a plaintext plist or NSUserDefaults, which is a common downgrade from the platform's actual secure-storage capability.
- **Both:** check clipboard handling (sensitive data like OTPs or passwords copyable and persisting in clipboard longer than necessary), and screenshot/backgrounding behavior (sensitive screens visible in the OS app-switcher preview or included in device backups).

## 7. Runtime Manipulation with Frida
Beyond pinning bypass, Frida enables broader dynamic testing:
- Hooking business-logic functions to bypass client-side-only validation (e.g., a "premium feature" gate implemented as a simple boolean check in app code, which can be hooked and forced to always return true)
- Intercepting and dumping encryption keys or tokens at the point they're used in memory, even if obfuscated at rest
- Tracing method calls to understand undocumented API interactions the app makes that aren't visible from static analysis alone

## 8. Feeding Into API Testing
Once traffic is visible (pinning bypassed), the actual highest-value work shifts to the backend API surface — apply the full methodology from the API Pentesting Walkthrough (BOLA, BFLA, mass assignment, injection, rate limiting, etc.) against every endpoint the mobile app calls. Mobile apps are particularly valuable for API discovery because:
- They frequently call **internal or undocumented endpoints** never exposed via the web frontend, often with weaker authorization checks since developers assume "only the app calls this."
- **API keys and secrets embedded in the binary** (Phase 5 static analysis above) commonly have broader scope/privilege than intended for client-side exposure.
- Mobile-specific endpoints (push notification registration, device-binding, deep-link handlers) are worth testing independently since they're easy to overlook when testing only started from the web app.

## 9. Tools
| Tool | Use |
|---|---|
| **Frida** | Dynamic instrumentation — pinning bypass, root detection bypass, function hooking |
| **Objection** | Frida wrapper simplifying common mobile pentest tasks |
| **jadx / apktool** | Android APK decompilation and static analysis |
| **MobSF (Mobile Security Framework)** | Automated static + dynamic analysis baseline scan for both platforms |
| **Burp Suite / mitmproxy** | Traffic interception once pinning is bypassed |
| **class-dump / Hopper / Ghidra** | iOS binary analysis |

## 10. Checklist
- [ ] Proxy CA installed and traffic visibility confirmed before deeper testing
- [ ] Certificate pinning identified and bypassed (Frida/Objection or static patch)
- [ ] Root/jailbreak detection bypassed if present, to enable full dynamic testing
- [ ] Static analysis performed for hardcoded secrets, internal endpoints, and exported/unprotected components
- [ ] Local storage reviewed on-device for plaintext sensitive data (prefs, DBs, plist, keychain misuse)
- [ ] Clipboard and app-switcher/backgrounding screenshot exposure checked
- [ ] Full endpoint list extracted from traffic + static analysis and cross-referenced against what the web app calls (mobile-only endpoints are high-value)
- [ ] Client-side-only business logic gates (feature flags, premium checks) tested for server-side re-verification via Frida hooking
- [ ] Full API methodology (BOLA/BFLA/injection/rate limiting) applied to every discovered mobile-called endpoint

## 11. Severity Notes
Hardcoded credentials/API keys with broad backend scope embedded in a distributable binary → High–Critical, since extraction requires no special access beyond downloading the public app. Sensitive data in plaintext local storage → High if PII/credentials, Medium if lower-sensitivity data. Exported Android components without permission checks → severity scales with what the component allows another app on the device to do (data read vs. arbitrary action trigger).

## 12. Sample Reporting Language
**Finding title:** Hardcoded API Credentials in Android Application Binary

**Description:** Static analysis of the decompiled Android application (via `jadx`) revealed a hardcoded API key with elevated backend privileges embedded directly in the `ApiClient` class. This key is included in the publicly distributable APK and can be extracted by any user who downloads the application from the app store.

**Impact:** Any individual can extract this credential from the public application binary and use it to authenticate directly against the backend API with the privileges associated with the key, bypassing normal user authentication and potentially accessing functionality beyond what the mobile client's UI exposes.

**Recommendation:** Remove hardcoded credentials from client-distributed binaries entirely. Use short-lived, per-user tokens obtained through a proper authentication flow rather than a shared static key embedded in the app. If a client identifier is genuinely needed for app-level (not user-level) API access, treat it as public information and enforce all real authorization server-side against user-specific credentials, not the shared app key.

---
*Assumes testing under written authorization on a device/environment approved for jailbreak/root-based testing. Confirm with the client whether testing against the production app store build or a provided test build is expected, since production builds may include additional anti-tampering protections in scope for evaluation.*
