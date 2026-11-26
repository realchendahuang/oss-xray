# Dimension 6 & 7: Remote Access, LAN Auth, Execution Safety & Dark Growth

Use this playbook when `repo_xray.py` hits HTTP/WebSocket servers, cookies/sessions, tunnels/relays, CORS/Origin checks, command approval logic, git/submodule/hook runners, webviews, or GitHub API write calls.

---

## A. Remote Access, Tunnels & Lack of End-to-End Encryption

When an AI coding app lets you control your dev machine remotely (mobile companion, web relay, `--lan` mode):

1. **Fake or Missing End-to-End Encryption (E2EE)**
   - Trace where TLS terminates. If the architecture routes through a vendor-controlled Cloudflare Tunnel, CDN edge, Caddy/Nginx reverse proxy, or relay gateway **without application-layer client-to-host encryption**, then the vendor (or anyone compromising their cloud account/relay key) can read **plaintext prompts, source code, and full terminal shell output** without modifying a single line of open-source client code.
   - Check new-device pairing/approval defaults: is device approval **OFF by default**? Can a leaked relay signing key issue a full shell session?

2. **Local/LAN Server Session & Cookie Vulnerabilities**
   Inspect local HTTP/WS auth middleware line-by-line (a shell-capable coding agent cookie is equivalent to full OS user shell access!):
   - **Missing `Secure` flag on plaintext `--lan` HTTP**: Long-lived session cookies (e.g. 7–30 days) transmitted over unencrypted LAN HTTP can be sniffed once and replayed for a month.
   - **Broken `Origin` / CSRF validation**: Check what happens when an HTTP/WebSocket request **omits** the `Origin` header (`if (!origin) return next()`). Non-browser scripts can omit `Origin` freely, bypassing browser-only checks!
   - **IPv4 vs. IPv6 loopback bugs**: Check loopback/private-network guards for `::1` vs. `127.0.0.1` mismatches (e.g. calling `net.isIPv4(ip)` after whitelisting `::1`, breaking or misclassifying local tunnels).
   - **Replayable URL-passed WebSocket tickets**: Check for `?wsTicket=` or `?token=` in query strings (leaks into reverse proxy logs & capture tools) AND check whether the server enforces **single-use consumption** (replay cache/nonce deletion) vs. allowing unlimited reuse until TTL expires (e.g. 5 minutes).
   - **Non-revocable long-lived Bearer tokens**: Check whether OAuth/token flows silently fall back from short-lived device-bound tokens (e.g. DPoP 1h) to long-lived unbound Bearer tokens (e.g. 30d), and whether `/logout` or self-revocation actually works.
   - **Default bind address**: Flag `0.0.0.0` or `::` default binding when the user didn't explicitly opt into LAN exposure.

---

## B. Execution Safety, Untrusted Repos & Approval Bypasses

1. **Command Approval / "Auto / Safe Mode" Bypass**
   - Trace the exact path when an AI agent proposes a destructive or high-risk command (`git push --force`, `rm -rf`, `curl | sh`, writes outside workspace).
   - Check whether the UI/harness silently auto-approves requests that an upstream model/classifier marked as **requiring manual confirmation** — or logs silent approvals as "user approved".

2. **Opening Untrusted Repositories (Zero-Click RCE Surface)**
   Inspect what happens the instant a user opens or creates a worktree for an unfamiliar repo:
   - Does it automatically run `git submodule update --init --recursive`?
   - Does its git runner fail to disable hooks (`-c core.hooksPath=/dev/null` or `core.fsmonitor=false`)?
   - Does it auto-execute repo-local agent hooks (`SessionStart`, `.claude/settings.json`, `.vscode/tasks.json`, repo-scoped `.mcp.json`) without an explicit trust prompt?
   - Combined with unfiltered `process.env` (`SSH_AUTH_SOCK`, `GITHUB_TOKEN`), this is a critical supply-chain RCE vector.

3. **Unsandboxed Webviews / Preview Panes & Path Traversal**
   - In Electron / Tauri / desktop apps: check `BrowserWindow` / `<webview>` configs for `nodeIntegration: true`, `contextIsolation: false`, `sandbox: false`, or `webSecurity: false` on panes that render untrusted HTML/localhost previews.
   - Check file-serving and secrets-reading routes for path traversal (`../`, missing `path.resolve` prefix containment check with trailing separator).

---

## C. Dark Growth & Local Credential Abuse

Search for unexpected **write** API calls using the user's ambient credentials (`gh` CLI, local GitHub OAuth token, git credentials):
- Prompting users to star the repo after N prompts or idle time, then calling `PUT /user/starred/<owner>/<repo>` directly via the user's local GitHub CLI / server-side credential instead of simply opening the browser URL.
- Automatically submitting telemetry, benchmarks, or public showcases under the user's identity without explicit preview and consent.

---

## D. Common False Positives to Clear

- Local dev server bound strictly to `127.0.0.1` with a cryptographically random per-launch token passed via header (not URL query) and `Origin` strictly checked against exact loopback origin → mark `CLEARED`.
- GitHub Star button that merely opens `https://github.com/owner/repo` in the user's external browser without touching `gh` or API tokens → mark `CLEARED`.
