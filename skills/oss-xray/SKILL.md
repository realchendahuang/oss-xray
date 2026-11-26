---
name: oss-xray
description: "Evidence-first privacy, telemetry, and security X-ray for open-source AI tools, Coding Agents, MCP servers, Electron apps, CLIs, and local dev environments. Use before installing or trusting an open-source repo, when auditing whether an app silently phones home, reads neighboring credentials (~/.claude.json, ~/.codex/auth.json, ~/.ssh, Keychain), spoofs vendor headers, fakes deletion, bypasses command approvals, exposes LAN/tunnel shell sessions, or contradicts its README/privacy claims in source code and git history; or when running a read-only self-check on a developer machine."
---

# oss-xray — Open-Source AI Tool Privacy & Security X-Ray

An **evidence-first, zero-speculation** audit skill for inspecting open-source AI tools, Coding Agents, MCP servers, desktop apps, and CLIs before you trust them with your code, tokens, and shell — plus a read-only self-check for your own machine.

> **Core Ethos**: *Don't trust marketing copy. Verify the checked-out code and git history.*
> **Own Safety Guarantee**: `oss-xray` is strictly read-only, makes zero network requests, collects zero telemetry, and never prints raw secret values.

---

## 1. Mode Selection

Pick the mode matching the user's request (or run both):

| Mode | Trigger | Entry Script | Reference Docs (JIT Load) |
| :--- | :--- | :--- | :--- |
| **Mode A · Repo X-Ray** | User points to a local repository or GitHub URL to audit before installing/using | `python3 scripts/repo_xray.py <repo_path>` | Load only relevant `references/01-*.md` ~ `04-*.md` based on scan hits + `references/report-template.md` |
| **Mode B · Host Self-Check** | User wants to check already-installed AI tools, exposed ports, credential permissions, and telemetry hygiene on their own macOS/Linux machine | `python3 scripts/host_xray.py` | Load `references/05-local-machine-check.md` + `references/report-template.md` |

If the user gives a GitHub URL instead of a local path, clone it into a temporary read-only inspection directory (e.g. `git clone --depth=200 <url> /tmp/oss-xray-<repo>` — shallow enough to be fast, deep enough for `git log` promise-diff forensics; never run `npm install`, `postinstall`, `make`, `git submodule update`, or execute repo hooks!).

> **CRITICAL SAFETY RULE WHEN INSPECTING UNTRUSTED REPOS**
> Never run package install scripts, build hooks, git hooks, or binaries from the repo being audited. Inspect statically with `repo_xray.py`, `rg`, `git show`, and file reads only.

---

## 2. Mode A Workflow — Repository X-Ray (5 Steps)

### Step 1: Run Deterministic Pre-Scan First (Save Tokens, Catch Blind Spots)

Always run the bundled zero-dependency scanner before reading files manually:

```bash
python3 <skill_dir>/scripts/repo_xray.py <repo_path> --format md
```

Useful flags:
- `--max-per-category 25` — expand match caps for large monorepos
- `--no-git` — skip `git log` forensics if auditing a zip archive without `.git`
- `--include-tests` — include test files (excluded from high-priority hits by default)
- `--json` — machine-readable output

### Step 2: Pin Exact Audited Revision

Record the exact commit SHA (`git rev-parse HEAD`), branch/tag, and audit date. Every claim in the final report must be pinned to this commit so anyone can reproduce it independently.

### Step 3: JIT Deep-Dive Verification Across the 8 Audit Dimensions

Do **NOT** copy raw scanner hits into the report as findings. A regex hit is only a **lead**, never proof. For every category that has leads — or that applies to the repo's architecture (e.g. desktop app, tunnel server, agent runner, CLI wrapper) — load the matching reference playbook and read the actual surrounding code:

1. **Telemetry, Opt-Out Theater & Claims-vs-Code Diff** → read `references/01-telemetry-and-claims.md`
   - Default-on telemetry (`PostHog`, `Axiom`, `Sentry`, `Mixpanel`, custom `ingest.*` relays)
   - Broken opt-out (env var ignored on Windows, read before login shell loads `~/.zshrc`, web/mobile bypass, `DO_NOT_TRACK` ignored)
   - Unsalted deterministic hashing / cross-device user stitching
   - `git log` forensics: silently deleted "zero telemetry" / "local-only" claims, rejected opt-out PRs, zero-advisory security patches
2. **Cross-Tool Credential Harvesting & Vendor Impersonation** → read `references/02-credentials-and-spoofing.md`
   - Reading neighboring tool secrets (`~/.claude.json`, `~/.codex/auth.json`, `~/.ssh`, `~/.aws`, OS Keychain / Credential Manager)
   - Env spoofing (e.g. injecting fake `SSH_CONNECTION` to force plaintext token fallback)
   - Hardcoded spoofed client headers / internal build numbers hitting undocumented private vendor endpoints (account ban risk)
   - Unfiltered `process.env` inheritance (`SSH_AUTH_SOCK`, `GITHUB_TOKEN`, API keys) into untrusted repo child processes
3. **Fake Delete, Local Persistence & Background Surveillance** → read `references/03-local-storage-and-surveillance.md`
   - Soft-delete disguised as "permanently delete" in SQLite / event logs (sensitive prompt retention & disk bloat)
   - Plaintext tokens written with world-readable permissions (`0644`) or logged in error payloads
   - Background process enumerators recording full OS command lines (`argv` secret leakage)
   - Unsolicited third-party leaks (internal corporate domains sent to favicon APIs, private model names pushed to public leaderboards)
4. **Remote Access, LAN Auth, Approval Bypass & Dark Growth** → read `references/04-remote-auth-and-execution.md`
   - Remote tunnels / relays without true End-to-End Encryption (TLS terminated at vendor proxy/CDN)
   - Long-lived shell-equivalent cookies missing `Secure` on HTTP `--lan`, empty `Origin` bypass, URL-passed replayable WebSocket tickets, non-revocable Bearer tokens, IPv4/IPv6 loopback bugs (`::1`)
   - Auto/Safe mode silently approving destructive commands (`git push --force`, `rm -rf`), auto-running `.gitmodules` / git hooks / repo `SessionStart` hooks, unsandboxed webview previews
   - Credential abuse for dark growth (silently using local GitHub auth to star repos or call write APIs)

### Step 4: Enforce the Zero-Speculation Evidence Gate

Before writing a single finding, verify EVERY claim against these hard rules:

1. **Exact Source Anchor Required**: Every finding MUST cite exact `path/to/file:L12-L34` (or `commit <sha>` / `git show <sha>`). No file path and line number = delete the claim.
2. **Trace the Call Path, Not Just the Symbol**: Confirm the code is reachable in production (not dead code, test fixture, doc example, or properly guarded behind an explicit opt-in default `false`).
3. **Three-Bucket Classification**:
   - `CONFIRMED` — Directly proven in checked-out source code or `git log` with reproducible anchor.
   - `NEEDS_RUNTIME_CHECK` — Code behavior depends on remote server, closed-source relay, build-time env flags, or OS runtime (state exact runtime/packet check needed).
   - `CLEARED` — Checked and confirmed safe or properly guarded (always include a brief Cleared section so the audit is fair and non-alarmist).
4. **Strict Neutrality & Factuality**: Report technical mechanisms, blast radius, and code-vs-claim discrepancies objectively. Never speculate about author intent, never use insults or ad hominem language.

### Step 5: Deliver Report + Actionable Mitigations

Format the final output using `references/report-template.md`. Every `CRITICAL` / `HIGH` finding MUST pair with a concrete user mitigation (exact opt-out env var, firewall/tunnel boundary, env stripping command, or safe alternative).

---

## 3. Mode B Workflow — Local Machine Self-Check (3 Steps)

When the user asks to inspect their **own machine** for exposed AI tools, credential permission leaks, or telemetry hygiene:

1. Read `references/05-local-machine-check.md`.
2. Run the strictly read-only host audit script:
   ```bash
   python3 <skill_dir>/scripts/host_xray.py --format md
   ```
3. Interpret findings calmly: separate expected local dev listeners (`127.0.0.1` / `::1`) from risky LAN exposures (`0.0.0.0` / `*`), flag overly permissive secret files (`> 0600`), highlight oversized local AI databases worth checking for soft-delete retention, and provide copy-pasteable hardening commands (`chmod 600`, `DO_NOT_TRACK=1`, isolated env launch wrappers).

> **NEVER read or print the contents of `~/.ssh/*`, `~/.aws/credentials`, `~/.claude.json`, `~/.codex/auth.json`, Keychain items, or secret env var values during Mode B.** Metadata (`stat` mode, size, existence, listening sockets) is all that is required.
