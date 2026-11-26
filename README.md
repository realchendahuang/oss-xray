# oss-xray

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20(Python%20stdlib)-brightgreen.svg)](#quick-start)
[![Zero Telemetry](https://img.shields.io/badge/Telemetry-0%20%7C%20Offline%20Read--Only-black.svg)](#own-safety-guarantee)
[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-Claude%20%7C%20Codex%20%7C%20Antigravity%20%7C%20Cursor-purple.svg)](#quick-start)

[English](./README.md) | [简体中文](./README_ZH.md)

**X-ray any open-source AI tool before you hand it your shell, tokens, and source code.**

`oss-xray` is a zero-dependency, strictly offline **Agent Skill** (with two standalone Python 3 stdlib pre-scanners) for auditing open-source AI coding agents, MCP servers, Electron desktop apps, and CLIs before you trust them — plus a read-only self-check for your own dev machine.

---

## Why This Exists

Every month, developers install a dozen shiny open-source AI tools, agent wrappers, and MCP servers. Nobody has time to read 200,000 lines of TypeScript, Go, Rust, or Python before running a binary.

Traditional static analyzers (Semgrep, CodeQL) scan for textbook web bugs like SQL injection. They **miss the real trust failures showing up in modern AI developer tools**:

| # | Audit Dimension | Concrete Patterns `oss-xray` Catches |
| :---: | :--- | :--- |
| **1** | **Silent Telemetry & Opt-Out Theater** | Default-on `PostHog` / `Axiom` / `Sentry` / custom `ingest.*` relays retaining raw copies; broken opt-out env vars (OS bypass, startup race before `~/.zshrc` loads); ignored `DO_NOT_TRACK`; unsalted SHA-256 cross-device user stitching |
| **2** | **Cross-Tool Credential Harvesting** | Silently reading sibling configs (`~/.claude.json`, `~/.codex/auth.json`, `~/.ssh`, `~/.aws`, OS Keychain); injecting fake env vars (like `SSH_CONNECTION`) to force plaintext token fallback; forwarding unfiltered `process.env` (`SSH_AUTH_SOCK`, `GITHUB_TOKEN`) into untrusted repo subprocesses |
| **3** | **Client Spoofing & Account Ban Risk** | Hardcoded spoofed client headers or internal build IDs hitting undocumented private vendor endpoints (`v1internal`, etc.) while claiming full ToS compliance |
| **4** | **Fake Delete & Sensitive Local Storage** | UI claiming *"permanently deleted"* while local SQLite retains every prompt and secret forever; tokens written with `0644` instead of `0600`; secrets dumped into logs |
| **5** | **Background Surveillance & External Leaks** | Always-on process enumerators recording full OS command lines (`argv` secret leaks); internal corporate domains sent to third-party favicon APIs; private Ollama / Azure model names sent to external leaderboards |
| **6** | **Remote Access, Tunnels & LAN Auth** | Remote relays with no true End-to-End Encryption (TLS terminated at vendor proxy/CDN); long-lived shell cookies missing `Secure` on HTTP `--lan`; empty `Origin` bypass; replayable URL `?wsTicket=`; non-revocable 30-day Bearer tokens |
| **7** | **Approval Bypass & Untrusted Repo RCE** | Auto/Safe mode silently approving destructive commands (`git push --force`); opening untrusted repos auto-running `.gitmodules` / git hooks / `SessionStart` hooks with host secrets attached; unsandboxed webview previews |
| **8** | **Claims vs. Code & `git log` Forensics** | Reconciling README / privacy pages / `SECURITY.md` against real code; catching silently deleted *"zero telemetry"* promises in `git log`, quiet zero-advisory security fixes, and dark-growth credential abuse (e.g., silent GitHub auto-starring) |

And **Mode B · Local Machine Self-Check** runs a strictly read-only check on your own macOS / Linux host: LAN-exposed TCP listeners (`0.0.0.0` / `*`), overly permissive credential files (`> 0600`), telemetry opt-out hygiene, oversized local AI SQLite stores, and secret tokens exposed in running process `argv`.

---

## Quick Start

### 1. Install as an Agent Skill (Recommended)

Via the standard Agent Skills CLI (lets you pick only the agent you want):

```bash
npx skills add realchendahuang/oss-xray
```

Or copy the single `skills/oss-xray` folder manually into whichever agent directory you use (no installer script required):

```bash
git clone https://github.com/realchendahuang/oss-xray.git
cp -r oss-xray/skills/oss-xray ~/.claude/skills/oss-xray   # or your preferred agent's skills dir
```

### 2. Run Standalone Without an AI Agent (Zero Dependencies)

Requires only Python 3.9+ stdlib — no `pip install`, no Docker, no Node:

```bash
# Mode A: Static 8-dimension pre-scan + git history forensics on any local repo
python3 skills/oss-xray/scripts/repo_xray.py /path/to/some-open-source-repo

# Mode B: Strictly read-only self-check on your own machine (macOS / Linux)
python3 skills/oss-xray/scripts/host_xray.py
```

Pass `--json` to either script for machine-readable output.

---

## What the Output Looks Like

### Mode A · Repo Pre-Scan + Verified Audit Report

```text
# oss-xray Pre-Scan Leads: `example-ai-client`
- Pinned Commit: `a1b2c3d4e5...` (branch: `main`, commits reachable: `200`)
- Files Scanned: `412` (skipped tests: `89`, skipped >1.5MB: `1`)

| Dimension                                            | Total Leads | Deep-Dive Reference                          |
| :--------------------------------------------------- | :---------: | :------------------------------------------- |
| Dim 1 · Telemetry, Analytics & Opt-Out Logic         |     18      | `references/01-telemetry-and-claims.md`      |
| Dim 2 · Cross-Tool Credentials, Keychain & Env       |      7      | `references/02-credentials-and-spoofing.md`  |
| Dim 6 · Remote Tunnels, LAN Exposure & WS Tickets    |     11      | `references/04-remote-auth-and-execution.md` |
| Public Privacy/Security Claims (Docs/README)         |      4      | `references/01-telemetry-and-claims.md`      |
```

Your coding agent then reads the actual surrounding code at those exact leads and outputs a strictly cited report:
- `CONFIRMED` — proven in checked-out code with `path/to/file:Lstart-Lend` or `git show <sha>` + copy-pasteable mitigation.
- `NEEDS_RUNTIME_CHECK` — behavior depends on a closed-source server or runtime flag + exact check command.
- `CLEARED` — dimensions checked and verified safe (balanced, non-alarmist).

### Mode B · Local Machine Self-Check (Real Example)

```text
## 1. Exposed Non-Loopback TCP Listeners (1 non-OS)
| Command | PID | Bind Address | Port | Note |
| `node`  | 923 | `*`          | 8080 | REVIEW: Exposed to LAN/network |

## 2. Sensitive Credential File Permissions (1 overpermissive / 5 checked)
| File                  | Mode    | Status |
| `~/.claude.json`      | `0o600` | OK (`0600`/`0400`) |
| `~/.codex/auth.json`  | `0o644` | **OVERPERMISSIVE** (run `chmod 600`) |

## 3. Telemetry Opt-Out & Ambient Secret Exposure
- Active Opt-Out Env Vars: None set (`DO_NOT_TRACK`, `TELEMETRY_DISABLED`, ...)
- Ambient High-Privilege Env Names Present (values hidden): `SSH_AUTH_SOCK`, `GITHUB_TOKEN`
```

---

## Example Prompts (In Claude Code / Codex / Antigravity / Cursor)

- **Audit a cloned repo before running it**:
  > Use `oss-xray` to audit `/tmp/some-ai-tool`. Pin the commit SHA, verify every lead in source code, reconcile README/privacy claims against the code, and give me copy-pasteable mitigations.
- **Audit from a GitHub URL (read-only)**:
  > Use `oss-xray` to do a read-only shallow clone (`--depth=200`, never install packages or run hooks) of `https://github.com/org/repo` and run a full 8-dimension X-ray.
- **Self-check your own Mac / Linux dev machine**:
  > Use `oss-xray` Mode B to check my machine for LAN-exposed dev/AI ports, overpermissive credential files, telemetry opt-out hygiene, and oversized local AI databases.

---

## How It Works (Two-Stage Architecture)

1. **Stage 1 · Deterministic Offline Pre-Scan (`scripts/repo_xray.py`)**
   Walks source files (skipping lockfiles, binaries, build output, and test fixtures by default), extracts exact `file:line` leads across all 8 dimensions, scans docs for public privacy claims, and runs read-only `git log` forensics for silently removed promises or quiet security fixes. Saves ~90% of LLM tokens and prevents blind spots.
2. **Stage 2 · JIT Evidence-First Verification (`SKILL.md` + `references/*.md`)**
   Your agent loads only the reference playbooks triggered by real leads, reads the actual source lines to trace call paths and defaults, rejects regex false positives, and writes a neutral report that passes the **Zero-Speculation Evidence Gate**.

---

## Own Safety Guarantee

An audit tool should be trivial to audit in 5 minutes (details in [SECURITY.md](./SECURITY.md)):

- **Zero telemetry. Zero network calls.** 100% local and offline.
- **Zero third-party dependencies.** Plain Markdown + two Python 3 stdlib scripts.
- **Strictly read-only.** Never modifies repos, never executes target install scripts or git hooks, never changes file permissions, and **never reads or prints secret file contents or secret env var values**.

---

## Repository Layout

```text
oss-xray/
├── README.md
├── README_ZH.md
├── SECURITY.md
├── LICENSE
└── skills/
    └── oss-xray/
        ├── SKILL.md
        ├── references/
        │   ├── 01-telemetry-and-claims.md
        │   ├── 02-credentials-and-spoofing.md
        │   ├── 03-local-storage-and-surveillance.md
        │   ├── 04-remote-auth-and-execution.md
        │   ├── 05-local-machine-check.md
        │   └── report-template.md
        └── scripts/
            ├── repo_xray.py
            └── host_xray.py
```

---

## Related Open-Source Skills

- [vibe-observability](https://github.com/realchendahuang/vibe-observability) — Give your AI coding agent eyes in production (Sentry, PostHog, Clarity, Prometheus, and live verification).
- [open-writing-skill](https://github.com/realchendahuang/open-writing-skill) — Zero-dependency open writing Skill skeleton.

## License

[MIT](./LICENSE)
