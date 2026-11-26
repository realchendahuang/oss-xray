# oss-xray

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20(Python%20stdlib)-brightgreen.svg)](#quick-start)
[![Zero Telemetry](https://img.shields.io/badge/Telemetry-0%20%7C%20Offline%20Read--Only-black.svg)](#own-safety-guarantee)

[English](./README.md) | [简体中文](./README_ZH.md)

**X-ray any open-source AI tool before you hand it your shell, tokens, and source code.**

`oss-xray` is a lightweight, zero-dependency **Agent Skill** (plus two standalone Python stdlib pre-scanners) for auditing open-source AI coding agents, MCP servers, Electron apps, CLIs, and your own developer machine.

---

## Why This Exists

Developers install dozens of new open-source AI tools, agent wrappers, and MCP servers every month. Nobody has time to read 200,000 lines of TypeScript, Go, Rust, or Python before running a binary.

Traditional static analyzers (Semgrep, CodeQL) check textbook web bugs like SQL injection. They **miss the trust failures that actually hurt AI developers**:

| # | Audit Dimension | What `oss-xray` Checks |
| :---: | :--- | :--- |
| **1** | **Silent Telemetry & Opt-Out Theater** | Default-on analytics (`PostHog`, `Axiom`, `Sentry`, custom `ingest.*` relays), broken opt-out env vars (OS bypass, startup race before `~/.zshrc`), ignored `DO_NOT_TRACK`, unsalted SHA-256 cross-device stitching |
| **2** | **Cross-Tool Credential Harvesting** | Silently reading sibling configs (`~/.claude.json`, `~/.codex/auth.json`, `~/.ssh`, `~/.aws`, OS Keychain), fake env injection (`SSH_CONNECTION`) to force plaintext fallback, unfiltered `process.env` forwarding (`SSH_AUTH_SOCK`, `GITHUB_TOKEN`) |
| **3** | **Client Spoofing & Account Ban Risk** | Hardcoded spoofed client headers / internal build IDs hitting undocumented private vendor APIs while claiming ToS compliance |
| **4** | **Fake Delete & Sensitive Local Storage** | UI claiming "permanently deleted" while SQLite keeps raw prompts forever, credentials written as `0644` instead of `0600`, tokens dumped into logs |
| **5** | **Background Surveillance & External Leaks** | Always-on process enumerators capturing full OS command lines (`argv` secret leaks), internal corporate domains sent to third-party favicon APIs, private Ollama/Azure model names leaked externally |
| **6** | **Remote Access, Tunnels & LAN Auth** | Remote control relays with no true End-to-End Encryption (vendor TLS termination), long-lived shell cookies missing `Secure` on HTTP `--lan`, empty `Origin` bypass, replayable URL WebSocket tickets, non-revocable Bearer tokens |
| **7** | **Approval Bypass & Untrusted Repo RCE** | Auto/Safe mode silently approving destructive commands (`git push --force`), opening untrusted repos triggering `.gitmodules` / git hooks / `SessionStart` hooks with host secrets attached, unsandboxed webview previews |
| **8** | **Claims vs. Code & `git log` Forensics** | Diffing README / privacy policies against actual code, spotting silently deleted *"zero telemetry"* promises in `git log`, quiet zero-advisory security fixes, and dark-growth credential abuse (e.g. silent GitHub auto-starring) |

Plus **Mode B · Local Machine Self-Check**: a strictly read-only check on your own macOS/Linux host for LAN-exposed TCP listeners, overly permissive credential files (`> 0600`), telemetry opt-out hygiene, oversized local AI SQLite stores, and secret tokens exposed in running process `argv`.

---

## Own Safety Guarantee

An audit tool must be effortless to audit itself:

- **Zero telemetry. Zero network requests.** Everything runs 100% locally and offline.
- **Zero third-party dependencies.** Only Markdown playbooks and two plain Python 3 stdlib scripts (`repo_xray.py` and `host_xray.py`) you can read in 5 minutes.
- **Strictly read-only.** Never modifies your repo, never runs `npm install` or untrusted git hooks, never edits permissions, and **never reads or prints secret file contents** during host self-checks.
- **Zero-Speculation Evidence Gate.** The Skill forbids AI hallucination: every `CONFIRMED` finding must cite an exact, verified `file:line` or `git show <sha>`, separates `CONFIRMED` / `NEEDS_RUNTIME_CHECK` / `CLEARED`, and pairs every risk with a concrete mitigation command.

---

## Quick Start

### Option 1: Install via Agent Skills CLI (`npx skills`)

Works with Claude Code, Codex, Cursor, Antigravity, OpenCode, and other Agent Skills compatible tools:

```bash
npx skills add realchendahuang/oss-xray
```

### Option 2: Clone & Install with `./install.sh`

```bash
git clone https://github.com/realchendahuang/oss-xray.git
cd oss-xray

# Pick your agent: antigravity | claude | codex | cursor | opencode | agents | project | all
./install.sh --target claude --symlink
# Or install to all detected global skill directories at once:
./install.sh --target all --symlink
```

### Option 3: Run the Standalone Pre-Scanners Directly (No AI Agent Needed)

```bash
# Mode A: Static pre-scan + git history forensics on any cloned repo
python3 skills/oss-xray/scripts/repo_xray.py /path/to/some-open-source-repo

# Mode B: Strictly read-only self-check on your own machine (macOS / Linux)
python3 skills/oss-xray/scripts/host_xray.py
```

Both scripts also support `--json` for piping into your own scripts or CI.

---

## Example Prompts (Inside Claude Code / Codex / Antigravity / Cursor)

- **Audit a local repo before running it**:
  > Use `oss-xray` to audit `/tmp/some-ai-tool`. Pin the commit SHA, verify every lead in source code, reconcile README/privacy claims against the code, and give me copy-pasteable mitigations.
- **Audit a GitHub repo from URL (read-only clone)**:
  > Use `oss-xray` to do a read-only clone (`--depth=200`, do not install or execute anything) of `https://github.com/org/repo` and run a full 8-dimension privacy & security X-ray.
- **Self-check your own dev machine**:
  > Use `oss-xray` Mode B to run a read-only self-check on my machine for LAN-exposed AI tools, credential file permissions, telemetry opt-out flags, and oversized local AI databases.

---

## Repository Layout

```text
oss-xray/
├── README.md
├── README_ZH.md
├── LICENSE
├── install.sh
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
