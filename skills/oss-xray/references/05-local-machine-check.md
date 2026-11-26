# Mode B: Local Machine Self-Check Playbook (macOS / Linux)

Use this playbook when the user asks to audit **already-installed** AI tools, coding agents, MCP servers, local dev servers, and credential hygiene on their own machine.

---

## 1. Non-Negotiable Privacy Rule

`host_xray.py` and the agent executing Mode B MUST obey three rules:
1. **Strictly Read-Only**: Never edit files, kill processes, or change permissions automatically. Only report findings and output copy-pasteable hardening commands for the user to run.
2. **Metadata Only — Never Read Secret Values**: For `~/.ssh/*`, `~/.aws/credentials`, `~/.claude.json`, `~/.codex/auth.json`, `~/.config/gh/hosts.yml`, `~/.netrc`, `~/.npmrc`, and Keychain items, check **only** existence, file size, and POSIX permission bits (`stat`). Never dump their contents.
3. **Redact Command-Line Arguments**: When inspecting running processes, display executable names and redacted flags only — never echo raw tokens, bearer strings, or API keys that may appear in process arguments.

---

## 2. Run the Read-Only Host Scanner

```bash
python3 <skill_dir>/scripts/host_xray.py --format md
```

Useful options:
- `--json` — structured output for deeper inspection
- `--large-db-mb 100` — customize threshold (default `200 MB`) for flagging oversized local AI app SQLite / data stores (potential soft-delete retention / log bloat)

---

## 3. How to Interpret Each Section

1. **Exposed Non-Loopback TCP Listeners (`0.0.0.0` / `::` / `*`)**
   - Separate expected OS services (e.g., macOS `ControlCenter` / AirPlay on 5000/7000, `mDNSResponder`) from developer/AI tools (`node`, `python`, `bun`, `deno`, `go`, `ollama`, `electron`, `t3`, `openclaw`, `mcp`, etc.).
   - Any AI coding dashboard, agent server, or local LLM gateway listening on `*` / `0.0.0.0` on coffee-shop/office Wi-Fi without TLS + strong auth is **HIGH / CRITICAL**.
   - Recommend rebinding to `127.0.0.1` or tunneling exclusively through encrypted Tailscale / WireGuard / SSH port-forwarding.

2. **Sensitive Credential File Permissions**
   - Any credential/config file listed with group or world access (e.g. `0644`, `0664`, `0666` instead of `0600`) should be tightened:
     ```bash
     chmod 600 <path>
     ```
   - Especially watch AI CLI auth files (`~/.claude.json`, `~/.codex/auth.json`, `~/.config/gh/hosts.yml`) and custom agent config files.

3. **Telemetry Opt-Out Hygiene**
   - Check whether global defensive opt-out variables are set in the active environment and shell startup files (`~/.zshrc`, `~/.bashrc`):
     ```bash
     export DO_NOT_TRACK=1
     export TELEMETRY_DISABLED=1
     export POSTHOG_DISABLED=1
     ```
   - Remind macOS GUI app users: setting env vars in `~/.zshrc` does **not** automatically reach Electron/GUI apps launched from Spotlight/Dock unless configured via `launchctl setenv` or the app's own managed policy / settings.

4. **Ambient Secret Exposure to Desktop/Agent Sessions**
   - Warn if `SSH_AUTH_SOCK` is active and high-privilege tokens (`GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `OPENAI_API_KEY`, etc.) are exported globally in the shell — remind the user to launch untrusted repos with a clean env wrapper:
     ```bash
     env -u SSH_AUTH_SOCK -u GITHUB_TOKEN -u GH_TOKEN <command>
     ```

5. **Oversized Local AI Databases (Soft-Delete Bloat Indicator)**
   - If a local AI tool's SQLite or data directory exceeds hundreds of MBs despite the user deleting old chats, suggest inspecting whether the app performs soft-deletes (retaining sensitive prompts on disk) and cleaning or vacuuming if appropriate.
