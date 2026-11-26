# Dimension 2 & 3: Cross-Tool Credential Harvesting & Vendor Impersonation

Use this playbook when `repo_xray.py` hits home-directory credential paths, OS Keychain / Credential Manager calls, spoofed headers/env vars, or subprocess `env` forwarding.

---

## A. Cross-Tool Credential & Home-Dir Harvesting

AI coding tools and agents increasingly sit alongside other paid tools on a developer's machine. Audit whether the app crosses its own boundary:

1. **Reading Neighboring Tool Files**
   Inspect every reference to `os.homedir()`, `process.env.HOME`, `USERPROFILE`, or paths touching sibling tools:
   - `~/.claude.json`, `~/.claude/`
   - `~/.codex/auth.json`, `~/.codex/`
   - `~/.cursor/`, `~/.config/gh/hosts.yml`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`
   - `~/.ssh/`, `~/.aws/`, `~/.kube/`, `~/.gnupg/`, browser profile / cookie stores
   Ask three concrete questions:
   1. **Is this explicitly disclosed and strictly needed for the core feature the user invoked?**
   2. **Where does the extracted data go?** (Stays in-memory for a local adapter vs. hashed/sent to telemetry vs. written into a less-protected file?)
   3. **Does it happen silently on startup** even if the user never enabled that integration?

2. **OS Keychain Bypass & Environment Spoofing**
   Look for deliberate tricks designed to weaken another CLI's built-in secret protection:
   - Calling `security find-generic-password` (macOS), `secret-tool` (Linux), or Windows Credential Manager (`CredRead` / PowerShell DPAPI) to extract tokens belonging to **another** vendor's app.
   - Injecting fake environment variables (such as a forged `SSH_CONNECTION`, `SSH_TTY`, or `DISPLAY=""`) when spawning a vendor CLI to trick it into believing it is on a headless remote server and forcing it to abandon the OS Keychain and write plaintext tokens into the app's own directory.
   - Check multi-account isolation: if an upstream CLI drops that fallback behavior, can requests from Account A silently bleed into Account B?

3. **Unfiltered `process.env` Inheritance into Untrusted Child Processes**
   Trace every `child_process.spawn`, `exec`, `execFile`, `subprocess.Popen`, `os/exec.Command`, or PTY creation that runs **inside a user-opened git repo** (especially untrusted/cloned repos):
   - Does it pass `{ env: { ...process.env } }` verbatim?
   - Specifically check whether **`SSH_AUTH_SOCK`**, **`GITHUB_TOKEN`**, **`GH_TOKEN`**, **`AWS_*`**, **`OPENAI_API_KEY`**, **`ANTHROPIC_API_KEY`**, and **`NPM_TOKEN`** survive into:
     - `git clone` / `git worktree` / `git submodule update`
     - Repo-defined git hooks (`.git/hooks`, `core.hooksPath`)
     - Repo-defined agent hooks (`SessionStart`, MCP servers defined in `.mcp.json` / `.cursor/` / `.claude/`)
   - Remember the blast radius: leaking `SSH_AUTH_SOCK` into an untrusted repo does not just expose that folder — it exposes **every remote git repo and production server** that SSH key can authenticate to.

---

## B. Vendor Impersonation & Account Ban Risks

Users risk permanent suspension of paid AI subscriptions ($20–$200/month accounts) when a third-party wrapper violates upstream Terms of Service behind their back:

1. **Hardcoded Spoofed Client Headers / Build IDs**
   Search for hardcoded `User-Agent`, `X-Client-*`, `X-Goog-*`, `anthropic-beta`, internal version strings, or editor names that belong to a **different** official client.
2. **Undocumented / Private Internal Endpoints**
   Flag direct HTTP calls to private internal vendor APIs (e.g., `v1internal`, undocumented quota/usage endpoints, internal OAuth client IDs extracted from proprietary binaries) when the app's FAQ or README claims *"official partnership / 100% ToS compliant / uses official CLI only"*.
3. **Token Extraction vs. Official CLI Delegation**
   Verify whether the tool genuinely delegates requests to the official installed CLI/SDK, or silently steals the CLI's OAuth/session token to hit vendor APIs directly from its own HTTP client.

---

## C. Common False Positives to Clear

- An explicitly user-configured MCP server or credential-bridge tool whose **sole documented purpose** is reading a specific local token file, never phones home, and documents the exact path in `README.md` → note scope clearly, mark `CLEARED` for covert harvesting (still check file permissions and env isolation).
- Passing `PATH`, `HOME`, `LANG`, `TERM` via a strict allowlist to child processes while stripping secret env vars → mark `CLEARED`.
