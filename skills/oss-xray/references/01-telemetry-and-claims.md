# Dimension 1 & 8: Telemetry, Opt-Out Theater & Claims-vs-Code Forensics

Use this playbook when `repo_xray.py` hits telemetry SDKs, analytics endpoints, hashing/identity helpers, or privacy claims in docs/git history.

---

## A. Silent & Default-On Telemetry Checks

1. **Default State Verification**
   - Trace the exact initialization path of `PostHog`, `Sentry`, `Axiom`, `Mixpanel`, `Amplitude`, `Segment`, `OpenTelemetry`, or custom HTTP `fetch`/`axios` beacons (`ingest.*`, `telemetry.*`, `analytics.*`, `metrics.*`).
   - Check the default value when **no** config file or env var exists:
     - `enabled !== "false"` or `!== "0"` → **OPT-OUT (default ON)**.
     - `enabled === "true"` → **OPT-IN (default OFF)**.
   - Check whether a closed-source self-hosted relay receives events first and retains a raw copy before forwarding to third-party analytics.

2. **Opt-Out Theater (Broken or Incomplete Kill Switches)**
   Check ALL six common opt-out failure modes:
   - **No UI toggle**: Can regular users turn it off in Settings, or must they edit `~/.zshrc` / system MDM / `/Library/Application Support/.../policy.json` / Windows Registry (`HKLM`)?
   - **Startup race / Shell env timing**: On macOS/Linux Electron desktop apps launched from Finder/Dock, does telemetry initialize **before** loading the user's login shell (`~/.zshrc` / `~/.bashrc`), silently ignoring shell-configured opt-out env vars?
   - **OS-specific bypass**: Does Windows or Linux desktop ignore saved opt-out config or env vars due to case sensitivity or platform branching?
   - **`DO_NOT_TRACK=1` ignored**: Check if standard `DO_NOT_TRACK` / `CI` env vars are respected.
   - **Surface blind spots**: When desktop telemetry is disabled, do **web builds**, **mobile companions**, **remote relays**, **"agent activity publishing"**, or **startup manifest/update checks** still phone home?
   - **Disk-side tracking persistence**: Even when telemetry is disabled, does startup still unconditionally generate a persistent tracking UUID on disk or hash linked account IDs?

3. **Payload Sensitivity & Cross-Device Stitching**
   Inspect the exact JSON payload serialized to telemetry / error / feedback endpoints:
   - **Unsalted deterministic hashing**: `createHash("sha256").update(emailOrAccountId).digest("hex")` with no per-install random salt allows trivial rainbow-table / server-side re-identification whenever the vendor also holds plaintext account IDs.
   - **Workspace & PII leakage**: Check for `process.cwd()`, `git.cwd`, absolute file paths (which leak OS username + private repo/client names), raw IP / `User-Agent` attached alongside `user_id` in log shippers (e.g. Axiom / Datadog / Sentry).
   - **Private infrastructure leakage**: Check if private Ollama model names, internal Azure deployment names, custom proxy base URLs, or company domains are sent without an explicit allowlist.
   - **Un-anonymous "anonymous" feedback**: Check whether "anonymous feedback" endpoints piggyback `install_id`, full OS/VM fingerprints, or batch into the same authenticated POST request as identified events.
   - **Account deletion leftovers**: Check if deleting an account cleans relay/telemetry DB rows and terminates active remote tunnels, or leaves stale rows/tunnels behind.

---

## B. Claims-vs-Code & `git log` Forensics

1. **Doc-vs-Code Reconciliation Table**
   Read `README.md`, `PRIVACY.md` / privacy policy pages, `SECURITY.md`, website landing source (`apps/web`, `docs/`), and FAQ files. Extract every concrete privacy/security promise:
   - *"No telemetry / Zero telemetry / Unless you opt in"*
   - *"Local-only / Conversations never leave your machine"*
   - *"End-to-end encrypted"*
   - *"Compliant with [Vendor] ToS"*
   Compare each claim line-by-line against the actual runtime code.

2. **`git log` Silent Change Forensics**
   Run targeted, read-only git forensics (when `.git` is present):
   ```bash
   # Find commits that added or deleted privacy/telemetry promises in docs/web
   git log -S "telemetry" --oneline -n 30 -- "README*" "docs/" "*privacy*" "*landing*" "*web*"
   git log -G "(zero|no)[ -]telemetry|opt[- ]in|never leaves|end-to-end" --oneline -n 30

   # Find recent quiet security/privacy fixes
   git log --grep="telemetry\|privacy\|security\|leak\|sanitize\|redact\|traversal\|origin\|cookie\|sandbox" -i --oneline -n 30
   ```
   Check whether:
   - A "zero telemetry" claim stayed live on the website/README months **after** default-on telemetry was merged.
   - Privacy promises were quietly removed in unrelated UI/landing commits with zero release note.
   - High-severity security fixes (path traversal, token leakage, unsandboxed webview, command injection) were merged quietly with **zero** GitHub Security Advisories or user upgrade warnings.

---

## C. Common False Positives to Clear

- Explicit crash-reporting or analytics SDKs that are gated behind `if (settings.telemetryOptIn === true)` with default `false` and a clear first-run consent prompt → mark `CLEARED`.
- Local-only SQLite metrics dashboards that never leave `127.0.0.1` → mark `CLEARED`.
- Standard version-check pings that send only app version + OS arch with no install UUID and have a working opt-out toggle → note as `INFO / LOW`, not `HIGH`.
