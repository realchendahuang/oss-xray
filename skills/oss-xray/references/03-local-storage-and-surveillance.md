# Dimension 4 & 5: Fake Delete, Local Storage & Background Surveillance

Use this playbook when `repo_xray.py` hits local databases (`sqlite`, `leveldb`, `jsonl`), delete handlers, file writes, process enumerators (`ps`, `wmic`, `sysinfo`, `pidusage`), or unexpected outbound URLs.

---

## A. Fake Delete & Sensitive Local Persistence

1. **Soft-Delete Disguised as Permanent Deletion**
   - Find every "Delete conversation / Delete thread / Clear history / Wipe data" UI handler and trace it all the way to the storage layer.
   - Check the UI copy ("permanently delete", "cannot be undone") against the SQL/storage query:
     - Does it only set `deleted_at = NOW()` / `archived = 1` while leaving full prompt history, code snippets, tool outputs, and secrets intact inside `*.sqlite` / append-only event projections?
     - Is `VACUUM` or actual `DELETE FROM` ever executed on dependent event/message/blob tables?
     - Can deleted threads silently grow local disk usage to tens of gigabytes?

2. **Insecure File Permissions & Secret Logging**
   - Check every `writeFile` / `open` writing OAuth tokens, API keys, session secrets, or cloud credentials:
     - Is `mode: 0o600` (owner read/write only) explicitly set on POSIX? Missing `mode` falls back to umask (`0644` — readable by any local user/process).
   - Check structured loggers (`pino`, `winston`, `console.error`, `tracing`, Sentry breadcrumbs) for:
     - Raw webhook secrets, device push tokens embedded in URLs, `Authorization` headers, or query-string tickets (`?token=`, `?wsTicket=`) written verbatim into logs or error telemetry.

---

## B. Background Process Surveillance & Unsolicited External Leaks

1. **Always-On Process / Command-Line Enumeration**
   - Search for polling intervals (`setInterval`, background threads, `sysinfo`, `ps aux`, `pgrep`, `lsof`, Windows `OpenProcess` / `QueryFullProcessImageName` / WMI `CommandLine`).
   - Verify three things:
     1. **Does it run continuously in the background** even when diagnostics UI is closed and no client is connected?
     2. **Does it capture full process `argv` / command-line arguments?** (Developer machines routinely pass tokens, DB passwords, `-H "Authorization: ..."`, and proxy credentials on command lines!)
     3. **Are those snapshots persisted to disk or shipped in telemetry/diagnostics?**

2. **Silent Third-Party Metadata Leaks**
   - **Favicon / Link Preview Leaks**: Does the frontend automatically send URLs mentioned in private chats or terminal output (including internal corporate domains like `jira.corp.internal`) to third-party services (`google.com/s2/favicons`, `icons.duckduckgo.com`, external link-preview proxies)?
   - **Private Model / Repo Name Leaks**: Check whether local Ollama model names, private enterprise Azure/Bedrock deployment IDs, or private repository names are sent to public leaderboards, telemetry dashboards, or third-party endpoints without an allowlist.
   - **Forced Phone-Home**: Even when telemetry and auto-update are turned off, does startup still make unconfigurable outbound requests (remote feature flags, manifests, A/B configs, font/CDN assets)?

3. **Resource / Token Quota Anomalies (Bonus Check)**
   - If the app wraps AI CLIs or renders Electron/WebGPU views, check for obvious runaway polling loops, redundant prompt replays/context duplication, or unthrottled GPU render loops when idle/backgrounded.

---

## C. Common False Positives to Clear

- Standard `git` or child-process PID lookup limited strictly to the app's **own** spawned child PID (e.g. killing a stuck subprocess on exit) without scanning unrelated host processes → mark `CLEARED`.
- Soft-delete that is explicitly labeled **"Archive"** or **"Move to Trash (auto-purged in 7 days)"** with a working hard-delete / purge path → mark `CLEARED`.
