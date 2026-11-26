# Security Policy

## Safety Model of `oss-xray`

Because `oss-xray` is used to audit untrusted repositories and developer machines, it enforces strict self-containment guarantees:

1. **Zero Network Access**: Neither `repo_xray.py` nor `host_xray.py` imports networking libraries (`urllib`, `http`, `socket`, `requests`) or initiates outbound network traffic.
2. **Zero Telemetry**: No analytics, crash reporters, install IDs, or phone-home beacons exist anywhere in this repository.
3. **Strictly Read-Only**:
   - `repo_xray.py` reads text files and runs read-only `git rev-parse` / `git log` queries. It never executes code, hooks, build scripts, or package installers from the audited repository.
   - `host_xray.py` inspects only POSIX `stat()` metadata (mode, size), TCP listening sockets (`lsof` / `ss`), non-secret opt-out environment variable names, and redacted process metadata (`ps`). It **never** reads or prints the contents of SSH keys, AWS credentials, `.claude.json`, `.codex/auth.json`, Keychain items, or secret environment variable values.
4. **Zero Third-Party Dependencies**: Everything runs on Python 3.9+ standard library and POSIX shell utilities so users can review the entire codebase in minutes.

## Auditing Untrusted Repositories Safely

When using `oss-xray` with an AI coding agent on an untrusted repository:

- Clone with `git clone --depth=200` into an isolated temporary directory.
- Do **not** run `npm install`, `pnpm install`, `pip install`, `make`, `git submodule update`, or open the untrusted repository with ambient `SSH_AUTH_SOCK` / `GITHUB_TOKEN` exported.

## Reporting a Vulnerability

If you discover a security bug, secret-redaction gap, command-injection edge case, or false-negative bypass in `oss-xray`, please open a GitHub Security Advisory on this repository or report it responsibly via the repository issues/contact channels with minimal reproduction steps.
