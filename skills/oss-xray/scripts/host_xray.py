#!/usr/bin/env python3
"""
oss-xray · host_xray.py
Zero-dependency, strictly read-only, offline local machine self-check for
developers running AI tools, Coding Agents, MCP servers, and local dashboards.

PRIVACY GUARANTEE:
- Never makes network calls.
- Never modifies files, permissions, or processes.
- Never reads or prints secret file contents or secret env var values.
  Only inspects POSIX metadata (stat mode/size), listening sockets, opt-out
  flag presence, and redacted process metadata.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

SENSITIVE_CRED_FILES = [
    "~/.claude.json",
    "~/.claude/.credentials.json",
    "~/.codex/auth.json",
    "~/.gemini/oauth_creds.json",
    "~/.config/gh/hosts.yml",
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.ssh/id_ecdsa",
    "~/.aws/credentials",
    "~/.kube/config",
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/.docker/config.json",
]

OPTOUT_ENV_VARS = [
    "DO_NOT_TRACK",
    "TELEMETRY_DISABLED",
    "POSTHOG_DISABLED",
    "NEXT_TELEMETRY_DISABLED",
    "HOMEBREW_NO_ANALYTICS",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
]

AMBIENT_SECRET_ENV_NAMES = [
    "SSH_AUTH_SOCK",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "CLOUDFLARE_API_TOKEN",
    "NPM_TOKEN",
]

AI_DATA_DIR_CANDIDATES = [
    "~/.claude",
    "~/.codex",
    "~/.cursor",
    "~/.opencode",
    "~/.windsurf",
    "~/.gemini",
    "~/.cline",
    "~/.ollama",
    "~/.config/opencode",
    "~/.config/Cursor",
    "~/.config/Code",
    "~/.local/share/opencode",
    "~/Library/Application Support/Cursor",
    "~/Library/Application Support/Claude",
    "~/Library/Application Support/Windsurf",
    "~/Library/Application Support/Antigravity",
]

AI_PROCESS_HINT_RE = re.compile(
    r"(claude|codex|cursor|windsurf|opencode|ollama|mcp|cloudflared|ngrok|tailscaled|aider|antigravity|lmstudio)",
    re.IGNORECASE,
)

ARGV_SECRET_LEAK_RE = re.compile(
    r"(\bsk-[A-Za-z0-9_-]{20,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{16}\b|"
    r"(?:^|\s)--?(?:api[-_]?key|access[-_]?token|auth[-_]?token|bearer[-_]?token|client[-_]?secret|password|passwd|secret[-_]?key)(?:=|\s+)[^\s\"']{6,}|"
    r"Authorization:\s*Bearer\s+\S{12,})",
    re.IGNORECASE,
)

SKIP_STORE_DIRS = {
    "Cache",
    "CachedData",
    "Code Cache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "GPUCache",
    "IndexedDB",
    "Service Worker",
    "Session Storage",
    "Local Storage",
    "WebStorage",
    "blob_storage",
    "extensions",
    "node_modules",
    ".git",
    "tmp",
    "temp",
    "Crashpad",
    "antigravity-browser-profile",
    "brain",
}

KNOWN_MACOS_SYSTEM_LISTENERS = {"ControlCe", "ControlCenter", "rapportd", "AirPlayXP", "mDNSRespo"}


def run_cmd(args: list[str], timeout: int = 8) -> str | None:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0 and not proc.stdout:
            return None
        return proc.stdout
    except Exception:
        return None


def check_listening_ports() -> dict[str, Any]:
    exposed: list[dict[str, Any]] = []
    loopback: list[dict[str, Any]] = []
    tool_used = "none"

    lsof_out = run_cmd(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    if lsof_out:
        tool_used = "lsof"
        seen: set[tuple[str, str, str]] = set()
        for line in lsof_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            comm, pid, user = parts[0], parts[1], parts[2]
            name_field = parts[-2] if parts[-1] == "(LISTEN)" else parts[-1]
            if ":" not in name_field:
                continue
            host, port = name_field.rsplit(":", 1)
            key = (comm, host, port)
            if key in seen:
                continue
            seen.add(key)

            is_loopback = host in {"127.0.0.1", "[::1]", "::1", "localhost"}
            entry = {
                "command": comm,
                "pid": pid,
                "user": user,
                "bind_host": host,
                "port": port,
                "is_known_os_service": comm in KNOWN_MACOS_SYSTEM_LISTENERS,
            }
            if is_loopback:
                loopback.append(entry)
            else:
                exposed.append(entry)
    else:
        ss_out = run_cmd(["ss", "-tlnp"])
        if ss_out:
            tool_used = "ss"
            for line in ss_out.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 5:
                    continue
                local_addr = parts[3]
                if ":" not in local_addr:
                    continue
                host, port = local_addr.rsplit(":", 1)
                proc_info = parts[5] if len(parts) > 5 else "unknown"
                m = re.search(r'"([^"]+)"', proc_info)
                comm = m.group(1) if m else proc_info[:24]
                is_loopback = host in {"127.0.0.1", "[::1]", "::1"}
                entry = {
                    "command": comm,
                    "pid": "?",
                    "user": "?",
                    "bind_host": host,
                    "port": port,
                    "is_known_os_service": False,
                }
                if is_loopback:
                    loopback.append(entry)
                else:
                    exposed.append(entry)

    return {
        "tool_used": tool_used,
        "exposed_non_loopback": exposed,
        "loopback_only_count": len(loopback),
        "loopback_only": loopback[:25],
    }


def check_credential_permissions() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for raw_path in SENSITIVE_CRED_FILES:
        p = Path(raw_path).expanduser()
        if not p.exists():
            continue
        try:
            st = p.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        mode_oct = oct(stat.S_IMODE(st.st_mode))
        overpermissive = bool(stat.S_IMODE(st.st_mode) & 0o077)
        results.append(
            {
                "path": raw_path,
                "mode": mode_oct,
                "size_bytes": st.st_size,
                "status": "OVERPERMISSIVE" if overpermissive else "OK",
                "fix": f"chmod 600 {raw_path}" if overpermissive else None,
            }
        )
    return results


def check_env_hygiene() -> dict[str, Any]:
    optout_status = {}
    for var in OPTOUT_ENV_VARS:
        val = os.environ.get(var)
        optout_status[var] = val if val is not None else None

    ambient_present = [var for var in AMBIENT_SECRET_ENV_NAMES if os.environ.get(var)]

    # Check shell rc files for DO_NOT_TRACK mention only (never echo lines or secrets)
    rc_has_dnt = {}
    for rc in ("~/.zshrc", "~/.bashrc", "~/.zprofile"):
        p = Path(rc).expanduser()
        if p.exists() and p.is_file():
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                rc_has_dnt[rc] = bool(re.search(r"^\s*export\s+DO_NOT_TRACK\s*=", content, re.M))
            except OSError:
                pass

    return {
        "optout_env_vars": optout_status,
        "shell_rc_do_not_track": rc_has_dnt,
        "ambient_high_privilege_env_names_present": ambient_present,
    }


def check_ai_local_stores(large_db_mb: int) -> dict[str, Any]:
    threshold_bytes = large_db_mb * 1024 * 1024
    large_dbs: list[dict[str, Any]] = []
    permissive_dbs: list[dict[str, Any]] = []
    dirs_checked: list[str] = []

    for raw_dir in AI_DATA_DIR_CANDIDATES:
        base = Path(raw_dir).expanduser()
        if not base.exists() or not base.is_dir():
            continue
        dirs_checked.append(raw_dir)
        base_depth = len(base.parts)
        for root, dirs, files in os.walk(base):
            cur = Path(root)
            if len(cur.parts) - base_depth >= 3:
                dirs[:] = []
            else:
                dirs[:] = [d for d in dirs if d not in SKIP_STORE_DIRS]
            for fname in files:
                lower = fname.lower()
                if not lower.endswith((".sqlite", ".sqlite3", ".db", ".jsonl")):
                    continue
                fpath = cur / fname
                try:
                    st = fpath.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                size_mb = round(st.st_size / (1024 * 1024), 1)
                mode_oct = oct(stat.S_IMODE(st.st_mode))
                rel_display = raw_dir + "/" + fpath.relative_to(base).as_posix()
                if st.st_size >= threshold_bytes:
                    large_dbs.append(
                        {
                            "path": rel_display,
                            "size_mb": size_mb,
                            "mode": mode_oct,
                        }
                    )
                if lower.endswith((".sqlite", ".sqlite3", ".db")) and (stat.S_IMODE(st.st_mode) & 0o077):
                    permissive_dbs.append(
                        {
                            "path": rel_display,
                            "size_mb": size_mb,
                            "mode": mode_oct,
                        }
                    )

    large_dbs.sort(key=lambda x: x["size_mb"], reverse=True)
    return {
        "threshold_mb": large_db_mb,
        "dirs_checked": dirs_checked,
        "large_data_files": large_dbs[:20],
        "world_or_group_readable_dbs": permissive_dbs[:20],
    }


def extract_process_name(args_str: str) -> str:
    # Handle macOS .app bundle paths with spaces cleanly
    m_app = re.search(r"/([^/]+\.app)/Contents/MacOS/([^\s]+)", args_str)
    if m_app:
        return m_app.group(2)
    first = args_str.split(None, 1)[0] if args_str else "unknown"
    return os.path.basename(first) or first


def check_ai_processes() -> dict[str, Any]:
    ai_procs: list[dict[str, Any]] = []
    argv_secret_warnings: list[dict[str, Any]] = []
    ps_out = run_cmd(["ps", "-eo", "pid=,args="])
    if not ps_out:
        return {"available": False, "ai_or_tunnel_processes": [], "argv_secret_warnings": []}

    my_pid = str(os.getpid())
    for line in ps_out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        pid, args_str = parts[0], parts[1]
        if pid == my_pid:
            continue
        comm_base = extract_process_name(args_str)

        # Detect if any process leaks raw secret-looking token on CLI argv (NEVER echo args_str!)
        if ARGV_SECRET_LEAK_RE.search(args_str):
            argv_secret_warnings.append(
                {
                    "pid": pid,
                    "command": comm_base,
                    "warning": "Secret-like token or credential flag detected in process command-line argv (readable by local process enumerators).",
                }
            )

        if AI_PROCESS_HINT_RE.search(comm_base) or AI_PROCESS_HINT_RE.search(args_str[:160]):
            ai_procs.append({"pid": pid, "command": comm_base})

    return {
        "available": True,
        "ai_or_tunnel_processes": ai_procs[:30],
        "argv_secret_warnings": argv_secret_warnings[:15],
    }


def render_markdown(report: dict[str, Any]) -> str:
    out: list[str] = []
    out.append("# oss-xray Local Machine Self-Check (Read-Only)")
    out.append("")
    out.append(f"- **Host OS**: `{report['host']['os']} {report['host']['release']}` (`{report['host']['arch']}`)")
    out.append(f"- **Timestamp**: `{report['timestamp']}`")
    out.append("- **Privacy Mode**: Strictly read-only, offline, zero secret contents inspected.")
    out.append("")

    # 1. Listening ports
    ports = report["listening_ports"]
    exposed = ports["exposed_non_loopback"]
    non_os_exposed = [e for e in exposed if not e["is_known_os_service"]]
    out.append(f"## 1. Exposed Non-Loopback TCP Listeners ({len(non_os_exposed)} non-OS / {len(exposed)} total)")
    out.append("")
    if exposed:
        out.append("| Command | PID | Bind Address | Port | Note |")
        out.append("| :--- | :--- | :--- | :---: | :--- |")
        for e in exposed:
            note = "Known macOS system service" if e["is_known_os_service"] else "REVIEW: Exposed to LAN/network"
            out.append(f"| `{e['command']}` | `{e['pid']}` | `{e['bind_host']}` | `{e['port']}` | {note} |")
    else:
        out.append("- None found. All detected TCP listeners are bound to loopback only.")
    out.append(f"- Loopback-only listeners (`127.0.0.1` / `::1`): `{ports['loopback_only_count']}` (checked via `{ports['tool_used']}`).")
    out.append("")

    # 2. Credential file permissions
    creds = report["credential_permissions"]
    bad_creds = [c for c in creds if c["status"] == "OVERPERMISSIVE"]
    out.append(f"## 2. Sensitive Credential File Permissions ({len(bad_creds)} overpermissive / {len(creds)} checked)")
    out.append("")
    if creds:
        out.append("| File | Mode | Size (bytes) | Status |")
        out.append("| :--- | :---: | :---: | :--- |")
        for c in creds:
            status = "**OVERPERMISSIVE** (run `chmod 600`)" if c["status"] == "OVERPERMISSIVE" else "OK (`0600`/`0400`)"
            out.append(f"| `{c['path']}` | `{c['mode']}` | `{c['size_bytes']}` | {status} |")
    else:
        out.append("- None of the standard credential files were found in `$HOME`.")
    out.append("")

    # 3. Telemetry & env hygiene
    env = report["env_hygiene"]
    out.append("## 3. Telemetry Opt-Out & Ambient Secret Exposure")
    out.append("")
    set_optouts = [f"`{k}={v}`" for k, v in env["optout_env_vars"].items() if v is not None]
    missing_optouts = [f"`{k}`" for k, v in env["optout_env_vars"].items() if v is None]
    out.append(f"- **Active Opt-Out Env Vars**: {', '.join(set_optouts) if set_optouts else 'None set in current shell'}")
    out.append(f"- **Not Set**: {', '.join(missing_optouts)}")
    if env["shell_rc_do_not_track"]:
        rc_str = ", ".join(f"`{k}`: {'yes' if v else 'no'}" for k, v in env["shell_rc_do_not_track"].items())
        out.append(f"- **`DO_NOT_TRACK` in Shell RC**: {rc_str}")
    ambient = env["ambient_high_privilege_env_names_present"]
    if ambient:
        out.append(f"- **Ambient High-Privilege Env Names Present (values hidden)**: {', '.join(f'`{x}`' for x in ambient)}")
        out.append("  - *Tip*: Before opening untrusted repos with AI tools, strip ambient creds via `env -u SSH_AUTH_SOCK -u GITHUB_TOKEN -u GH_TOKEN <tool>`.")
    else:
        out.append("- **Ambient High-Privilege Env Names Present**: None detected in current shell.")
    out.append("")

    # 4. Local AI databases
    stores = report["ai_local_stores"]
    out.append(f"## 4. Local AI Tool Data Stores (Threshold >= {stores['threshold_mb']} MB)")
    out.append("")
    if stores["large_data_files"]:
        out.append("### Oversized Local Databases / Logs (Check for Soft-Delete Retention)")
        for item in stores["large_data_files"]:
            out.append(f"- `{item['path']}` — **{item['size_mb']} MB** (mode `{item['mode']}`)")
    else:
        out.append(f"- No AI tool SQLite/JSONL files >= `{stores['threshold_mb']} MB` found in checked directories.")
    if stores["world_or_group_readable_dbs"]:
        out.append("")
        out.append(f"### Group/World-Readable AI SQLite Databases ({len(stores['world_or_group_readable_dbs'])} shown)")
        for item in stores["world_or_group_readable_dbs"][:10]:
            out.append(f"- `{item['path']}` — mode `{item['mode']}` ({item['size_mb']} MB)")
    out.append("")

    # 5. Active AI / Tunnel processes & argv warnings
    procs = report["processes"]
    out.append("## 5. Active AI / Tunnel Processes & CLI Argv Hygiene")
    out.append("")
    if procs["argv_secret_warnings"]:
        out.append("### WARNING: Secret-Like Token Detected in Running Process Command-Line Args")
        for w in procs["argv_secret_warnings"]:
            out.append(f"- PID `{w['pid']}` (`{w['command']}`): {w['warning']}")
    else:
        out.append("- No secret-like tokens detected in visible process `argv` lines.")
    ai_p = procs["ai_or_tunnel_processes"]
    if ai_p:
        unique_comms = sorted({p["command"] for p in ai_p})
        out.append(f"- **Active AI / Tunnel / Proxy Processes ({len(ai_p)})**: {', '.join(f'`{c}`' for c in unique_comms)}")
    out.append("")

    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Zero-dependency, strictly read-only local machine privacy & security self-check."
    )
    parser.add_argument("--format", choices=("md", "json"), default="md", help="Output format (default: md)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Shortcut for --format json")
    parser.add_argument(
        "--large-db-mb",
        type=int,
        default=150,
        help="Flag AI tool SQLite/JSONL files larger than this size in MB (default: 150)",
    )
    args = parser.parse_args()

    report = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {
            "os": platform.system(),
            "release": platform.release(),
            "arch": platform.machine(),
        },
        "listening_ports": check_listening_ports(),
        "credential_permissions": check_credential_permissions(),
        "env_hygiene": check_env_hygiene(),
        "ai_local_stores": check_ai_local_stores(max(1, args.large_db_mb)),
        "processes": check_ai_processes(),
    }

    if args.as_json or args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(render_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
