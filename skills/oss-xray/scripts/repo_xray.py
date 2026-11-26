#!/usr/bin/env python3
"""
oss-xray · repo_xray.py
Zero-dependency, strictly read-only, offline static pre-scanner for open-source
AI tools, Coding Agents, MCP servers, Electron apps, and CLIs.

Produces exact file:line leads across 8 privacy/security dimensions plus
optional git-history promise/security-fix forensics. Every hit is a LEAD to be
verified by reading surrounding source code — never reported blindly as proof.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".cache",
    ".parcel-cache",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    "out",
    "target",
    "vendor",
    "Pods",
    "coverage",
    ".gradle",
    ".idea",
    "storybook-static",
}

SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".bmp", ".tiff",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".dmg", ".pkg", ".exe",
    ".dll", ".so", ".dylib", ".wasm", ".bin", ".dat", ".sqlite", ".sqlite3", ".db",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".map", ".lock", ".pyc", ".pyo", ".class", ".jar", ".o", ".a",
}

SKIP_FILENAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "Cargo.lock",
    "poetry.lock",
    "uv.lock",
    "composer.lock",
    "Gemfile.lock",
    "go.sum",
}

CODE_EXTS = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".py", ".go", ".rs", ".java", ".kt", ".swift", ".rb", ".php",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".cs",
    ".sh", ".bash", ".zsh", ".ps1",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".env",
    ".astro", ".vue", ".svelte", ".html",
}

DOC_EXTS = {".md", ".mdx", ".txt", ".rst", ".astro", ".html"}

TEST_PATH_RE = re.compile(
    r"(^|/)(\_\_tests\_\_|tests?|spec|fixtures|mocks|e2e)/|"
    r"\.(test|spec|e2e)\.[^/]+$|_test\.go$|^test_[^/]+\.py$",
    re.IGNORECASE,
)

SECRET_REDACT_RE = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,})\b"
)

MAX_FILE_BYTES = 1_500_000  # 1.5 MB guard against giant bundled/generated files


# (category_key, category_title, reference_doc, [(rule_id, regex_pattern)])
CATEGORIES: list[tuple[str, str, str, list[tuple[str, re.Pattern[str]]]]] = [
    (
        "telemetry_and_optout",
        "Dim 1 · Telemetry, Analytics & Opt-Out Logic",
        "references/01-telemetry-and-claims.md",
        [
            ("telemetry_sdk", re.compile(r"\b(posthog|axiom|mixpanel|amplitude|segment|sentry|telemetry|analytics)\b", re.I)),
            ("ingest_endpoint", re.compile(r"https?://[^\s'\"`]*(ingest|telemetry|analytics|metrics|track|beacon)[^\s'\"`]*", re.I)),
            ("optout_env", re.compile(r"\b(DO_NOT_TRACK|TELEMETRY_ENABLED|TELEMETRY_DISABLED|DISABLE_TELEMETRY|OPT_OUT|managed[-_]?policy)\b", re.I)),
            ("identity_hash", re.compile(r"(createHash\s*\(\s*['\"]sha256['\"]|sha256).{0,80}(user|account|email|device|install|claude|codex|id)", re.I)),
        ],
    ),
    (
        "cross_tool_credentials",
        "Dim 2 · Cross-Tool Credentials, Keychain & Env Forwarding",
        "references/02-credentials-and-spoofing.md",
        [
            ("neighbor_creds", re.compile(r"(\.claude\.json|\.codex[/\\]auth\.json|\.config[/\\]gh[/\\]hosts|\.ssh[/\\]|\.aws[/\\]credentials|\.netrc|\.npmrc|\.cursor[/\\])", re.I)),
            ("os_keychain", re.compile(r"(find-generic-password|secret-tool|CredRead|keytar|credential[-_]?manager|Keychain)", re.I)),
            ("env_spoof", re.compile(r"(SSH_CONNECTION|SSH_TTY)\s*[:=]")),
            ("env_inherit", re.compile(r"(SSH_AUTH_SOCK|GITHUB_TOKEN|GH_TOKEN|\.\.\.process\.env|os\.environ\.copy\()")),
        ],
    ),
    (
        "vendor_impersonation",
        "Dim 3 · Client Spoofing & Private Vendor Endpoints",
        "references/02-credentials-and-spoofing.md",
        [
            ("private_endpoint", re.compile(r"(v1internal|googleapis\.com[^\s'\"`]*internal|usageLimits|/v1/quota|fetchQuota)", re.I)),
            ("spoofed_headers", re.compile(r"(['\"](User-Agent|X-Client-Name|X-Client-Version|X-Goog-Api-Client|anthropic-beta)['\"]\s*:\s*['\"][^'\"]{4,})", re.I)),
        ],
    ),
    (
        "storage_and_fake_delete",
        "Dim 4 · Local Storage, Soft-Delete & File Permissions",
        "references/03-local-storage-and-surveillance.md",
        [
            ("soft_delete", re.compile(r"\b(deleted_at|deletedAt|soft_?delete|is_deleted|isDeleted)\b")),
            ("sqlite_store", re.compile(r"(\.sqlite3?\b|\b(better-sqlite3|sqlite3|CREATE TABLE|VACUUM)\b)", re.I)),
            ("secret_write", re.compile(r"(writeFile|writeFileSync|open\().{0,80}(token|secret|auth|cred|cookie|key)", re.I)),
        ],
    ),
    (
        "process_and_outbound_leaks",
        "Dim 5 · Background Process Scanning & External Metadata Leaks",
        "references/03-local-storage-and-surveillance.md",
        [
            ("process_enum", re.compile(r"(OpenProcess|QueryFullProcessImageName|pidusage|sysinfo|resource[-_]?monitor|ps\s+-e|ps\s+aux|wmic\s+process|cmdline)", re.I)),
            ("favicon_leak", re.compile(r"(google\.com/s2/favicons|icons\.duckduckgo\.com|favicon\.yandex)", re.I)),
            ("cwd_or_model_leak", re.compile(r"(git\.cwd|process\.cwd\(\)|leaderboard|ollama)", re.I)),
        ],
    ),
    (
        "remote_auth_and_lan",
        "Dim 6 · Remote Tunnels, LAN Exposure, Cookies & WS Tickets",
        "references/04-remote-auth-and-execution.md",
        [
            ("lan_or_bind", re.compile(r"(--lan\b|['\"]0\.0\.0\.0['\"]|['\"]::['\"]|cloudflared|tunnel)", re.I)),
            ("cookie_origin", re.compile(r"(wsTicket|sameSite|httpOnly|\bsecure\s*:\s*false|!origin\b|origin\s*===?\s*undefined|isIPv4|::1)", re.I)),
            ("long_ttl_token", re.compile(r"(30\s*\*\s*24\s*\*\s*60|2592000|current_session_revoke|DPoP|/oauth/token)", re.I)),
        ],
    ),
    (
        "execution_and_sandbox",
        "Dim 7 · Approval Bypass, Untrusted Repo Hooks & Webview Sandbox",
        "references/04-remote-auth-and-execution.md",
        [
            ("git_hooks_submod", re.compile(r"(submodule\s+update|core\.hooksPath|SessionStart|\.gitmodules|bypassPermissions|auto[-_]?approve)", re.I)),
            ("webview_sandbox", re.compile(r"(nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false|sandbox\s*:\s*false|webSecurity\s*:\s*false)")),
            ("destructive_cmd", re.compile(r"(git\s+push\s+--force|rm\s+-rf)", re.I)),
        ],
    ),
    (
        "dark_growth_and_claims",
        "Dim 8 · Dark Growth (Auto-Star) & Public Privacy Claims",
        "references/01-telemetry-and-claims.md",
        [
            ("auto_star_api", re.compile(r"(/user/starred/|starred/|gh\s+api\s+-X\s+PUT)", re.I)),
        ],
    ),
]

CLAIM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("zero_telemetry_claim", re.compile(r"\b(no|zero)\s+telemetry\b|unless\s+you\s+opt[- ]?in|opt[- ]?in\s+only", re.I)),
    ("local_only_claim", re.compile(r"\b(local[- ]?only|never\s+leaves\s+your\s+(machine|device|computer)|100%\s+local)\b", re.I)),
    ("e2e_claim", re.compile(r"\b(end[- ]to[- ]end\s+encrypt|e2ee|zero[- ]knowledge)\b", re.I)),
    ("perm_delete_claim", re.compile(r"\b(permanently\s+delet|cannot\s+be\s+undone|wipe\s+all\s+data)\b", re.I)),
    ("tos_claim", re.compile(r"\b(fully\s+compliant|terms\s+of\s+service|gdpr\s+compliant)\b", re.I)),
]


def redact_snippet(text: str, limit: int = 160) -> str:
    cleaned = " ".join(text.strip().split())
    cleaned = SECRET_REDACT_RE.sub("[REDACTED_SECRET]", cleaned)
    if len(cleaned) > limit:
        return cleaned[: limit - 3] + "..."
    return cleaned


def is_binary_chunk(chunk: bytes) -> bool:
    return b"\x00" in chunk


def run_git(repo: Path, args: list[str], timeout: int = 10) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout.strip()
    except Exception:
        return None


def collect_git_forensics(repo: Path) -> dict[str, Any]:
    if not (repo / ".git").exists():
        return {"available": False}

    head = run_git(repo, ["rev-parse", "HEAD"]) or "unknown"
    branch = run_git(repo, ["rev-parse", "--abbrev-ref", "HEAD"]) or "unknown"
    commit_count = run_git(repo, ["rev-list", "--count", "HEAD"]) or "unknown"

    promise_commits_raw = run_git(
        repo,
        [
            "log",
            "-G",
            r"(zero|no)[ -]telemetry|opt[- ]?in|never leaves|end-to-end",
            "-i",
            "--oneline",
            "-n",
            "20",
        ],
        timeout=15,
    )
    security_commits_raw = run_git(
        repo,
        [
            "log",
            "-E",
            "--grep=telemetry|privacy|security|gdpr|leak|redact|sanitize|traversal|origin|cookie|sandbox|bypass",
            "-i",
            "--oneline",
            "-n",
            "25",
        ],
        timeout=15,
    )

    return {
        "available": True,
        "head": head,
        "branch": branch,
        "commit_count": commit_count,
        "promise_diff_commits": [line for line in (promise_commits_raw or "").splitlines() if line.strip()],
        "security_privacy_commits": [line for line in (security_commits_raw or "").splitlines() if line.strip()],
    }


def scan_repo(repo: Path, max_per_category: int, include_tests: bool, run_git_checks: bool) -> dict[str, Any]:
    hits: dict[str, list[dict[str, Any]]] = defaultdict(list)
    counts: dict[str, int] = defaultdict(int)
    claims: list[dict[str, Any]] = []
    claim_total = 0
    files_scanned = 0
    files_skipped_tests = 0
    files_skipped_large = 0

    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for fname in sorted(files):
            if fname in SKIP_FILENAMES:
                continue
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()
            if ext in SKIP_EXTS or fname.endswith(".min.js") or fname.endswith(".min.css"):
                continue

            rel = fpath.relative_to(repo).as_posix()
            is_test = bool(TEST_PATH_RE.search(rel))
            if is_test and not include_tests:
                files_skipped_tests += 1
                continue

            is_doc = (
                ext in DOC_EXTS
                or fname.upper().startswith(("README", "PRIVACY", "SECURITY", "CHANGELOG"))
                or "/docs/" in f"/{rel.lower()}"
            )
            is_code = ext in CODE_EXTS or fname in {"Dockerfile", "Makefile"}
            if not (is_code or is_doc):
                continue

            try:
                size = fpath.stat().st_size
                if size == 0 or size > MAX_FILE_BYTES:
                    if size > MAX_FILE_BYTES:
                        files_skipped_large += 1
                    continue
                raw = fpath.read_bytes()
            except OSError:
                continue

            if is_binary_chunk(raw[:4096]):
                continue

            text = raw.decode("utf-8", errors="ignore")
            files_scanned += 1
            lines = text.splitlines()

            for lineno, line in enumerate(lines, start=1):
                if len(line) > 2000:
                    continue  # likely minified single-line asset

                if is_code:
                    for cat_key, _, _, rules in CATEGORIES:
                        for rule_id, pattern in rules:
                            if pattern.search(line):
                                counts[cat_key] += 1
                                if len(hits[cat_key]) < max_per_category:
                                    hits[cat_key].append(
                                        {
                                            "rule": rule_id,
                                            "file": rel,
                                            "line": lineno,
                                            "snippet": redact_snippet(line),
                                        }
                                    )
                                break  # at most one hit per line per category

                if is_doc:
                    for claim_id, cpat in CLAIM_PATTERNS:
                        if cpat.search(line):
                            claim_total += 1
                            if len(claims) < max_per_category:
                                claims.append(
                                    {
                                        "rule": claim_id,
                                        "file": rel,
                                        "line": lineno,
                                        "snippet": redact_snippet(line),
                                    }
                                )
                            break

    git_info = collect_git_forensics(repo) if run_git_checks else {"available": False}

    # Check key trust files at root
    trust_files = []
    for candidate in ("README.md", "SECURITY.md", "PRIVACY.md", "LICENSE", "package.json", "pyproject.toml", "go.mod", "Cargo.toml"):
        if (repo / candidate).exists():
            trust_files.append(candidate)

    return {
        "repo": str(repo.resolve()),
        "files_scanned": files_scanned,
        "files_skipped_tests": files_skipped_tests,
        "files_skipped_large": files_skipped_large,
        "root_trust_files": trust_files,
        "git": git_info,
        "categories": [
            {
                "key": cat_key,
                "title": title,
                "reference": ref_doc,
                "total_hits": counts[cat_key],
                "shown_hits": hits[cat_key],
            }
            for cat_key, title, ref_doc, _ in CATEGORIES
        ],
        "public_claims": {
            "total_hits": claim_total,
            "shown_hits": claims,
        },
    }


def render_markdown(result: dict[str, Any]) -> str:
    out: list[str] = []
    git = result["git"]
    out.append(f"# oss-xray Pre-Scan Leads: `{Path(result['repo']).name}`")
    out.append("")
    out.append(f"- **Path**: `{result['repo']}`")
    if git.get("available"):
        out.append(f"- **Pinned Commit**: `{git['head']}` (branch: `{git['branch']}`, commits reachable: `{git['commit_count']}`)")
    else:
        out.append("- **Pinned Commit**: `(no .git directory or --no-git)`")
    out.append(
        f"- **Files Scanned**: `{result['files_scanned']}` "
        f"(skipped tests: `{result['files_skipped_tests']}`, skipped >1.5MB: `{result['files_skipped_large']}`)"
    )
    out.append(f"- **Root Trust Files**: {', '.join(f'`{f}`' for f in result['root_trust_files']) or 'None found'}")
    out.append("")
    out.append("> **Reminder**: These are static leads only. Read surrounding code before marking anything `CONFIRMED`.")
    out.append("")

    out.append("## Summary by Audit Dimension")
    out.append("")
    out.append("| Dimension | Total Leads | Shown | Deep-Dive Reference |")
    out.append("| :--- | :---: | :---: | :--- |")
    for cat in result["categories"]:
        out.append(f"| {cat['title']} | {cat['total_hits']} | {len(cat['shown_hits'])} | `{cat['reference']}` |")
    out.append(
        f"| Public Privacy/Security Claims (Docs/README) | {result['public_claims']['total_hits']} | "
        f"{len(result['public_claims']['shown_hits'])} | `references/01-telemetry-and-claims.md` |"
    )
    out.append("")

    for cat in result["categories"]:
        if not cat["shown_hits"]:
            continue
        out.append(f"## {cat['title']} ({cat['total_hits']} leads)")
        out.append("")
        for h in cat["shown_hits"]:
            out.append(f"- `{h['file']}:{h['line']}` `[{h['rule']}]` — `{h['snippet']}`")
        if cat["total_hits"] > len(cat["shown_hits"]):
            out.append(f"- *(+{cat['total_hits'] - len(cat['shown_hits'])} more leads; re-run with `--max-per-category` or `rg`)*")
        out.append("")

    if result["public_claims"]["shown_hits"]:
        out.append(f"## Public Claims Found in Docs/README ({result['public_claims']['total_hits']} leads)")
        out.append("")
        for c in result["public_claims"]["shown_hits"]:
            out.append(f"- `{c['file']}:{c['line']}` `[{c['rule']}]` — `{c['snippet']}`")
        out.append("")

    if git.get("available"):
        out.append("## Git History Forensics")
        out.append("")
        p_commits = git.get("promise_diff_commits", [])
        s_commits = git.get("security_privacy_commits", [])
        out.append(f"### Commits Adding/Removing Privacy Promises ({len(p_commits)} shown)")
        if p_commits:
            for line in p_commits:
                out.append(f"- `{line}`")
        else:
            out.append("- None matched.")
        out.append("")
        out.append(f"### Commits Matching Security/Privacy/Telemetry Keywords ({len(s_commits)} shown)")
        if s_commits:
            for line in s_commits:
                out.append(f"- `{line}`")
        else:
            out.append("- None matched.")
        out.append("")

    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Zero-dependency, read-only privacy & security pre-scanner for open-source repositories."
    )
    parser.add_argument("repo_path", help="Path to local git repository or extracted source directory")
    parser.add_argument("--format", choices=("md", "json"), default="md", help="Output format (default: md)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Shortcut for --format json")
    parser.add_argument("--max-per-category", type=int, default=15, help="Max leads printed per category (default: 15)")
    parser.add_argument("--include-tests", action="store_true", help="Include test/fixture files in scan")
    parser.add_argument("--no-git", action="store_true", help="Skip git history forensics")
    args = parser.parse_args()

    repo = Path(args.repo_path).expanduser()
    if not repo.exists() or not repo.is_dir():
        print(f"Error: Directory not found: {repo}", file=sys.stderr)
        return 2

    result = scan_repo(
        repo=repo,
        max_per_category=max(1, args.max_per_category),
        include_tests=args.include_tests,
        run_git_checks=not args.no_git,
    )

    if args.as_json or args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(render_markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
