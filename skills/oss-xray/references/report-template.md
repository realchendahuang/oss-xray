# Evidence-First Audit Report Template

Every audit delivered by `oss-xray` MUST follow this structure and pass the **Zero-Speculation Gate** before output.

## Pre-Flight Gate (Self-Check Before Outputting)

- [ ] Audited commit SHA (or host OS + timestamp for Mode B) is pinned at the top.
- [ ] Every `CONFIRMED` item includes an exact `file:line` anchor (or `git show <sha>` command) verified by reading the actual file — zero guesses from raw regex output.
- [ ] Every `NEEDS_RUNTIME_CHECK` item states the exact command or packet inspection required to confirm/refute it.
- [ ] `CLEARED` section documents dimensions that were checked and found clean (fair, balanced, non-alarmist).
- [ ] Every `CRITICAL` / `HIGH` finding has a concrete, copy-pasteable mitigation.
- [ ] Tone is strictly technical, neutral, and reproducible — zero ad hominem claims or speculation on author motives.

---

## Report Structure

```markdown
# oss-xray Audit Report: <Repo Name or Host Check>

- **Target**: `<repo URL / local path>` (or `Local Host: <OS>`)
- **Pinned Revision**: `<full git commit SHA>` (`<branch/tag>`) — or N/A for Mode B
- **Audit Date**: `YYYY-MM-DD`
- **Overall Risk Verdict**: `LOW` | `MEDIUM` | `HIGH` | `CRITICAL`
- **One-Line Summary**: <Single factual sentence summarizing the highest-impact verified findings.>

---

## 1. Confirmed Findings (`CONFIRMED`)

### [<SEVERITY: CRITICAL|HIGH|MEDIUM|LOW>] <Short Factual Title>
- **Dimension**: <e.g. Dim 1 · Silent Telemetry / Dim 6 · LAN Auth>
- **Evidence**: `<path/to/file>:<Lstart>-<Lend>` (and/or `git show <sha>`)
- **What the Code Does**: <2–4 concise technical sentences describing the exact verified mechanism and reachable call path.>
- **Claim vs. Reality** *(include when contradicting docs/README)*: `<doc_file>:<L>` states X; `<code_file>:<L>` actually does Y.
- **Blast Radius**: <Concrete impact on user privacy, credentials, account standing, or host shell.>
- **Mitigation**:
  ```bash
  <Exact opt-out command, env stripping, firewall/tunnel rule, or config patch>
  ```

---

## 2. Needs Runtime Verification (`NEEDS_RUNTIME_CHECK`)

- **<Item>**: <Code anchor> — <Why static analysis alone cannot prove it (e.g., closed-source relay, build-time flag) + exact runtime check command.>

---

## 3. Checked & Cleared (`CLEARED`)

- **<Dimension / Check>**: Checked `<files>` — <brief factual reason it passed (e.g. telemetry strictly opt-in default false; loopback-only bind `127.0.0.1`; `0600` permissions enforced).>

---

## 4. Quick Hardening Checklist (Copy-Paste Mitigations)

1. <Most urgent user action + exact command>
2. <Second user action + exact command>
3. <Optional safe alternative or isolation wrapper>
```
