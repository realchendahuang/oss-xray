# oss-xray（开源 X 光机）

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20(Python%20stdlib)-brightgreen.svg)](#快速上手)
[![Zero Telemetry](https://img.shields.io/badge/Telemetry-0%20%7C%20Offline%20Read--Only-black.svg)](#自身安全承诺)
[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-Claude%20%7C%20Codex%20%7C%20Antigravity%20%7C%20Cursor-purple.svg)](#快速上手)

[English](./README.md) | [简体中文](./README_ZH.md)

**把终端、API 密钥和源码交出去之前，先给任何开源 AI 工具照一遍 X 光。**

`oss-xray` 是一个零第三方依赖、纯离线只读的 **Agent Skill**（附带两个 Python 3 标准库快扫脚本），专门用来在安装或信任任何开源 AI 编程客户端、Coding Agent、MCP Server、Electron 桌面应用或 CLI 之前做隐私与安全体检，同时支持一键对本机开发环境做只读自查。

---

## 为什么做这个项目

现在开发者每个月都会装十几个新的开源 AI 工具、Agent 壳和 MCP Server，没人有时间在运行之前通读十几万行 TypeScript / Go / Rust / Python 源码。

传统静态扫描器（Semgrep、CodeQL）主要查 SQL 注入、XSS 这些传统 Web 漏洞，**扫不出当下开源 AI 工具最常见、最致命的 8 类隐蔽信任暗坑**：

| # | 审计维度 | `oss-xray` 重点核查的具体模式 |
| :---: | :--- | :--- |
| **1** | **静默遥测与假开关** | 默认开启的 `PostHog` / `Axiom` / `Sentry` / 自建 `ingest.*` 中转留存副本；关闭环境变量失效（OS 平台忽略、启动读取早于 `~/.zshrc` 加载）；无视 `DO_NOT_TRACK`；无盐 SHA-256 跨设备串人 |
| **2** | **越界读取隔壁工具凭证** | 私读 `~/.claude.json`、`~/.codex/auth.json`、`~/.ssh`、`~/.aws` 或系统钥匙串；伪造环境变量（如假 `SSH_CONNECTION`）逼第三方 CLI 降级落明文凭证；将 `SSH_AUTH_SOCK`、`GITHUB_TOKEN` 等完整 `process.env` 透传进陌生仓库子进程 |
| **3** | **客户端伪装与封号风险** | 硬编码冒充官方客户端请求头或内部构建号直连未公开后端接口（如 `v1internal`），表面宣称合规实则让用户付费账号承担封号风险 |
| **4** | **假删除与敏感本地落盘** | 界面宣称“永久删除”但本地 SQLite 实际只做软删除、长期留存所有对话与敏感输出；密钥文件落盘权限过宽（`0644` 而非 `0600`）；日志或遥测泄漏令牌 |
| **5** | **后台静默监控与信息外泄** | 常驻轮询枚举整台机器进程命令行参数（随时扫出 `argv` 明文 API Key）；把私网域名发给第三方 favicon 接口；将内网私有 Ollama / Azure 模型名外泄到公开榜单 |
| **6** | **远程控制、局域网与隧道盲区** | 远程中继无真正端到端加密（TLS 在厂商代理/CDN 解包）；长效高权 Cookie 在明文 `--lan` 缺 `Secure`；省略 `Origin` 直接放行；URL 传可重放 `?wsTicket=`；30 天裸 Bearer 无法自吊销 |
| **7** | **审批绕过与陌生仓库零点击执行** | Auto / Safe 模式静默放行高危命令（如 `git push --force`）；打开陌生仓库自动跑 `.gitmodules` / git hooks / `SessionStart` hooks；内置浏览器预览页未开沙箱隔离 |
| **8** | **宣传口径 vs 源码与 `git log` 取证** | 逐条核对 README / 隐私页 / `SECURITY.md` 与实际源码；用 `git log` 追查静默删除“零遥测”承诺、零公告静默修高危洞，以及借用户本机凭据静默刷 Star 等暗黑增长动作 |

同时内置 **模式 B · 本机已装工具自查**：对你的 macOS / Linux 开发机跑纯只读体检，排查暴露在局域网的 TCP 监听端口（`0.0.0.0` / `*`）、权限过宽的密钥文件（`> 0600`）、遥测关闭环境变量卫生、异常膨胀的本地 AI SQLite 数据库，以及正在运行的进程命令行里是否裸露密钥参数。

---

## 快速上手

### 方式一：一键安装为 Agent Skill（推荐）

通过标准 Agent Skills CLI 安装（交互式只选你自己用的那一个客户端，绝不乱写其他目录）：

```bash
npx skills add realchendahuang/oss-xray
```

或者零安装脚本，直接把单个 `skills/oss-xray` 目录复制到你自己用的 Agent 技能目录：

```bash
git clone https://github.com/realchendahuang/oss-xray.git
cp -r oss-xray/skills/oss-xray ~/.claude/skills/oss-xray   # 换成你当前使用的 Agent 目录即可
```

### 方式二：不装 Agent，直接单跑零依赖脚本

仅需 Python 3.9+ 标准库，无需 `pip install`、无需 Docker、无需 Node：

```bash
# 模式 A：对本地克隆的任意开源仓库跑 8 维快扫 + git 历史承诺取证
python3 skills/oss-xray/scripts/repo_xray.py /path/to/some-open-source-repo

# 模式 B：对本机（macOS / Linux）跑只读隐私、端口与权限体检
python3 skills/oss-xray/scripts/host_xray.py
```

两个脚本均支持 `--json` 参数输出结构化 JSON，方便接入自定义脚本或 CI。

---

## 实际输出长什么样

### 模式 A · 仓库快扫线索 + 铁证审计报告

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

随后由你的 Coding Agent 逐一读入线索所在源码上下文，输出严格分档的审计报告：
- `CONFIRMED` — 源码或 `git show <sha>` 实证，附精确 `file:line` 与可直接复制的止损命令；
- `NEEDS_RUNTIME_CHECK` — 依赖闭源服务端或运行时开关的行为，附具体复核/抓包方式；
- `CLEARED` — 已核查并确认干净的维度（客观平衡，不制造无端焦虑）。

### 模式 B · 本机只读体检示例

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

## 对话触发示例（Claude Code / Codex / Antigravity / Cursor）

- **安装前先审本地开源仓库**：
  > 用 `oss-xray` 帮我给 `/tmp/某个AI工具` 做一次完整源码 X 光审计，锁定当前 commit，逐条核对 README 宣传与真实代码差异，并给出止损命令。
- **给一个 GitHub 链接做只读审计**：
  > 用 `oss-xray` 只读浅克隆 `https://github.com/org/repo`（`--depth=200`，严禁执行安装脚本和 hooks），跑一遍 8 维隐私与安全体检。
- **给自己的开发机做一次只读体检**：
  > 用 `oss-xray` 模式 B 查一下我这台电脑上有没有暴露到局域网的 AI 工具端口、权限过宽的密钥文件、遥测关闭配置和异常膨胀的本地数据库。

---

## 两阶段工作原理

1. **第一阶段 · 确定性离线快扫（`scripts/repo_xray.py`）**
   跳过锁文件、二进制、构建产物与测试样例，秒级定位 8 大维度的精确 `file:line` 线索，同时扫描文档隐私承诺并跑只读 `git log` 历史取证——直接帮 Agent 省下约 90% 上下文 Token 且避免肉眼漏文件。
2. **第二阶段 · 按需加载清单 + 零幻觉铁证核验（`SKILL.md` + `references/*.md`）**
   Agent 只按命中的维度按需读取对应深度检查清单，亲自核对上下文调用链与默认值、过滤正则误报，按**零幻觉铁证门禁**输出中立、可复现的审计报告。

---

## 自身安全承诺

审计工具本身必须 5 分钟就能自己审完（详见 [SECURITY.md](./SECURITY.md)）：

- **零遥测、零联网**：全程 100% 本地离线运行。
- **零第三方依赖**：只有纯 Markdown 手册与两个 Python 3 标准库脚本。
- **严格只读、绝不碰密钥明文**：绝不修改目标仓库，绝不执行待审仓库的安装脚本或 git hooks；本机体检只读文件权限/大小等元数据与监听端口，**绝不读取或打印任何密钥文件内容和敏感环境变量值**。

---

## 仓库结构

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

## 同系列开源 Skill

- [vibe-observability](https://github.com/realchendahuang/vibe-observability) — 上线后的全栈可观测性与只读信号回采 Skill 套件。
- [open-writing-skill](https://github.com/realchendahuang/open-writing-skill) — 零代码依赖开源通用写作 Skill 骨架。

## 开源协议

[MIT](./LICENSE)
