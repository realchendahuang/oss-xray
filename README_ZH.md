# oss-xray（开源 X 光机）

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20(Python%20stdlib)-brightgreen.svg)](#快速上手)
[![Zero Telemetry](https://img.shields.io/badge/Telemetry-0%20%7C%20Offline%20Read--Only-black.svg)](#自身安全承诺)

[English](./README.md) | [简体中文](./README_ZH.md)

**把你的终端、API 密钥和源码交出去之前，先给任何开源 AI 工具照一遍 X 光。**

`oss-xray` 是一个零第三方依赖、纯离线只读的 **Agent Skill**（附带两个 Python 标准库快扫脚本），专门用来在安装或信任任何开源 AI 编程工具、Coding Agent、MCP Server、Electron 桌面端或 CLI 之前做隐私与安全体检，同时支持一键对本机已装开发环境做只读自查。

---

## 为什么做这个项目

现在开发者每个月都会装十几个新的开源 AI 工具、Agent 壳和 MCP Server，但没人有时间在运行之前自己通读十几万行源码。

传统的静态扫描器（Semgrep、CodeQL）只查 SQL 注入、XSS 这些传统 Web 漏洞，**根本扫不出当下 AI 工具最常见、最致命的 8 类隐蔽暗坑**：

| # | 审计维度 | `oss-xray` 重点核查什么 |
| :---: | :--- | :--- |
| **1** | **静默遥测与假开关** | 默认开启的上报（`PostHog`、`Axiom`、`Sentry`、自建 `ingest.*` 中转留存副本）、关闭环境变量失效（Windows 忽略、启动读取早于 `~/.zshrc` 加载）、无视 `DO_NOT_TRACK`、无盐 SHA-256 跨设备串人 |
| **2** | **越界读取隔壁工具凭证** | 私读 `~/.claude.json`、`~/.codex/auth.json`、`~/.ssh`、`~/.aws` 或系统钥匙串；伪造环境变量（如假 `SSH_CONNECTION`）逼第三方 CLI 降级落明文凭证；将 `SSH_AUTH_SOCK`、`GITHUB_TOKEN` 等完整 `process.env` 透传进陌生仓库子进程 |
| **3** | **客户端伪装与封号风险** | 硬编码冒充官方客户端请求头或内部构建号直连未公开后端接口，表面宣称合规实则让用户付费订阅承担封号风险 |
| **4** | **假删除与敏感本地落盘** | 界面宣称“永久删除”但 SQLite 实际只做软删除保留全部历史与敏感输出；密钥文件落盘权限过宽（`0644` 而非 `0600`）；日志或遥测泄漏令牌 |
| **5** | **后台静默监控与信息外泄** | 常驻轮询枚举整台机器进程命令行参数（随时扫出明文 API Key）；把私网域名发给第三方 favicon 接口；将内网私有模型名外泄到公开榜单 |
| **6** | **远程控制、局域网与隧道盲区** | 远程中继无真正端到端加密（TLS 在厂商网关解包）；长效高权 Cookie 在明文 `--lan` 缺 `Secure`；省略 `Origin` 直接放行；URL 传可重放 WebSocket 票据；高权 Bearer 无法自吊销 |
| **7** | **审批绕过与陌生仓库零点击执行** | Auto / Safe 模式静默放行高危命令（如 `git push --force`）；打开陌生仓库自动跑 `.gitmodules` / git hooks / `SessionStart` hooks；内置浏览器预览页未开沙箱隔离 |
| **8** | **宣传口径 vs 源码与 `git log` 取证** | 逐条核对 README / 隐私政策 / `SECURITY.md` 与实际源码；用 `git log` 追查静默删除“零遥测”承诺、零公告静默修高危洞，以及借用户本机凭据静默刷 Star 等暗黑增长动作 |

同时内置 **模式 B · 本机已装工具自查**：纯只读扫描你自己的 macOS / Linux 开发机，排查暴露在局域网的 TCP 监听端口、权限过宽的密钥文件（`> 0600`）、遥测关闭环境变量卫生、异常膨胀的本地 AI 数据库（疑似假删除残留），以及正在运行的进程命令行里是否裸露密钥参数。

---

## 自身安全承诺

审计工具本身必须最经得起审计：

- **零遥测、零联网**：全程 100% 本地离线运行，不发任何外联请求。
- **零第三方依赖**：仅包含 Markdown 审计手册与两个纯 Python 3 标准库脚本（`repo_xray.py`、`host_xray.py`），5 分钟就能自己通读源码。
- **严格只读、不碰密钥明文**：绝不修改目标仓库，绝不执行待审仓库的 `npm install` 或 git hooks；本机体检仅读取文件元数据（路径、权限位、大小）和网络监听状态，**绝不读取或打印任何密钥文件内容和敏感环境变量值**。
- **零幻觉铁证门禁**：强制要求每一条 `CONFIRMED` 结论必须附可复现的 `file:line` 或 `git show <sha>`，严格区分为「源码实证 / 需运行时抓包复核 / 已排除误报」，并为每条高危项配套可直接复制执行的止损命令。

---

## 快速上手

### 方式一：通过 Agent Skills CLI 一键安装（推荐）

支持 Claude Code、Codex、Cursor、Antigravity、OpenCode 等主流 Coding Agent：

```bash
npx skills add realchendahuang/oss-xray
```

### 方式二：Clone 后用 `./install.sh` 安装到指定 Agent

```bash
git clone https://github.com/realchendahuang/oss-xray.git
cd oss-xray

# 可选目标：antigravity | claude | codex | cursor | opencode | agents | project | all
./install.sh --target antigravity --symlink
# 或一次性软链到全部全局目录：
./install.sh --target all --symlink
```

### 方式三：不装 Agent，直接单独跑零依赖快扫脚本

```bash
# 模式 A：对本地克隆的任意开源仓库跑 8 维快扫 + git 历史取证
python3 skills/oss-xray/scripts/repo_xray.py /path/to/some-open-source-repo

# 模式 B：对本机（macOS / Linux）跑只读隐私与端口自查
python3 skills/oss-xray/scripts/host_xray.py
```

两个脚本均支持 `--json` 输出，方便接入你自己的脚本或 CI。

---

## 对话触发示例（在 Claude Code / Codex / Antigravity / Cursor 中）

- **安装前先审本地仓库**：
  > 用 `oss-xray` 帮我给 `/tmp/某个AI工具` 做一次完整源码 X 光审计，锁定当前 commit，逐条核对 README 宣传与真实代码差异，并给出止损命令。
- **给一个 GitHub 链接做只读审计**：
  > 用 `oss-xray` 只读浅克隆 `https://github.com/org/repo`（严禁执行安装脚本和 hooks），跑一遍 8 维隐私与安全体检。
- **给自己的开发机做一次只读体检**：
  > 用 `oss-xray` 模式 B 查一下我这台电脑上有没有暴露到局域网的 AI 工具端口、权限过宽的密钥文件、遥测关闭配置和异常膨胀的本地数据库。

---

## 仓库结构

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

## 同系列开源 Skill

- [vibe-observability](https://github.com/realchendahuang/vibe-observability) — 上线后的全栈可观测性与只读信号回采 Skill 套件。
- [open-writing-skill](https://github.com/realchendahuang/open-writing-skill) — 零代码依赖开源通用写作 Skill 骨架。

## 开源协议

[MIT](./LICENSE)
