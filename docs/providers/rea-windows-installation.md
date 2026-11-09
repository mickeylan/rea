# Windows 安装与配置 REA

> 适用版本：`rea-agents` 6.5.0；更新日期：2026-10-16。
>
> 本文介绍 REA 本身的安装、命令行验证、Agent/MCP 配置、升级和常见故障。Ghidra 的安装与 Windows 专项排错见 [REA + Ghidra Windows 配置与排错](rea-windows-ghidra-setup.md)。

## 1. REA 是什么

REA 同时提供：

- `rea` 命令行工具；
- MCP server，供 Claude Code、Codex、Cursor 等客户端调用；
- 配套 workflow skill；
- 对 Ghidra、Hopper、IDA 等外部分析引擎的适配。

REA 默认在本机分析。安装 REA 不等于安装 Ghidra、Java、Node.js 或其他分析引擎；这些组件必须由用户单独准备。

## 2. Windows 前置条件

### Node.js

REA 6.5.0 支持：

```text
Node.js 22.x，且 >= 22.19.0
Node.js 24.x，且 >= 24.11.0
Node.js 26 或更高版本
```

检查实际生效的版本和路径：

```powershell
node --version
npm --version
Get-Command node
Get-Command npm
```

如果电脑上安装过多个 Node.js，`Get-Command node -All` 可以帮助确认是否被旧版本抢先解析。

### PowerShell

以下示例使用 PowerShell 7 或 Windows PowerShell。路径含空格时始终使用引号。不要把 API token、密码或私钥写入脚本或 MCP 配置。

## 3. 选择安装方式

### 方式 A：先用 `npx` 运行，推荐首次安装

无需永久全局安装：

```powershell
npx -y rea-agents@latest --version
npx -y rea-agents@latest doctor --json
npx -y rea-agents@latest setup
```

优点是每次可以明确选择最新版本；缺点是首次运行需要从 npm registry 获取包。

需要固定版本时：

```powershell
npx -y rea-agents@6.5.0 --version
```

### 方式 B：全局安装

```powershell
npm install --global rea-agents@6.5.0
rea --version
```

查看 npm 全局位置：

```powershell
npm config get prefix
Get-Command rea
```

如果全局目录没有进入 `PATH`，可以改用明确的独立目录：

```powershell
npm install --global rea-agents@6.5.0 --prefix D:\npm-global
$env:PATH = "D:\npm-global;$env:PATH"
D:\npm-global\rea.cmd --version
```

永久修改 `PATH` 前先确认该目录确实包含 `rea.cmd`。不要覆盖原有用户 `PATH`；应追加或使用 Windows 环境变量界面编辑。

### 方式 C：源码开发环境

仅在需要修改 REA 源码时使用：

```powershell
git clone https://github.com/morluto/rea.git
Set-Location rea
npm ci
npm run build:cached
node scripts/rea.mjs --version
```

源码 checkout 不应使用 `rea update` 更新；应通过 Git 更新，再运行锁定依赖安装和项目检查。

## 4. 安装后的最小验证

```powershell
rea --version
rea doctor --json
rea providers --json
rea capabilities --json
```

`doctor` 是只读诊断，不会修改配置。未配置的可选 provider 或 Agent 可能导致总体 `healthy` 为 false；应重点查看当前任务对应的 scoped check，例如：

```powershell
rea doctor --provider ghidra --json
rea doctor --client claude_code --skill --json
```

静态 JavaScript 工作流不依赖 Ghidra，可作为基础 smoke test：

```powershell
rea analyze-javascript-application "C:\path\to\app" --json
```

## 5. 配置 Agent 和 MCP

### 使用交互式 setup

```powershell
rea setup
```

setup 会：

1. 检测支持的客户端；
2. 显示将修改的文件和内容；
3. 等待确认；
4. 备份已有配置；
5. 写入 REA MCP 注册和可选 workflow skill。

它不会自动安装或升级 Node.js、npm、Java、Ghidra 或其他无关软件。

### 写入前预览

```powershell
rea setup --client claude_code --skill=false --dry-run
rea setup --json
```

自动化环境应明确指定范围并显式批准：

```powershell
rea setup --client claude_code --yes --json
```

不要仅因为客户端被检测到就假定它应被修改。

### 配置后验证

重启 Agent 客户端，然后运行：

```powershell
rea doctor --client claude_code --skill --json
```

如果客户端有自己的 MCP 列表命令，也应检查它实际读取的配置。例如 Claude Code：

```powershell
claude mcp list
```

## 6. 手工 MCP 注册

优先使用 `rea setup`。确需手工配置时，推荐用绝对的 Node 路径和 REA entry point，避免 GUI 客户端继承到不同的 `PATH`。

示例结构：

```json
{
  "mcpServers": {
    "rea": {
      "command": "C:\\Program Files\\nodejs\\node.exe",
      "args": [
        "D:\\npm-global\\node_modules\\rea-agents\\scripts\\rea.mjs",
        "mcp"
      ]
    }
  }
}
```

实际配置键名由客户端决定。写入前确认：

```powershell
Get-Command node
npm root --global
Test-Path "D:\npm-global\node_modules\rea-agents\scripts\rea.mjs"
```

修改后必须彻底重启 MCP 客户端。终端中的环境变量不会自动进入已经运行的 GUI 应用。

## 7. 配置分析 provider

REA 本身可以正常安装，但原生二进制分析还需要 provider。查看当前可用性：

```powershell
rea providers --json
rea doctor --provider ghidra --json
```

Windows 上 Ghidra 需要用户自行安装 Ghidra 12.1.x 和兼容的 64 位完整 JDK，并配置：

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\tools\ghidra_12.1.4_PUBLIC"
$env:JAVA_HOME = "C:\tools\jdk-21"
$env:REA_ANALYSIS_PROVIDER = "ghidra"
```

详见 [REA + Ghidra Windows 配置与排错](rea-windows-ghidra-setup.md)。

## 8. 常用命令

```powershell
# 查看原生二进制概况
rea analyze "C:\targets\sample.exe" --provider ghidra --json

# 搜索字符串或名称
rea search "C:\targets\sample.exe" "license" --provider ghidra --json

# 分析函数
rea function "C:\targets\sample.exe" 0x140001000 --provider ghidra --json

# 检查 Cython Windows 扩展
rea inspect-cython-extension "C:\targets\module.pyd" --provider ghidra --format json
```

`inspect-cython-extension` 只接受原生、非托管的 PE shared-library `.pyd`；它不会导入或执行 Python 扩展。

## 9. 更新和卸载

全局 npm 安装可以使用：

```powershell
rea update
```

也可以由 npm 明确管理：

```powershell
npm install --global rea-agents@latest
```

`npx` 用户通过指定 `@latest` 获取新版本。源码 checkout 应通过 Git 更新。

移除 REA-owned Agent 注册和 skill：

```powershell
rea uninstall
```

如需同时清理 REA cache/state，先预览并确认 `--purge-data` 的影响。不要手工删除无法确认 ownership 的文件。

## 10. 常见问题

### `rea` 不是内部或外部命令

检查：

```powershell
npm config get prefix
Get-Command rea -ErrorAction SilentlyContinue
Get-ChildItem "$(npm config get prefix)" -Filter "rea*"
```

临时解决可使用完整路径或 `npx -y rea-agents@latest`。之后修复用户 `PATH`，不要覆盖系统原有内容。

### Node.js 版本不满足要求

```powershell
node --version
Get-Command node -All
```

升级到受支持版本，并重新打开终端和 GUI 客户端。仅安装新版本但继续从旧目录解析 `node.exe` 不会解决问题。

### 终端可用，但 Agent 中不可用

常见原因：

- Agent 在修改配置前已经启动；
- GUI 没继承当前 PowerShell 的临时环境变量；
- MCP 注册使用了另一个 Node/REA 路径；
- 客户端读取的是另一份配置文件。

处理顺序：

1. 用绝对路径验证 Node 和 REA entry point；
2. 运行 `rea setup --dry-run` 查看目标配置；
3. 运行 scoped `rea doctor`；
4. 完全退出并重启客户端；
5. 查看客户端自己的 MCP 列表和日志。

### `doctor` 总体不健康，但命令能运行

REA 会同时报告未配置的可选 provider、Agent 和 skill。使用 task-scoped doctor 判断当前工作流：

```powershell
rea doctor --provider ghidra --json
```

不要把无关 optional check 的失败误认为当前 provider 不可用。

### npm 权限或 prefix 问题

优先使用用户可写 prefix 或 `npx`，不要以管理员身份反复安装来掩盖 ownership 问题。确认目录 ownership 后再调整配置。

## 11. 安全与可复现建议

- 从官方 GitHub、REA 网站或 `rea-agents` npm package 获取 REA；
- 为自动化固定版本，例如 `rea-agents@6.5.0`；
- 保存 `rea --version`、provider 版本、目标 digest 和实际运行命令；
- provider 认证信息不要写入日志或文档；
- 使用本地、稳定、不随分析期间变化的目标文件；
- 对重要结果保存 Evidence 或 analysis snapshot。

## 相关文档

- [完整安装与 setup 参考](installation.md)
- [REA + Ghidra Windows 配置与排错](rea-windows-ghidra-setup.md)
- [Windows Ghidra P0 的正式边界](windows-ghidra-p0.md)
- [CLI 参考](cli.md)
- [MCP contracts](mcp-contracts.md)
