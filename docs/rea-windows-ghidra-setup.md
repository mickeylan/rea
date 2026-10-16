# Windows 配置 REA + Ghidra

> 适用版本：`rea-agents` 6.5.0、Ghidra 12.1.x；更新日期：2026-10-16。
>
> 本文假设 REA 已安装。REA 本身的安装、Agent/MCP 注册和升级见 [Windows 安装与配置 REA](rea-windows-installation.md)；错误索引和逐项处理见 [Windows REA/Ghidra 故障排除](rea-windows-troubleshooting.md)。正式支持边界以 [Windows Ghidra P0](windows-ghidra-p0.md) 为准。

## 1. 先理解 Windows Ghidra 边界

REA 的 Windows Ghidra provider 是实验性的只读 P0 边界。当前主要接受：

- Windows 10 或更高版本，x64 主机；
- 固定本地 NTFS 卷上的目标和临时目录；
- 原生、非托管的 x86 或 x86-64 PE EXE/DLL；
- 显式配置的 raw NMOS 6502 image；
- Ghidra 12.1.x，已验证版本为 12.1.4；
- 与 Ghidra 要求一致的 64 位完整 JDK，当前 12.1 releases 要求 JDK 21+。

Windows P0 不代表所有 Ghidra 功能均可用。它不会控制 Ghidra GUI，不保存用户数据库，不修改原始可执行文件，也不授予数据库 annotation/mutation authority。

REA 不会安装或升级 Ghidra、Java、Node.js、npm 或 Python。Ghidra 和 JDK 必须由用户准备。

## 2. 安装 Ghidra

从 Ghidra 官方发布渠道下载 12.1.x archive，并解压到固定目录，例如：

```text
C:\tools\ghidra_12.1.4_PUBLIC
```

目录内应存在类似文件：

```text
support\analyzeHeadless.bat
Ghidra\application.properties
Ghidra\Features\Decompiler\os\win_x86_64\decompile.exe
```

验证：

```powershell
$ghidra = "C:\tools\ghidra_12.1.4_PUBLIC"
Test-Path "$ghidra\support\analyzeHeadless.bat"
Test-Path "$ghidra\Ghidra\application.properties"
Test-Path "$ghidra\Ghidra\Features\Decompiler\os\win_x86_64\decompile.exe"
```

三个结果都应为 `True`。如果目录层级多了一层，例如：

```text
C:\tools\ghidra_12.1.4_PUBLIC\ghidra_12.1.4_PUBLIC\support
```

则 `GHIDRA_INSTALL_DIR` 应指向真正包含 `support` 和 `Ghidra` 的内层目录。

不要把 `GHIDRA_INSTALL_DIR` 指向：

- `ghidraRun.bat` 文件本身；
- `support` 子目录；
- Ghidra project 目录；
- ZIP 文件；
- 名称正确但缺少完整 release 内容的目录。

## 3. 安装完整 JDK

Ghidra 12.1.x 当前需要 64 位完整 JDK 21 或更高版本。完整 JDK 必须同时包含：

```text
bin\java.exe
bin\javac.exe
```

例如：

```text
C:\tools\jdk-21
```

验证：

```powershell
$jdk = "C:\tools\jdk-21"
Test-Path "$jdk\bin\java.exe"
Test-Path "$jdk\bin\javac.exe"
& "$jdk\bin\java.exe" -version
& "$jdk\bin\javac.exe" -version
& "$jdk\bin\java.exe" --list-modules | Select-String '^jdk.compiler@'
```

如果只有 `java.exe`、没有 `javac.exe` 或 `jdk.compiler`，通常安装的是 JRE 或裁剪 runtime，不能编译 REA bridge。

不要把 `JAVA_HOME` 指向：

- `bin` 子目录；
- `java.exe` 文件；
- 32 位 JDK；
- 只含 JRE 的目录；
- 与 Windows 主机架构不匹配的 JVM。

## 4. 在当前 PowerShell 会话中配置

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\tools\ghidra_12.1.4_PUBLIC"
$env:JAVA_HOME = "C:\tools\jdk-21"
$env:REA_ANALYSIS_PROVIDER = "ghidra"
```

检查：

```powershell
$env:GHIDRA_INSTALL_DIR
$env:JAVA_HOME
Test-Path "$env:GHIDRA_INSTALL_DIR\support\analyzeHeadless.bat"
Test-Path "$env:JAVA_HOME\bin\javac.exe"
```

临时环境变量只对当前 PowerShell 及其子进程有效。已经打开的 GUI Agent/MCP client 不会自动获得这些值。

### 可选：保存为用户环境变量

确认路径无误后：

```powershell
[Environment]::SetEnvironmentVariable(
  "GHIDRA_INSTALL_DIR",
  "C:\tools\ghidra_12.1.4_PUBLIC",
  "User"
)
[Environment]::SetEnvironmentVariable(
  "JAVA_HOME",
  "C:\tools\jdk-21",
  "User"
)
[Environment]::SetEnvironmentVariable(
  "REA_ANALYSIS_PROVIDER",
  "ghidra",
  "User"
)
```

然后关闭并重新打开终端和 Agent。不要用空值覆盖机器级配置，修改前可先记录当前值。

## 5. 用 scoped doctor 验证

```powershell
rea doctor --provider ghidra --json
rea providers --json
```

建议把 JSON 保存下来：

```powershell
rea doctor --provider ghidra --json |
  Set-Content -Encoding utf8 .\rea-ghidra-doctor.json
```

重点检查：

- Ghidra release 是否为 12.1.x；
- `analyzeHeadless.bat` 是否存在；
- Java 是否为 64 位完整 JDK；
- Java major 是否在 Ghidra 声明范围内；
- decompiler binary 是否适配 Windows x64；
- Windows native control artifact 是否与 REA package 匹配；
- 临时目录和目标路径是否满足本地 NTFS、无 reparse/UNC/ADS 等约束。

总体 doctor 可能因无关 optional provider 或 Agent 配置而不健康。判断 Ghidra 时应使用 `--provider ghidra` 的 scoped result。

## 6. 第一次真实分析

先选择一个可再分发、非敏感、较小的原生 x64 PE 文件。示例：

```powershell
rea analyze "C:\targets\sample.exe" --provider ghidra --json
```

搜索字符串：

```powershell
rea search "C:\targets\sample.exe" "example" --provider ghidra --json
```

分析函数：

```powershell
rea function "C:\targets\sample.exe" 0x140001000 --provider ghidra --json
```

首次 cold import 可能较慢。不要因为客户端几十秒没有响应就立即认定失败；查看 REA/客户端超时和 provider diagnostic。

### 分析 `.pyd`

`.pyd` 是 Windows Python native extension，本质上通常是 PE DLL。REA 的公共保守检查命令：

```powershell
rea inspect-cython-extension `
  "C:\targets\module.pyd" `
  --provider ghidra `
  --format json
```

该工作流：

- 要求目标是原生、非托管 PE shared-library；
- 要求路径扩展名为 `.pyd`，不区分大小写；
- 在同一个 retained binary session 中读取 names 和 defined strings；
- 返回 Evidence、coverage 和 limitations；
- 不导入或执行 Python 模块；
- 不声称恢复原始源码、精确签名或完整控制流。

## 7. 配置 MCP 客户端

优先让 setup 生成并备份配置：

```powershell
rea setup --dry-run
rea setup
```

如果 Agent 从 GUI 启动，最可靠的方法是把 provider 环境显式写入其 MCP registration。示例：

```json
{
  "mcpServers": {
    "rea": {
      "command": "C:\\Program Files\\nodejs\\node.exe",
      "args": [
        "D:\\npm-global\\node_modules\\rea-agents\\scripts\\rea.mjs",
        "mcp"
      ],
      "env": {
        "REA_ANALYSIS_PROVIDER": "ghidra",
        "GHIDRA_INSTALL_DIR": "C:\\tools\\ghidra_12.1.4_PUBLIC",
        "JAVA_HOME": "C:\\tools\\jdk-21"
      }
    }
  }
}
```

路径仅为示例。实际 entry point 可用下面的命令定位：

```powershell
npm root --global
Get-Command node
Get-Command rea
```

修改配置后完全退出并重启客户端，再运行：

```powershell
rea doctor --client claude_code --json
```

如果客户端支持，检查 MCP server 状态或工具列表。

## 8. 安全和生命周期语义

在 Windows Ghidra P0 中：

1. REA 以 native handle 检查目标路径和文件身份；
2. 从已准入的 source handle 创建私有 immutable snapshot；
3. Ghidra 导入 snapshot 到临时 project；
4. bridge 只在默认 auto-analysis 完成后提供结果；
5. session close、取消或失败时清理临时 project 和私有运行目录；
6. 原始目标字节不会被修改；
7. Ghidra GUI 数据库不会被保存或关闭。

Windows transport 使用经过认证的 IPv4 loopback endpoint。bearer token 保留在私有 descriptor 中，并从诊断输出中删除。

如果 cleanup 失败，REA 应保留仍归属自身但未安全清理的资源，而不是假装清理成功。

## 9. 路径建议

当前启动逻辑对含空格路径使用引用和绝对路径；“路径有空格”本身不应被当成普遍根因。不过为了减少第三方 wrapper、旧 shell 或客户端转义问题，排错时可以临时使用短而明确的目录：

```text
C:\tools\ghidra_12.1.4_PUBLIC
C:\tools\jdk-21
D:\npm-global
C:\targets\sample.exe
```

不要把“换到无空格路径后恢复”直接等同于根因已证明。应保留原错误、实际解析出的 executable/argument、doctor classification 和 failure stage。

## 10. 可复现配置脚本

保存为 `rea-ghidra-env.ps1`：

```powershell
$ErrorActionPreference = "Stop"

$env:GHIDRA_INSTALL_DIR = "C:\tools\ghidra_12.1.4_PUBLIC"
$env:JAVA_HOME = "C:\tools\jdk-21"
$env:REA_ANALYSIS_PROVIDER = "ghidra"

if (-not (Test-Path "$env:GHIDRA_INSTALL_DIR\support\analyzeHeadless.bat")) {
  throw "Ghidra headless launcher not found"
}
if (-not (Test-Path "$env:JAVA_HOME\bin\java.exe")) {
  throw "java.exe not found"
}
if (-not (Test-Path "$env:JAVA_HOME\bin\javac.exe")) {
  throw "javac.exe not found; a full JDK is required"
}

rea --version
rea doctor --provider ghidra --json
rea providers --json
```

脚本不安装任何软件，也不写永久环境变量。

## 11. 下一步

如果 doctor 或分析命令失败，请按 [Windows REA/Ghidra 故障排除](rea-windows-troubleshooting.md) 中的错误分类处理，并记录：

- `rea --version`；
- `node --version`；
- Ghidra version；
- `java -version` 和 `javac -version`；
- `rea doctor --provider ghidra --json`；
- 完整命令、退出码和已脱敏错误文本；
- 目标格式、架构和 SHA-256（允许披露时）。

## 相关文档

- [Windows 安装与配置 REA](rea-windows-installation.md)
- [Windows REA/Ghidra 故障排除](rea-windows-troubleshooting.md)
- [Windows Ghidra P0 正式边界](windows-ghidra-p0.md)
- [Ghidra provider 语义](ghidra-provider.md)
- [Native binary investigation](native-investigation.md)
