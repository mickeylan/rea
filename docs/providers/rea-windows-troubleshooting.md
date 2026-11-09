# Windows REA/Ghidra 故障排除

> 适用版本：`rea-agents` 6.5.0；更新日期：2026-10-16。
>
> 安装步骤见 [Windows 安装与配置 REA](rea-windows-installation.md)；Ghidra 配置见 [Windows 配置 REA + Ghidra](rea-windows-ghidra-setup.md)。本文按可观察错误和 provider classification 排查，不把一次历史修复经验当成通用根因。

## 1. 先收集最小诊断包

在同一个 PowerShell 会话中运行：

```powershell
$ErrorActionPreference = "Continue"

node --version
npm --version
rea --version
Get-Command node
Get-Command rea

$env:JAVA_HOME
$env:GHIDRA_INSTALL_DIR
Test-Path "$env:JAVA_HOME\bin\java.exe"
Test-Path "$env:JAVA_HOME\bin\javac.exe"
Test-Path "$env:GHIDRA_INSTALL_DIR\support\analyzeHeadless.bat"

rea doctor --provider ghidra --json |
  Tee-Object -FilePath .\rea-ghidra-doctor.json
rea providers --json |
  Tee-Object -FilePath .\rea-providers.json
```

不要在诊断包中包含 API key、token、密码、私钥或敏感目标内容。REA 会对 transport authentication credential 做脱敏，但用户自己的 shell 输出仍需检查。

记录失败命令的退出码：

```powershell
rea analyze "C:\targets\sample.exe" --provider ghidra --json
$LASTEXITCODE
```

## 2. 先判断错误属于哪一层

| 层                      | 典型症状                                  | 首要检查                                                 |
| ----------------------- | ----------------------------------------- | -------------------------------------------------------- |
| CLI discovery           | `rea` 找不到                              | npm prefix、`PATH`、`Get-Command rea`                    |
| Node runtime            | engine/version 错误                       | `node --version`、实际 node 路径                         |
| Ghidra discovery        | installation invalid                      | `GHIDRA_INSTALL_DIR`、release layout                     |
| Java                    | JRE、位数或版本错误                       | `JAVA_HOME`、`java`、`javac`、`jdk.compiler`             |
| Windows native controls | `runtime_missing` / `runtime_unavailable` | package version、native artifact、NTFS、DACL、Job Object |
| Target admission        | `unsupported_target`                      | format、architecture、managed、path/filesystem           |
| Provider startup        | bridge 启动前退出或超时                   | headless launcher、Java、路径、logs、timeout             |
| Provider output         | `unreadable_output`                       | provider output schema、profile consistency              |
| MCP/client              | shell 可用，Agent 不可用                  | 客户端配置、绝对路径、env、重启                          |
| Snapshot                | replay miss 或 stale                      | target identity、profile digest、workflow revision       |

## 3. `rea` 命令找不到

症状：

```text
rea : The term 'rea' is not recognized
```

检查：

```powershell
npm config get prefix
npm root --global
Get-Command rea -ErrorAction SilentlyContinue
Get-ChildItem "$(npm config get prefix)" -Filter "rea*"
```

临时运行：

```powershell
npx -y rea-agents@latest --version
```

如果使用独立 prefix：

```powershell
npm install --global rea-agents@6.5.0 --prefix D:\npm-global
D:\npm-global\rea.cmd --version
$env:PATH = "D:\npm-global;$env:PATH"
```

不要以管理员权限反复安装来掩盖 prefix ownership 或 `PATH` 问题。

## 4. Node.js 版本不兼容

REA 6.5.0 支持：

```text
^22.19.0 || ^24.11.0 || >=26.0.0
```

检查所有候选：

```powershell
Get-Command node -All
node --version
```

常见情况是新版本已安装，但旧目录在 `PATH` 更靠前。调整后重新启动终端和 GUI 客户端。

## 5. `GHIDRA_INSTALL_DIR` 无效

症状可能包括：

```text
Set GHIDRA_INSTALL_DIR to an extracted Ghidra 12.1.x release directory
```

检查：

```powershell
$g = $env:GHIDRA_INSTALL_DIR
Test-Path $g
Test-Path "$g\Ghidra\application.properties"
Test-Path "$g\support\analyzeHeadless.bat"
Get-Content "$g\Ghidra\application.properties" |
  Select-String 'application.version|application.java'
```

常见原因：

- 指向 archive 而不是解压目录；
- 指向外层目录，真正 release 又嵌套一层；
- 指向 `support` 或 launcher 文件；
- 明确环境变量指向旧目录，阻止了 `PATH` discovery fallback；
- Ghidra release 不属于 12.1.x。

显式设置的无效 `GHIDRA_INSTALL_DIR` 优先级高于 discovery；REA 会报告错误而不是静默换一个安装。

## 6. Java 是 JRE、版本过旧或架构不匹配

症状示例：

```text
runtime only
accepted: 64-bit full JDK 21 or newer
```

检查：

```powershell
$j = $env:JAVA_HOME
Test-Path "$j\bin\java.exe"
Test-Path "$j\bin\javac.exe"
& "$j\bin\java.exe" -version
& "$j\bin\javac.exe" -version
& "$j\bin\java.exe" --list-modules | Select-String '^jdk.compiler@'
```

修复原则：

- 使用完整 64 位 JDK；
- 当前 Ghidra 12.1 releases 使用 JDK 21+；
- `JAVA_HOME` 指向 JDK 根目录，不是 `bin`；
- JVM 报告的 OS/architecture 必须和 Windows host/decompiler 一致；
- 移除会伪造 `os.name`、`os.arch` 或破坏启动的 Java helper options。

修改后：

```powershell
rea doctor --provider ghidra --json
```

## 7. `runtime_missing`：Windows native artifact 缺失或不匹配

Windows Ghidra P0 依赖与 REA package 匹配的 Windows x64 native addon。npm release 应自带该 artifact，不需要用户手工编译。

检查：

```powershell
rea --version
rea doctor --provider ghidra --json
npm root --global
```

常见原因：

- package 安装不完整；
- 复制了 JS 文件但遗漏 native artifact/manifest；
- artifact 属于另一个 REA version、Node-API 或 PE machine；
- antivirus/quarantine 删除或拦截文件；
- 使用了不完整的源码 build output。

处理：

1. 确认从官方 npm package 或仓库获取；
2. 重新安装同一明确版本；
3. 不要从另一台机器或旧版本拷贝 `.node` 文件；
4. 重新运行 scoped doctor。

改变 MCP 配置、重装 Ghidra或重装 Java不能补齐缺失的 REA native artifact。

源码开发环境可运行仓库自己的 artifact verifier；普通 npm 用户不需要这样做。

## 8. `runtime_unavailable`：native self-test 或调用失败

这表示 artifact 可能存在，但 native operation/self-test 失败。doctor 会保留 `windows_native_failure` stage 和 remediation。

重点检查：

- 目标和临时目录是否位于固定本地 NTFS；
- 当前用户是否可以创建、读写和删除临时文件；
- DACL readback 是否成功；
- Job Object ownership 是否可用；
- endpoint/private descriptor 是否能创建；
- security software 是否阻止 addon 或 child process；
- 原始 OS error code 和 operation。

不要先重装 Java/Ghidra；它们通常不能修复 native self-test failure。

## 9. `unsupported_host`

此错误不是所有问题的总称。它应表示 host/platform 边界确实不受支持，例如：

- 非 Windows 10+ x64；
- 不支持的 host architecture；
- 需要仅 Linux/macOS 支持的 operation。

如果 Windows x64 上缺的是 native artifact，合理分类应更接近 `runtime_missing`；如果 native invocation 失败，应更接近 `runtime_unavailable`。记录 doctor 的实际 classification 和 failure stage，不要只截取顶层一句文本。

## 10. `unsupported_target`

Windows P0 主要接受本地 NTFS 上的原生 x86/x86-64 PE EXE/DLL。常见拒绝原因：

- managed PE/CLI；
- 不支持的 CPU architecture；
- 文件不是 PE，或 header malformed；
- UNC path；
- WSL/Linux path；
- 网络盘、非 NTFS 卷；
- alternate data stream；
- reparse point、junction、符号链接或其他无法证明身份的路径；
- target 在分析过程中改变；
- `.pyd` 专用 workflow 收到 `.dll` 或其他扩展名。

基础检查：

```powershell
Get-Item "C:\targets\sample.exe" | Format-List FullName,Length,Attributes,LinkType
Get-Volume -DriveLetter C | Format-List DriveLetter,FileSystem,DriveType
Get-FileHash "C:\targets\sample.exe" -Algorithm SHA256
```

不要通过复制到不受信任位置来规避 identity 检查。可复制到自己控制的固定本地 NTFS 目录，然后重新计算 digest 并记录这是另一个文件 coordinate。

## 11. Ghidra bridge 启动前退出

症状：

```text
Ghidra exited before bridge startup
```

这只是 startup-stage 结果，不单独证明根因。需要查看 retained stderr、选择的 executable 和 arguments。

依次检查：

```powershell
rea doctor --provider ghidra --json
Test-Path "$env:GHIDRA_INSTALL_DIR\support\analyzeHeadless.bat"
& "$env:JAVA_HOME\bin\java.exe" -version
& "$env:JAVA_HOME\bin\javac.exe" -version
```

历史上，某些旧路径组合或 wrapper 可能把包含空格的路径错误拆分，例如：

```text
D:\Program Files (x86)\nodejs\...
```

当前 REA Windows launcher 使用绝对 `cmd.exe`、固定 switches 和 quoted tokens；含空格路径本身不应被视为已证明根因。如果换到 `D:\npm-global` 后恢复，应同时比较：

- 旧/新 `node.exe`；
- REA package version；
- entry point；
- bridge path；
- MCP config；
- actual stderr。

排错时可以临时使用短路径减少外部客户端转义变量，但报告中应将结论写成“该配置下恢复”，而不是“证明路径空格是根因”。

## 12. 启动超时

cold Ghidra import 和 default auto-analysis 可能超过客户端默认的几十秒超时。REA 的真实 provider lane允许更长 startup deadline，但 MCP client 可能先取消请求。

处理：

1. 先在终端执行同一目标的 CLI 命令；
2. 区分 client timeout 与 provider timeout；
3. 查看取消是否触发 session cleanup；
4. 使用更小 fixture 做 smoke test；
5. 调整客户端 request timeout，而不是修改 Ghidra analysis 结果。

不要因为一次超时就假定 provider 不支持目标。

## 13. 终端可运行，MCP 客户端不可运行

这是最常见的配置分歧之一。

检查：

- 客户端是否完全重启；
- MCP config 实际位置；
- registration 中的 `command` 和 `args` 是否为绝对路径；
- GUI 是否继承 `JAVA_HOME` 和 `GHIDRA_INSTALL_DIR`；
- registration 是否显式带 `env`；
- 客户端是否仍引用旧全局 npm prefix；
- 同名 `rea` server 是否重复注册。

建议：

```powershell
rea setup --client claude_code --dry-run
rea doctor --client claude_code --json
claude mcp list
```

客户端名称按实际使用者替换。

## 14. MCP 返回 `unreadable_output`

这表示 provider output 无法安全转换为公开 contract，或组合 workflow 的输入证据不一致。例如：

- primitive 输出 schema malformed；
- `list_names` 与 `list_strings` 来自不同 analysis profile；
- active target identity 丢失；
- snapshot/output 与当前 contract 不兼容。

REA 对 Cython `.pyd` workflow 会：

- malformed `list_names` 后立即停止，不再请求 `list_strings`；
- profile mismatch 时拒绝生成混合 Evidence；
- 无 active target 时在 provider primitive 前失败。

不要把 typed failure 转换为空列表或“未发现”。保留完整错误 projection 和 operation。

## 15. Snapshot 没有 replay

Snapshot replay key 会受到目标身份、operation、参数和 analysis profile 等因素影响。以下变化可能合理导致 miss：

- target digest 或 canonical identity 改变；
- provider/version/profile 改变；
- workflow revision 改变；
- operation 参数改变；
- snapshot 不包含该 Evidence；
- snapshot malformed 或不适用于当前 target。

检查 snapshot path 是否由同一 CLI/MCP workflow 使用。不要为了强制命中而删除 identity/profile 检查。

## 16. 临时目录或 cleanup 错误

REA 只有在 ownership 可证明时才删除资源。cleanup 失败时保留资源比删除未知归属文件更安全。

收集：

- session close error；
- retained path；
- process ownership diagnostics；
- Job Object state；
- antivirus/file-lock 情况；
- 是否仍有 Ghidra/Java child process。

不要在尚有 owner process 活动时递归删除 private runtime。先关闭 session/client，再按报告路径处理。

## 17. 输出为空是否表示目标中不存在

不一定。

例如 `list_strings` 只报告 Ghidra-defined String Data。packed、加密、动态构造或未被定义的数据可能缺失。空 inventory 只说明在当前 provider/profile/coverage 下没有观察到，不证明目标中绝对不存在。

同样：

- 没有 Cython marker 不证明不是 Cython；
- qualified name string 不证明恢复了 Python 类/函数；
- native ABI signature 不等于 Python 调用约定；
- successful decompilation 不等于恢复原始源码。

## 18. `.pyd` 专项检查

使用：

```powershell
rea inspect-cython-extension `
  "C:\targets\module.pyd" `
  --provider ghidra `
  --format json
```

如果拒绝：

1. 文件扩展名必须是 `.pyd`；
2. PE role 必须是 shared-library；
3. 必须是 unmanaged native PE；
4. architecture 必须在 Windows P0 范围内；
5. 路径必须通过 native admission。

该命令不会 import/execute `.pyd`。如果目标 import 会触发副作用，不要用 Python 验证它；应继续静态分析。

## 19. 如何写有效 issue

附上：

- observed result；
- 最小命令；
- exit code；
- `rea --version`、Node/Ghidra/JDK version；
- scoped doctor JSON（脱敏）；
- provider classification 和 failure stage；
- target format/architecture/digest（允许披露时）；
- 是否 CLI 和 MCP 都复现；
- 未进行的验证和 Unknown。

不要声称执行过未执行的 runtime reproduction。缺少叙述或证据时明确写 `NOT_ENOUGH_INFO` 及原因。

## 20. 快速决策树

```text
rea 找不到？
  └─ 检查 npm prefix / PATH / Get-Command

rea 能启动但 doctor 报 Ghidra 无效？
  └─ 检查 GHIDRA_INSTALL_DIR 和 release layout

Java 不健康？
  └─ 检查完整 64 位 JDK、javac、jdk.compiler、版本范围

runtime_missing？
  └─ 检查匹配的 REA Windows native artifact/package

runtime_unavailable？
  └─ 检查 native self-test、NTFS、DACL、Job Object、security software

unsupported_target？
  └─ 检查 PE/architecture/managed/path/filesystem/identity

CLI 成功但 MCP 失败？
  └─ 检查客户端实际 config、绝对路径、env 和重启

unreadable_output？
  └─ 保留 typed error；检查 schema/profile/active target/snapshot
```

## 相关文档

- [Windows 安装与配置 REA](rea-windows-installation.md)
- [Windows 配置 REA + Ghidra](rea-windows-ghidra-setup.md)
- [Windows Ghidra P0 正式边界](windows-ghidra-p0.md)
- [完整安装参考](installation.md)
- [Issue reporting guidance](../CONTRIBUTING.md#reporting-issues)
