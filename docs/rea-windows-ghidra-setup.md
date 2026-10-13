# REA + Ghidra Windows 配置指南

## 问题描述

在 Windows 环境下安装 REA 后，执行 `rea inspect --provider ghidra` 报错：

```
Ghidra exited before bridge startup
系统找不到指定的路径: \nodejs\node_modules\rea-agents\bridge\ghidra
```

## 根本原因

REA 默认全局安装到 Node.js 目录：

```
D:\Program Files (x86)\nodejs\
```

路径中包含空格 `(x86)`，且 REA 内部使用相对路径 `../../bridge/ghidra/` 来定位 Java bridge 源文件。当 Node.js 或 Java 解析这些包含空格的路径时，可能出现参数解析错误，导致 Ghidra headless 启动失败。

## 解决方案

将 REA 安装到**无空格路径**，例如 `D:\npm-global`。

### 步骤 1：卸载旧的 REA（可选）

```powershell
npm uninstall -g rea-agents
```

### 步骤 2：安装到无空格路径

```powershell
npm install -g rea-agents --prefix D:\npm-global
```

### 步骤 3：配置环境变量

必须设置两个环境变量：

```powershell
$env:JAVA_HOME = "D:\Java\openjdk-23.0.2"
$env:GHIDRA_INSTALL_DIR = "D:\dev_tools\ghidra"
```

> **注意**：`JAVA_HOME` 必须指向 **JDK 21+**（完整 JDK，不只是 JRE）。Ghidra 12.1.x 需要 JDK 21 或更高版本。

### 步骤 4：验证环境

```powershell
rea doctor --json
```

检查输出中 `ghidra-java` 项是否为 `healthy`：

```json
{
  "name": "ghidra-java",
  "ok": true,
  "classification": "healthy",
  "detail": "23.0.2; 64-bit; JDK; D:\\Java\\openjdk-23.0.2"
}
```

### 步骤 5：运行 REA 分析

```powershell
$env:JAVA_HOME = "D:\Java\openjdk-23.0.2"
$env:GHIDRA_INSTALL_DIR = "D:\dev_tools\ghidra"
D:\npm-global\rea.cmd inspect "C:\path\to\target.pyd" --provider ghidra --json
```

## 完整 PowerShell 配置脚本

建议将以下内容保存为 `rea-ghidra.ps1`：

```powershell
# REA + Ghidra 环境配置
$env:JAVA_HOME = "D:\Java\openjdk-23.0.2"
$env:GHIDRA_INSTALL_DIR = "D:\dev_tools\ghidra"
$env:PATH = "D:\npm-global;$env:PATH"

# 验证环境
Write-Host "Environment Check:" -ForegroundColor Cyan
rea doctor --json | ConvertFrom-Json | Select-Object -ExpandProperty scope_checks |
    Where-Object { $_.name -like "ghidra*" } | Format-Table name, ok, detail

# 示例分析命令
Write-Host "`nExample Usage:" -ForegroundColor Cyan
Write-Host 'rea inspect "C:\path\to\target.pyd" --provider ghidra --json'
Write-Host 'rea search "C:\path\to\target.pyd" "PyInit_" --provider ghidra --json'
Write-Host 'rea decompile "C:\path\to\target.pyd" "function_name" --provider ghidra --json'
```

## 环境要求总结

| 组件             | 要求                          | 说明                             |
| ---------------- | ----------------------------- | -------------------------------- |
| **Node.js**      | >= 22.19 或 >= 24.11 或 >= 26 | REA 运行平台                     |
| **Java**         | JDK 21+ (64-bit)              | 必须设置 `JAVA_HOME`，不能用 JRE |
| **Ghidra**       | 12.1.x                        | 设置 `GHIDRA_INSTALL_DIR`        |
| **REA 安装路径** | 无空格路径                    | 如 `D:\npm-global`               |
| **目标文件**     | 本地 NTFS 路径                | 不支持 UNC、WSL 等               |

## 故障排除

### 错误 1：Java 版本不支持

```
java: 1.8.0_252; 64-bit; runtime only
accepted: 64-bit full JDK 21 or newer
```

**解决**：安装 JDK 21+ 并设置 `JAVA_HOME`

### 错误 2：Ghidra 未配置

```
reason: Set GHIDRA_INSTALL_DIR to an extracted Ghidra 12.1.x release directory
```

**解决**：下载 Ghidra 12.1.4，解压到任意目录，设置 `GHIDRA_INSTALL_DIR`

### 错误 3：Ghidra 启动后崩溃

```
failure_message: Ghidra exited before bridge startup
stderr: 系统找不到指定的路径: \nodejs\node_modules\rea-agents\bridge\ghidra
```

**解决**：将 REA 安装到无空格路径（如 `D:\npm-global`）

## 验证测试

成功后会看到类似输出：

```json
{
  "subject": {
    "name": "J:\\path\\to\\TE_Prompt_Text.pyd",
    "digest": { "sha256": "f6fa9076c33b7ea4..." },
    "format": "pe",
    "architecture": "x86_64"
  },
  "normalized_result": {
    "document": "target-f6fa9076c33b.pyd",
    "procedure_count": 301,
    "string_count": 411
  }
}
```

## 相关文档

- [Windows Ghidra P0 官方文档](./windows-ghidra-p0.md)
- [REA 安装指南](./installation.md)
- [Native 分析文档](./native-investigation.md)
