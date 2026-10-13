# 使用 REA + Ghidra 分析 Python .pyd 文件实战指南

> 日期：2026-10-13
> 工具：REA 6.4.0 + Ghidra 12.1.4
> 目标：Cython 编译的 ComfyUI 自定义节点

---

## 背景

本文档记录使用 REA (Reverse Engineer Anything) 配合 Ghidra 分析 Windows Python `.pyd` 文件的完整流程。`.pyd` 文件本质上是 Cython 或其他工具将 Python 扩展编译成的 Windows DLL，无法直接反编译回原始 Python 源码，但可以通过逆向工程理解其功能逻辑。

---

## 第一部分：环境配置

### 问题描述

初次安装 REA 后执行 `rea inspect --provider ghidra` 报错：

```
Ghidra exited before bridge startup
系统找不到指定的路径: \nodejs\node_modules\rea-agents\bridge\ghidra
```

### 根本原因

| 因素         | 说明                                         |
| ------------ | -------------------------------------------- |
| REA 安装位置 | 默认安装到 `D:\Program Files (x86)\nodejs\`  |
| 路径含空格   | `(x86)` 包含空格，导致 Java 文件路径解析失败 |
| Java 版本    | Ghidra 12.1.x 需要 JDK 21+                   |

### 解决方案

将 REA 安装到**无空格路径**：

```powershell
# 1. 卸载旧版本（可选）
npm uninstall -g rea-agents

# 2. 安装到无空格路径
npm install -g rea-agents --prefix D:\npm-global

# 3. 设置环境变量
$env:JAVA_HOME = "D:\Java\openjdk-23.0.2"
$env:GHIDRA_INSTALL_DIR = "D:\dev_tools\ghidra"

# 4. 验证环境
D:\npm-global\rea.cmd doctor --json
```

### 验证成功的标志

```json
{
  "name": "ghidra-java",
  "ok": true,
  "classification": "healthy",
  "detail": "23.0.2; 64-bit; JDK; D:\\Java\\openjdk-23.0.2"
}
```

---

## 第二部分：分析流程

### 典型分析步骤

```
┌─────────────────────────────────────────────────────────┐
│  Step 1: 获取概览                                        │
│  rea inspect target.pyd --provider ghidra               │
│  → 了解文件结构、函数数量、字符串数量                      │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  Step 2: 定位入口点                                      │
│  rea search target.pyd "PyInit_" --provider ghidra      │
│  → 找到 Python 模块初始化函数                             │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  Step 3: 搜索关键字符串                                  │
│  rea search target.pyd "类名\|函数名" --provider ghidra  │
│  → 定位感兴趣的函数和类                                   │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  Step 4: 追踪调用关系                                    │
│  rea trace target.pyd "函数名" --provider ghidra        │
│  → 找到引用该字符串的函数地址                              │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│  Step 5: 反编译函数                                      │
│  rea decompile target.pyd "函数地址" --provider ghidra  │
│  → 获取伪代码，理解实现逻辑                               │
└─────────────────────────────────────────────────────────┘
```

---

## 第三部分：实战案例

### 目标文件

`TE_Prompt_Text.pyd` — ComfyUI 自定义节点，用于处理文本和引用标签。

### Step 1: 获取概览

```powershell
$env:JAVA_HOME = "D:\Java\openjdk-23.0.2"
$env:GHIDRA_INSTALL_DIR = "D:\dev_tools\ghidra"

D:\npm-global\rea.cmd inspect "J:\path\to\TE_Prompt_Text.pyd" --provider ghidra --json
```

**输出关键信息**：

| 指标       | 数值                    |
| ---------- | ----------------------- |
| 文件格式   | PE (x86_64 DLL)         |
| 入口函数   | `PyInit_TE_Prompt_Text` |
| 函数总数   | 301                     |
| 字符串总数 | 411                     |
| 代码段大小 | 44544 bytes             |

### Step 2: 搜索入口点

```powershell
D:\npm-global\rea.cmd search "J:\path\to\TE_Prompt_Text.pyd" "PyInit_" --provider ghidra --json
```

**发现**：

```
PyInit_TE_Prompt_Text @ 0x18000f855
```

### Step 3: 反编译入口函数

```powershell
D:\npm-global\rea.cmd decompile "J:\path\to\TE_Prompt_Text.pyd" "PyInit_TE_Prompt_Text" --provider ghidra --json
```

**伪代码**：

```c
void PyInit_TE_Prompt_Text(void)
{
  PyModuleDef_Init(&DAT_180011af0);
  return;
}
```

这是标准的 Python 扩展模块初始化代码，调用 `PyModuleDef_Init` 注册模块定义。

### Step 4: 搜索关键字符串

```powershell
D:\npm-global\rea.cmd search "J:\path\to\TE_Prompt_Text.pyd" "build_text" --provider ghidra --json
```

**发现多个引用地址**：

```
0x18000c848: "build_text"
0x18000c860: "custom_nodes.TE_image.TE_Prompt_Text.TEPromptTextNode.build_text"
0x18000e420: "TEPromptTextNode.build_text"
0x18000e488: "build_text"
```

### Step 5: 追踪调用关系

```powershell
D:\npm-global\rea.cmd trace "J:\path\to\TE_Prompt_Text.pyd" "build_text" --provider ghidra --json
```

**关键发现**：

- `build_text` 被函数 `FUN_1800032b0` 引用（多处）
- `build_text` 被函数 `FUN_1800036c0` 引用

### Step 6: 反编译核心函数

**包装函数 (FUN_1800032b0)**：

- 地址范围：`0x1800032b0 - 0x1800036b4`
- 大小：1029 bytes
- 功能：参数解析、类型检查、错误处理

**实现函数 (FUN_1800036c0)**：

- 地址范围：`0x1800036c0 - 0x1800038e7`
- 大小：552 bytes
- 功能：核心逻辑实现

---

## 第四部分：逆向还原

### 原始伪代码分析

从 `FUN_1800036c0` 的反编译结果，关键逻辑如下：

```c
// 参数解析
param_3 = text
param_4 = reference_labels (可选)

// 布尔值检查
if (text is None or text is False):
    return ""

// 字符串转换
if (text 不是 Unicode 类型):
    text = PyObject_Str(text)

// 创建字典
result_dict = PyDict_New()

// 如果提供了 reference_labels
if (reference_labels):
    if (reference_labels 不是 Unicode):
        reference_labels = PyObject_Str(reference_labels)

    // 将 reference_labels 添加到字典，键为 "reference_labels"
    PyDict_SetItem(result_dict, "reference_labels", reference_labels)

    // 返回元组 (text, result_dict)
    return (text, result_dict)

// 否则直接返回文本
return text
```

### 还原的 Python 等价代码

```python
def build_text(self, text, reference_labels=None):
    """
    构建带引用标签的文本

    Parameters:
        self: ComfyUI 节点实例
        text: 输入文本（必需）
        reference_labels: 引用标签（可选）

    Returns:
        - 有 reference_labels: (text, {"reference_labels": reference_labels})
        - 无 reference_labels: text
        - text 为 None/False: ""
    """
    # 处理 None/False
    if not text:
        return ""

    # 确保 text 是字符串
    if not isinstance(text, str):
        text = str(text)

    # 如果提供了 reference_labels
    if reference_labels:
        if not isinstance(reference_labels, str):
            reference_labels = str(reference_labels)

        # 返回元组格式
        return (text, {"reference_labels": reference_labels})

    return text
```

---

## 第五部分：Cython .pyd 特征识别

### 编译特征

| 特征               | 说明                      |
| ------------------ | ------------------------- |
| `__pyx_*`          | Cython 生成的内部函数前缀 |
| `__Pyx_*`          | Cython 辅助函数           |
| `PyInit_*`         | Python 模块初始化入口     |
| `PyMethodDef`      | Python 方法定义表         |
| `PyModuleDef_Init` | 模块定义结构初始化        |

### 字符串特征

| 字符串                    | 含义                     |
| ------------------------- | ------------------------ |
| `custom_nodes.xxx.xxx`    | Python 模块路径          |
| `source_py_backup/xxx.py` | 源代码路径（编译时泄露） |
| `/te_xxx/view_reference`  | API 路由                 |

### 函数命名模式

| 模式                    | 用途            |
| ----------------------- | --------------- |
| `__pyx_pw_*`            | Python 包装函数 |
| `__pyx_pf_*`            | Python 函数实现 |
| `__pyx_scope_struct__*` | 闭包结构体      |

---

## 第六部分：实用 REA 命令参考

### 基础命令

```powershell
# 概览
rea inspect <file> --provider ghidra --json

# 搜索字符串
rea search <file> "<pattern>" --provider ghidra --json

# 反编译函数
rea decompile <file> "<function_name|address>" --provider ghidra --json

# 获取函数详情
rea function <file> "<function_name|address>" --provider ghidra --json
```

### 进阶命令

```powershell
# 追踪引用
rea trace <file> "<pattern>" --provider ghidra --json

# 查看交叉引用
rea xrefs <file> --address <address> --provider ghidra --json

# 读取字节
rea read-bytes <file> --address <address> --count <n> --provider ghidra --json

# 查看调用图
rea get-call-graph <file> --provider ghidra --json
```

### 常用搜索模式

| 模式          | 用途               |
| ------------- | ------------------ |
| `PyInit_`     | Python 入口点      |
| `PyExc_*`     | Python 异常类型    |
| `PyUnicode_*` | Unicode 字符串操作 |
| `PyDict_*`    | 字典操作           |
| `PyTuple_*`   | 元组操作           |
| `class_name`  | 特定类             |
| `method_name` | 特定方法           |

---

## 第七部分：分析成果总结

### 发现的信息

| 类别         | 详情                                                     |
| ------------ | -------------------------------------------------------- |
| **模块信息** | `TE_Prompt_Text`, `custom_nodes.TE_image.TE_Prompt_Text` |
| **显示名称** | `Prompt TEXT`                                            |
| **入口点**   | `PyInit_TE_Prompt_Text @ 0x18000f855`                    |
| **核心函数** | `TEPromptTextNode.build_text()`                          |
| **API 端点** | `/te_prompt_text/view_reference`                         |
| **编译工具** | Cython                                                   |

### 函数签名还原

```python
class TEPromptTextNode:
    @staticmethod
    def INPUT_TYPES():
        """ComfyUI 节点输入类型定义"""
        ...

    @staticmethod
    def build_text(text: str, reference_labels: str = None) -> str | tuple:
        """
        构建带引用标签的文本

        Args:
            text: 输入文本
            reference_labels: 可选的引用标签

        Returns:
            str: 如果没有 reference_labels
            tuple: (text, {"reference_labels": labels}) 如果有 reference_labels
        """
```

### 功能解读

```
输入:
  text = "Hello World"
  reference_labels = "[1,2,3]"

输出:
  ("Hello World", {"reference_labels": "[1,2,3]"})

用途:
  ComfyUI 使用元组格式来传递带有标签的文本，
  便于前端渲染和交互。
```

---

## 第八部分：局限性说明

| 限制                        | 说明                             |
| --------------------------- | -------------------------------- |
| ❌ 无法还原原始 Python 源码 | Cython 编译后丢失高级语法        |
| ❌ 无法还原变量名           | 除非保留了调试符号               |
| ⚠️ 符号可能被 strip         | 需要通过字符串和结构推断         |
| ⚠️ 内联优化                 | 小函数可能被编译器内联           |
| ⚠️ 类型推断                 | Python 对象在 C 层面类型信息丢失 |

### 可观察和可推断的信息

| 信息类型       | 能力边界                                                   |
| -------------- | ---------------------------------------------------------- |
| 模块初始化符号 | 可观察 `PyInit_*` 符号；缺失时不能证明文件不是 Python 扩展 |
| 限定名称       | 可保留字符串候选；不能仅凭字符串证明类、方法或导出关系     |
| 函数签名       | 仅在符号、包装器和调用点证据充分时可部分推断               |
| 参数类型       | CPython API 可提供局部类型提示，不等同于原始类型声明       |
| 返回值逻辑     | 可从选定函数伪代码推断部分路径，需保留反编译器局限         |
| 核心算法       | 简单控制流通常可理解；优化、内联和间接调用可能保持未知     |
| 变量命名       | 除非符号或字符串保留，否则通常无法恢复                     |
| 注释           | 无法从编译产物恢复                                         |

所有推断都应绑定到具体地址、符号、字符串或伪代码证据，并与观察事实分开报告。

---

## 附录：配置脚本

### 快速启动脚本 (rea-pyd.ps1)

```powershell
# REA + Ghidra 环境配置
$env:JAVA_HOME = "D:\Java\openjdk-23.0.2"
$env:GHIDRA_INSTALL_DIR = "D:\dev_tools\ghidra"
$env:PATH = "D:\npm-global;$env:PATH"

# 定义分析函数
function Analyze-Pyd {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$false)]
        [string]$SearchPattern = ""
    )

    Write-Host "=== REA + Ghidra Analysis ===" -ForegroundColor Cyan
    Write-Host "Target: $FilePath" -ForegroundColor White

    if ($SearchPattern) {
        Write-Host "`nSearching for: $SearchPattern" -ForegroundColor Yellow
        D:\npm-global\rea.cmd search $FilePath $SearchPattern --provider ghidra --json
    }
}

# 使用示例
# Analyze-Pyd -FilePath "J:\path\to\target.pyd" -SearchPattern "PyInit_"
```

### 环境变量持久化

```powershell
# 添加到 PowerShell 配置文件
$profilePath = $PROFILE
$envContent = @'
$env:JAVA_HOME = "D:\Java\openjdk-23.0.2"
$env:GHIDRA_INSTALL_DIR = "D:\dev_tools\ghidra"
$env:PATH = "D:\npm-global;$env:PATH"
'@

Add-Content -Path $profilePath -Value $envContent
```

---

## 参考链接

- [REA 官方文档](https://rea.tools/)
- [REA Windows Ghidra 配置](./windows-ghidra-p0.md)
- [Ghidra 下载](https://github.com/NationalSecurityAgency/ghidra/releases)
- [Cython 官方文档](https://cython.readthedocs.io/)

---

## 结语

通过 REA + Ghidra 的组合，我们成功分析了 Cython 编译的 `.pyd` 文件：

1. **环境配置** — 解决了空格路径和 Java 版本问题
2. **流程建立** — 确立了 6 步分析流程
3. **逆向还原** — 从伪代码还原了函数签名和逻辑
4. **文档沉淀** — 形成了可复用的分析方法

虽然无法 100% 还原原始源码，但通过逆向工程，我们可以：

- 理解模块结构和功能
- 还原函数签名和参数类型
- 分析核心算法的逻辑
- 理解与其他系统的交互方式

这对于学习闭源库的工作原理、编写兼容替代品、或进行安全审计都非常有价值。
