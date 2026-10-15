# REA Cython .pyd 分析模块提案

> 提案日期：2026-10-13
> 状态：草稿
> 基于：TE_Prompt_Text.pyd 逆向分析经验

---

## 1. 概述

### 1.1 目标

为 REA 添加一个专门分析 Cython 编译的 Python `.pyd` 文件的模块，提供：

1. **自动识别** — 检测文件是否为 Cython .pyd
2. **入口点定位** — 找到 `PyInit_*` 模块初始化函数
3. **API 重建** — 提取和还原 Python 可调用的函数签名
4. **类结构分析** — 识别 Python 类及其方法
5. **流程追踪** — 追踪函数调用链，理解核心逻辑

### 1.2 设计原则

| 原则                  | 说明                                 |
| --------------------- | ------------------------------------ |
| **复用现有 Provider** | 利用 Ghidra 进行反编译，不重复造轮子 |
| **工作流封装**        | 将多步骤操作封装为单一命令           |
| **证据驱动**          | 返回分析结果时附带证据和置信度       |
| **渐进式分析**        | 支持从概览到深入的多层次分析         |

### 1.3 当前实现边界与通用化方向

当前已发布的公共入口是 CLI `inspect-cython-extension` 与 MCP `inspect_cython_extension`。它们复用活动 `BinarySession`，在同一 provider 会话中组合 `list_names` 和 `list_strings`，并返回带来源、analysis profile、locations、limitations 和取消语义的只读 Evidence。早期独立启动反编译器、直接调用 provider 内部实现或导入目标模块的方案均已废弃。

最终实现必须是通用 Cython `.pyd` 模块，而不是针对某个样本的脚本。`TE_Prompt_Text.pyd` 与 `TE_Qwen_Image_2_1_Prompt_Enhancer.pyd` 只承担复杂真实样本和回归证据的角色；其中的 ComfyUI、Qwen、模型路径和业务字段不会进入公共领域模型。通用层按以下阶段演进：

1. **有界 inventory**：确认 CPython 初始化器、Cython markers、候选限定名和源码路径。
2. **候选归属**：把 wrapper、implementation body、method table 和初始化对象建模为带置信度及来源地址的候选，而不是直接宣称已恢复 Python API。
3. **调用约定恢复**：解析 Cython wrapper 的位置参数范围、关键字顺序、必填/可选槽位及静态默认值；无法证明时保持 Unknown。
4. **返回路径摘要**：区分公共返回、辅助调用参数、异常传播和清理路径，并保留覆盖范围。
5. **按需深挖**：只对调用者选择的候选函数执行反编译、值流和调用图分析，避免把整份大型 inventory 放入上下文。

这些阶段应共享 CLI/MCP contracts、Evidence 与 snapshot 语义，并保持 provider-neutral。样本专用解释只能出现在分析报告或测试 fixture 中。

阶段 2–3 的领域边界已开始落地：`cythonWrapperConventionObservationSchema` 接收 adapter 归一化后的 wrapper 事实，`projectCythonCallingConventionCandidate` 将其投影为候选调用约定。位置参数上下界、关键字顺序、槽位名称、必填/可选状态和静态默认值分别保留 Known/Unknown；冲突观察不会被择一提升为事实。`CythonWrapperConventionPort` 与 `CythonWrapperConventionService` 已提供 application 层边界，验证 adapter 输出并保留 provider、analysis profile、limitations 和 locations。

`GhidraCythonWrapperConventionAdapter` 已接入现有结构化 `analyze_function` dossier。首个保守版本只投影 wrapper 身份、直接 callee 候选、call-site 来源地址和 value-flow 截断状态；它明确不读取 pseudocode 文本，也不会将任意 callee 宣称为 implementation body。

Ghidra bridge 的通用 high-p-code contract 现已进一步包含稳定的 `block_id`、每个 block 的起始地址、保留 operation IDs 和 successor IDs。TypeScript 边界严格检查 block/operation/successor 引用、唯一性与地址格式。该信息仍只是 decompiler CFG 事实，不表达 Cython 参数语义。

使用与 6.5.0 匹配且经 manifest/digest 验证的 Windows native controls 后，真实 Qwen `.pyd` 已成功返回该新 contract：`INPUT_TYPES` body 为 3,000 个保留 operations、330 个 blocks，`enhance_prompt` wrapper 为 3,000 个保留 operations、140 个 blocks；两者均无 null block identity 或悬空 successor。

Bridge 现在会继续遍历但不序列化超预算 operation，使 `omitted_operations_lower_bound` 对本次完整迭代给出精确计数而不增加响应大小。真实测量为：`INPUT_TYPES` body 共 19,645 个 operations（遗漏 16,645），`enhance_prompt` wrapper 共 10,097 个（遗漏 7,097）。这说明直接把上限扩大到完整函数会显著增加序列化、token 和内存成本，不符合有界分析要求。两者继续报告 `truncated=true`，因此不能宣称完整 parser path，也不能提升参数范围、关键字表或默认槽位。下一步应返回比较/分支/调用根及其 def-use/CFG 闭包的定向切片，而不是扩大完整 p-code 输出。该能力仍不公开为 CLI/MCP 操作。

---

## 2. 架构设计

### 2.1 模块位置

```
src/
├── cython/                          # 新增 Cython 分析模块
│   ├── CythonTypes.ts               # 类型定义
│   ├── CythonAnalyzer.ts            # 核心分析逻辑
│   ├── CythonStrings.ts             # 字符串模式识别
│   ├── CythonSignatures.ts          # 函数签名还原
│   ├── CythonContracts.ts           # 工具契约定义
│   └── index.ts                     # 模块导出
```

### 2.2 依赖关系

```
Cython Module
    ↓
┌───────────────────────────────┐
│  利用现有 Ghidra Provider      │
│  (无需编写 Java 桥接代码)       │
└───────────────────────────────┘
    ↓
┌───────────────────────────────┐
│  Application Layer             │
│  (共享 CLI/MCP 工作流)         │
└───────────────────────────────┘
```

### 2.3 工作流程

```
┌─────────────────────────────────────────────────────────────┐
│  analyze_pyd <file>                                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. [静态检查] 确认是 PE DLL + Python 扩展                   │
│     ↓                                                       │
│  2. [Ghidra] 搜索 "PyInit_*" → 定位入口点                   │
│     ↓                                                       │
│  3. [Ghidra] 搜索 Python 相关字符串                          │
│     ↓                                                       │
│  4. [Ghidra] 识别导出函数和 PyMethodDef                      │
│     ↓                                                       │
│  5. [Ghidra] 反编译关键函数                                  │
│     ↓                                                       │
│  6. [分析层] 还原函数签名和参数类型                           │
│     ↓                                                       │
│  7. [分析层] 生成 API 文档                                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. API 设计

### 3.1 核心工具

#### 3.1.1 `inspect_pyd`

**功能**：全面检查 .pyd 文件基本信息

```typescript
{
  name: "inspect_pyd",
  description: "Inspect a Cython-compiled .pyd file and return module metadata",
  inputSchema: {
    path: string,              // .pyd 文件路径
    options?: {
      includeStrings?: boolean,  // 是否包含所有字符串
      includeExports?: boolean,   // 是否包含导出函数
    }
  },
  outputSchema: {
    artifact: {
      path: string,
      sha256: string,
      bytes: number
    },
    module: {
      name: string,            // 模块名 (从 PyInit_* 提取)
      pythonPath: string,      // Python 路径 (如 custom_nodes.xxx)
      displayName: string,     // 显示名称
    },
    entryPoint: {
      address: string,         // PyInit_* 地址
      signature: string        // 函数签名
    },
    functions: [{
      name: string,
      address: string,
      type: "function" | "class" | "method",
      signature: string,
      references: string[]
    }],
    statistics: {
      procedureCount: number,
      stringCount: number,
      pythonClassCount: number,
      exportCount: number
    },
    evidence: Evidence[]
  }
}
```

#### 3.1.2 `decompile_pyd_function`

**功能**：反编译特定函数并还原签名

```typescript
{
  name: "decompile_pyd_function",
  description: "Decompile a specific function from a .pyd file and reconstruct its logic",
  inputSchema: {
    path: string,
    function: string,          // 函数名或地址
    options?: {
      includeCallGraph?: boolean,
      includeStrings?: boolean,
      maxCallDepth?: number
    }
  },
  outputSchema: {
    function: {
      name: string,
      address: string,
      signature: {
        parameters: [{
          name: string,
          type: string,
          optional: boolean,
          default: any
        }],
        returns: string
      },
      logic: {
        pseudocode: string,    // Ghidra 伪代码
       还原: string,           // Python 等价代码
        description: string    // 功能描述
      },
      callGraph: {
        callers: string[],
        callees: string[],
        externalCalls: string[]
      },
      strings: string[]
    },
    evidence: Evidence[]
  }
}
```

#### 3.1.3 `reconstruct_pyd_api`

**功能**：重建完整的 Python API

```typescript
{
  name: "reconstruct_pyd_api",
  description: "Reconstruct the Python API surface from a .pyd file",
  inputSchema: {
    path: string,
    options?: {
      includeImplementation?: boolean,
      includeTypes?: boolean
    }
  },
  outputSchema: {
    api: {
      module: {
        name: string,
        docstring: string
      },
      classes: [{
        name: string,
        bases: string[],
        methods: [{
          name: string,
          signature: string,
          docstring: string,
          implementation: string
        }],
        classAttributes: [{
          name: string,
          type: string,
          value: any
        }]
      }],
      functions: [{
        name: string,
        signature: string,
        docstring: string,
        implementation: string
      }]
    },
    rawExports: [{
      name: string,
      address: string,
      type: string
    }],
    evidence: Evidence[]
  }
}
```

#### 3.1.4 `trace_pyd_execution`

**功能**：追踪函数执行流程

```typescript
{
  name: "trace_pyd_execution",
  description: "Trace the execution flow of a Python-callable function",
  inputSchema: {
    path: string,
    function: string,
    maxDepth?: number
  },
  outputSchema: {
    trace: {
      entryPoint: string,
      flow: [{
        address: string,
        name: string,
        pseudocode: string,
        calls: string[],
        pythonEquivalent: string
      }]
    },
    callTree: {
      root: string,
      nodes: TreeNode[]
    }
  }
}
```

---

## 4. Cython 特征识别

### 4.1 字符串模式

```typescript
const CYTHON_PATTERNS = {
  // 入口点
  initPattern: /PyInit_\w+/,

  // 模块路径
  modulePathPattern: /custom_nodes\.[\w.]+/,

  // 类定义
  classPattern: /\w+Node\w*/,

  // 方法模式
  methodPattern: /\w+\.\w+\.\w+/,

  // Cython 辅助函数
  cythonHelperPattern: /__pyx_|__Pyx_/,

  // API 路由
  apiRoutePattern: /\/\w+(_\w+)*/,

  // Python 类型
  pythonTypePattern: /PyUnicode_|PyDict_|PyList_|PyTuple_/,

  // 源码路径泄露
  sourcePathPattern: /[A-Z]:\\[\w\\]+\.(py|c|pyx)/,
};
```

### 4.2 函数识别策略

| 策略           | 说明                                |
| -------------- | ----------------------------------- |
| **导出表分析** | 识别 DLL 导出函数                   |
| **字符串引用** | 找 "xxx.yyy.zzz" 格式的 Python 路径 |
| **交叉引用**   | 追踪 PyInit_* 和 PyMethodDef 的引用 |
| **类型特征**   | 识别 PyObject* 参数和返回值模式     |

---

## 5. 函数签名还原

### 5.1 参数类型推断

从 CPython API 调用模式推断参数类型：

```typescript
// 参数计数逻辑 (从反编译代码中提取)
function inferParameterCount(pseudocode: string): number {
  // 检查 PyTuple_Size() 调用
  // 检查参数访问 param_2[n] 模式
}

// 类型推断
function inferParameterType(apiCall: string): string {
  if (apiCall.includes("PyUnicode_")) return "str";
  if (apiCall.includes("PyLong_")) return "int";
  if (apiCall.includes("PyFloat_")) return "float";
  if (apiCall.includes("PyDict_")) return "dict";
  if (apiCall.includes("PyList_")) return "list";
  if (apiCall.includes("PyTuple_")) return "tuple";
  return "object";
}
```

### 5.2 返回值还原

```typescript
// 从反编译代码还原返回值
function inferReturnValue(pseudocode: string): ReturnInfo {
  // 检查 Py_None 返回
  // 检查 PyUnicode_FromString 返回
  // 检查 PyTuple_New 返回
  // 检查 PyDict_New 返回
}
```

---

## 6. 实现计划

### 6.1 Phase 1: 基础框架 (1-2 天)

- [ ] 创建 `src/cython/` 目录结构
- [ ] 定义 `CythonTypes.ts` 类型系统
- [ ] 实现 `CythonStrings.ts` 模式识别
- [ ] 创建基础工具契约

### 6.2 Phase 2: 核心分析 (2-3 天)

- [ ] 实现 `CythonAnalyzer.ts` 核心逻辑
- [ ] 集成 Ghidra Provider 调用
- [ ] 实现 `inspect_pyd` 工具
- [ ] 添加单元测试

### 6.3 Phase 3: 高级功能 (2-3 天)

- [ ] 实现 `CythonSignatures.ts` 签名还原
- [ ] 实现 `decompile_pyd_function` 工具
- [ ] 实现 `reconstruct_pyd_api` 工具
- [ ] 添加集成测试

### 6.4 Phase 4: 优化和文档 (1 天)

- [ ] 性能优化
- [ ] 错误处理完善
- [ ] 文档编写
- [ ] 示例和教程

---

## 7. 示例输出

### 7.1 `inspect_pyd` 输出示例

```json
{
  "artifact": {
    "path": "TE_Prompt_Text.pyd",
    "sha256": "f6fa9076c33b7ea4eb7de4943b37e00cae39ffe00f6422db794a26b48c34c7be",
    "bytes": 72704
  },
  "module": {
    "name": "TE_Prompt_Text",
    "pythonPath": "custom_nodes.TE_image.TE_Prompt_Text",
    "displayName": "Prompt TEXT"
  },
  "entryPoint": {
    "address": "0x18000f855",
    "signature": "PyObject* PyInit_TE_Prompt_Text(void)"
  },
  "functions": [
    {
      "name": "TEPromptTextNode.build_text",
      "address": "0x1800036c0",
      "type": "method",
      "signature": "def build_text(text: str, reference_labels: str = None) -> str | tuple",
      "references": ["0x1800032b0", "0x1800038bd"]
    }
  ],
  "statistics": {
    "procedureCount": 301,
    "stringCount": 411,
    "pythonClassCount": 1,
    "exportCount": 1
  }
}
```

### 7.2 `reconstruct_pyd_api` 输出示例

```python
"""
TE_Prompt_Text - ComfyUI Text Prompt Node

Auto-generated from reverse engineering.
CAUTION: This is inferred code, not original source.
"""

class TEPromptTextNode:
    """
    ComfyUI node for building text with reference labels.
    """

    @staticmethod
    def INPUT_TYPES():
        """
        Returns the input types for this node.
        """
        # TODO: Inferred from analysis
        return {
            "required": {
                "text": ("STRING", {"multiline": True})
            },
            "optional": {
                "reference_labels": ("STRING",)
            }
        }

    @staticmethod
    def build_text(text: str, reference_labels: str = None) -> str | tuple:
        """
        Build text with optional reference labels.

        Args:
            text: Input text
            reference_labels: Optional reference labels (e.g., "[1,2,3]")

        Returns:
            str: Plain text if no reference_labels
            tuple: (text, {"reference_labels": labels}) if provided
        """
        if not text:
            return ""

        if not isinstance(text, str):
            text = str(text)

        if reference_labels:
            if not isinstance(reference_labels, str):
                reference_labels = str(reference_labels)
            return (text, {"reference_labels": reference_labels})

        return text
```

---

## 8. 技术考虑

### 8.1 局限性

| 限制               | 影响           | 缓解措施           |
| ------------------ | -------------- | ------------------ |
| 无法还原原始变量名 | API 可读性差   | 使用推断的通用命名 |
| 内联优化丢失       | 调用链不完整   | 尽量追踪关键函数   |
| 类型信息丢失       | 参数类型不准确 | 基于 API 模式推断  |
| 注释无法恢复       | 理解成本高     | 生成描述性文档     |

### 8.2 依赖项

| 组件    | 版本要求 | 说明            |
| ------- | -------- | --------------- |
| Ghidra  | 12.1.x   | 底层反编译引擎  |
| Java    | JDK 21+  | Ghidra 运行要求 |
| Node.js | 22.19+   | REA 运行平台    |
| REA     | 6.4.0+   | 基础框架        |

---

## 9. 测试计划

### 9.1 单元测试

```typescript
// CythonStrings.test.ts
describe("CythonStrings", () => {
  it("should identify PyInit_ patterns");
  it("should extract module names from paths");
  it("should recognize Python class patterns");
});

// CythonSignatures.test.ts
describe("CythonSignatures", () => {
  it("should infer parameter count from pseudocode");
  it("should infer str type from PyUnicode_");
  it("should reconstruct function signature");
});
```

### 9.2 集成测试

```typescript
// 使用真实 .pyd 文件测试
const testCases = [
  "TE_Prompt_Text.pyd",
  "task_runner.pyd",
  "config_manager.pyd",
];

for (const pyd of testCases) {
  // 测试完整的分析流程
}
```

---

## 10. 后续扩展

### 10.1 可能的扩展方向

| 方向                 | 说明                         |
| -------------------- | ---------------------------- |
| **PyInstaller 支持** | 分析打包的 Python 可执行文件 |
| **.pyc 支持**        | 解析 Python 字节码           |
| **混淆检测**         | 识别代码混淆技术             |
| **依赖分析**         | 分析 .pyd 依赖的其他 DLL     |
| **自动化 POC**       | 生成可运行的 Python 包装器   |

### 10.2 长期目标

1. 支持更多 Python 扩展类型（.so, .dylib）
2. 与 Python AST 模块集成
3. 生成更准确的类型注解
4. 可视化调用图

---

## 11. 结论

本提案为 REA 设计了一个专门分析 Cython .pyd 文件的模块，通过：

1. **复用 Ghidra** — 利用现有的反编译能力
2. **工作流封装** — 将复杂分析简化为单一命令
3. **证据驱动** — 提供可验证的分析结果
4. **渐进式设计** — 从基础到高级功能分阶段实现

该模块将使 REA 能够更好地支持 Python 扩展模块的逆向工程，降低分析门槛，提高效率。

---

## 当前实现状态

当前只保留经过测试的、无副作用的领域投影：

- `src/domain/cythonExtension.ts`
  - 精确识别 `PyInit_*` 初始化符号；
  - 保留限定名称和源码路径字符串观察；
  - 识别 `__pyx_` / `__Pyx_` Cython 标记；
  - 从精确 CPython API 符号产生有界类型提示；
  - 明确报告覆盖范围、未知项和限制。
- `src/cython.test.ts`
  - 覆盖正例、负例、完整与不完整清单，以及不把字符串升级为源码事实的约束。

早期通过子进程再次调用 `rea` 的 `src/cython/ghidra.ts`、推测性代码生成器和独立脚本已经移除。它们无法复用现有 `BinarySession`，也不能正确保留 Evidence、取消和清理语义。

## 尚未集成的能力

| 能力             | 状态   | 要求                                                                       |
| ---------------- | ------ | -------------------------------------------------------------------------- |
| 应用工作流       | 待实现 | 通过 `AnalysisOperationPort` 在同一会话读取 `list_names` 与 `list_strings` |
| CLI 命令         | 待实现 | 复用 `runDirectAnalysis`、provider 选择、取消和清理                        |
| MCP 工具         | 待实现 | 添加严格契约、Effects、Evidence 和会话准入                                 |
| 真实 Ghidra 验证 | 待实现 | 使用可再分发 `.pyd` fixture 验证 Windows 清单覆盖                          |
| 函数级深入分析   | 后续   | 由调用者从返回候选中明确选择函数，再使用现有函数分析原语                   |

## 建议的第一版边界

第一版只回答：

1. 是否观察到 CPython 扩展初始化符号；
2. 是否观察到 Cython 标记；
3. 哪些限定名称和源码路径字符串被观察到；
4. 哪些 CPython API 符号提供了局部类型提示；
5. 检查了多少名称和字符串，覆盖是否完整。

第一版不生成 Python 源码，不声明字符串代表类或方法，不推断完整函数签名，也不把缺失标记解释为“不是 Cython”。

## 下一步计划

1. 在 application 层实现基于 `AnalysisOperationPort` 的只读工作流；
2. 使用现有 session 同次读取 `list_names` 和 `list_strings`；
3. 创建 derived Evidence，保留两次原语调用的 provider、profile、locations 和 limitations；
4. 添加 CLI/MCP 合约与边界测试；
5. 完成真实 Windows Ghidra 验证后再宣传 `.pyd` 检查能力。
