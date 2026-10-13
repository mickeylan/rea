/**
 * Cython .pyd 完整分析器
 *
 * 利用 Ghidra 进行完整分析并生成 Python 代码
 */

import {
  createGhidraSession,
  type GhidraSession,
  type SearchResult,
} from "./ghidra.js";
import { extractModuleName, isPythonModulePath, isClassName } from "./index.js";

// ============================================================================
// 类型定义
// ============================================================================

interface PythonModule {
  name: string;
  pythonPath: string;
  displayName: string | null;
  docstring: string | null;
}

interface CythonFunction {
  name: string;
  qualifiedName: string;
  address: string;
  type: string;
  signature: {
    parameters: Array<{ name: string; type: string; optional: boolean }>;
    returns: string;
  };
  description: string | null;
  references: string[];
}

interface PydStatistics {
  procedureCount: number;
  stringCount: number;
  pythonClassCount: number;
  exportCount: number;
}

export interface AnalysisResult {
  module: PythonModule;
  entryPoint: {
    address: string;
    signature: string;
  };
  functions: CythonFunction[];
  statistics: PydStatistics;
  rawStrings: string[];
}

export interface FunctionAnalysis {
  name: string;
  qualifiedName: string;
  address: string;
  pseudocode: string;
  signature: {
    parameters: Array<{ name: string; type: string; optional: boolean }>;
    returns: string;
  };
  callers: string[];
  callees: string[];
  description: string;
}

// ============================================================================
// Cython 分析器
// ============================================================================

/**
 * Cython .pyd 分析器
 */
export class CythonAnalyzer {
  private session: GhidraSession;

  constructor(session?: GhidraSession) {
    this.session = session || createGhidraSession();
  }

  /**
   * 完整分析 .pyd 文件
   */
  async analyze(filePath: string): Promise<AnalysisResult | null> {
    // 1. 搜索入口点
    const initResults = await this.session.search(filePath, "PyInit_");
    if (initResults.length === 0) {
      console.error("No PyInit_* entry point found");
      return null;
    }

    const entryPoint = initResults[0];
    if (!entryPoint) return null;

    const moduleName = extractModuleName(entryPoint.value);

    // 2. 搜索所有相关字符串
    const allStrings: SearchResult[] = [];

    // 搜索 Python 相关模式
    const patterns = [
      "Node",
      "INPUT_TYPES",
      "custom_nodes",
      "display_name",
      "/api/",
      "/te_",
    ];

    for (const pattern of patterns) {
      const results = await this.session.search(filePath, pattern);
      allStrings.push(...results);
    }

    // 3. 提取模块信息
    const module = this.extractModuleInfo(allStrings, moduleName);

    // 4. 提取函数信息
    const functions = this.extractFunctions(allStrings);

    // 5. 计算统计
    const statistics = this.calculateStatistics(allStrings, functions);

    return {
      module,
      entryPoint: {
        address: entryPoint.address,
        signature: `PyObject* ${entryPoint.value}(void)`,
      },
      functions,
      statistics,
      rawStrings: allStrings.map((s) => s.value),
    };
  }

  /**
   * 分析特定函数
   */
  async analyzeFunction(
    filePath: string,
    functionName: string,
  ): Promise<FunctionAnalysis | null> {
    // 获取伪代码
    const pseudocode = await this.session.decompile(filePath, functionName);
    if (!pseudocode) {
      return null;
    }

    // 获取引用
    const refs = await this.session.trace(filePath, functionName);

    // 推断签名
    const signature = this.inferSignature(pseudocode);

    // 生成描述
    const description = this.generateDescription(functionName, pseudocode);

    return {
      name: functionName,
      qualifiedName: functionName,
      address: refs[0]?.sourceAddress || "",
      pseudocode,
      signature,
      callers: refs
        .filter((r: any) => r.targetName === functionName)
        .map((r: any) => r.sourceAddress),
      callees: refs
        .filter((r: any) => r.containingProcedure === functionName)
        .map((r: any) => r.targetName),
      description,
    };
  }

  /**
   * 提取模块信息
   */
  private extractModuleInfo(
    strings: SearchResult[],
    moduleName: string,
  ): PythonModule {
    let pythonPath = "";

    for (const s of strings) {
      if (isPythonModulePath(s.value)) {
        pythonPath = s.value;
        break;
      }
    }

    if (!pythonPath) {
      pythonPath = `custom_nodes.${moduleName}`;
    }

    return {
      name: moduleName,
      pythonPath,
      displayName: null,
      docstring: null,
    };
  }

  /**
   * 提取函数信息
   */
  private extractFunctions(strings: SearchResult[]): CythonFunction[] {
    const functions: CythonFunction[] = [];
    const processed = new Set<string>();

    for (const s of strings) {
      const value = s.value;

      // 跳过太短的或已处理的
      if (!value || value.length < 3 || processed.has(value)) continue;

      // 检查类名
      const parts = value.split(".");
      if (parts.length >= 3) {
        const lastPart = parts[parts.length - 1] || "";
        const secondLast = parts[parts.length - 2] || "";

        if (isClassName(secondLast) && !lastPart.startsWith("_")) {
          processed.add(value);

          functions.push({
            name: lastPart,
            qualifiedName: value,
            address: s.address,
            type: "method",
            signature: {
              parameters: [],
              returns: "object",
            },
            description: null,
            references: [s.address],
          });
        }
      }
    }

    return functions;
  }

  /**
   * 计算统计
   */
  private calculateStatistics(
    strings: SearchResult[],
    functions: CythonFunction[],
  ): PydStatistics {
    const classNames = new Set<string>();

    for (const f of functions) {
      const parts = f.qualifiedName.split(".");
      if (parts.length >= 3) {
        classNames.add(parts[parts.length - 2] || "");
      }
    }

    return {
      procedureCount: strings.length,
      stringCount: new Set(strings.map((s) => s.value)).size,
      pythonClassCount: classNames.size,
      exportCount: functions.filter((f) => f.type === "method").length,
    };
  }

  /**
   * 从伪代码推断函数签名
   */
  private inferSignature(pseudocode: string): {
    parameters: Array<{ name: string; type: string; optional: boolean }>;
    returns: string;
  } {
    const parameters: Array<{ name: string; type: string; optional: boolean }> =
      [];
    let returns = "object";

    // 检测参数
    const paramMatches = pseudocode.match(/param_\d+/g) || [];
    const uniqueParams = [...new Set(paramMatches)];

    for (const param of uniqueParams) {
      const paramIndex = parseInt(param.replace("param_", ""), 10);

      // 推断类型
      let type = "object";

      // 检查 PyUnicode (字符串)
      if (pseudocode.includes("PyUnicode_")) {
        type = "str";
      }

      // 检查 PyLong (整数)
      if (pseudocode.includes("PyLong_")) {
        type = "int";
      }

      // 检查 PyTuple (元组)
      if (pseudocode.includes("PyTuple_")) {
        type = "tuple";
      }

      // 检查 PyDict (字典)
      if (pseudocode.includes("PyDict_")) {
        type = "dict";
      }

      // self 通常是第一个参数
      if (paramIndex === 1) {
        parameters.push({ name: "self", type, optional: false });
      } else {
        parameters.push({
          name: `arg${paramIndex - 1}`,
          type,
          optional: false,
        });
      }
    }

    // 如果没有检测到参数，添加 self
    if (parameters.length === 0) {
      parameters.push({ name: "self", type: "object", optional: false });
    }

    // 推断返回类型
    if (pseudocode.includes("Py_None")) {
      returns = "None";
    } else if (pseudocode.includes("PyUnicode_From")) {
      returns = "str";
    } else if (
      pseudocode.includes("PyTuple_New") ||
      pseudocode.includes("PyTuple_SetItem")
    ) {
      returns = "tuple";
    } else if (pseudocode.includes("PyDict_New")) {
      returns = "dict";
    }

    return { parameters, returns };
  }

  /**
   * 生成函数描述
   */
  private generateDescription(
    functionName: string,
    pseudocode: string,
  ): string {
    const parts: string[] = [];

    if (pseudocode.includes("PyErr_")) {
      parts.push("error handling");
    }
    if (pseudocode.includes("PyUnicode_")) {
      parts.push("string operations");
    }
    if (pseudocode.includes("PyTuple_") || pseudocode.includes("PyList_")) {
      parts.push("sequence operations");
    }
    if (pseudocode.includes("PyDict_")) {
      parts.push("dictionary operations");
    }

    if (parts.length > 0) {
      return `Function performs: ${parts.join(", ")}`;
    }

    return "Cython-compiled Python extension function";
  }
}

// ============================================================================
// 代码生成
// ============================================================================

/**
 * 生成 Python 代码
 */
export function generatePythonCode(result: AnalysisResult): string {
  const lines: string[] = [];

  // 模块 docstring
  lines.push('"""');
  lines.push(`${result.module.pythonPath} - Auto-generated Python code`);
  lines.push("");
  lines.push(
    "NOTE: This code is inferred from binary analysis, not original source.",
  );
  lines.push('"""');
  lines.push("");

  // 导入
  lines.push("from typing import Any, List, Dict, Optional, Tuple");
  lines.push("from pathlib import Path");
  lines.push("");

  // 类
  const classes = new Map<string, CythonFunction[]>();

  for (const func of result.functions) {
    const parts = func.qualifiedName.split(".");
    if (parts.length >= 3) {
      const className = parts[parts.length - 2] || "";
      const methodName = parts[parts.length - 1] || "";

      if (className && methodName) {
        if (!classes.has(className)) {
          classes.set(className, []);
        }
        classes.get(className)!.push(func);
      }
    }
  }

  // 生成类代码
  for (const [className, methods] of classes) {
    lines.push(`class ${className}:`);
    lines.push('    """');
    lines.push(`    ComfyUI custom node class`);
    lines.push('    """');
    lines.push("");

    // INPUT_TYPES
    lines.push("    @classmethod");
    lines.push("    def INPUT_TYPES(cls):");
    lines.push('        """Define node input types."""');
    lines.push("        return {");
    lines.push('            "required": {},');
    lines.push('            "optional": {},');
    lines.push("        }");
    lines.push("");

    // 方法
    for (const method of methods) {
      const params = method.signature.parameters
        .filter((p: any) => p.name !== "self")
        .map((p: any) => `${p.name}: ${p.type} = None`)
        .join(", ");

      lines.push(`    @staticmethod`);
      lines.push(
        `    def ${method.name}(${params}) -> ${method.signature.returns}:`,
      );

      if (method.description) {
        lines.push(`        """${method.description}"""`);
      }

      lines.push("        # TODO: Implement based on analysis");
      lines.push("        pass");
      lines.push("");
    }

    lines.push("");
  }

  // ComfyUI 注册
  if (classes.size > 0) {
    lines.push("# ComfyUI Node Registration");
    lines.push("NODE_CLASS_MAPPINGS = {");
    for (const className of classes.keys()) {
      lines.push(`    "${className}": ${className},`);
    }
    lines.push("}");
    lines.push("");
    lines.push("NODE_DISPLAY_NAME_MAPPINGS = {");
    for (const className of classes.keys()) {
      const displayName = className.replace(/([A-Z])/g, " $1").trim();
      lines.push(`    "${className}": "${displayName}",`);
    }
    lines.push("}");
  }

  return lines.join("\n");
}

// ============================================================================
// 工厂函数
// ============================================================================

/**
 * 创建 Cython 分析器
 */
export function createCythonAnalyzer(session?: GhidraSession): CythonAnalyzer {
  return new CythonAnalyzer(session);
}

// ============================================================================
// CLI 工具函数
// ============================================================================

/**
 * 一键分析并生成代码
 */
export async function analyzeAndGenerate(
  filePath: string,
): Promise<string | null> {
  const analyzer = createCythonAnalyzer();

  console.log(`Analyzing ${filePath}...`);

  const result = await analyzer.analyze(filePath);
  if (!result) {
    console.error("Analysis failed");
    return null;
  }

  console.log(`Found ${result.functions.length} functions`);
  console.log(`Found ${result.statistics.pythonClassCount} classes`);

  const code = generatePythonCode(result);

  return code;
}
