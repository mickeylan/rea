/**
 * Cython .pyd 分析模块
 *
 * 提供 Cython 编译的 Python 扩展模块 (.pyd) 的类型定义和工具函数
 *
 * @example
 * ```typescript
 * import { extractModuleName, inferPythonTypeFromApiCall } from './cython/index.js';
 *
 * // 从 PyInit_* 提取模块名
 * extractModuleName('PyInit_TE_Prompt_Text')  // => 'TE_Prompt_Text'
 *
 * // 从 CPython API 调用推断 Python 类型
 * inferPythonTypeFromApiCall('PyUnicode_FromString')  // => 'str'
 * ```
 */

import { z } from "zod";

// ============================================================================
// 基础类型定义
// ============================================================================

/** Cython 函数类型 */
export const cythonFunctionTypeSchema = z.enum([
  "function",
  "class",
  "method",
  "init",
  "wrapper",
  "helper",
]);
export type CythonFunctionType = z.infer<typeof cythonFunctionTypeSchema>;

/** Python 类型推断 */
export const pythonTypeSchema = z.enum([
  "str",
  "int",
  "float",
  "bool",
  "list",
  "tuple",
  "dict",
  "set",
  "None",
  "object",
  "bytes",
]);
export type PythonType = z.infer<typeof pythonTypeSchema>;

/** 函数参数 */
export const functionParameterSchema = z.strictObject({
  name: z.string(),
  type: pythonTypeSchema,
  optional: z.boolean().default(false),
  default: z.unknown().nullable().optional(),
});
export type FunctionParameter = z.infer<typeof functionParameterSchema>;

/** 函数签名 */
export const functionSignatureSchema = z.strictObject({
  parameters: z.array(functionParameterSchema),
  returns: pythonTypeSchema,
});
export type FunctionSignature = z.infer<typeof functionSignatureSchema>;

// ============================================================================
// Cython 特征字符串模式
// ============================================================================

/** Cython 特征字符串模式 */
export const CYTHON_STRING_PATTERNS = {
  // 入口点: PyInit_*
  initPattern: /^PyInit_\w+$/,

  // 模块路径: custom_nodes.xxx.xxx
  modulePathPattern: /^custom_nodes(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+$/,

  // 类定义: XxxNode, XxxClass 等
  classPattern: /^[A-Z][a-zA-Z0-9]*Node[A-Z]?[a-zA-Z0-9]*$/,

  // 源码路径: C:\path\to\file.py
  sourcePathPattern: /^([A-Z]:\\[\w\\/.]+|\/[\w/\.]+)\.(py|pyx|c)$/i,

  // API 路由: /te_xxx/yyy
  apiRoutePattern: /^\/[a-z_][a-z0-9_]*(?:\/[a-z_][a-z0-9_]*)*$/,
} as const;

/** 导出函数名模式 */
export const EXPORT_PATTERNS = {
  pyInit: /^PyInit_\w+$/,
  cythonWrapper: /^__pyx_pw_\d+\w+$/,
  cythonImpl: /^__pyx_pf_\d+\w+$/,
} as const;

/** CPython API 到 Python 类型的映射 */
export const CPYTHON_TYPE_MAP = {
  PyUnicode_Type: "str",
  PyUnicode_FromString: "str",
  PyUnicode_Concat: "str",
  PyObject_Str: "str",
  PyLong_Type: "int",
  PyLong_FromLong: "int",
  PyFloat_Type: "float",
  PyDict_Type: "dict",
  PyDict_New: "dict",
  PyList_Type: "list",
  PyList_New: "list",
  PyTuple_Type: "tuple",
  PyTuple_New: "tuple",
  Py_NoneStruct: "None",
  Py_TrueStruct: "bool",
  Py_FalseStruct: "bool",
} as const;

// ============================================================================
// 工具函数
// ============================================================================

/** 从 PyInit_* 提取模块名 */
export function extractModuleName(pyInitName: string): string {
  const match = pyInitName.match(/^PyInit_(.+)$/);
  return match?.[1] ?? pyInitName;
}

/** 判断字符串是否为 Python 模块路径 */
export function isPythonModulePath(value: string): boolean {
  return CYTHON_STRING_PATTERNS.modulePathPattern.test(value);
}

/** 判断字符串是否为类名 */
export function isClassName(value: string): boolean {
  return CYTHON_STRING_PATTERNS.classPattern.test(value);
}

/** 判断字符串是否为源码路径 */
export function isSourcePath(value: string): boolean {
  return CYTHON_STRING_PATTERNS.sourcePathPattern.test(value);
}

/** 从全限定名提取组件 */
export function parseQualifiedName(qualifiedName: string): {
  module: string;
  className: string | null;
  methodName: string;
} {
  const parts = qualifiedName.split(".");
  if (parts.length === 1) {
    return { module: "", className: null, methodName: parts[0]! };
  }

  const lastPart = parts[parts.length - 1] ?? "";
  const isMethodLike = /^[a-z][a-z0-9_]*$/.test(lastPart);

  if (isMethodLike && parts.length >= 3) {
    const classPart = parts[parts.length - 2] ?? "";
    return {
      module: parts.slice(0, -2).join("."),
      className: classPart || null,
      methodName: lastPart,
    };
  }

  return {
    module: parts.slice(0, -1).join("."),
    className: null,
    methodName: lastPart,
  };
}

/** 推断参数类型 */
export function inferPythonTypeFromApiCall(apiCall: string): PythonType {
  for (const [pattern, type] of Object.entries(CPYTHON_TYPE_MAP)) {
    if (apiCall.includes(pattern)) {
      return type;
    }
  }
  return "object";
}

/** 检查是否为 Python 对象类型 */
export function isPythonObjectType(typeName: string): boolean {
  return typeName in CPYTHON_TYPE_MAP;
}

// ============================================================================
// Ghidra 会话封装
// ============================================================================

export { createGhidraSession } from "./ghidra.js";
export type {
  GhidraSession,
  SearchResult,
  FunctionInfo,
  Reference,
} from "./ghidra.js";

// ============================================================================
// Cython 分析器
// ============================================================================

export {
  createCythonAnalyzer,
  analyzeAndGenerate,
  generatePythonCode,
} from "./analyzer.js";
export type { AnalysisResult, FunctionAnalysis } from "./analyzer.js";
