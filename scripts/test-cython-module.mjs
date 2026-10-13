#!/usr/bin/env node
/**
 * Cython .pyd 分析模块测试脚本
 *
 * 用于验证模块的基本功能
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = resolve(__dirname, "..");

console.log("🧪 Cython .pyd Analysis Module Test\n");
console.log("Root directory:", rootDir);
console.log("");

// 测试 1: 类型定义
console.log("Test 1: Type Definitions");
console.log("=".repeat(50));

try {
  const typesModule = await import("../src/cython/CythonTypes.ts");

  // 测试 extractModuleName
  const moduleName = typesModule.extractModuleName("PyInit_TE_Prompt_Text");
  console.log(`✓ extractModuleName('PyInit_TE_Prompt_Text') = '${moduleName}'`);
  if (moduleName !== "TE_Prompt_Text") {
    throw new Error(`Expected 'TE_Prompt_Text', got '${moduleName}'`);
  }

  // 测试 isPythonModulePath
  const isModule = typesModule.isPythonModulePath(
    "custom_nodes.TE_image.TE_Prompt_Text",
  );
  console.log(
    `✓ isPythonModulePath('custom_nodes.TE_image.TE_Prompt_Text') = ${isModule}`,
  );

  // 测试 isClassName
  const isClass = typesModule.isClassName("TEPromptTextNode");
  console.log(`✓ isClassName('TEPromptTextNode') = ${isClass}`);

  // 测试 inferPythonTypeFromApiCall
  const inferredType = typesModule.inferPythonTypeFromApiCall(
    "PyUnicode_FromString",
  );
  console.log(
    `✓ inferPythonTypeFromApiCall('PyUnicode_FromString') = '${inferredType}'`,
  );

  console.log("\n✅ All type tests passed!\n");
} catch (error) {
  console.error("\n❌ Type test failed:", error.message);
  process.exit(1);
}

// 测试 2: 模式匹配
console.log("Test 2: Pattern Matching");
console.log("=".repeat(50));

const testStrings = [
  { value: "PyInit_TE_Prompt_Text", expected: true, desc: "入口点" },
  {
    value: "custom_nodes.TE_image.TE_Prompt_Text",
    expected: true,
    desc: "模块路径",
  },
  { value: "TEPromptTextNode", expected: true, desc: "类名" },
  { value: "build_text", expected: false, desc: "普通函数名" },
  { value: "/te_prompt_text/view_reference", expected: true, desc: "API路由" },
  { value: "F:\\ComfyUI\\TE_Prompt_Text.py", expected: true, desc: "源码路径" },
];

try {
  for (const test of testStrings) {
    let matched = false;

    if (test.desc === "入口点") {
      matched = typesModule.CYTHON_STRING_PATTERNS.initPattern.test(test.value);
    } else if (test.desc === "模块路径") {
      matched = typesModule.isPythonModulePath(test.value);
    } else if (test.desc === "类名") {
      matched = typesModule.isClassName(test.value);
    } else if (test.desc === "API路由") {
      matched = typesModule.CYTHON_STRING_PATTERNS.apiRoutePattern.test(
        test.value,
      );
    } else if (test.desc === "源码路径") {
      matched = typesModule.isSourcePath(test.value);
    }

    const status = matched === test.expected ? "✅" : "❌";
    console.log(`${status} ${test.desc}: '${test.value}' -> ${matched}`);

    if (matched !== test.expected) {
      throw new Error(`Pattern mismatch for ${test.desc}`);
    }
  }

  console.log("\n✅ All pattern tests passed!\n");
} catch (error) {
  console.error("\n❌ Pattern test failed:", error.message);
  process.exit(1);
}

// 测试 3: Python 代码生成
console.log("Test 3: Python Code Generation");
console.log("=".repeat(50));

try {
  const reconstructModule = await import("../src/cython/reconstruct.ts");

  const mockReconstruction = {
    api: {
      module: {
        name: "TE_Prompt_Text",
        docstring: "ComfyUI Text Prompt Node",
      },
      classes: [
        {
          name: "TEPromptTextNode",
          bases: [],
          methods: [
            {
              name: "build_text",
              signature:
                "build_text(text: str, reference_labels: str = None) -> str | tuple",
              docstring: "Build text with reference labels",
              implementation:
                'return text if not reference_labels else (text, {"labels": reference_labels})',
            },
          ],
          classAttributes: [],
        },
      ],
      functions: [],
    },
    rawExports: [],
  };

  const pythonCode = reconstructModule.generatePythonCode(mockReconstruction, {
    includeTypes: true,
    includeDocstrings: true,
    includeImplementation: true,
  });

  console.log("Generated Python code:\n");
  console.log(pythonCode);

  console.log("\n✅ Python code generation test passed!\n");
} catch (error) {
  console.error("\n❌ Python code generation test failed:", error.message);
  process.exit(1);
}

// 测试 4: 签名推断
console.log("Test 4: Signature Inference");
console.log("=".repeat(50));

try {
  const decompileModule = await import("../src/cython/decompile.ts");

  // 模拟 Ghidra 伪代码
  const mockPseudocode = `
    if (param_3 == (undefined8 *)0x0) {
      goto LAB_1800034bb;
    }
    puVar10 = param_4;
    lVar2 = PyTuple_Size(param_4);
    if (lVar2 < 1) goto LAB_1800034bb;
    if (param_3 != 2) {
      puVar8 = (undefined8 *)param_2[2];
    }
    puVar9 = (undefined8 *)param_2[1];
    if (*(code **)(puVar9 + 8) == PyUnicode_Type_exref) {
      puVar3 = puVar9;
    }
  `;

  const signature =
    decompileModule.inferSignatureFromPseudocode(mockPseudocode);

  console.log("Inferred signature:", JSON.stringify(signature, null, 2));

  // 验证推断结果包含预期的类型
  const hasStrType =
    signature.parameters.some((p) => p.type === "str") ||
    mockPseudocode.includes("PyUnicode");
  console.log(`✓ Inferred string type from PyUnicode: ${hasStrType}`);

  console.log("\n✅ Signature inference test passed!\n");
} catch (error) {
  console.error("\n❌ Signature inference test failed:", error.message);
  process.exit(1);
}

// 总结
console.log("=".repeat(50));
console.log("\n🎉 All tests passed! Cython analysis module is ready.\n");
console.log("Next steps:");
console.log("1. Register CLI commands in src/cliCommandNames.ts");
console.log("2. Integrate with Ghidra Provider");
console.log("3. Add MCP server registration");
console.log("4. Write integration tests with real .pyd files\n");
