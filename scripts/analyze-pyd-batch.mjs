#!/usr/bin/env node
/**
 * 批量分析 Cython .pyd 文件
 *
 * 使用方式:
 *   node scripts/analyze-pyd-batch.mjs <directory>
 *   node scripts/analyze-pyd-batch.mjs J:\mickeylan\ComfyUI\custom_nodes\TE_MAN
 */

import { readdirSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, basename, dirname } from "node:path";
import { spawn } from "node:child_process";

// 环境配置
const JAVA_HOME = "D:\\Java\\openjdk-23.0.2";
const GHIDRA_INSTALL_DIR = "D:\\dev_tools\\ghidra";
const REA_CMD = "D:\\npm-global\\rea.cmd";

// 颜色输出
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
};

function log(message, color = "reset") {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

// 执行 REA 命令
function runRea(args) {
  return new Promise((resolve, reject) => {
    const proc = spawn(REA_CMD, args, {
      env: { ...process.env, JAVA_HOME, GHIDRA_INSTALL_DIR },
      shell: true,
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });
    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      resolve({ code, stdout, stderr });
    });

    proc.on("error", reject);
  });
}

// 分析单个 .pyd 文件
async function analyzePyd(pydPath) {
  const results = {
    path: pydPath,
    name: basename(pydPath),
    moduleName: "",
    entryPoint: "",
    functions: [],
    statistics: {},
    errors: [],
  };

  try {
    // 1. 搜索 PyInit_* 入口点
    log(`  🔍 搜索入口点...`, "blue");
    const initResult = await runRea([
      "search",
      pydPath,
      "PyInit_",
      "--provider",
      "ghidra",
      "--json",
    ]);

    if (initResult.code === 0 && initResult.stdout) {
      try {
        const initData = JSON.parse(initResult.stdout);
        const inits = initData.normalized_result || [];
        results.entryPoint = inits[0]?.value || "";
        results.moduleName = results.entryPoint.replace("PyInit_", "");
      } catch (e) {
        results.errors.push("入口点解析失败");
      }
    }

    // 2. 获取概览
    log(`  📊 获取概览...`, "blue");
    const inspectResult = await runRea([
      "inspect",
      pydPath,
      "--provider",
      "ghidra",
      "--json",
    ]);

    if (inspectResult.code === 0 && inspectResult.stdout) {
      try {
        const inspectData = JSON.parse(inspectResult.stdout);
        results.statistics = {
          procedures: inspectData.normalized_result?.procedure_count || 0,
          strings: inspectData.normalized_result?.string_count || 0,
          sha256: inspectData.subject?.digest?.sha256 || "",
        };
      } catch (e) {
        results.errors.push("概览解析失败");
      }
    }

    // 3. 搜索关键字符串
    log(`  🔤 搜索字符串...`, "blue");
    const patterns = ["Node", "display_name", "INPUT_TYPES", "/api/", "/te_"];

    for (const pattern of patterns) {
      const searchResult = await runRea([
        "search",
        pydPath,
        pattern,
        "--provider",
        "ghidra",
        "--json",
      ]);

      if (searchResult.code === 0 && searchResult.stdout) {
        try {
          const searchData = JSON.parse(searchResult.stdout);
          const matches = searchData.normalized_result || [];

          for (const match of matches) {
            if (match.value && !results.functions.includes(match.value)) {
              // 过滤有意义的字符串
              if (
                match.value.length > 2 &&
                !match.value.match(/^[\x00-\x7F]+$/)
              ) {
                results.functions.push(match.value);
              }
            }
          }
        } catch (e) {
          // 忽略解析错误
        }
      }
    }
  } catch (error) {
    results.errors.push(error.message);
  }

  return results;
}

// 批量分析目录中的 .pyd 文件
async function analyzeDirectory(dirPath) {
  log(`\n${colors.bright}🚀 开始批量分析 .pyd 文件${colors.reset}`, "green");
  log(`📁 目录: ${dirPath}\n`, "cyan");

  // 获取所有 .pyd 文件
  const files = readdirSync(dirPath).filter((f) => f.endsWith(".pyd"));
  log(`📋 找到 ${files.length} 个 .pyd 文件\n`, "yellow");

  const results = [];

  for (let i = 0; i < files.length; i++) {
    const pydPath = join(dirPath, files[i]);
    log(`[${i + 1}/${files.length}] 分析 ${files[i]}...`, "bright");

    const result = await analyzePyd(pydPath);
    results.push(result);

    // 显示简要结果
    log(`   模块: ${result.moduleName || "N/A"}`, "green");
    log(`   入口: ${result.entryPoint || "N/A"}`, "green");
    log(`   函数: ${result.statistics.procedures || 0}`, "green");
    if (result.errors.length > 0) {
      log(`   错误: ${result.errors.join(", ")}`, "yellow");
    }
    log("");
  }

  // 生成报告
  const reportPath = join(dirname(dirPath), "pyd_analysis_report.md");
  generateReport(results, reportPath);

  return results;
}

// 生成 Markdown 报告
function generateReport(results, reportPath) {
  log(`\n${colors.bright}📝 生成报告...${colors.reset}`, "green");

  let md = `# Cython .pyd 文件分析报告

> 生成时间: ${new Date().toISOString()}

## 概览

| 文件数 | 模块数 | 总函数 | 总字符串 |
|--------|--------|--------|----------|
| ${results.length} | ${results.filter((r) => r.moduleName).length} | ${results.reduce((s, r) => s + (r.statistics.procedures || 0), 0)} | ${results.reduce((s, r) => s + (r.statistics.strings || 0), 0)} |

## 详细分析

`;

  for (const result of results) {
    md += `### ${result.name}

| 属性 | 值 |
|------|-----|
| **模块名** | \`${result.moduleName || "N/A"}\` |
| **入口点** | \`${result.entryPoint || "N/A"}\` |
| **函数数** | ${result.statistics.procedures || 0} |
| **字符串数** | ${result.statistics.strings || 0} |
| **SHA256** | \`${(result.statistics.sha256 || "").substring(0, 16)}...\` |
| **路径** | \`${result.path}\` |

`;

    if (result.functions.length > 0) {
      md += `**发现的关键字符串:**
\`\`\`
${result.functions.slice(0, 20).join("\n")}
${result.functions.length > 20 ? `... 还有 ${result.functions.length - 20} 个` : ""}
\`\`\`

`;
    }

    if (result.errors.length > 0) {
      md += `**错误:**
${result.errors.map((e) => `- ${e}`).join("\n")}

`;
    }

    md += `---\n\n`;
  }

  writeFileSync(reportPath, md, "utf8");
  log(`✅ 报告已生成: ${reportPath}`, "green");
}

// 主函数
async function main() {
  const dirPath =
    process.argv[2] || "J:\\mickeylan\\ComfyUI\\custom_nodes\\TE_MAN";

  if (!existsSync(dirPath)) {
    log(`❌ 目录不存在: ${dirPath}`, "red");
    process.exit(1);
  }

  await analyzeDirectory(dirPath);
}

main().catch(console.error);
