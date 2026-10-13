#!/usr/bin/env node
/**
 * Cython .pyd 文件分析工具
 * 
 * 使用方式:
 *   node scripts/analyze-pyd.mjs <file>           # 分析并输出 Python 代码
 *   node scripts/analyze-pyd.mjs <file> --json     # 输出 JSON 格式
 *   node scripts/analyze-pyd.mjs <file> --inspect # 仅概览
 *   node scripts/analyze-pyd.mjs <file> --decompile <function> # 反编译特定函数
 */

import { spawn } from 'child_process';

// ============================================================================
// 配置
// ============================================================================

const CONFIG = {
  javaHome: process.env.JAVA_HOME || 'D:\\Java\\openjdk-23.0.2',
  ghidraInstallDir: process.env.GHIDRA_INSTALL_DIR || 'D:\\dev_tools\\ghidra',
  reaCommand: process.env.REA_COMMAND || 'D:\\npm-global\\rea.cmd',
  timeout: 180000,
};

// ============================================================================
// 辅助函数
// ============================================================================

function log(message, color = '\x1b[0m') {
  console.log(`${color}${message}\x1b[0m`);
}

function runCommand(command, args, env = {}) {
  return new Promise((resolve, reject) => {
    const fullEnv = {
      ...process.env,
      JAVA_HOME: CONFIG.javaHome,
      GHIDRA_INSTALL_DIR: CONFIG.ghidraInstallDir,
      ...env,
    };
    
    const proc = spawn(command, args, {
      env: fullEnv,
      shell: true,
      timeout: CONFIG.timeout,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    
    let stdout = '';
    let stderr = '';
    
    proc.stdout?.on('data', (data) => { stdout += data.toString(); });
    proc.stderr?.on('data', (data) => { stderr += data.toString(); });
    
    proc.on('close', (code) => {
      resolve({ code: code || 0, stdout, stderr });
    });
    
    proc.on('error', reject);
  });
}

// ============================================================================
// Ghidra 分析
// ============================================================================

async function inspectPyd(filePath) {
  log(`\n📊 检查文件: ${filePath}`, '\x1b[36m');
  log(`   使用命令: ${CONFIG.reaCommand}`, '\x1b[90m');
  
  const result = await runCommand(CONFIG.reaCommand, [
    'inspect', filePath, '--provider', 'ghidra', '--json'
  ]);
  
  log(`   返回码: ${result.code}`, '\x1b[90m');
  if (result.stdout) {
    log(`   输出: ${result.stdout.substring(0, 200)}`, '\x1b[90m');
  }
  if (result.stderr) {
    log(`   错误: ${result.stderr.substring(0, 200)}`, '\x1b[31m');
  }
  
  if (result.code !== 0 || !result.stdout.trim()) {
    throw new Error('Inspect failed');
  }
  
  return JSON.parse(result.stdout);
}

async function searchPyd(filePath, pattern) {
  const result = await runCommand(CONFIG.reaCommand, [
    'search', filePath, pattern, '--provider', 'ghidra', '--json'
  ]);
  
  if (result.code !== 0 || !result.stdout.trim()) {
    return [];
  }
  
  try {
    const data = JSON.parse(result.stdout);
    return data.normalized_result || [];
  } catch {
    return [];
  }
}

async function decompilePyd(filePath, functionName) {
  const result = await runCommand(CONFIG.reaCommand, [
    'decompile', filePath, functionName, '--provider', 'ghidra', '--json'
  ]);
  
  if (result.code !== 0 || !result.stdout.trim()) {
    return null;
  }
  
  try {
    const data = JSON.parse(result.stdout);
    return data.normalized_result?.pseudocode || null;
  } catch {
    return null;
  }
}

async function tracePyd(filePath, pattern) {
  const result = await runCommand(CONFIG.reaCommand, [
    'trace', filePath, pattern, '--provider', 'ghidra', '--json'
  ]);
  
  if (result.code !== 0 || !result.stdout.trim()) {
    return [];
  }
  
  try {
    const data = JSON.parse(result.stdout);
    return data.normalized_result || [];
  } catch {
    return [];
  }
}

// ============================================================================
// 分析流程
// ============================================================================

async function analyzePyd(filePath) {
  log('🚀 开始分析 Cython .pyd 文件', '\x1b[32m');
  log('=' .repeat(60), '\x1b[90m');
  
  // 1. 检查文件
  const inspect = await inspectPyd(filePath);
  
  console.log('\n📋 文件信息:');
  console.log(`   路径: ${inspect.subject?.name || filePath}`);
  console.log(`   格式: ${inspect.subject?.format || 'unknown'}`);
  console.log(`   架构: ${inspect.subject?.architecture || 'unknown'}`);
  console.log(`   函数数: ${inspect.normalized_result?.procedure_count || 0}`);
  console.log(`   字符串数: ${inspect.normalized_result?.string_count || 0}`);
  
  // 2. 搜索入口点
  log('\n🔍 搜索 PyInit_* 入口点...', '\x1b[36m');
  const initResults = await searchPyd(filePath, 'PyInit_');
  
  if (initResults.length > 0) {
    const entryPoint = initResults[0];
    const moduleName = entryPoint.value.replace('PyInit_', '');
    console.log(`   入口点: ${entryPoint.value}`);
    console.log(`   模块名: ${moduleName}`);
    console.log(`   地址: ${entryPoint.address}`);
  }
  
  // 3. 搜索类和方法
  log('\n🔍 搜索 Python 类和方法...', '\x1b[36m');
  
  const patterns = ['Node', 'INPUT_TYPES', 'custom_nodes', 'display_name'];
  const allStrings = [];
  
  for (const pattern of patterns) {
    const results = await searchPyd(filePath, pattern);
    allStrings.push(...results);
  }
  
  // 4. 提取类信息
  const classes = new Map();
  const classPattern = /^[A-Z][a-zA-Z0-9]*Node[A-Z]?[a-zA-Z0-9]*$/;
  const methodPattern = /^(.+)\.([^\.]+)\.([^\.]+)$/;
  
  for (const s of allStrings) {
    const value = s.value;
    if (!value || value.length < 3) continue;
    
    const parts = value.split('.');
    if (parts.length >= 3) {
      const className = parts[parts.length - 2];
      const methodName = parts[parts.length - 1];
      
      if (classPattern.test(className) && !methodName.startsWith('_')) {
        if (!classes.has(className)) {
          classes.set(className, []);
        }
        classes.get(className).push({
          name: methodName,
          qualifiedName: value,
          address: s.address,
        });
      }
    }
  }
  
  // 5. 显示结果
  log('\n📦 发现的类:', '\x1b[33m');
  
  if (classes.size === 0) {
    console.log('   (未发现类)');
  }
  
  for (const [className, methods] of classes) {
    console.log(`\n   ${className}:`);
    for (const method of methods.slice(0, 10)) {
      console.log(`     - ${method.name}`);
    }
    if (methods.length > 10) {
      console.log(`     ... 还有 ${methods.length - 10} 个方法`);
    }
  }
  
  // 6. 生成 Python 代码
  log('\n📝 生成的 Python 代码:', '\x1b[32m');
  
  const code = generatePythonCode(inspect, classes);
  console.log('\n' + code);
  
  return { inspect, classes, code };
}

function generatePythonCode(inspect, classes) {
  const lines = [];
  
  const moduleName = inspect.subject?.name?.replace('.pyd', '') || 'Module';
  
  lines.push('"""');
  lines.push(`${moduleName} - Auto-generated Python code`);
  lines.push('');
  lines.push('Generated from .pyd binary analysis');
  lines.push('NOTE: This code is inferred, not original source.');
  lines.push('"""');
  lines.push('');
  lines.push('from typing import Any, List, Dict, Optional, Tuple');
  lines.push('');
  
  for (const [className, methods] of classes) {
    lines.push('');
    lines.push(`class ${className}:`);
    lines.push('    """ComfyUI custom node class."""');
    lines.push('');
    lines.push('    @classmethod');
    lines.push('    def INPUT_TYPES(cls):');
    lines.push('        """Define node input types."""');
    lines.push('        return {');
    lines.push('            "required": {},');
    lines.push('            "optional": {},');
    lines.push('        }');
    lines.push('');
    
    for (const method of methods.slice(0, 20)) {
      lines.push('    @staticmethod');
      lines.push(`    def ${method.name}(self, *args, **kwargs) -> Any:`);
      lines.push(`        """Python method: ${method.qualifiedName}"""`);
      lines.push('        raise NotImplementedError("Implement based on analysis")');
      lines.push('');
    }
    
    lines.push('');
    lines.push('# ComfyUI Registration');
    lines.push('NODE_CLASS_MAPPINGS = {');
    lines.push(`    "${className}": ${className},`);
    lines.push('}');
    lines.push('NODE_DISPLAY_NAME_MAPPINGS = {');
    lines.push(`    "${className}": "${className.replace(/([A-Z])/g, ' $1').trim()}",`);
    lines.push('}');
  }
  
  return lines.join('\n');
}

// ============================================================================
// 主函数
// ============================================================================

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log(`
Cython .pyd 分析工具

使用方式:
  node scripts/analyze-pyd.mjs <file>           # 分析并输出代码
  node scripts/analyze-pyd.mjs <file> --json     # 输出 JSON 格式
  node scripts/analyze-pyd.mjs <file> --inspect # 仅概览
  node scripts/analyze-pyd.mjs <file> --decompile <func> # 反编译函数

环境变量:
  JAVA_HOME           Java 安装目录
  GHIDRA_INSTALL_DIR  Ghidra 安装目录
  `);
    process.exit(0);
  }
  
  const filePath = args[0];
  const options = args.slice(1);
  
  try {
    if (options.includes('--inspect')) {
      const result = await inspectPyd(filePath);
      console.log(JSON.stringify(result, null, 2));
    } else if (options.includes('--decompile')) {
      const funcName = options[options.indexOf('--decompile') + 1];
      if (!funcName) {
        console.error('Error: --decompile requires a function name');
        process.exit(1);
      }
      const pseudocode = await decompilePyd(filePath, funcName);
      if (pseudocode) {
        console.log(pseudocode);
      } else {
        console.error(`Error: Could not decompile ${funcName}`);
        process.exit(1);
      }
    } else if (options.includes('--json')) {
      const result = await analyzePyd(filePath);
      console.log(JSON.stringify(result, null, 2));
    } else {
      await analyzePyd(filePath);
    }
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();
