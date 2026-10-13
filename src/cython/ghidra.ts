/**
 * Cython .pyd Ghidra 分析会话
 *
 * 封装与 Ghidra Provider 的交互
 */

import { spawn } from "child_process";
import type { ChildProcess } from "child_process";

// ============================================================================
// 类型定义
// ============================================================================

export interface SearchResult {
  address: string;
  value: string;
  type: "string" | "procedure";
}

export interface FunctionInfo {
  address: string;
  name: string;
  signature: string;
  pseudocode: string;
  callers: string[];
  callees: string[];
}

export interface Reference {
  sourceAddress: string;
  targetAddress: string;
  targetName: string;
  containingProcedure: string | null;
}

export interface InspectionResult {
  artifact: {
    path: string;
    sha256: string;
    bytes: number;
    format: string;
    architecture: string;
  };
  normalized_result: {
    document: string;
    procedure_count: number;
    string_count: number;
  };
}

export interface GhidraOptions {
  javaHome?: string;
  ghidraInstallDir?: string;
  timeout?: number;
}

// ============================================================================
// Ghidra 会话
// ============================================================================

/**
 * Ghidra 分析会话
 *
 * 封装 REA CLI 命令的执行
 */
export class GhidraSession {
  private javaHome: string;
  private ghidraInstallDir: string;
  private timeout: number;

  constructor(options: GhidraOptions = {}) {
    this.javaHome =
      options.javaHome || process.env.JAVA_HOME || "D:\\Java\\openjdk-23.0.2";
    this.ghidraInstallDir =
      options.ghidraInstallDir ||
      process.env.GHIDRA_INSTALL_DIR ||
      "D:\\dev_tools\\ghidra";
    this.timeout = options.timeout || 120000;
  }

  /**
   * 执行 REA 命令
   */
  private async runRea(
    args: string[],
  ): Promise<{ code: number; stdout: string; stderr: string }> {
    const env: Record<string, string> = {
      ...(process.env as Record<string, string>),
      JAVA_HOME: this.javaHome,
      GHIDRA_INSTALL_DIR: this.ghidraInstallDir,
    };

    return new Promise((resolve) => {
      // 尝试多个可能的 rea 命令位置
      const reaCommands = ["rea", "rea.cmd", "D:\\npm-global\\rea.cmd"];

      let tried = 0;

      const tryCommand = (cmd: string) => {
        let proc: ChildProcess;

        try {
          proc = spawn(cmd, args, { env: env as any, shell: true });
        } catch {
          if (tried < reaCommands.length - 1) {
            tried++;
            tryCommand(reaCommands[tried]!);
            return;
          }
          resolve({ code: 1, stdout: "", stderr: "Failed to spawn process" });
          return;
        }

        let stdout = "";
        let stderr = "";

        proc.stdout?.on("data", (data) => {
          stdout += data.toString();
        });
        proc.stderr?.on("data", (data) => {
          stderr += data.toString();
        });

        proc.on("close", (code) => {
          if (code === 0 || (stdout && stdout.includes("error"))) {
            resolve({ code: code || 0, stdout, stderr });
          } else if (tried < reaCommands.length - 1) {
            tried++;
            tryCommand(reaCommands[tried]!);
          } else {
            resolve({ code: code || 1, stdout, stderr });
          }
        });

        proc.on("error", () => {
          if (tried < reaCommands.length - 1) {
            tried++;
            tryCommand(reaCommands[tried]!);
          } else {
            resolve({ code: 1, stdout, stderr });
          }
        });
      };

      tryCommand(reaCommands[0]!);
    });
  }

  /**
   * 检查文件
   */
  async inspect(filePath: string): Promise<InspectionResult | null> {
    try {
      const result = await this.runRea([
        "inspect",
        filePath,
        "--provider",
        "ghidra",
        "--json",
      ]);

      if (result.code !== 0 || !result.stdout.trim()) {
        return null;
      }

      return JSON.parse(result.stdout) as InspectionResult;
    } catch (error) {
      console.error("Inspect failed:", error);
      return null;
    }
  }

  /**
   * 搜索字符串或函数
   */
  async search(filePath: string, pattern: string): Promise<SearchResult[]> {
    try {
      const result = await this.runRea([
        "search",
        filePath,
        pattern,
        "--provider",
        "ghidra",
        "--json",
      ]);

      if (result.code !== 0 || !result.stdout.trim()) {
        return [];
      }

      const data = JSON.parse(result.stdout);
      return (data.normalized_result || []) as SearchResult[];
    } catch (error) {
      console.error("Search failed:", error);
      return [];
    }
  }

  /**
   * 反编译函数
   */
  async decompile(
    filePath: string,
    functionName: string,
  ): Promise<string | null> {
    try {
      const result = await this.runRea([
        "decompile",
        filePath,
        functionName,
        "--provider",
        "ghidra",
        "--json",
      ]);

      if (result.code !== 0 || !result.stdout.trim()) {
        return null;
      }

      const data = JSON.parse(result.stdout);
      return (data.normalized_result?.pseudocode as string) || null;
    } catch (error) {
      console.error("Decompile failed:", error);
      return null;
    }
  }

  /**
   * 追踪引用
   */
  async trace(filePath: string, pattern: string): Promise<Reference[]> {
    try {
      const result = await this.runRea([
        "trace",
        filePath,
        pattern,
        "--provider",
        "ghidra",
        "--json",
      ]);

      if (result.code !== 0 || !result.stdout.trim()) {
        return [];
      }

      const data = JSON.parse(result.stdout);
      return (data.normalized_result || []) as Reference[];
    } catch (error) {
      console.error("Trace failed:", error);
      return [];
    }
  }

  /**
   * 获取函数信息
   */
  async getFunction(
    filePath: string,
    functionName: string,
  ): Promise<FunctionInfo | null> {
    const pseudocode = await this.decompile(filePath, functionName);
    const refs = await this.trace(filePath, functionName);

    if (!pseudocode) {
      return null;
    }

    return {
      address: refs[0]?.sourceAddress || "",
      name: functionName,
      signature: `unknown ${functionName}()`,
      pseudocode,
      callers: refs
        .filter((r) => r.targetName === functionName)
        .map((r) => r.sourceAddress),
      callees: refs
        .filter((r) => r.sourceAddress === functionName)
        .map((r) => r.targetName),
    };
  }
}

// ============================================================================
// 工厂函数
// ============================================================================

/**
 * 创建 Ghidra 会话
 */
export function createGhidraSession(options?: GhidraOptions): GhidraSession {
  return new GhidraSession(options);
}
