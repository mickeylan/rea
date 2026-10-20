import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import pino from "pino";
import { expect, it, vi } from "vitest";

import {
  createAnalysisExecution,
  type AnalysisProvider,
} from "../../../src/application/AnalysisProvider.js";
import { runDirectAnalysis as executeDirectAnalysis } from "../../../src/application/DirectAnalysis.js";
import { registerCoreBinaryCommands } from "../../../src/cli/coreBinaryCommands.js";
import type { CliInstance } from "../../../src/cli/types.js";
import { CLI_COMMANDS } from "../../../src/cliCommandNames.js";
import type { DirectAnalysis } from "../../../src/composition/directAnalysis.js";
import { parseConfig } from "../../../src/config/parseConfig.js";
import { createAnalysisProfile } from "../../../src/domain/analysisProfile.js";
import { pe } from "../../../src/domain/binaryTarget.fixture.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { ok } from "../../../src/domain/result.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

it("dispatches Cython extension inspection with exact native-open choices", async () => {
  const commands = new Map<
    string,
    {
      run(input: {
        args: { path: string };
        options: {
          snapshot?: string;
          provider?: "ghidra";
          "target-format"?: "pe";
          architecture?: "x86_64";
          "entry-point"?: string;
        };
      }): Promise<unknown>;
    }
  >();
  const cli = {
    command: (name: string, definition: unknown) => {
      commands.set(
        name,
        definition as typeof commands extends Map<string, infer V> ? V : never,
      );
      return cli;
    },
  } as unknown as CliInstance;
  const logger = pino({ enabled: false });
  const output = { observed: true };
  const runDirectAnalysis = vi.fn(
    async () => output,
  ) as unknown as DirectAnalysis["runDirectAnalysis"];
  registerCoreBinaryCommands(cli, logger, runDirectAnalysis);
  const command = commands.get(CLI_COMMANDS.inspectCythonExtension);
  if (command === undefined)
    throw new Error("Cython extension CLI command was not registered");

  const result = await command.run({
    args: { path: "./fixture.pyd" },
    options: {
      snapshot: "./fixture.snapshot.json",
      provider: "ghidra",
      "target-format": "pe",
      architecture: "x86_64",
      "entry-point": "0x180001000",
    },
  });

  expect(result).toBe(output);
  expect(runDirectAnalysis).toHaveBeenCalledExactlyOnceWith(
    "./fixture.pyd",
    "inspect_cython_extension",
    {},
    {
      logger,
      snapshotPath: "./fixture.snapshot.json",
      providerId: "ghidra",
      formatHint: "pe",
      architecture: "x86_64",
      entryPoint: "0x180001000",
    },
  );
});

it("executes Cython inspection through the one-shot CLI lifecycle", async () => {
  const directory = await createTestTempDirectory("rea-cython-cli-");
  const path = join(directory, "fixture.pyd");
  await writeFile(path, pe(0x8664, 64, 0x2002));
  const identity = { id: "fixture", name: "Fixture", version: "1" } as const;
  const profile = createAnalysisProfile(identity, { fixture: true });
  const calls: string[] = [];
  let starts = 0;
  let closes = 0;
  const provider: AnalysisProvider = {
    identity: () => identity,
    resolveAnalysisProfile: () => Promise.resolve(ok({ profile })),
    capabilities: () =>
      (["list_names", "list_strings"] as const).map((operation) => ({
        operation,
        provider: identity,
        available: true,
        reason: null,
        cachePolicy: "snapshot" as const,
        effects: {
          mutatesArtifact: false,
          launchesProcess: false,
          mayShowUi: false,
          mayAccessNetwork: false,
          mayWriteFilesystem: false,
          changesPermissions: false,
          requiresRoot: false,
        },
        limitations: [],
      })),
    createClient: () => {
      starts += 1;
      return {
        execute: (operation) => {
          calls.push(operation);
          const value =
            operation === "list_names"
              ? [
                  { address: "0x1000", value: "PyInit_fixture" },
                  { address: "0x1010", value: "__pyx_pw_1fixture" },
                ]
              : operation === "list_strings"
                ? [{ address: "0x2000", value: "package.Widget.build" }]
                : null;
          return Promise.resolve(
            ok(
              createAnalysisExecution(value, identity, {
                analysisProfile: profile,
              }),
            ),
          );
        },
        close: () => {
          closes += 1;
          return Promise.resolve(ok(null));
        },
      };
    },
  };
  const createSession = () => createTestBinarySession(provider);
  const dependencies = {
    readConfiguration: () => parseConfig({}),
    createBinarySession: createSession,
    createNativeDispatchBinarySession: createSession,
    createArtifactBinarySession: createSession,
    createNativeBinarySession: createSession,
    createManagedBinarySession: createSession,
  };
  const logger = pino({ enabled: false });
  const runDirectAnalysis: DirectAnalysis["runDirectAnalysis"] = (
    inputPath,
    tool,
    arguments_,
    options,
  ) =>
    executeDirectAnalysis(dependencies, inputPath, tool, arguments_, options);

  const commands = new Map<string, { run(input: unknown): Promise<unknown> }>();
  const cli = {
    command: (name: string, definition: unknown) => {
      commands.set(
        name,
        definition as { run(input: unknown): Promise<unknown> },
      );
      return cli;
    },
  } as unknown as CliInstance;
  registerCoreBinaryCommands(cli, logger, runDirectAnalysis);
  const command = commands.get(CLI_COMMANDS.inspectCythonExtension);
  if (command === undefined)
    throw new Error("Cython command was not registered");

  const output = await command.run({ args: { path }, options: {} });
  const evidence = parseEvidence(output);

  expect(evidence).toMatchObject({
    operation: "inspect_cython_extension",
    provider: { id: "rea-workflow" },
    normalized_result: {
      python_extension: { status: "confirmed", module_names: ["fixture"] },
      cython: { status: "detected" },
    },
  });
  expect(starts).toBe(1);
  expect(calls).toEqual(["list_names", "list_strings"]);
  expect(closes).toBe(1);
});
