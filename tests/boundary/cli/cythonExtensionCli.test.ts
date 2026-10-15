import pino from "pino";
import { expect, it, vi } from "vitest";

import { registerCoreBinaryCommands } from "../../../src/cli/coreBinaryCommands.js";
import type { CliInstance } from "../../../src/cli/types.js";
import { CLI_COMMANDS } from "../../../src/cliCommandNames.js";
import type { DirectAnalysis } from "../../../src/composition/directAnalysis.js";

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
