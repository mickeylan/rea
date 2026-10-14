import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, expect, it } from "vitest";

import type { AnalysisClient } from "../../../src/application/AnalysisProvider.js";
import { pe } from "../../../src/domain/binaryTarget.fixture.js";
import { ok } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import { observed } from "../../fixtures/analysisExecution.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const resources: Array<{ close(): Promise<unknown> }> = [];

afterEach(async () => {
  await Promise.all(resources.splice(0).map((resource) => resource.close()));
});

it("inspects one admitted pyd target through MCP in the retained session", async () => {
  const directory = await createTestTempDirectory("rea-cython-mcp-");
  const path = join(directory, "example.pyd");
  await writeFile(path, pe(0x8664, 64, 0x2002));

  const calls: string[] = [];
  const session = createTestBinarySession(
    () =>
      ({
        execute: (operation) => {
          calls.push(operation);
          if (operation === "list_names")
            return Promise.resolve(
              observed([
                { address: "0x1000", value: "PyInit_example" },
                { address: "0x1010", value: "__pyx_pw_1example" },
              ]),
            );
          if (operation === "list_strings")
            return Promise.resolve(
              observed([
                { address: "0x2000", value: "package.module.Widget.build" },
              ]),
            );
          return Promise.resolve(observed(null));
        },
        close: () => Promise.resolve(ok(null)),
      }) satisfies AnalysisClient,
  );
  const opened = await session.open(path);
  if (!opened.ok) throw opened.error;

  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "cython-extension-test", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  resources.push(client, server, session);
  await server.connect(serverTransport);
  await client.connect(clientTransport);

  const response = await client.callTool({
    name: "inspect_cython_extension",
    arguments: {},
  });

  expect(response.isError).not.toBe(true);
  expect(response.structuredContent).toMatchObject({
    subject: {
      local_path: path,
      format: "pe",
      architecture: "x86_64",
    },
    provider: { id: "rea-workflow" },
    operation: "inspect_cython_extension",
    confidence: "derived",
    normalized_result: {
      python_extension: {
        status: "confirmed",
        module_names: ["example"],
      },
      cython: { status: "detected" },
      coverage: {
        names_examined: 2,
        strings_examined: 1,
        complete: true,
      },
    },
  });
  expect(calls).toEqual(["health", "list_names", "list_strings"]);
});
