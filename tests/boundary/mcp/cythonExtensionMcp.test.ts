import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, expect, it } from "vitest";

import {
  createAnalysisExecution,
  type AnalysisClient,
} from "../../../src/application/AnalysisProvider.js";
import { createAnalysisProfile } from "../../../src/domain/analysisProfile.js";
import { analysisErrorProjectionSchema } from "../../../src/contracts/errorSchemas.js";
import { pe } from "../../../src/domain/binaryTarget.fixture.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { ok } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import { observed } from "../../fixtures/analysisExecution.js";
import { advertisedMcpToolSchemas } from "../../fixtures/advertisedMcpTool.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const resources: Array<{ close(): Promise<unknown> }> = [];

const responseText = (response: { readonly content: readonly unknown[] }) =>
  response.content
    .flatMap((part) =>
      typeof part === "object" &&
      part !== null &&
      "text" in part &&
      typeof part.text === "string"
        ? [part.text]
        : [],
    )
    .join("");

afterEach(async () => {
  await Promise.all(resources.splice(0).map((resource) => resource.close()));
});

const connectSessionServer = async (
  session: ReturnType<typeof createTestBinarySession>,
): Promise<Client> => {
  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "cython-extension-test", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  resources.push(client, server, session);
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return client;
};

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

  const client = await connectSessionServer(session);
  const schemas = await advertisedMcpToolSchemas(
    client,
    "inspect_cython_extension",
  );
  expect(schemas.ajv.validate(schemas.inputSchema, {})).toBe(true);
  expect(schemas.ajv.validate(schemas.inputSchema, { unexpected: true })).toBe(
    false,
  );

  const response = await client.callTool({
    name: "inspect_cython_extension",
    arguments: {},
  });

  expect(response.isError).not.toBe(true);
  expect(
    schemas.ajv.validate(schemas.outputSchema, response.structuredContent),
    JSON.stringify(schemas.ajv.errors),
  ).toBe(true);
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
  const evidence = parseEvidence(response.structuredContent);
  expect(
    session
      .exportEvidenceBundle()
      .records.some((record) => record.evidence_id === evidence.evidence_id),
  ).toBe(true);
});

it("rejects unknown input fields before provider execution", async () => {
  const calls: string[] = [];
  const session = createTestBinarySession(
    () =>
      ({
        execute: (operation) => {
          calls.push(operation);
          return Promise.resolve(observed([]));
        },
        close: () => Promise.resolve(ok(null)),
      }) satisfies AnalysisClient,
  );
  const client = await connectSessionServer(session);

  const response = await client.callTool({
    name: "inspect_cython_extension",
    arguments: { unexpected: true },
  });

  expect(response.isError).toBe(true);
  expect(response.structuredContent).toBeUndefined();
  expect(calls).toEqual([]);
});

it("fails fast on malformed names without requesting strings", async () => {
  const directory = await createTestTempDirectory("rea-cython-mcp-malformed-");
  const path = join(directory, "malformed.pyd");
  await writeFile(path, pe(0x8664, 64, 0x2002));
  const calls: string[] = [];
  const session = createTestBinarySession(
    () =>
      ({
        execute: (operation) => {
          calls.push(operation);
          return Promise.resolve(
            observed(operation === "list_names" ? { invalid: true } : []),
          );
        },
        close: () => Promise.resolve(ok(null)),
      }) satisfies AnalysisClient,
  );
  const opened = await session.open(path);
  if (!opened.ok) throw opened.error;
  const client = await connectSessionServer(session);

  const response = await client.callTool({
    name: "inspect_cython_extension",
    arguments: {},
  });

  expect(response.isError).toBe(true);
  const error = analysisErrorProjectionSchema.parse(
    JSON.parse(responseText(response)).error,
  );
  expect(error.code).toBe("unreadable_output");
  expect(calls).toEqual(["health", "list_names"]);
});

it("stops between inventories on MCP cancellation without retaining partial Evidence", async () => {
  const directory = await createTestTempDirectory("rea-cython-mcp-cancel-");
  const path = join(directory, "cancelled.pyd");
  await writeFile(path, pe(0x8664, 64, 0x2002));
  const calls: string[] = [];
  let notifyStarted: (() => void) | undefined;
  const started = new Promise<void>((resolve) => {
    notifyStarted = resolve;
  });
  const session = createTestBinarySession(
    () =>
      ({
        execute: (operation, _parameters, options) => {
          calls.push(operation);
          if (operation === "health") return Promise.resolve(observed(null));
          if (operation !== "list_names") return Promise.resolve(observed([]));
          notifyStarted?.();
          return new Promise((resolve) => {
            options?.signal?.addEventListener(
              "abort",
              () =>
                resolve(
                  observed([{ address: "0x1000", value: "PyInit_cancelled" }]),
                ),
              { once: true },
            );
          });
        },
        close: () => Promise.resolve(ok(null)),
      }) satisfies AnalysisClient,
  );
  const opened = await session.open(path);
  if (!opened.ok) throw opened.error;
  const client = await connectSessionServer(session);
  const controller = new AbortController();

  const request = client.callTool(
    { name: "inspect_cython_extension", arguments: {} },
    { signal: controller.signal },
  );
  await started;
  controller.abort();

  await expect(request).rejects.toThrow();
  await expect.poll(() => calls).toEqual(["health", "list_names"]);
  expect(session.exportEvidenceBundle().records).toEqual([]);
});

it("rejects inventories produced under different analysis profiles", async () => {
  const directory = await createTestTempDirectory("rea-cython-mcp-profile-");
  const path = join(directory, "profile-mismatch.pyd");
  await writeFile(path, pe(0x8664, 64, 0x2002));
  const provider = { id: "fixture", name: "Fixture", version: "1" };
  const namesProfile = createAnalysisProfile(provider, { fixture: "names" });
  const stringsProfile = createAnalysisProfile(provider, {
    fixture: "strings",
  });
  const calls: string[] = [];
  const session = createTestBinarySession(
    () =>
      ({
        execute: (operation) => {
          calls.push(operation);
          const value =
            operation === "list_names"
              ? [{ address: "0x1000", value: "PyInit_profile_mismatch" }]
              : operation === "list_strings"
                ? []
                : null;
          return Promise.resolve(
            ok(
              createAnalysisExecution(value, provider, {
                analysisProfile:
                  operation === "list_strings" ? stringsProfile : namesProfile,
              }),
            ),
          );
        },
        close: () => Promise.resolve(ok(null)),
      }) satisfies AnalysisClient,
  );
  const opened = await session.open(path);
  if (!opened.ok) throw opened.error;
  const client = await connectSessionServer(session);

  const response = await client.callTool({
    name: "inspect_cython_extension",
    arguments: {},
  });

  expect(response.isError).toBe(true);
  const error = analysisErrorProjectionSchema.parse(
    JSON.parse(responseText(response)).error,
  );
  expect(error.code).toBe("unreadable_output");
  expect(calls).toEqual(["health", "list_names", "list_strings"]);
});

it("rejects a native PE target that is not a pyd before inventory work", async () => {
  const directory = await createTestTempDirectory("rea-cython-mcp-target-");
  const path = join(directory, "example.dll");
  await writeFile(path, pe(0x8664, 64, 0x2002));
  const calls: string[] = [];
  const session = createTestBinarySession(
    () =>
      ({
        execute: (operation) => {
          calls.push(operation);
          return Promise.resolve(observed([]));
        },
        close: () => Promise.resolve(ok(null)),
      }) satisfies AnalysisClient,
  );
  const opened = await session.open(path);
  if (!opened.ok) throw opened.error;
  const client = await connectSessionServer(session);

  const response = await client.callTool({
    name: "inspect_cython_extension",
    arguments: {},
  });

  expect(response.isError).toBe(true);
  const error = analysisErrorProjectionSchema.parse(
    JSON.parse(responseText(response)).error,
  );
  expect(error).toMatchObject({
    code: "unsupported_target",
    details: { path },
  });
  expect(calls).toEqual(["health"]);
});

it("fails closed before provider execution without an active target", async () => {
  const calls: string[] = [];
  const session = createTestBinarySession(
    () =>
      ({
        execute: (operation) => {
          calls.push(operation);
          return Promise.resolve(observed([]));
        },
        close: () => Promise.resolve(ok(null)),
      }) satisfies AnalysisClient,
  );
  const client = await connectSessionServer(session);

  const response = await client.callTool({
    name: "inspect_cython_extension",
    arguments: {},
  });

  expect(response.isError).toBe(true);
  const error = analysisErrorProjectionSchema.parse(
    JSON.parse(responseText(response)).error,
  );
  expect(error.code).toBe("unreadable_output");
  expect(calls).toEqual([]);
});
