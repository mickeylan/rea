import { expect, it } from "vitest";

import type {
  AnalysisOperation,
  AnalysisOperationPort,
  ExecutionOptions,
} from "../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import { createAnalysisProfile } from "../domain/analysisProfile.js";
import {
  ghidraFunctionDossier,
  ghidraFunctionIdentity,
} from "../domain/ghidraValues.fixture.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { ok } from "../domain/result.js";
import { GhidraCythonWrapperConventionAdapter } from "./GhidraCythonWrapperConventionAdapter.js";

const provider = { id: "ghidra", name: "Ghidra", version: "12.1.4" };
const profile = createAnalysisProfile(provider, { fixture: true });

class RecordingAnalysis implements AnalysisOperationPort {
  readonly calls: Array<{
    operation: AnalysisOperation;
    parameters: Readonly<Record<string, JsonValue>>;
  }> = [];

  constructor(private readonly result: unknown) {}

  execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    _options?: ExecutionOptions,
  ) {
    this.calls.push({ operation, parameters });
    return Promise.resolve(
      ok(
        createAnalysisExecution(this.result, provider, {
          analysisProfile: profile,
          limitations: ["provider limitation"],
          locations: [{ kind: "address", address: "0x401000" }],
        }),
      ),
    );
  }
}

it("retains structured Ghidra callees as candidates without parsing pseudocode", async () => {
  const base = ghidraFunctionDossier() as Record<string, JsonValue>;
  const procedure = ghidraFunctionIdentity();
  const callee = {
    ...ghidraFunctionIdentity(),
    address: "0x401020",
    name: "__pyx_pf_1module_build",
    body: {
      available: true,
      provenance: "ghidra-function-body-address-set",
      ranges: [{ start: "0x401020", end: "0x401025" }],
      total_bytes: 6,
      span_bytes: 6,
      non_contiguous: false,
      contains_entry: true,
    },
  };
  const reference = {
    source_address: "0x401004",
    target_address: "0x401020",
    source_procedure: procedure,
    target_procedure: callee,
    kind: {
      available: true,
      provenance: "ghidra-reference-manager",
      type: "UNCONDITIONAL_CALL",
      flow: true,
      call: true,
      jump: false,
      data: false,
      read: false,
      write: false,
      indirect: false,
      computed: false,
      conditional: false,
      terminal: false,
      primary: true,
      operand_index: 0,
      external: false,
    },
  };
  const analysis = new RecordingAnalysis({
    ...base,
    pseudocode: "this text is deliberately not parsed",
    callees: [callee],
    outgoing_references: [reference],
  });

  const result = await new GhidraCythonWrapperConventionAdapter(
    analysis,
  ).observe("0x401000");

  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(analysis.calls).toEqual([
    {
      operation: "analyze_function",
      parameters: { procedure: "0x401000" },
    },
  ]);
  expect(result.value.result).toMatchObject({
    wrapper: { address: "0x401000", name: "fixture_main" },
    callable_names: [],
    positional_bounds: [],
    keyword_orders: [],
    slots: [],
    implementation_candidates: [
      {
        address: "0x401020",
        name: "__pyx_pf_1module_build",
        relationship: "callee",
        confidence: "candidate",
        evidence_addresses: ["0x401004"],
      },
    ],
    coverage: {
      wrapper_complete: true,
      parser_paths_complete: false,
      truncated: false,
    },
  });
  expect(result.value.analysisProfile).toEqual(profile);
  expect(result.value.limitations).toContain("provider limitation");
});

it("fails closed on a malformed function dossier", async () => {
  const result = await new GhidraCythonWrapperConventionAdapter(
    new RecordingAnalysis({ invalid: true }),
  ).observe("0x401000");

  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error._tag).toBe("AnalysisOutputError");
});

it("reports unavailable value flow instead of inventing convention facts", async () => {
  const dossier = ghidraFunctionDossier() as Record<string, JsonValue>;
  const result = await new GhidraCythonWrapperConventionAdapter(
    new RecordingAnalysis({
      ...dossier,
      native_value_flow: {
        available: false,
        reason: "Decompiler unavailable",
        limitations: ["No structured value flow."],
      },
    }),
  ).observe("0x401000");

  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.result).toMatchObject({
    positional_bounds: [],
    keyword_orders: [],
    slots: [],
    coverage: { parser_paths_complete: false, truncated: false },
  });
  expect(result.value.limitations).toContain(
    "Structured native value flow was unavailable for this wrapper.",
  );
});
