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

it("retains a complete parameter-bound branch as a candidate, not a final range", async () => {
  const dossier = ghidraFunctionDossier() as Record<string, JsonValue>;
  const comparison = {
    id: "0x401000#0",
    address: "0x401000",
    sequence: 0,
    opcode: "INT_SLESS",
    is_dead: false,
    block_membership: "member",
    block_id: "block:0",
    input_definitions_complete: true,
    inputs: [
      {
        kind: "register",
        size_bytes: 8,
        location: "register:0x8",
        constant_hex: null,
      },
      {
        kind: "constant",
        size_bytes: 8,
        location: null,
        constant_hex: "11",
      },
    ],
    output: {
      kind: "unique",
      size_bytes: 1,
      location: "unique:0x10",
      constant_hex: null,
    },
  };
  const branch = {
    id: "0x401004#1",
    address: "0x401004",
    sequence: 1,
    opcode: "CBRANCH",
    is_dead: false,
    block_membership: "member",
    block_id: "block:0",
    input_definitions_complete: true,
    inputs: [
      {
        kind: "address",
        size_bytes: 8,
        location: "0x401020",
        constant_hex: null,
      },
      comparison.output,
    ],
    output: null,
  };
  const result = await new GhidraCythonWrapperConventionAdapter(
    new RecordingAnalysis({
      ...dossier,
      native_value_flow: {
        available: true,
        provenance: "ghidra-high-pcode",
        operations: [comparison, branch],
        blocks: [
          {
            id: "block:0",
            start_address: "0x401000",
            operation_ids: [comparison.id, branch.id],
            successor_ids: ["block:1", "block:2"],
          },
          {
            id: "block:1",
            start_address: "0x401010",
            operation_ids: [],
            successor_ids: [],
          },
          {
            id: "block:2",
            start_address: "0x401020",
            operation_ids: [],
            successor_ids: [],
          },
        ],
        def_use: [
          { definition: comparison.id, use: branch.id, input_index: 1 },
        ],
        effects: [
          {
            operation: branch.id,
            kind: "conditional_branch",
            operand_input: null,
            value_input: 1,
            branch_target_block: "block:2",
            branch_fallthrough_block: "block:1",
          },
        ],
        parameters: [{ ordinal: 2, name: "param_3", data_type: "/longlong" }],
        parameter_uses: [{ ordinal: 2, use: comparison.id, input_index: 0 }],
        semantic_roots_total: 2,
        semantic_roots_retained: 2,
        truncated: false,
        omitted_operations_lower_bound: 0,
        known_omitted_inputs: 0,
        known_omitted_edges: 0,
        limitations: ["Fixture structured flow."],
      },
    }),
  ).observe("0x401000");

  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.result).toMatchObject({
    positional_bounds: [],
    integer_bound_candidates: [
      {
        parameter_ordinal: 2,
        comparison: "signed-less-than",
        parameter_operand: "left",
        constant: 17,
        comparison_address: "0x401000",
        branch_address: "0x401004",
        taken_block: "block:2",
        fallthrough_block: "block:1",
      },
    ],
  });
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
