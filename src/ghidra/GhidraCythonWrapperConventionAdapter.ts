import type {
  AnalysisOperationPort,
  ExecutionOptions,
} from "../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import type { CythonWrapperConventionPort } from "../application/cython/CythonWrapperConventionPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import {
  cythonWrapperConventionObservationSchema,
  type CythonWrapperConventionObservation,
} from "../domain/cythonExtension.js";
import { functionDossierSchema } from "../domain/hopperValues.js";
import { err, ok, type Result } from "../domain/result.js";

const OPERATION = "inspect_cython_wrapper_convention";

/** Adapt one retained Ghidra function dossier without parsing pseudocode text. */
export class GhidraCythonWrapperConventionAdapter implements CythonWrapperConventionPort {
  constructor(private readonly analysis: AnalysisOperationPort) {}

  async observe(
    wrapper: string,
    options?: ExecutionOptions,
  ): Promise<
    Result<
      Awaited<
        ReturnType<CythonWrapperConventionPort["observe"]>
      > extends Result<infer Execution, AnalysisError>
        ? Execution
        : never,
      AnalysisError
    >
  > {
    const execution = await this.analysis.execute(
      "analyze_function",
      { procedure: wrapper },
      options,
    );
    if (!execution.ok) return execution;
    const parsed = functionDossierSchema.safeParse(execution.value.result);
    if (!parsed.success)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Ghidra returned a malformed function dossier for the selected wrapper.",
          { cause: parsed.error },
        ),
      );
    const observation = observeDossier(parsed.data);
    return ok(
      createAnalysisExecution(observation, execution.value.provider, {
        ...(execution.value.analysisProfile === undefined
          ? {}
          : { analysisProfile: execution.value.analysisProfile }),
        limitations: [
          ...execution.value.limitations,
          ...observation.limitations,
        ],
        locations: execution.value.locations,
        ...(execution.value.subject === null
          ? {}
          : { subject: execution.value.subject }),
      }),
    );
  }
}

type FunctionDossier = ReturnType<typeof functionDossierSchema.parse>;
type AvailableValueFlow = Extract<
  NonNullable<FunctionDossier["native_value_flow"]>,
  { available: true }
>;

const comparisonNames = {
  INT_EQUAL: "equal",
  INT_NOTEQUAL: "not-equal",
  INT_LESS: "less-than",
  INT_LESSEQUAL: "less-than-or-equal",
  INT_SLESS: "signed-less-than",
  INT_SLESSEQUAL: "signed-less-than-or-equal",
} as const;

const observeIntegerBoundCandidates = (flow: AvailableValueFlow) => {
  const operations = new Map(
    flow.operations.map((operation) => [operation.id, operation]),
  );
  return flow.effects.flatMap((effect) => {
    if (
      effect.kind !== "conditional_branch" ||
      effect.value_input === null ||
      effect.branch_target_block === null ||
      effect.branch_fallthrough_block === null
    )
      return [];
    const branch = operations.get(effect.operation);
    if (branch?.input_definitions_complete !== true) return [];
    const conditionEdge = flow.def_use.find(
      ({ use, input_index }) =>
        use === effect.operation && input_index === effect.value_input,
    );
    if (conditionEdge === undefined) return [];
    const comparison = operations.get(conditionEdge.definition);
    if (
      comparison === undefined ||
      comparison.input_definitions_complete !== true ||
      !(comparison.opcode in comparisonNames) ||
      comparison.inputs.length !== 2
    )
      return [];
    const constantIndex = comparison.inputs.findIndex(
      ({ kind, constant_hex }) => kind === "constant" && constant_hex !== null,
    );
    if (
      constantIndex < 0 ||
      comparison.inputs[1 - constantIndex]?.kind === "constant"
    )
      return [];
    const parameterUse = flow.parameter_uses.find(
      ({ use, input_index }) =>
        use === comparison.id && input_index === 1 - constantIndex,
    );
    if (parameterUse === undefined) return [];
    const constant = parseComparisonConstant(
      comparison.inputs[constantIndex]!,
      comparison.opcode.startsWith("INT_S"),
    );
    if (constant === null) return [];
    return [
      {
        parameter_ordinal: parameterUse.ordinal,
        comparison:
          comparisonNames[comparison.opcode as keyof typeof comparisonNames],
        parameter_operand:
          constantIndex === 1 ? ("left" as const) : ("right" as const),
        constant,
        comparison_address: comparison.address,
        branch_address: branch.address,
        taken_block: effect.branch_target_block,
        fallthrough_block: effect.branch_fallthrough_block,
      },
    ];
  });
};

type AvailableNativeApi = Extract<
  NonNullable<FunctionDossier["native_api"]>,
  { available: true }
>;

const observeJumpTableCandidates = (
  flow: AvailableValueFlow,
  tables: AvailableNativeApi["jump_tables"],
  dossier: FunctionDossier,
) => {
  const operationsByAddress = new Map<
    string,
    AvailableValueFlow["operations"]
  >();
  for (const operation of flow.operations) {
    const existing = operationsByAddress.get(operation.address) ?? [];
    existing.push(operation);
    operationsByAddress.set(operation.address, existing);
  }
  return tables.flatMap((table) => {
    const dispatches = (
      operationsByAddress.get(table.dispatch_address) ?? []
    ).filter(
      ({ opcode, input_definitions_complete }) =>
        opcode === "BRANCHIND" && input_definitions_complete,
    );
    if (dispatches.length !== 1) return [];
    const dispatch = dispatches[0]!;
    const parameterUses = flow.parameter_uses.filter(
      ({ use, input_index }) => use === dispatch.id && input_index === 0,
    );
    if (parameterUses.length !== 1) return [];
    const knownCaseValues = [
      ...new Set(
        table.mappings.flatMap(({ case_value }) =>
          case_value === null ? [] : [case_value],
        ),
      ),
    ].sort((left, right) => left - right);
    const entryCounts = [
      ...new Set(
        table.data_sources.flatMap(({ entry_count }) =>
          entry_count === null ? [] : [entry_count],
        ),
      ),
    ].sort((left, right) => left - right);
    const contiguous = knownCaseValues.every(
      (value, index) =>
        index === 0 || value === knownCaseValues[index - 1]! + 1,
    );
    const reachability = createReachability(flow, dossier);
    return [
      {
        parameter_ordinal: parameterUses[0]!.ordinal,
        dispatch_address: table.dispatch_address,
        known_case_values: knownCaseValues,
        mappings: table.mappings.map(
          ({ case_value, target_address, confidence }) => ({
            case_value,
            target_address,
            confidence,
            ...reachability(target_address),
          }),
        ),
        default_targets: table.default_targets.map(
          ({ target_address, confidence }) => ({
            target_address,
            confidence,
            ...reachability(target_address),
          }),
        ),
        entry_counts: entryCounts,
        unknown_mapping_count: table.mappings.filter(
          ({ case_value }) => case_value === null,
        ).length,
        default_target_count: table.default_targets.length,
        cases_complete:
          entryCounts.length === 1 &&
          knownCaseValues.length === entryCounts[0] &&
          contiguous,
        default_known: table.default_targets.length > 0,
      },
    ];
  });
};

const createReachability = (
  flow: AvailableValueFlow,
  dossier: FunctionDossier,
) => {
  const blocksByStart = new Map(
    flow.blocks.map((block) => [block.start_address, block]),
  );
  const blocksById = new Map(flow.blocks.map((block) => [block.id, block]));
  const operations = new Map(
    flow.operations.map((operation) => [operation.id, operation]),
  );
  const callsBySite = new Map<
    string,
    { target_address: string; target_name: string | null }[]
  >();
  for (const reference of dossier.outgoing_references) {
    if (
      !reference.kind.available ||
      !reference.kind.call ||
      reference.target_procedure === null
    )
      continue;
    const calls = callsBySite.get(reference.source_address) ?? [];
    calls.push({
      target_address: reference.target_procedure.address,
      target_name: reference.target_procedure.name,
    });
    callsBySite.set(reference.source_address, calls);
  }
  const rootsComplete =
    flow.semantic_roots_retained === flow.semantic_roots_total;
  return (targetAddress: string) => {
    const start = blocksByStart.get(targetAddress);
    if (start === undefined)
      return { reachable_calls: [], reachability_complete: false };
    const pending = [start.id];
    const visited = new Set<string>();
    const calls = new Map<
      string,
      {
        call_site: string;
        target_address: string;
        target_name: string | null;
      }
    >();
    let complete = rootsComplete;
    while (pending.length > 0) {
      const blockId = pending.pop()!;
      if (visited.has(blockId)) continue;
      visited.add(blockId);
      const block = blocksById.get(blockId);
      if (block === undefined) {
        complete = false;
        continue;
      }
      for (const operationId of block.operation_ids) {
        const operation = operations.get(operationId);
        if (operation === undefined) {
          complete = false;
          continue;
        }
        if (operation.opcode !== "CALL") continue;
        for (const target of callsBySite.get(operation.address) ?? []) {
          const call = { call_site: operation.address, ...target };
          calls.set(JSON.stringify(call), call);
        }
      }
      for (const successor of block.successor_ids) pending.push(successor);
    }
    return {
      reachable_calls: [...calls.values()].sort(
        (left, right) =>
          left.call_site.localeCompare(right.call_site) ||
          left.target_address.localeCompare(right.target_address),
      ),
      reachability_complete: complete,
    };
  };
};

const parseComparisonConstant = (
  input: AvailableValueFlow["operations"][number]["inputs"][number],
  signed: boolean,
): number | null => {
  if (input.constant_hex === null || input.size_bytes < 1) return null;
  let value = BigInt(`0x${input.constant_hex}`);
  if (signed) {
    const bits = BigInt(input.size_bytes * 8);
    const sign = 1n << (bits - 1n);
    if ((value & sign) !== 0n) value -= 1n << bits;
  }
  const number = Number(value);
  return Number.isSafeInteger(number) ? number : null;
};

const observeDossier = (
  dossier: ReturnType<typeof functionDossierSchema.parse>,
): CythonWrapperConventionObservation => {
  const referencesByTarget = new Map<string, string[]>();
  for (const reference of dossier.outgoing_references) {
    if (
      !reference.kind.available ||
      reference.kind.call !== true ||
      reference.target_procedure === null
    )
      continue;
    const addresses =
      referencesByTarget.get(reference.target_procedure.address) ?? [];
    addresses.push(reference.source_address);
    referencesByTarget.set(reference.target_procedure.address, addresses);
  }
  const candidates = dossier.callees.map(({ address, name }) => ({
    address,
    name,
    relationship: "callee" as const,
    confidence: "candidate" as const,
    evidence_addresses: [
      ...new Set(
        referencesByTarget.get(address) ?? [dossier.procedure.address],
      ),
    ].sort(),
  }));
  const valueFlow = dossier.native_value_flow;
  const truncated = valueFlow?.available === true && valueFlow.truncated;

  return cythonWrapperConventionObservationSchema.parse({
    wrapper: {
      address: dossier.procedure.address,
      name: dossier.procedure.name,
    },
    callable_names: [],
    implementation_candidates: candidates,
    positional_bounds: [],
    integer_bound_candidates:
      valueFlow?.available === true
        ? observeIntegerBoundCandidates(valueFlow)
        : [],
    jump_table_candidates:
      valueFlow?.available === true && dossier.native_api?.available === true
        ? observeJumpTableCandidates(
            valueFlow,
            dossier.native_api.jump_tables,
            dossier,
          )
        : [],
    keyword_orders: [],
    slots: [],
    coverage: {
      wrapper_complete: dossier.procedure.body?.available === true,
      parser_paths_complete: false,
      truncated,
    },
    limitations: [
      "Ghidra direct callees are retained as implementation candidates; call membership alone does not prove wrapper/body ownership.",
      "The current structured dossier does not expose decoded Cython keyword tables, argument-count predicates, or default-slot assignments.",
      ...(valueFlow === null || valueFlow.available === false
        ? ["Structured native value flow was unavailable for this wrapper."]
        : [
            ...(valueFlow.semantic_roots_retained ===
            valueFlow.semantic_roots_total
              ? [
                  "All observed comparison, branch, call, and return roots were retained; their def-use ancestors may still be incomplete when the operation budget was reached.",
                ]
              : [
                  "The operation budget omitted observed comparison, branch, call, or return roots.",
                ]),
            ...valueFlow.limitations,
          ]),
    ],
  });
};
