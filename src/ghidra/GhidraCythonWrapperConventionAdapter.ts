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
