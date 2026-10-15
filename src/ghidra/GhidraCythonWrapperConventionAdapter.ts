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
