import { extname } from "node:path";
import { z } from "zod";

import type {
  AnalysisOperationPort,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
  AnalysisUnsupportedTargetError,
} from "../../domain/analysisErrorCore.js";
import {
  cythonExtensionInspectionSchema,
  inspectCythonExtensionInventories,
  type CythonExtensionObservation,
} from "../../domain/cythonExtension.js";
import type { BinaryTarget } from "../../domain/binaryTargetTypes.js";
import { analysisProfilesEqual } from "../../domain/analysisProfile.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { err, ok, type Result } from "../../domain/result.js";
import { addressedValue } from "../../contracts/toolOutputSchemaPrimitives.js";
import {
  REA_WORKFLOW_PROVIDER,
  workflowAnalysisProfile,
} from "../InvestigationProviders.js";

const OPERATION = "inspect_cython_extension";
const inventorySchema = z.array(addressedValue);

/** Compose complete native inventories into one conservative extension observation. */
export class CythonExtensionInspectionService {
  async inspect(
    analysis: AnalysisOperationPort,
    target: BinaryTarget,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const admission = admitTarget(target);
    if (!admission.ok) return admission;
    if (isAborted(options?.signal))
      return err(new AnalysisCancelledError(OPERATION));

    const namesExecution = await analysis.execute("list_names", {}, options);
    if (!namesExecution.ok) return namesExecution;
    if (isAborted(options?.signal))
      return err(new AnalysisCancelledError(OPERATION));

    const stringsExecution = await analysis.execute("list_strings", {}, options);
    if (!stringsExecution.ok) return stringsExecution;
    if (isAborted(options?.signal))
      return err(new AnalysisCancelledError(OPERATION));

    const names = parseInventory("list_names", namesExecution.value.result);
    if (!names.ok) return names;
    const strings = parseInventory("list_strings", stringsExecution.value.result);
    if (!strings.ok) return strings;

    const result = inspectCythonExtensionInventories({
      names: observations(names.value),
      strings: observations(strings.value),
      complete: true,
    });
    const profiles = [
      namesExecution.value.analysisProfile,
      stringsExecution.value.analysisProfile,
    ].filter((profile) => profile !== undefined);
    if (
      profiles.length === 2 &&
      !analysisProfilesEqual(profiles[0]!, profiles[1]!)
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Provider inventories were produced under different analysis profiles.",
        ),
      );
    const upstreamProfile = profiles[0];
    const limitations = unique([
      "Derived from complete provider name and defined-string inventories in one admitted binary session.",
      ...namesExecution.value.limitations,
      ...stringsExecution.value.limitations,
      ...result.limitations,
    ]);

    return ok(
      createEvidence(target, REA_WORKFLOW_PROVIDER, {
        operation: OPERATION,
        parameters: {},
        result: cythonExtensionInspectionSchema.parse(result),
        confidence: "derived",
        limitations,
        locations: uniqueLocations([
          ...namesExecution.value.locations,
          ...stringsExecution.value.locations,
        ]),
        ...(upstreamProfile === undefined
          ? {}
          : { analysisProfile: workflowAnalysisProfile(upstreamProfile) }),
      }),
    );
  }
}

const admitTarget = (
  target: BinaryTarget,
): Result<null, AnalysisUnsupportedTargetError> => {
  if (
    target.kind === "executable" &&
    target.format === "pe" &&
    target.executableRole === "shared-library" &&
    !target.managed &&
    extname(target.path).toLowerCase() === ".pyd"
  )
    return ok(null);
  return err(
    new AnalysisUnsupportedTargetError(
      OPERATION,
      target.path,
      "Expected an explicit native PE shared library whose selected path ends in .pyd.",
    ),
  );
};

const parseInventory = (
  operation: "list_names" | "list_strings",
  value: unknown,
): Result<z.infer<typeof inventorySchema>, AnalysisOutputError> => {
  const parsed = inventorySchema.safeParse(value);
  return parsed.success
    ? ok(parsed.data)
    : err(
        new AnalysisOutputError(
          OPERATION,
          `${operation} returned malformed address/value inventory.`,
          { cause: parsed.error },
        ),
      );
};

const observations = (
  values: z.infer<typeof inventorySchema>,
): CythonExtensionObservation[] =>
  values.map(({ address, value }) => ({ address, value }));

const unique = (values: readonly string[]): string[] => [...new Set(values)];

const uniqueLocations = <T>(values: readonly T[]): T[] => {
  const uniqueValues = new Map<string, T>();
  for (const value of values) uniqueValues.set(JSON.stringify(value), value);
  return [...uniqueValues.values()];
};

const isAborted = (signal: AbortSignal | undefined): boolean =>
  signal?.aborted === true;
