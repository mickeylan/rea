import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  cythonWrapperConventionObservationSchema,
  projectCythonCallingConventionCandidate,
} from "../../domain/cythonExtension.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { CythonWrapperConventionPort } from "./CythonWrapperConventionPort.js";

const OPERATION = "inspect_cython_wrapper_convention";

/** Validate and project one provider-normalized wrapper observation. */
export class CythonWrapperConventionService {
  async inspect(
    port: CythonWrapperConventionPort,
    wrapper: string,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (isAborted(options?.signal))
      return err(new AnalysisCancelledError(OPERATION));

    const observed = await port.observe(wrapper, options);
    if (!observed.ok) return observed;
    const parsed = cythonWrapperConventionObservationSchema.safeParse(
      observed.value.result,
    );
    if (!parsed.success)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Provider returned a malformed normalized Cython wrapper observation.",
          { cause: parsed.error },
        ),
      );

    const projected = createAnalysisExecution(
      projectCythonCallingConventionCandidate(parsed.data),
      observed.value.provider,
      {
        ...(observed.value.rawResult === null
          ? {}
          : { rawResult: observed.value.rawResult }),
        ...(observed.value.analysisProfile === undefined
          ? {}
          : { analysisProfile: observed.value.analysisProfile }),
        limitations: observed.value.limitations,
        locations: observed.value.locations,
        ...(observed.value.subject === null
          ? {}
          : { subject: observed.value.subject }),
      },
    );
    if (isAborted(options?.signal))
      return err(new AnalysisCancelledError(OPERATION));
    return ok(projected);
  }
}

const isAborted = (signal: AbortSignal | undefined): boolean =>
  signal?.aborted === true;
