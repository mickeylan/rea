import { expect, it } from "vitest";

import { createAnalysisProfile } from "../../domain/analysisProfile.js";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { err, ok } from "../../domain/result.js";
import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { CythonWrapperConventionPort } from "./CythonWrapperConventionPort.js";
import { CythonWrapperConventionService } from "./CythonWrapperConventionService.js";

const provider = { id: "fixture", name: "Fixture", version: "1" };
const profile = createAnalysisProfile(provider, { fixture: true });
const observation = {
  wrapper: { address: "0x1000", name: "__pyx_pw_1module_1build" },
  callable_names: [{ address: "0x1010", value: "build" }],
  implementation_candidates: [],
  positional_bounds: [{ minimum: 2, maximum: 3, evidence_address: "0x1020" }],
  keyword_orders: [
    { names: ["self", "prompt", "image"], evidence_addresses: ["0x1030"] },
  ],
  slots: [],
  coverage: {
    wrapper_complete: true,
    parser_paths_complete: true,
    truncated: false,
  },
  limitations: [],
};

const port = (
  result: unknown,
  after?: () => void,
): CythonWrapperConventionPort => ({
  observe: (_wrapper: string, _options?: ExecutionOptions) => {
    after?.();
    return Promise.resolve(
      ok(
        createAnalysisExecution(result, provider, {
          analysisProfile: profile,
          limitations: ["fixture limitation"],
          locations: [{ kind: "address", address: "0x1000" }],
        }),
      ),
    );
  },
});

it("projects normalized wrapper observations and preserves provenance", async () => {
  const result = await new CythonWrapperConventionService().inspect(
    port(observation),
    "0x1000",
  );

  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.provider).toEqual(provider);
  expect(result.value.analysisProfile).toEqual(profile);
  expect(result.value.limitations).toEqual(["fixture limitation"]);
  expect(result.value.locations).toEqual([
    { kind: "address", address: "0x1000" },
  ]);
  expect(result.value.result).toMatchObject({
    callable_name_candidate: { status: "known", value: "build" },
    positional: { status: "known", minimum: 2, maximum: 3 },
  });
});

it("fails closed on malformed normalized observations", async () => {
  const result = await new CythonWrapperConventionService().inspect(
    port({ invalid: true }),
    "0x1000",
  );

  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error._tag).toBe("AnalysisOutputError");
});

it("does not invoke the port after prior cancellation", async () => {
  const controller = new AbortController();
  controller.abort();
  let called = false;
  const result = await new CythonWrapperConventionService().inspect(
    port(observation, () => {
      called = true;
    }),
    "0x1000",
    { signal: controller.signal },
  );

  expect(result.ok).toBe(false);
  expect(called).toBe(false);
  if (!result.ok) expect(result.error._tag).toBe("AnalysisCancelledError");
});

it("honors cancellation after the provider observation", async () => {
  const controller = new AbortController();
  const result = await new CythonWrapperConventionService().inspect(
    port(observation, () => controller.abort()),
    "0x1000",
    { signal: controller.signal },
  );

  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error._tag).toBe("AnalysisCancelledError");
});

it("preserves provider failures", async () => {
  const failure = new AnalysisOutputError("fixture", "failed");
  const failingPort: CythonWrapperConventionPort = {
    observe: () => Promise.resolve(err(failure)),
  };
  const result = await new CythonWrapperConventionService().inspect(
    failingPort,
    "0x1000",
  );

  expect(result).toEqual(err(failure));
});
