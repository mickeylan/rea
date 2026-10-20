import { describe, expect, it } from "vitest";

import { createAnalysisProfile } from "../../domain/analysisProfile.js";
import { createAnalysisExecution } from "../AnalysisProvider.js";
import type {
  AnalysisOperation,
  AnalysisOperationPort,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { err, ok } from "../../domain/result.js";
import type { BinaryTarget } from "../../domain/binaryTargetTypes.js";
import { CythonExtensionInspectionService } from "./CythonExtensionInspectionService.js";

const target: BinaryTarget = {
  kind: "executable",
  format: "pe",
  path: "C:\\fixtures\\example.pyd",
  sha256: "a".repeat(64),
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
  executableRole: "shared-library",
  managed: false,
};

const provider = { id: "fake", name: "Fake provider", version: "1" };
const profile = createAnalysisProfile(provider, { fixture: true });

class RecordingAnalysis implements AnalysisOperationPort {
  readonly calls: AnalysisOperation[] = [];

  constructor(
    readonly names: unknown,
    readonly strings: unknown,
    readonly afterNames?: () => void,
    readonly namesProfile: ReturnType<
      typeof createAnalysisProfile
    > | null = profile,
    readonly stringsProfile: ReturnType<
      typeof createAnalysisProfile
    > | null = profile,
    readonly namesSubject: BinaryTarget | undefined = target,
    readonly stringsSubject: BinaryTarget | undefined = target,
  ) {}

  execute(
    operation: AnalysisOperation,
    _parameters: Readonly<Record<string, never>>,
    _options?: ExecutionOptions,
  ) {
    this.calls.push(operation);
    if (operation === "list_names") {
      this.afterNames?.();
      return Promise.resolve(
        ok(
          createAnalysisExecution(this.names, provider, {
            ...(this.namesProfile === null
              ? {}
              : { analysisProfile: this.namesProfile }),
            limitations: ["names limitation"],
            locations: [{ kind: "address", address: "0x1000" }],
            ...(this.namesSubject === undefined
              ? {}
              : { subject: this.namesSubject }),
          }),
        ),
      );
    }
    return Promise.resolve(
      ok(
        createAnalysisExecution(this.strings, provider, {
          ...(this.stringsProfile === null
            ? {}
            : { analysisProfile: this.stringsProfile }),
          limitations: ["strings limitation"],
          locations: [{ kind: "address", address: "0x2000" }],
          ...(this.stringsSubject === undefined
            ? {}
            : { subject: this.stringsSubject }),
        }),
      ),
    );
  }
}

const nameInventory = [
  { address: "0x1000", value: "PyInit_example" },
  { address: "0x1010", value: "__pyx_pw_1example" },
  { address: "EXTERNAL:0x1", value: "PyUnicode_FromString" },
];
const stringInventory = [
  { address: "0x2000", value: "package.module.Widget.build" },
  { address: "0x2010", value: "C:\\build\\module.pyx" },
];

const expectSubjectMismatchRejected = async (
  mismatch: "list_names" | "list_strings",
  expectedCalls: readonly AnalysisOperation[],
): Promise<void> => {
  const otherTarget = { ...target, sha256: "b".repeat(64) };
  const analysis = new RecordingAnalysis(
    nameInventory,
    stringInventory,
    undefined,
    profile,
    profile,
    mismatch === "list_names" ? otherTarget : target,
    mismatch === "list_strings" ? otherTarget : target,
  );
  const result = await new CythonExtensionInspectionService().inspect(
    analysis,
    target,
  );
  expect(result.ok).toBe(false);
  expect(analysis.calls).toEqual(expectedCalls);
  if (!result.ok) expect(result.error._tag).toBe("AnalysisOutputError");
};

const expectProviderFailurePreserved = async (
  failingOperation: "list_names" | "list_strings",
  expectedCalls: readonly AnalysisOperation[],
): Promise<void> => {
  const failure = new AnalysisOutputError(
    failingOperation,
    "fixture provider failure",
  );
  const calls: AnalysisOperation[] = [];
  const analysis: AnalysisOperationPort = {
    execute: (operation) => {
      calls.push(operation);
      if (operation === failingOperation) return Promise.resolve(err(failure));
      return Promise.resolve(
        ok(
          createAnalysisExecution(nameInventory, provider, {
            analysisProfile: profile,
          }),
        ),
      );
    },
  };
  const result = await new CythonExtensionInspectionService().inspect(
    analysis,
    target,
  );
  expect(result).toEqual(err(failure));
  expect(calls).toEqual(expectedCalls);
};

describe("CythonExtensionInspectionService", () => {
  it("composes one admitted session into derived Evidence", async () => {
    const analysis = new RecordingAnalysis(nameInventory, stringInventory);
    const result = await new CythonExtensionInspectionService().inspect(
      analysis,
      target,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(analysis.calls).toEqual(["list_names", "list_strings"]);
    expect(result.value.operation).toBe("inspect_cython_extension");
    expect(result.value.confidence).toBe("derived");
    expect(result.value.provider.id).toBe("rea-workflow");
    expect(result.value.analysis_profile?.parameters).toMatchObject({
      workflow_revision: 1,
    });
    expect(result.value.normalized_result).toMatchObject({
      python_extension: { status: "confirmed", module_names: ["example"] },
      cython: { status: "detected" },
      coverage: { names_examined: 3, strings_examined: 2, complete: true },
    });
    expect(result.value.locations).toEqual([
      { kind: "address", address: "0x1000" },
      { kind: "address", address: "0x2000" },
    ]);
    expect(result.value.limitations).toContain("names limitation");
    expect(result.value.limitations).toContain("strings limitation");
  });

  it("rejects targets outside the native .pyd PE boundary before provider work", async () => {
    const analysis = new RecordingAnalysis(nameInventory, stringInventory);
    const result = await new CythonExtensionInspectionService().inspect(
      analysis,
      { ...target, path: "C:\\fixtures\\example.dll" },
    );

    expect(result.ok).toBe(false);
    expect(analysis.calls).toEqual([]);
    if (!result.ok)
      expect(result.error._tag).toBe("AnalysisUnsupportedTargetError");
  });

  it("fails closed on malformed provider inventory", async () => {
    const analysis = new RecordingAnalysis({ invalid: true }, stringInventory);
    const result = await new CythonExtensionInspectionService().inspect(
      analysis,
      target,
    );

    expect(result.ok).toBe(false);
    expect(analysis.calls).toEqual(["list_names"]);
    if (!result.ok) expect(result.error._tag).toBe("AnalysisOutputError");
  });

  it("fails closed on malformed strings after accepting names", async () => {
    const analysis = new RecordingAnalysis(nameInventory, { invalid: true });
    const result = await new CythonExtensionInspectionService().inspect(
      analysis,
      target,
    );

    expect(result.ok).toBe(false);
    expect(analysis.calls).toEqual(["list_names", "list_strings"]);
    if (!result.ok) expect(result.error._tag).toBe("AnalysisOutputError");
  });

  it.each([
    { failingOperation: "list_names", expectedCalls: ["list_names"] },
    {
      failingOperation: "list_strings",
      expectedCalls: ["list_names", "list_strings"],
    },
  ] as const)(
    "preserves a typed $failingOperation provider failure",
    ({ failingOperation, expectedCalls }) =>
      expectProviderFailurePreserved(failingOperation, expectedCalls),
  );

  it.each([
    { mismatch: "list_names", expectedCalls: ["list_names"] },
    { mismatch: "list_strings", expectedCalls: ["list_names", "list_strings"] },
  ] as const)(
    "rejects a $mismatch subject bound to another target",
    ({ mismatch, expectedCalls }) =>
      expectSubjectMismatchRejected(mismatch, expectedCalls),
  );

  it("does not invoke provider primitives after prior cancellation", async () => {
    const controller = new AbortController();
    controller.abort();
    const analysis = new RecordingAnalysis(nameInventory, stringInventory);

    const result = await new CythonExtensionInspectionService().inspect(
      analysis,
      target,
      { signal: controller.signal },
    );

    expect(result.ok).toBe(false);
    expect(analysis.calls).toEqual([]);
    if (!result.ok) expect(result.error._tag).toBe("AnalysisCancelledError");
  });

  it("honors cancellation between primitive observations", async () => {
    const controller = new AbortController();
    const analysis = new RecordingAnalysis(nameInventory, stringInventory, () =>
      controller.abort(),
    );
    const result = await new CythonExtensionInspectionService().inspect(
      analysis,
      target,
      { signal: controller.signal },
    );

    expect(result.ok).toBe(false);
    expect(analysis.calls).toEqual(["list_names"]);
    if (!result.ok) expect(result.error._tag).toBe("AnalysisCancelledError");
  });

  it("omits a partial upstream profile from combined Evidence", async () => {
    const analysis = new RecordingAnalysis(
      nameInventory,
      stringInventory,
      undefined,
      profile,
      null,
    );
    const result = await new CythonExtensionInspectionService().inspect(
      analysis,
      target,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.analysis_profile).toBeNull();
    expect(result.value.limitations).toContain(
      "At least one provider inventory omitted its analysis profile; the combined Evidence is not bound to the remaining profile.",
    );
  });

  it("rejects inventories produced under different profiles", async () => {
    const otherProfile = createAnalysisProfile(provider, { fixture: false });
    const analysis = new RecordingAnalysis(
      nameInventory,
      stringInventory,
      undefined,
      profile,
      otherProfile,
    );
    const result = await new CythonExtensionInspectionService().inspect(
      analysis,
      target,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error._tag).toBe("AnalysisOutputError");
  });
});

describe("Cython extension provider provenance", () => {
  it("rejects inventories from different providers without profiles", async () => {
    const otherProvider = { id: "other", name: "Other", version: "1" };
    const calls: AnalysisOperation[] = [];
    const analysis: AnalysisOperationPort = {
      execute: (operation) => {
        calls.push(operation);
        return Promise.resolve(
          ok(
            createAnalysisExecution(
              operation === "list_names" ? nameInventory : stringInventory,
              operation === "list_names" ? provider : otherProvider,
              { subject: target },
            ),
          ),
        );
      },
    };

    const result = await new CythonExtensionInspectionService().inspect(
      analysis,
      target,
    );

    expect(result.ok).toBe(false);
    expect(calls).toEqual(["list_names", "list_strings"]);
    if (!result.ok) expect(result.error._tag).toBe("AnalysisOutputError");
  });
});
