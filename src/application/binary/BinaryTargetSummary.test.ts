import { describe, expect, it } from "vitest";

import type { BinaryTarget } from "../../domain/binaryTargetTypes.js";
import { binaryTargetSummary } from "./BinaryTargetSummary.js";

const identity = {
  path: "C:\\fixtures\\example.pyd",
  sha256: "a".repeat(64),
};

describe("binaryTargetSummary", () => {
  it("preserves PE role and managed declarations for capability admission", () => {
    const target: BinaryTarget = {
      ...identity,
      kind: "executable",
      format: "pe",
      architecture: "x86_64",
      availableArchitectures: ["x86_64"],
      executableRole: "shared-library",
      managed: false,
    };

    expect(binaryTargetSummary(target)).toMatchObject({
      path: identity.path,
      format: "pe",
      executable_role: "shared-library",
      managed: false,
    });
  });

  it("does not invent PE fields for other executable formats", () => {
    const target: BinaryTarget = {
      ...identity,
      kind: "executable",
      format: "elf",
      architecture: "x86_64",
      availableArchitectures: ["x86_64"],
    };

    expect(binaryTargetSummary(target)).not.toHaveProperty("executable_role");
    expect(binaryTargetSummary(target)).not.toHaveProperty("managed");
  });
});
