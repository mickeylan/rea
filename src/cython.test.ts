import { describe, expect, it } from "vitest";

import {
  extractCpythonModuleName,
  inspectCythonExtensionInventories,
  isPythonQualifiedName,
  isPythonSourcePath,
  projectCythonCallingConventionCandidate,
  pythonTypeHintFromCpythonSymbol,
  splitPythonQualifiedName,
} from "./domain/cythonExtension.js";

describe("Cython extension observations", () => {
  it("recognizes exact CPython initializer identities", () => {
    expect(extractCpythonModuleName("PyInit_TE_Prompt_Text")).toBe(
      "TE_Prompt_Text",
    );
    expect(extractCpythonModuleName("prefix_PyInit_module")).toBeNull();
    expect(extractCpythonModuleName("PyInit_bad-name")).toBeNull();
  });

  it("preserves qualified names without assigning class or function semantics", () => {
    const value =
      "custom_nodes.TE_image.TE_Prompt_Text.TEPromptTextNode.build_text";
    expect(isPythonQualifiedName(value)).toBe(true);
    expect(splitPythonQualifiedName(value)).toEqual([
      "custom_nodes",
      "TE_image",
      "TE_Prompt_Text",
      "TEPromptTextNode",
      "build_text",
    ]);
    expect(splitPythonQualifiedName("not dotted")).toBeNull();
  });

  it("recognizes retained source coordinates without treating them as source files", () => {
    expect(isPythonSourcePath("C:\\build\\module.pyx")).toBe(true);
    expect(isPythonSourcePath("/build/module.py")).toBe(true);
    expect(isPythonSourcePath("module.py")).toBe(false);
  });

  it("returns bounded hints only for exact CPython API symbols", () => {
    expect(pythonTypeHintFromCpythonSymbol("PyUnicode_FromString")).toBe("str");
    expect(pythonTypeHintFromCpythonSymbol("PyDict_New")).toBe("dict");
    expect(pythonTypeHintFromCpythonSymbol("prefix_PyDict_New")).toBeNull();
    expect(pythonTypeHintFromCpythonSymbol("unknown_helper")).toBeNull();
  });

  it("projects observations without upgrading strings into recovered source", () => {
    const inspection = inspectCythonExtensionInventories({
      names: [
        { address: "0x1000", value: "PyInit_example" },
        { address: "EXTERNAL:0x1", value: "PyUnicode_FromString" },
        { address: "0x1010", value: "__pyx_pw_1example" },
      ],
      strings: [
        { address: "0x2000", value: "package.module.Widget.build" },
        { address: "0x2010", value: "C:\\build\\module.pyx" },
        { address: "0x2020", value: "__Pyx_PyObject_Call" },
        {
          address: "0x2030",
          value: "package.module.__pyx_scope_struct_generator",
        },
        { address: "0x2040", value: "package.module.not__pyx_marker" },
      ],
      complete: true,
    });

    expect(inspection.python_extension).toEqual({
      status: "confirmed",
      initializers: [{ address: "0x1000", value: "PyInit_example" }],
      module_names: ["example"],
    });
    expect(inspection.cython).toMatchObject({
      status: "detected",
      markers: expect.arrayContaining([
        {
          address: "0x2030",
          value: "package.module.__pyx_scope_struct_generator",
        },
      ]),
    });
    expect(inspection.cython.markers).not.toContainEqual({
      address: "0x2040",
      value: "package.module.not__pyx_marker",
    });
    expect(inspection.qualified_name_candidates).toEqual([
      { address: "0x2000", value: "package.module.Widget.build" },
      {
        address: "0x2030",
        value: "package.module.__pyx_scope_struct_generator",
      },
      { address: "0x2040", value: "package.module.not__pyx_marker" },
    ]);
    expect(inspection.source_path_observations).toEqual([
      { address: "0x2010", value: "C:\\build\\module.pyx" },
    ]);
    expect(inspection.cpython_type_hints).toEqual([
      {
        address: "EXTERNAL:0x1",
        value: "PyUnicode_FromString",
        category: "str",
      },
    ]);
    expect(inspection.limitations[0]).toContain("not proof of source recovery");
  });
});

describe("Cython wrapper convention candidates", () => {
  it("projects a normalized wrapper convention with retained evidence", () => {
    const candidate = projectCythonCallingConventionCandidate({
      wrapper: { address: "0x1000", name: "__pyx_pw_1module_1build" },
      callable_names: [{ address: "0x1010", value: "build" }],
      implementation_candidates: [
        {
          address: "0x2000",
          name: "__pyx_pf_1module_build",
          relationship: "callee",
          confidence: "derived",
          evidence_addresses: ["0x1020"],
        },
      ],
      positional_bounds: [
        { minimum: 2, maximum: 4, evidence_address: "0x1030" },
      ],
      integer_bound_candidates: [],
      jump_table_candidates: [
        {
          parameter_ordinal: 2,
          dispatch_address: "0x1038",
          known_case_values: [2, 3, 4],
          entry_counts: [3],
          unknown_mapping_count: 1,
          default_target_count: 0,
          cases_complete: true,
          default_known: false,
        },
      ],
      keyword_orders: [
        {
          names: ["self", "prompt", "image", "seed"],
          evidence_addresses: ["0x1040"],
        },
      ],
      slots: [
        {
          index: 0,
          name: "self",
          presence: "required",
          evidence_address: "0x1040",
        },
        {
          index: 1,
          name: "prompt",
          presence: "required",
          evidence_address: "0x1048",
        },
        {
          index: 2,
          name: "image",
          presence: "optional",
          default: { status: "static", value: null },
          evidence_address: "0x1050",
        },
      ],
      coverage: {
        wrapper_complete: true,
        parser_paths_complete: true,
        truncated: false,
      },
      limitations: [],
    });

    expect(candidate.callable_name_candidate).toEqual({
      status: "known",
      value: "build",
    });
    expect(candidate.positional).toEqual({
      status: "known",
      minimum: 2,
      maximum: 4,
    });
    expect(candidate.keyword_order).toEqual({
      status: "known",
      value: ["self", "prompt", "image", "seed"],
    });
    expect(candidate.jump_table_candidates).toEqual([
      expect.objectContaining({
        parameter_ordinal: 2,
        known_case_values: [2, 3, 4],
        cases_complete: true,
        default_known: false,
      }),
    ]);
    expect(candidate.slots[2]).toMatchObject({
      index: 2,
      presence: "optional",
      default: {
        status: "static",
        value: null,
        evidence_address: "0x1050",
      },
    });
    expect(candidate.evidence_addresses).toContain("0x1020");
  });

  it("keeps conflicting or incomplete wrapper facts unknown", () => {
    const candidate = projectCythonCallingConventionCandidate({
      wrapper: { address: "0x1000", name: null },
      callable_names: [
        { address: "0x1010", value: "build" },
        { address: "0x1020", value: "render" },
      ],
      implementation_candidates: [],
      positional_bounds: [
        { minimum: 1, maximum: 2, evidence_address: "0x1030" },
        { minimum: 1, maximum: 3, evidence_address: "0x1040" },
      ],
      integer_bound_candidates: [],
      jump_table_candidates: [],
      keyword_orders: [],
      slots: [
        {
          index: 1,
          name: "prompt",
          presence: "required",
          default: { status: "none-observed" },
          evidence_address: "0x1050",
        },
        {
          index: 1,
          name: "text",
          presence: "optional",
          default: { status: "static", value: "" },
          evidence_address: "0x1060",
        },
      ],
      coverage: {
        wrapper_complete: false,
        parser_paths_complete: false,
        truncated: true,
      },
      limitations: [],
    });

    expect(candidate.callable_name_candidate.status).toBe("unknown");
    expect(candidate.positional.status).toBe("unknown");
    expect(candidate.keyword_order.status).toBe("unknown");
    expect(candidate.slots).toEqual([
      expect.objectContaining({
        index: 1,
        name: expect.objectContaining({ status: "unknown" }),
        presence: "unknown",
        default: expect.objectContaining({ status: "unknown" }),
      }),
    ]);
    expect(candidate.limitations.at(-1)).toContain("Incomplete wrapper");
  });
});

describe("Cython incomplete inventory observations", () => {
  it("reports missing markers and incomplete coverage as unknown", () => {
    const inspection = inspectCythonExtensionInventories({
      names: [],
      strings: [],
      complete: false,
    });

    expect(inspection.python_extension.status).toBe("unknown");
    expect(inspection.cython.status).toBe("unknown");
    expect(inspection.coverage.complete).toBe(false);
    expect(inspection.limitations).toHaveLength(3);
  });
});
