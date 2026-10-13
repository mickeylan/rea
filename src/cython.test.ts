import { describe, expect, it } from "vitest";

import {
  extractCpythonModuleName,
  inspectCythonExtensionInventories,
  isPythonQualifiedName,
  isPythonSourcePath,
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
      ],
      complete: true,
    });

    expect(inspection.python_extension).toEqual({
      status: "confirmed",
      initializers: [{ address: "0x1000", value: "PyInit_example" }],
      module_names: ["example"],
    });
    expect(inspection.cython.status).toBe("detected");
    expect(inspection.qualified_name_candidates).toEqual([
      { address: "0x2000", value: "package.module.Widget.build" },
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
