import { z } from "zod";

/** Python value categories suggested by CPython API observations. */
export const pythonValueCategorySchema = z.enum([
  "str",
  "int",
  "float",
  "bool",
  "list",
  "tuple",
  "dict",
  "set",
  "None",
  "object",
  "bytes",
]);
export type PythonValueCategory = z.infer<typeof pythonValueCategorySchema>;

const CPYTHON_TYPE_HINTS = {
  PyUnicode_Type: "str",
  PyUnicode_FromString: "str",
  PyUnicode_Concat: "str",
  PyObject_Str: "str",
  PyLong_Type: "int",
  PyLong_FromLong: "int",
  PyFloat_Type: "float",
  PyDict_Type: "dict",
  PyDict_New: "dict",
  PyList_Type: "list",
  PyList_New: "list",
  PyTuple_Type: "tuple",
  PyTuple_New: "tuple",
  Py_NoneStruct: "None",
  Py_TrueStruct: "bool",
  Py_FalseStruct: "bool",
} as const satisfies Readonly<Record<string, PythonValueCategory>>;

const pythonModulePathPattern =
  /^(?:[A-Za-z_][A-Za-z0-9_]*\.)+[A-Za-z_][A-Za-z0-9_]*$/u;
const sourcePathPattern =
  /^(?:[A-Za-z]:\\[^\r\n]+|\/[^\r\n]+)\.(?:py|pyx|c)$/iu;
const pythonIdentifierPattern = /^[A-Za-z_][A-Za-z0-9_]*$/u;

/** Extract an exact CPython extension module name from its initializer symbol. */
export const extractCpythonModuleName = (symbol: string): string | null => {
  const match = /^PyInit_([A-Za-z_][A-Za-z0-9_]*)$/u.exec(symbol);
  return match?.[1] ?? null;
};

/** Recognize a dotted Python identity without assigning function or class meaning. */
export const isPythonQualifiedName = (value: string): boolean =>
  pythonModulePathPattern.test(value);

/** Recognize a Python/Cython source coordinate retained as a string observation. */
export const isPythonSourcePath = (value: string): boolean =>
  sourcePathPattern.test(value);

/** Split a dotted identity while preserving uncertainty about the owning object. */
export const splitPythonQualifiedName = (
  value: string,
): readonly string[] | null => {
  if (!isPythonQualifiedName(value)) return null;
  const parts = value.split(".");
  return parts.every((part) => pythonIdentifierPattern.test(part))
    ? parts
    : null;
};

/** Return a bounded type hint from one exact CPython API symbol observation. */
export const pythonTypeHintFromCpythonSymbol = (
  symbol: string,
): PythonValueCategory | null => {
  for (const [api, category] of Object.entries(CPYTHON_TYPE_HINTS))
    if (symbol === api || symbol.startsWith(`${api}_`)) return category;
  return null;
};

const observationSchema = z.strictObject({
  address: z.string().min(1),
  value: z.string(),
});
export type CythonExtensionObservation = z.infer<typeof observationSchema>;

const locatedValueSchema = observationSchema;
const typeHintSchema = observationSchema.extend({
  category: pythonValueCategorySchema,
});

/** Conservative projection of symbol and string inventories for one native module. */
export const cythonExtensionInspectionSchema = z.strictObject({
  python_extension: z.strictObject({
    status: z.enum(["confirmed", "unknown"]),
    initializers: z.array(locatedValueSchema),
    module_names: z.array(z.string().min(1)),
  }),
  cython: z.strictObject({
    status: z.enum(["detected", "unknown"]),
    markers: z.array(locatedValueSchema),
  }),
  qualified_name_candidates: z.array(locatedValueSchema),
  source_path_observations: z.array(locatedValueSchema),
  cpython_type_hints: z.array(typeHintSchema),
  coverage: z.strictObject({
    names_examined: z.number().int().nonnegative(),
    strings_examined: z.number().int().nonnegative(),
    complete: z.boolean(),
  }),
  limitations: z.array(z.string()),
});
export type CythonExtensionInspection = z.infer<
  typeof cythonExtensionInspectionSchema
>;

const compareObservation = (
  left: CythonExtensionObservation,
  right: CythonExtensionObservation,
): number =>
  left.address.localeCompare(right.address) ||
  left.value.localeCompare(right.value);

const uniqueObservations = (
  observations: readonly CythonExtensionObservation[],
): CythonExtensionObservation[] => {
  const unique = new Map<string, CythonExtensionObservation>();
  for (const observation of observations)
    unique.set(`${observation.address}\u0000${observation.value}`, observation);
  return [...unique.values()].sort(compareObservation);
};

const isCythonMarker = (value: string): boolean =>
  /(?:^|\.)(?:__pyx_|__Pyx_)/u.test(value);

/**
 * Project complete provider inventories without claiming recovered source,
 * functions, classes, signatures, or runtime behavior.
 */
export const inspectCythonExtensionInventories = (input: {
  readonly names: readonly CythonExtensionObservation[];
  readonly strings: readonly CythonExtensionObservation[];
  readonly complete: boolean;
}): CythonExtensionInspection => {
  const names = uniqueObservations(input.names);
  const strings = uniqueObservations(input.strings);
  const initializers = names.filter(
    ({ value }) => extractCpythonModuleName(value) !== null,
  );
  const moduleNames = [
    ...new Set(
      initializers.flatMap(({ value }) => {
        const moduleName = extractCpythonModuleName(value);
        return moduleName === null ? [] : [moduleName];
      }),
    ),
  ].sort();
  const markers = uniqueObservations(
    [...names, ...strings].filter(({ value }) => isCythonMarker(value)),
  );
  const qualifiedNames = strings.filter(({ value }) =>
    isPythonQualifiedName(value),
  );
  const sourcePaths = strings.filter(({ value }) => isPythonSourcePath(value));
  const typeHints = names.flatMap((observation) => {
    const category = pythonTypeHintFromCpythonSymbol(observation.value);
    return category === null ? [] : [{ ...observation, category }];
  });
  const limitations = [
    "Qualified names and source paths are retained string observations, not proof of source recovery, class ownership, callable signatures, or runtime behavior.",
    ...(markers.length === 0
      ? [
          "No Cython marker was observed in the supplied inventories; stripped or undefined data may still be present.",
        ]
      : []),
    ...(input.complete
      ? []
      : [
          "The supplied provider inventories were not established as complete.",
        ]),
  ];

  return cythonExtensionInspectionSchema.parse({
    python_extension: {
      status: initializers.length === 0 ? "unknown" : "confirmed",
      initializers,
      module_names: moduleNames,
    },
    cython: {
      status: markers.length === 0 ? "unknown" : "detected",
      markers,
    },
    qualified_name_candidates: qualifiedNames,
    source_path_observations: sourcePaths,
    cpython_type_hints: typeHints,
    coverage: {
      names_examined: names.length,
      strings_examined: strings.length,
      complete: input.complete,
    },
    limitations,
  });
};
