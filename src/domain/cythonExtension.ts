import { z } from "zod";

import { jsonValueSchema } from "./jsonValue.js";

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

const unknownFactSchema = z.strictObject({
  status: z.literal("unknown"),
  reason: z.string().min(1),
});
const knownStringSchema = z.strictObject({
  status: z.literal("known"),
  value: z.string().min(1),
});
const knownStringListSchema = z.strictObject({
  status: z.literal("known"),
  value: z.array(z.string().min(1)),
});
const knownPositionalBoundsSchema = z.strictObject({
  status: z.literal("known"),
  minimum: z.number().int().nonnegative(),
  maximum: z.number().int().nonnegative(),
});
const slotNameSchema = z.discriminatedUnion("status", [
  knownStringSchema,
  unknownFactSchema,
]);
const slotPresenceSchema = z.enum(["required", "optional", "unknown"]);
const slotDefaultSchema = z.discriminatedUnion("status", [
  z.strictObject({
    status: z.literal("static"),
    value: jsonValueSchema,
    evidence_address: z.string().min(1),
  }),
  z.strictObject({
    status: z.literal("none-observed"),
    evidence_address: z.string().min(1),
  }),
  unknownFactSchema,
]);

/** Provider-neutral observations about one generated Cython wrapper. */
export const cythonWrapperConventionObservationSchema = z.strictObject({
  wrapper: z.strictObject({
    address: z.string().min(1),
    name: z.string().min(1).nullable(),
  }),
  callable_names: z.array(locatedValueSchema),
  implementation_candidates: z.array(
    z.strictObject({
      address: z.string().min(1),
      name: z.string().min(1).nullable(),
      relationship: z.enum(["callee", "tail-call", "unknown"]),
      confidence: z.enum(["candidate", "derived"]),
      evidence_addresses: z.array(z.string().min(1)),
    }),
  ),
  positional_bounds: z.array(
    z.strictObject({
      minimum: z.number().int().nonnegative(),
      maximum: z.number().int().nonnegative(),
      evidence_address: z.string().min(1),
    }),
  ),
  integer_bound_candidates: z.array(
    z.strictObject({
      parameter_ordinal: z.number().int().nonnegative(),
      comparison: z.enum([
        "equal",
        "not-equal",
        "less-than",
        "less-than-or-equal",
        "signed-less-than",
        "signed-less-than-or-equal",
      ]),
      parameter_operand: z.enum(["left", "right"]),
      constant: z.number().int().safe(),
      comparison_address: z.string().min(1),
      branch_address: z.string().min(1),
      taken_block: z.string().min(1),
      fallthrough_block: z.string().min(1),
    }),
  ),
  jump_table_candidates: z.array(
    z.strictObject({
      parameter_ordinal: z.number().int().nonnegative(),
      dispatch_address: z.string().min(1),
      known_case_values: z.array(z.number().int().safe()),
      entry_counts: z.array(z.number().int().nonnegative()),
      unknown_mapping_count: z.number().int().nonnegative(),
      default_target_count: z.number().int().nonnegative(),
      cases_complete: z.boolean(),
      default_known: z.boolean(),
    }),
  ),
  keyword_orders: z.array(
    z.strictObject({
      names: z.array(z.string().min(1)),
      evidence_addresses: z.array(z.string().min(1)).min(1),
    }),
  ),
  slots: z.array(
    z.strictObject({
      index: z.number().int().nonnegative(),
      name: z.string().min(1).optional(),
      presence: z.enum(["required", "optional"]).optional(),
      default: z
        .discriminatedUnion("status", [
          z.strictObject({
            status: z.literal("static"),
            value: jsonValueSchema,
          }),
          z.strictObject({ status: z.literal("none-observed") }),
        ])
        .optional(),
      evidence_address: z.string().min(1),
    }),
  ),
  coverage: z.strictObject({
    wrapper_complete: z.boolean(),
    parser_paths_complete: z.boolean(),
    truncated: z.boolean(),
  }),
  limitations: z.array(z.string()),
});
export type CythonWrapperConventionObservation = z.infer<
  typeof cythonWrapperConventionObservationSchema
>;

/** Conservative candidate calling convention; unknown facts remain explicit. */
export const cythonCallingConventionCandidateSchema = z.strictObject({
  wrapper: cythonWrapperConventionObservationSchema.shape.wrapper,
  callable_name_candidate: z.discriminatedUnion("status", [
    knownStringSchema,
    unknownFactSchema,
  ]),
  implementation_candidates:
    cythonWrapperConventionObservationSchema.shape.implementation_candidates,
  positional: z.discriminatedUnion("status", [
    knownPositionalBoundsSchema,
    unknownFactSchema,
  ]),
  integer_bound_candidates:
    cythonWrapperConventionObservationSchema.shape.integer_bound_candidates,
  jump_table_candidates:
    cythonWrapperConventionObservationSchema.shape.jump_table_candidates,
  keyword_order: z.discriminatedUnion("status", [
    knownStringListSchema,
    unknownFactSchema,
  ]),
  slots: z.array(
    z.strictObject({
      index: z.number().int().nonnegative(),
      name: slotNameSchema,
      presence: slotPresenceSchema,
      default: slotDefaultSchema,
      evidence_addresses: z.array(z.string().min(1)),
    }),
  ),
  coverage: cythonWrapperConventionObservationSchema.shape.coverage,
  evidence_addresses: z.array(z.string().min(1)),
  limitations: z.array(z.string()),
});
export type CythonCallingConventionCandidate = z.infer<
  typeof cythonCallingConventionCandidateSchema
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

const sameJson = (left: unknown, right: unknown): boolean =>
  JSON.stringify(left) === JSON.stringify(right);

const uniqueValues = <T>(values: readonly T[]): T[] => {
  const unique = new Map<string, T>();
  for (const value of values) unique.set(JSON.stringify(value), value);
  return [...unique.values()];
};

/** Project normalized wrapper observations without promoting conflicts to facts. */
export const projectCythonCallingConventionCandidate = (
  raw: CythonWrapperConventionObservation,
): CythonCallingConventionCandidate => {
  const observation = cythonWrapperConventionObservationSchema.parse(raw);
  const callableNames = uniqueObservations(observation.callable_names);
  const bounds = uniqueValues(
    observation.positional_bounds.map(({ minimum, maximum }) => ({
      minimum,
      maximum,
    })),
  );
  const keywordOrders = uniqueValues(
    observation.keyword_orders.map(({ names }) => names),
  );
  const slots = [...new Set(observation.slots.map(({ index }) => index))]
    .sort((left, right) => left - right)
    .map((index) => {
      const observations = observation.slots.filter(
        (candidate) => candidate.index === index,
      );
      const names = uniqueValues(
        observations.flatMap(({ name }) => (name === undefined ? [] : [name])),
      );
      const presences = uniqueValues(
        observations.flatMap(({ presence }) =>
          presence === undefined ? [] : [presence],
        ),
      );
      const defaults = observations.filter(
        ({ default: value }) => value !== undefined,
      );
      const uniqueDefaults = uniqueValues(
        defaults.map(({ default: value }) => value),
      );
      const defaultObservation =
        uniqueDefaults.length === 1
          ? defaults.find(({ default: value }) =>
              sameJson(value, uniqueDefaults[0]),
            )
          : undefined;
      return {
        index,
        name:
          names.length === 1
            ? { status: "known" as const, value: names[0]! }
            : {
                status: "unknown" as const,
                reason:
                  names.length === 0
                    ? "No slot name observation was supplied."
                    : "Conflicting slot name observations were supplied.",
              },
        presence: presences.length === 1 ? presences[0]! : ("unknown" as const),
        default:
          uniqueDefaults.length === 1 &&
          defaultObservation?.default !== undefined
            ? defaultObservation.default.status === "static"
              ? {
                  status: "static" as const,
                  value: defaultObservation.default.value,
                  evidence_address: defaultObservation.evidence_address,
                }
              : {
                  status: "none-observed" as const,
                  evidence_address: defaultObservation.evidence_address,
                }
            : {
                status: "unknown" as const,
                reason:
                  uniqueDefaults.length === 0
                    ? "No static default observation was supplied."
                    : "Conflicting static default observations were supplied.",
              },
        evidence_addresses: [
          ...new Set(
            observations.map(({ evidence_address }) => evidence_address),
          ),
        ].sort(),
      };
    });
  const evidenceAddresses = [
    observation.wrapper.address,
    ...callableNames.map(({ address }) => address),
    ...observation.implementation_candidates.flatMap(
      ({ evidence_addresses: addresses }) => addresses,
    ),
    ...observation.positional_bounds.map(
      ({ evidence_address }) => evidence_address,
    ),
    ...observation.integer_bound_candidates.flatMap(
      ({ comparison_address, branch_address }) => [
        comparison_address,
        branch_address,
      ],
    ),
    ...observation.jump_table_candidates.map(
      ({ dispatch_address }) => dispatch_address,
    ),
    ...observation.keyword_orders.flatMap(
      ({ evidence_addresses: addresses }) => addresses,
    ),
    ...observation.slots.map(({ evidence_address }) => evidence_address),
  ];

  return cythonCallingConventionCandidateSchema.parse({
    wrapper: observation.wrapper,
    callable_name_candidate:
      callableNames.length === 1
        ? { status: "known", value: callableNames[0]!.value }
        : {
            status: "unknown",
            reason:
              callableNames.length === 0
                ? "No callable name observation was supplied."
                : "Conflicting callable name observations were supplied.",
          },
    implementation_candidates: uniqueValues(
      observation.implementation_candidates,
    ).sort((left, right) => left.address.localeCompare(right.address)),
    positional:
      bounds.length === 1 && bounds[0]!.minimum <= bounds[0]!.maximum
        ? { status: "known", ...bounds[0]! }
        : {
            status: "unknown",
            reason:
              bounds.length === 0
                ? "No positional bound observation was supplied."
                : "Conflicting or invalid positional bound observations were supplied.",
          },
    integer_bound_candidates: uniqueValues(
      observation.integer_bound_candidates,
    ).sort(
      (left, right) =>
        left.comparison_address.localeCompare(right.comparison_address) ||
        left.branch_address.localeCompare(right.branch_address),
    ),
    jump_table_candidates: uniqueValues(observation.jump_table_candidates).sort(
      (left, right) =>
        left.dispatch_address.localeCompare(right.dispatch_address),
    ),
    keyword_order:
      keywordOrders.length === 1
        ? { status: "known", value: keywordOrders[0]! }
        : {
            status: "unknown",
            reason:
              keywordOrders.length === 0
                ? "No keyword order observation was supplied."
                : "Conflicting keyword order observations were supplied.",
          },
    slots,
    coverage: observation.coverage,
    evidence_addresses: [...new Set(evidenceAddresses)].sort(),
    limitations: [
      "The native ABI signature is not a Python calling convention.",
      "Wrapper/body ownership remains a candidate unless explicit relationship evidence supports it.",
      ...observation.limitations,
      ...(!observation.coverage.wrapper_complete ||
      !observation.coverage.parser_paths_complete ||
      observation.coverage.truncated
        ? [
            "Incomplete wrapper or parser-path coverage prevents a complete calling-convention claim.",
          ]
        : []),
    ],
  });
};

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
