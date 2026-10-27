import { z } from "zod";
import { nativeAddressObservationSchema } from "../domain/native/nativeAddress.js";
import {
  availableNativeApiBoundarySchema,
  unavailableNativeApiBoundarySchema,
} from "../domain/native/nativeApiBoundary.js";
import {
  availableNativeValueFlowSchema,
  unavailableNativeValueFlowSchema,
  nativePcodeBlockSchema,
  nativePcodeOperationSchema,
  nativeVarnodeSchema,
} from "../domain/native/nativeValueFlow.js";

const jumpTable = availableNativeApiBoundarySchema.shape.jump_tables.element;
const ghidraJumpTable = jumpTable.extend({
  dispatch_address: nativeAddressObservationSchema,
  data_sources: z.array(
    jumpTable.shape.data_sources.element.extend({
      address: nativeAddressObservationSchema,
    }),
  ),
  mappings: z.array(
    jumpTable.shape.mappings.element.extend({
      target_address: nativeAddressObservationSchema,
    }),
  ),
  default_targets: z.array(
    jumpTable.shape.default_targets.element.extend({
      target_address: nativeAddressObservationSchema,
    }),
  ),
});

/** Ghidra API facts carry canonical coordinates and HighFunction provenance. */
export const ghidraNativeApiBoundary = z.discriminatedUnion("available", [
  unavailableNativeApiBoundarySchema,
  availableNativeApiBoundarySchema.extend({
    provenance: z.literal("ghidra-high-function"),
    jump_tables: z.array(ghidraJumpTable),
  }),
]);

const ghidraVarnode = nativeVarnodeSchema.extend({
  location: nativeAddressObservationSchema.nullable(),
});
const ghidraPcodeOperation = nativePcodeOperationSchema.extend({
  address: nativeAddressObservationSchema,
  inputs: z.array(ghidraVarnode),
  output: ghidraVarnode.nullable(),
});
const ghidraPcodeBlock = nativePcodeBlockSchema.extend({
  start_address: nativeAddressObservationSchema,
});

/** Validate relationships only after each p-code observation has been admitted. */
export const ghidraNativeValueFlow = z.discriminatedUnion("available", [
  unavailableNativeValueFlowSchema,
  availableNativeValueFlowSchema
    .extend({
      operations: z.array(ghidraPcodeOperation),
      blocks: z.array(ghidraPcodeBlock),
    })
    .superRefine((value, context) => {
      const { operations } = value;
      const operationIds = new Set(operations.map(({ id }) => id));
      if (operationIds.size !== operations.length)
        context.addIssue({
          code: "custom",
          message: "Ghidra p-code operation identifiers are not unique",
        });
      const blockIds = new Set(value.blocks.map(({ id }) => id));
      if (blockIds.size !== value.blocks.length)
        context.addIssue({
          code: "custom",
          message: "Ghidra p-code block identifiers are not unique",
        });
      const listedOperations = new Set<string>();
      if (
        value.blocks.some(
          ({ operation_ids, successor_ids }) =>
            operation_ids.some(
              (operation) =>
                !operationIds.has(operation) ||
                (listedOperations.has(operation)
                  ? true
                  : (listedOperations.add(operation), false)),
            ) ||
            successor_ids.some((successor) => !blockIds.has(successor)),
        ) ||
        operations.some(
          ({ block_membership, block_id }) =>
            (block_id !== null && !blockIds.has(block_id)) ||
            (block_membership === "member") !== (block_id !== null),
        )
      )
        context.addIssue({
          code: "custom",
          message: "Ghidra p-code block relationships are inconsistent",
        });
      if (
        value.def_use.some(
          ({ definition, use }) =>
            !operationIds.has(definition) || !operationIds.has(use),
        ) ||
        value.effects.some(
          ({ operation, kind, branch_target_block, branch_fallthrough_block }) =>
            !operationIds.has(operation) ||
            (branch_target_block !== null &&
              !blockIds.has(branch_target_block)) ||
            (branch_fallthrough_block !== null &&
              !blockIds.has(branch_fallthrough_block)) ||
            (kind !== "conditional_branch" &&
              (branch_target_block !== null ||
                branch_fallthrough_block !== null)) ||
            (branch_target_block !== null &&
              branch_target_block === branch_fallthrough_block),
        )
      )
        context.addIssue({
          code: "custom",
          message: "Ghidra p-code relationship references a missing operation",
        });
      if (value.semantic_roots_retained > value.semantic_roots_total)
        context.addIssue({
          code: "custom",
          message: "Ghidra retained more semantic roots than it examined",
        });
      if (
        value.truncated !==
        (value.omitted_operations_lower_bound > 0 ||
          value.known_omitted_inputs > 0 ||
          value.known_omitted_edges > 0)
      )
        context.addIssue({
          code: "custom",
          message: "Ghidra p-code truncation flag contradicts omitted counts",
        });
    }),
]);
