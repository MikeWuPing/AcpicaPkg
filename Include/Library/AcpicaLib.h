/** @file
  AcpicaLib - ACPICA AML disassembler library public interface.

  The library wraps the ACPICA disassembler engine (pinned upstream clone
  under Library/AcpicaDisasmLib/acpica, never modified) behind a single
  entry point that turns a raw AML table image into ASL text.

  Copyright (c) 2026, Mike Wu. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef ACPICALIB_H_
#define ACPICALIB_H_

#include <Uefi.h>

/**
  One row-range <-> AML-range mapping entry produced by the self-driven
  disassembly walk (AcpicaDisasmAmlEx).

  RowStart/RowEnd bound the rows of the ASL output text that the parse op
  rendered, inclusive on both ends (row 0 = first output row; a row is the
  text between two '\n'). AmlOff is the offset of the op in the table image
  (0 = table start, header included). AmlLen is the length of the op's AML
  span: the distance to the next op at a different AML offset (the last
  entry extends to the end of the table); entries sharing one offset (e.g.
  the synthetic root scope op and the first statement of the table, both at
  offset sizeof(ACPI_TABLE_HEADER)) receive the same span.

  The table is sorted by AmlOff ascending (a post-pass reorders the
  entries; the last entry extends to the end of the table). The structure
  mirrors the Core-side ACPI_ROW_MAP (AcpiViewMap.h); AcpicaPkg
  deliberately does not include GudumpInfoPkg headers (Task 6 copies the
  fields over).
**/
typedef struct {
  UINTN RowStart;
  UINTN RowEnd;
  UINTN AmlOff;
  UINTN AmlLen;
} ACPI_AML_ROW_MAP;

/**
  Disassemble one AML table (DSDT/SSDT/FADT-less raw table image) with the
  self-driven parse-tree walk, and optionally produce the row-to-AML
  mapping table.

  Self-driven walk: AcpiDmWalkParseTree is driven with wrapper-owned
  callbacks that replicate the upstream dmwalk.c static callbacks
  (AcpiDmDescendingOp/AcpiDmAscendingOp), rendering each op via
  AcpiDmDisassembleOneOp and recording the output row range and the AML
  offset of every op that produced text.

  @param[in]  AmlTable    Pointer to the table image; the first 36 bytes are
                          the ACPI table header (DSDT header) followed by the
                          AML byte stream.
  @param[in]  TableLen    Total size of the image in bytes, header included.
                          Must be >= sizeof (ACPI_TABLE_HEADER).
  @param[out] OutText     Receives an AllocatePool()-allocated NUL-terminated
                          ASL text buffer (caller frees with FreePool).
  @param[out] OutSize     Receives the text length in bytes, NUL excluded.
  @param[out] OutMap      Optional. Receives an AllocatePool()-allocated
                          array of ACPI_AML_ROW_MAP entries (caller frees
                          with FreePool). Pass NULL to skip mapping
                          recording. On failure *OutMap is NULL.
  @param[out] OutMapCount Optional. Receives the number of entries in
                          *OutMap. Ignored when OutMap is NULL.

  @retval EFI_SUCCESS          Disassembly succeeded.
  @retval EFI_INVALID_PARAMETER  Bad argument (NULL out-pointer, short table).
  @retval EFI_OUT_OF_RESOURCES   Output buffer or mapping table allocation
                                 failed.
  @retval EFI_COMPROMISED_DATA   The ACPICA parse/disassemble pass failed.
  @retval EFI_DEVICE_ERROR       One-time subsystem init failed.

  On failure *OutText is NULL, *OutSize is 0, *OutMap is NULL and
  *OutMapCount is 0.

  @param[in] ProgressCb  Optional (M15). Progress notification fired
                         periodically while the disassembly pass runs:
                         Percent is 0-100 (estimated from the walk's
                         current AML offset vs TableLen). The callback
                         runs on the disassembly thread (UEFI single
                         thread) — callers may lv_refr_now() there to
                         render a progress bar so a large table does not
                         look hung. NULL = no notifications.
  @param[in] ProgressCtx Opaque context passed to ProgressCb.
**/

/* M15 progress callback type (must precede the function declaration).
   Kept as a plain function-pointer parameter (no typedef) so the header
   compiles in any include order. */
EFI_STATUS
AcpicaDisasmAmlEx (
  const UINT8      *AmlTable,
  UINTN            TableLen,
  UINT8            **OutText,
  UINTN            *OutSize,
  ACPI_AML_ROW_MAP **OutMap,
  UINTN            *OutMapCount,
  VOID             (*ProgressCb) (UINT32 Percent, VOID *Context),
  VOID             *ProgressCtx
  );

#endif /* ACPICALIB_H_ */
