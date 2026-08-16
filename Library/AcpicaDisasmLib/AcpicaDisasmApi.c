/** @file
  AcpicaDisasmApi.c - public entry AcpicaDisasmAmlEx().

  Replicates the upstream AdParseTable sequence (common/dmtables.c) at the
  public-API level: set integer width -> create root scope op -> create
  walk state -> init pass-1 parse -> parse AML -> parse deferred opcodes ->
  find resource templates. The final disassembly is then driven by the
  wrapper itself (M8.5 T1): AcpiDmWalkParseTree is called with the
  wrapper-owned callbacks AcpiDmDescendingOp/AcpiDmAscendingOp below,
  which replicate the upstream dmwalk.c static callbacks line-for-line
  (upstream source pinned at ACPICA 20260408, dmwalk.c L514-L1296; each
  block cites the upstream line range it mirrors). Every op is rendered
  through the public AcpiDmDisassembleOneOp, and the wrapper additionally
  records a row-range <-> AML-offset mapping table (ACPI_AML_ROW_MAP) that
  links each output row of the ASL text back to the AML bytes that
  produced it. Pass 2 (namespace load, AcpiNsOneCompleteParse) is
  intentionally skipped, so External/unresolved names are emitted as
  written (same semantics as iasl without -e).

  Why a self-driven walk instead of the upstream AcpiDmDisassemble: the
  wrapper needs per-op visibility (output row range + AML offset + length)
  that the upstream one-shot API does not expose. The two static callbacks
  in dmwalk.c cannot be hooked from outside the component, so the walk is
  re-implemented here against the public API surface (AcpiDmWalkParseTree,
  AcpiDmDisassembleOneOp, AcpiDmBlockType/ListType/Indent/CloseOperator/
  CommaIfListMember/CheckForSymbolicOpcode and the other public helpers),
  keeping the output byte-identical to AcpiDmDisassemble (shadow-verified
  under QEMU: size + byte-for-byte match, see M8.5 T1 report).

  Notes vs. upstream:
  - AcpiGbl_ParseOpRoot is defined here: upstream defines it in
    common/adisasm.c, which this port does not compile, and no compiled
    component references it besides this file.
  - All disassembler text flows through AcpiOsPrintf into a growable RAM
    buffer owned by the OSL; the buffer pointer must be re-read via
    AcpicaOsGetOutput() after the disassembly pass (growth reallocation).
  - Output rows are tracked by the OSL (AcpicaOsGetLineCount, incremented
    per '\n' written); the row counters are reset by AcpicaOsClearOutput.

  Copyright (c) 2026, Mike Wu. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/BaseMemoryLib.h>   /* CopyMem/ZeroMem (map helpers) */
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
/* Public interface of this library: ACPI_AML_ROW_MAP + AcpicaDisasmAmlEx
   (M8.5 T1). Must precede acpi.h like the other EDK2 headers. */
#include <Library/AcpicaLib.h>

#include "acpi.h"
#include "accommon.h"   /* MUST precede acdisasm.h: aclocal.h defines
                           ACPI_PARSE_OBJECT which amlresrc.h relies on */
#include "acdisasm.h"
#include "acparser.h"
#include "acdispat.h"
#include "acnamesp.h"
#include "acutils.h"
#include "amlcode.h"    /* AML_* opcode constants (replica of dmwalk.c's
                           callback code uses them directly) */

/* Not declared in acglobal.h for this ACPICA version (upstream defines it
   in common/adisasm.c, which is not compiled); the wrapper owns it. */
ACPI_PARSE_OBJECT *AcpiGbl_ParseOpRoot;

/* OSL output-buffer access (AcpicaOsUefi.c) */
VOID AcpicaOsSetOutput (UINT8 *Buf, UINTN Cap);
VOID AcpicaOsClearOutput (VOID);
VOID AcpicaOsGetOutput (UINT8 **OutBuf, UINTN *OutLen);
UINTN AcpicaOsGetLineCount (VOID);

/* One-time in-process initialization (AcpiInitializeSubsystem is idempotent
   by design but we guard it anyway). */
static BOOLEAN gInit = FALSE;

/******************************************************************************
 *
 * Self-driven disassembly walk (M8.5 T1)
 *
 * The wrapper drives AcpiDmWalkParseTree with the two callbacks below,
 * replicating the upstream static callbacks in dmwalk.c (AcpiDmDescendingOp
 * L514-L1026, AcpiDmAscendingOp L1042-L1296). The ACPI_OP_WALK_INFO
 * instance is shared between both callbacks exactly like upstream (it
 * carries Level/Count/LastLevel/BitOffset/Flags between the two), and the
 * nested bank-field walk inside the descending callback drives the same
 * wrapper callbacks with the same context, mirroring upstream's recursive
 * AcpiDmWalkParseTree call.
 *
 * The one structural difference vs. upstream is the row-map recording.
 * Each op is pushed onto a pending stack when its descending callback
 * starts (row counter + AML offset + output length snapshot), and the
 * entry is finalized when the ascending callback ends (row counter after
 * the op's own output, including its closing paren/brace text). Entries
 * whose op produced no text at all (IGNORE/NOOP/Externals suppression
 * paths) are dropped so a row is never attributed to an op that did not
 * write it. Rows are recorded as [RowStart, RowEnd] inclusive, where
 * RowStart/RowEnd are the OSL row counters (0-based) at descending entry
 * and ascending exit.
 *
 *****************************************************************************/

/* Pending (op started rendering but not yet ascended) map entry. */
typedef struct {
  UINTN RowStart;     /* OSL row counter at descending entry */
  UINTN AmlOff;       /* op offset within the table image (0 = table start) */
  UINTN LenBefore;    /* output length at descending entry (text detection) */
} ACPI_DM_PENDING;

typedef struct {
  /* MUST be the first member: AcpiDmWalkParseTree unconditionally casts
     the context to ACPI_OP_WALK_INFO* and writes Info->Level before
     invoking the callbacks (upstream passes &Info; the nested bank-field
     walk does the same reset on the same struct). ACPI_OP_WALK_INFO's
     Level is its 5th field (offset 32 on x64) - the cast is safe solely
     because Walk is the first member of this struct, so &Ctx ==
     (ACPI_OP_WALK_INFO *) &Ctx->Walk. */
  ACPI_OP_WALK_INFO Walk;
  UINT8             *StartAml;  /* AML stream start minus the table header
                                   (== table image start; AmlOff origin) */
  UINTN             TableLen;   /* table image size (AmlOff bound check) */
  BOOLEAN           Record;     /* caller requested a map (OutMap != NULL) */
  BOOLEAN           MapOk;      /* map/pending allocation health */
  ACPI_AML_ROW_MAP  *Map;       /* finalized entries (ascending order) */
  UINTN              MapCount;
  UINTN              MapCap;
  ACPI_DM_PENDING   *Pending;   /* in-flight entries (LIFO) */
  UINTN              PendCount;
  UINTN              PendCap;
  /* M15 progress: fired periodically from the descending callback
     (every 2048 ops), Percent = AmlOff*100/TableLen. */
  VOID             (*ProgressCb) (UINT32 Percent, VOID *Context);
  VOID             *ProgressCtx;
  UINTN            ProgressTick;   /* op counter since last notification */
} ACPI_DM_CTX;

static ACPI_STATUS
AcpiDmDescendingOp (
  ACPI_PARSE_OBJECT *Op,
  UINT32            Level,
  void              *Context
  );

static ACPI_STATUS
AcpiDmAscendingOp (
  ACPI_PARSE_OBJECT *Op,
  UINT32            Level,
  void              *Context
  );

/**
  Push a pending map entry at the start of an op's descending callback.

  @param[in,out] Ctx  Walk context.
  @param[in]     Op   The parse op about to be rendered.

  @retval AE_OK        Pending entry pushed (or map recording disabled).
  @retval AE_NO_MEMORY Pending array could not grow.
**/
static ACPI_STATUS
AcpiDmPushPending (
  ACPI_DM_CTX       *Ctx,
  ACPI_PARSE_OBJECT *Op
  )
{
  ACPI_DM_PENDING *NewBuf;
  ACPI_DM_PENDING *P;
  UINTN            NewCap;
  UINT8           *Dummy;
  UINTN            OutLen;

  if (!Ctx->Record)
  {
    return AE_OK;
  }

  if (Ctx->PendCount == Ctx->PendCap)
  {
    NewCap = (Ctx->PendCap == 0) ? 256 : Ctx->PendCap * 2;
    NewBuf = AllocatePool (NewCap * sizeof (ACPI_DM_PENDING));
    if (NewBuf == NULL)
    {
      Ctx->MapOk = FALSE;
      return AE_NO_MEMORY;
    }

    if (Ctx->Pending != NULL)
    {
      CopyMem (NewBuf, Ctx->Pending, Ctx->PendCount * sizeof (ACPI_DM_PENDING));
      FreePool (Ctx->Pending);
    }

    Ctx->Pending = NewBuf;
    Ctx->PendCap = NewCap;
  }

  P = &Ctx->Pending[Ctx->PendCount++];
  P->RowStart = AcpicaOsGetLineCount ();
  P->AmlOff   = (UINTN)Op->Common.Aml - (UINTN)Ctx->StartAml;
  AcpicaOsGetOutput (&Dummy, &OutLen);
  P->LenBefore = OutLen;
  return AE_OK;
}

/**
  Finalize the pending entry of an op at the end of its ascending callback:
  the top pending entry is the op that just ascended (walk visits are
  strictly LIFO, including the nested bank-field walk). Entries whose op
  wrote no output bytes are dropped.

  @param[in,out] Ctx  Walk context.

  @retval AE_OK        Pending entry finalized.
  @retval AE_NO_MEMORY Map array could not grow.
**/
static ACPI_STATUS
AcpiDmFinalizeMap (
  ACPI_DM_CTX *Ctx
  )
{
  ACPI_DM_PENDING  *P;
  ACPI_AML_ROW_MAP *NewMap;
  ACPI_AML_ROW_MAP *M;
  UINTN             NewCap;
  UINT8             *OutBuf;
  UINTN             OutLen;

  if (!Ctx->Record || Ctx->PendCount == 0)
  {
    return AE_OK;
  }

  P = &Ctx->Pending[Ctx->PendCount - 1];
  Ctx->PendCount--;

  /* M-2 hardening: an op pointer outside the table (only possible via a
     broken parse tree; Op->Common.Aml - StartAml would underflow to a
     huge value and pollute the sort + AmlLen fill) drops the entry. The
     push stayed unconditional so the LIFO pairing with the ascending
     callback is unaffected. */
  if (P->AmlOff > Ctx->TableLen)
  {
    return AE_OK;
  }

  AcpicaOsGetOutput (&OutBuf, &OutLen);
  if (OutLen == P->LenBefore)
  {
    /* Op produced no output text (IGNORE/NOOP/etc.) - no row to map. */
    return AE_OK;
  }

  if (Ctx->MapCount == Ctx->MapCap)
  {
    NewCap = (Ctx->MapCap == 0) ? 256 : Ctx->MapCap * 2;
    NewMap = AllocatePool (NewCap * sizeof (ACPI_AML_ROW_MAP));
    if (NewMap == NULL)
    {
      Ctx->MapOk = FALSE;
      return AE_NO_MEMORY;
    }

    if (Ctx->Map != NULL)
    {
      CopyMem (NewMap, Ctx->Map, Ctx->MapCount * sizeof (ACPI_AML_ROW_MAP));
      FreePool (Ctx->Map);
    }

    Ctx->Map = NewMap;
    Ctx->MapCap = NewCap;
  }

  M = &Ctx->Map[Ctx->MapCount++];
  M->RowStart = P->RowStart;
  /* Rows are [RowStart, RowEnd] inclusive: the row counter at ascending
     exit points one past the last written row when the op's output ends
     with '\n' (the newline only opens the next row, it does not write it),
     so back off in that case. */
  M->RowEnd   = AcpicaOsGetLineCount ();
  if (OutBuf[OutLen - 1] == '\n')
  {
    M->RowEnd--;
  }

  M->AmlOff   = P->AmlOff;
  M->AmlLen   = 0;                          /* filled by the post-pass */
  return AE_OK;
}

/**
  Post-pass over the finalized map: sort entries by AML offset (insertion
  sort - the walk visits ops roughly in AML order, so the array is nearly
  sorted) and fill AmlLen with the distance to the NEXT DIFFERENT offset in
  AML order (the last entry extends to the end of the table). Entries that
  share one offset (e.g. the synthetic root scope op vs the first statement
  of the table, both at offset sizeof(ACPI_TABLE_HEADER)) receive the same
  span: each covers the rows its own text produced, so sharing the byte
  span between them is unambiguous for row lookups and avoids zero-length
  entries.

  @param[in,out] Ctx       Walk context (Map entries are reordered in place).
  @param[in]     TableLen  Total table image size (AmlLen end bound).
**/
static VOID
AcpiDmFinalizeLengths (
  ACPI_DM_CTX *Ctx,
  UINTN       TableLen
  )
{
  ACPI_AML_ROW_MAP Key;
  UINTN            i;
  UINTN            j;

  for (i = 1; i < Ctx->MapCount; i++)
  {
    Key = Ctx->Map[i];
    j = i;
    while (j > 0 && Ctx->Map[j - 1].AmlOff > Key.AmlOff)
    {
      Ctx->Map[j] = Ctx->Map[j - 1];
      j--;
    }

    Ctx->Map[j] = Key;
  }

  for (i = 0; i < Ctx->MapCount; i++)
  {
    j = i + 1;
    while (j < Ctx->MapCount && Ctx->Map[j].AmlOff == Ctx->Map[i].AmlOff)
    {
      j++;
    }

    if (j < Ctx->MapCount)
    {
      Ctx->Map[i].AmlLen = Ctx->Map[j].AmlOff - Ctx->Map[i].AmlOff;
    }
    else
    {
      Ctx->Map[i].AmlLen = TableLen - Ctx->Map[i].AmlOff;
    }
  }
}

/* ==================== replica of dmwalk.c AcpiDmDescendingOp =============
   Upstream: source/components/disassembler/dmwalk.c L514-L1026 (ACPICA
   20260408). Copied verbatim except: Context carries the wrapper ACPI_DM_CTX
   (Info = &Ctx->Walk), every early `return (AE_OK)`/`return (AE_CTRL_DEPTH)`
   becomes a jump to the single exit point (so the pending entry is always
   pushed at entry and the map recording happens for every path), and the
   nested bank-field walk drives the wrapper callbacks with the same Ctx.
   The ACPI_ASL_COMPILER-only branches are absent from the callbacks; the
   comment-capture blocks are kept (their ASL_CV_* macros compile to no-ops
   in this build). ======================================================== */

static ACPI_STATUS
AcpiDmDescendingOp (
  ACPI_PARSE_OBJECT *Op,
  UINT32            Level,
  void              *Context
  )
{
  ACPI_DM_CTX        *Ctx = Context;
  ACPI_OP_WALK_INFO  *Info = &Ctx->Walk;
  const ACPI_OPCODE_INFO *OpInfo;
  UINT32             Name;
  ACPI_PARSE_OBJECT  *NextOp;
  ACPI_PARSE_OBJECT  *NextOp2;
  UINT32             AmlOffset;
  ACPI_STATUS        Status;

  Status = AcpiDmPushPending (Ctx, Op);
  if (ACPI_FAILURE (Status))
  {
    return Status;
  }

  /* M15 progress: every 2048 ops, notify the caller with the walk's AML
     progress (Percent 0-100). The callback may render a progress bar
     (lv_refr_now) so a large table does not look hung. 2048 keeps the
     render cost low on slow emulators (every-op lv_refr_now would stall
     the walk); a 256KB table visits ~100k+ ops -> ~50 notifications. */
  if (Ctx->ProgressCb != NULL)
  {
    if (++Ctx->ProgressTick >= 2048)
    {
      UINTN AmlOff;

      Ctx->ProgressTick = 0;
      AmlOff = (UINTN) Op->Common.Aml - (UINTN) Ctx->StartAml;
      if (Ctx->TableLen > 0)
      {
        UINT32 Pct = (UINT32) ((AmlOff * 100) / Ctx->TableLen);

        if (Pct > 100)
        {
          Pct = 100;
        }

        Ctx->ProgressCb (Pct, Ctx->ProgressCtx);
      }
    }
  }

  /* Determine which file this parse node is contained in. (dmwalk.c L528) */

  if (AcpiGbl_CaptureComments)
  {
    ASL_CV_LABEL_FILENODE (Op);

    if (Level != 0 && ASL_CV_FILE_HAS_SWITCHED (Op))
    {
      ASL_CV_SWITCH_FILES (Level, Op);
    }

    /* If this parse node has regular comments, print them here. */

    ASL_CV_PRINT_ONE_COMMENT (Op, AML_COMMENT_STANDARD, NULL, Level);
  }

  OpInfo = AcpiPsGetOpcodeInfo (Op->Common.AmlOpcode);

  /* Listing support to dump the AML code after the ASL statement (L546) */

  if (AcpiGbl_DmOpt_Listing)
  {
    /* We only care about these classes of objects */

    if ((OpInfo->Class == AML_CLASS_NAMED_OBJECT) ||
        (OpInfo->Class == AML_CLASS_CONTROL) ||
        (OpInfo->Class == AML_CLASS_CREATE) ||
        ((OpInfo->Class == AML_CLASS_EXECUTE) && (!Op->Common.Next)))
    {
      if (AcpiGbl_DmOpt_Listing && Info->PreviousAml)
      {
        /* Dump the AML byte code for the previous Op */

        if (Op->Common.Aml > Info->PreviousAml)
        {
          AcpiOsPrintf ("\n");
          AcpiUtDumpBuffer (
            (Info->StartAml + Info->AmlOffset),
            (Op->Common.Aml - Info->PreviousAml),
            DB_BYTE_DISPLAY, Info->AmlOffset);
          AcpiOsPrintf ("\n");
        }

        Info->AmlOffset = (Op->Common.Aml - Info->StartAml);
      }

      Info->PreviousAml = Op->Common.Aml;
    }
  }

  if (Op->Common.DisasmFlags & ACPI_PARSEOP_IGNORE)
  {
    /* Ignore this op -- it was handled elsewhere (L578) */

    Status = AE_CTRL_DEPTH;
    goto Done;
  }

  if (Op->Common.DisasmOpcode == ACPI_DASM_IGNORE_SINGLE)
  {
    /* Ignore this op, but not it's children (L585) */

    goto Done;
  }

  if (Op->Common.AmlOpcode == AML_IF_OP)
  {
    NextOp = AcpiPsGetDepthNext (NULL, Op);
    if (NextOp)
    {
      NextOp->Common.DisasmFlags |= ACPI_PARSEOP_PARAMETER_LIST;

      /* Don't emit the actual embedded externals unless asked */

      if (!AcpiGbl_DmEmitExternalOpcodes)
      {
        /*
         * A Zero predicate indicates the possibility of one or more
         * External() opcodes within the If() block.
         */
        if (NextOp->Common.AmlOpcode == AML_ZERO_OP)
        {
          NextOp2 = NextOp->Common.Next;

          if (NextOp2 &&
              (NextOp2->Common.AmlOpcode == AML_EXTERNAL_OP))
          {
            /* Ignore the If 0 block and all children */

            Op->Common.DisasmFlags |= ACPI_PARSEOP_IGNORE;
            Status = AE_CTRL_DEPTH;
            goto Done;
          }
        }
      }
    }
  }

  /* Level 0 is at the Definition Block level (L624) */

  if (Level == 0)
  {
    /* In verbose mode, print the AML offset, opcode and depth count */

    if (Info->WalkState)
    {
      AmlOffset = (UINT32) ACPI_PTR_DIFF (Op->Common.Aml,
          Info->WalkState->ParserState.AmlStart);
      if (AcpiGbl_DmOpt_Verbose)
      {
        if (AcpiGbl_CmSingleStep)
        {
          AcpiOsPrintf ("%5.5X/%4.4X: ",
              AmlOffset, (UINT32) Op->Common.AmlOpcode);
        }
        else
        {
          AcpiOsPrintf ("AML Offset %5.5X, Opcode %4.4X: ",
              AmlOffset, (UINT32) Op->Common.AmlOpcode);
        }
      }
    }

    if (Op->Common.AmlOpcode == AML_SCOPE_OP)
    {
      /* This is the beginning of the Definition Block */

      AcpiOsPrintf ("{\n");

      /* Emit all External() declarations here */

      if (!AcpiGbl_DmEmitExternalOpcodes)
      {
        AcpiDmEmitExternals ();
      }

      goto Done;
    }
  }
  else if ((AcpiDmBlockType (Op->Common.Parent) & BLOCK_BRACE) &&
       (!(Op->Common.DisasmFlags & ACPI_PARSEOP_PARAMETER_LIST)) &&
       (!(Op->Common.DisasmFlags & ACPI_PARSEOP_ELSEIF)) &&
       (Op->Common.AmlOpcode != AML_INT_BYTELIST_OP))
  {
    /*
     * This is a first-level element of a term list,
     * indent a new line
     */
    switch (Op->Common.AmlOpcode)
    {
    case AML_NOOP_OP:
      /*
       * Optionally just ignore this opcode. Some tables use
       * NoOp opcodes for "padding" out packages that the BIOS
       * changes dynamically. This can leave hundreds or
       * thousands of NoOp opcodes that if disassembled,
       * cannot be compiled because they are syntactically
       * incorrect.
       */
      if (AcpiGbl_IgnoreNoopOperator)
      {
        Op->Common.DisasmFlags |= ACPI_PARSEOP_IGNORE;
        goto Done;
      }

      ACPI_FALLTHROUGH;

    default:

      AcpiDmIndent (Level);
      break;
    }

    Info->LastLevel = Level;
    Info->Count = 0;
  }

  /*
   * This is an inexpensive mechanism to try and keep lines from getting
   * too long. When the limit is hit, start a new line at the previous
   * indent plus one. A better but more expensive mechanism would be to
   * keep track of the current column.
   */
  Info->Count++;
  if (Info->Count /* +Info->LastLevel */ > 12)
  {
    Info->Count = 0;
    AcpiOsPrintf ("\n");
    AcpiDmIndent (Info->LastLevel + 1);
  }

  /* If ASL+ is enabled, check for a C-style operator */

  if (AcpiDmCheckForSymbolicOpcode (Op, Info))
  {
    goto Done;
  }

  /* Print the opcode name */

  AcpiDmDisassembleOneOp (NULL, Info, Op);

  if ((Op->Common.DisasmOpcode == ACPI_DASM_LNOT_PREFIX) ||
      (Op->Common.AmlOpcode == AML_INT_CONNECTION_OP))
  {
    goto Done;
  }

  if ((Op->Common.AmlOpcode == AML_NAME_OP) ||
      (Op->Common.AmlOpcode == AML_RETURN_OP))
  {
    Info->Level--;
  }

  if (Op->Common.AmlOpcode == AML_EXTERNAL_OP)
  {
    Op->Common.DisasmFlags |= ACPI_PARSEOP_IGNORE;
    Status = AE_CTRL_DEPTH;
    goto Done;
  }

  /* Start the opcode argument list if necessary */

  if ((OpInfo->Flags & AML_HAS_ARGS) ||
      (Op->Common.AmlOpcode == AML_EVENT_OP))
  {
    /* This opcode has an argument list */

    if (AcpiDmBlockType (Op) & BLOCK_PAREN)
    {
      AcpiOsPrintf (" (");
      if (!(AcpiDmBlockType (Op) & BLOCK_BRACE))
      {
        ASL_CV_PRINT_ONE_COMMENT (Op, AMLCOMMENT_INLINE, " ", 0);
      }
    }

    /* If this is a named opcode, print the associated name value */

    if (OpInfo->Flags & AML_NAMED)
    {
      switch (Op->Common.AmlOpcode)
      {
      case AML_ALIAS_OP:

        NextOp = AcpiPsGetDepthNext (NULL, Op);
        NextOp->Common.DisasmFlags |= ACPI_PARSEOP_IGNORE;
        AcpiDmNamestring (NextOp->Common.Value.Name);
        AcpiOsPrintf (", ");

        ACPI_FALLTHROUGH;

      default:

        Name = AcpiPsGetName (Op);
        if (Op->Named.Path)
        {
          AcpiDmNamestring (Op->Named.Path);
        }
        else
        {
          AcpiDmDumpName (Name);
        }

        if (Op->Common.AmlOpcode != AML_INT_NAMEDFIELD_OP)
        {
          if (AcpiGbl_DmOpt_Verbose)
          {
            (void) AcpiPsDisplayObjectPathname (NULL, Op);
          }
        }
        break;
      }

      switch (Op->Common.AmlOpcode)
      {
      case AML_METHOD_OP:

        AcpiDmMethodFlags (Op);
        ASL_CV_CLOSE_PAREN (Op, Level);

        /* Emit description comment for Method() with a predefined ACPI name */

        AcpiDmPredefinedDescription (Op);
        break;

      case AML_NAME_OP:

        /* Check for _HID and related EISAID() */

        AcpiDmCheckForHardwareId (Op);
        AcpiOsPrintf (", ");
        ASL_CV_PRINT_ONE_COMMENT (Op, AML_NAMECOMMENT, NULL, 0);
        break;

      case AML_REGION_OP:

        AcpiDmRegionFlags (Op);
        break;

      case AML_POWER_RESOURCE_OP:

        /* Mark the next two Ops as part of the parameter list */

        AcpiOsPrintf (", ");
        NextOp = AcpiPsGetDepthNext (NULL, Op);
        NextOp->Common.DisasmFlags |= ACPI_PARSEOP_PARAMETER_LIST;

        NextOp = NextOp->Common.Next;
        NextOp->Common.DisasmFlags |= ACPI_PARSEOP_PARAMETER_LIST;
        goto Done;

      case AML_PROCESSOR_OP:

        /* Mark the next three Ops as part of the parameter list */

        AcpiOsPrintf (", ");
        NextOp = AcpiPsGetDepthNext (NULL, Op);
        NextOp->Common.DisasmFlags |= ACPI_PARSEOP_PARAMETER_LIST;

        NextOp = NextOp->Common.Next;
        NextOp->Common.DisasmFlags |= ACPI_PARSEOP_PARAMETER_LIST;

        NextOp = NextOp->Common.Next;
        NextOp->Common.DisasmFlags |= ACPI_PARSEOP_PARAMETER_LIST;
        goto Done;

      case AML_MUTEX_OP:
      case AML_DATA_REGION_OP:

        AcpiOsPrintf (", ");
        goto Done;

      case AML_EVENT_OP:
      case AML_ALIAS_OP:

        goto Done;

      case AML_SCOPE_OP:
      case AML_DEVICE_OP:
      case AML_THERMAL_ZONE_OP:

        ASL_CV_CLOSE_PAREN (Op, Level);
        break;

      default:

        AcpiOsPrintf ("*** Unhandled named opcode %X\n",
            Op->Common.AmlOpcode);
        break;
      }
    }

    else switch (Op->Common.AmlOpcode)
    {
    case AML_FIELD_OP:
    case AML_BANK_FIELD_OP:
    case AML_INDEX_FIELD_OP:

      Info->BitOffset = 0;

      /* Name of the parent OperationRegion */

      NextOp = AcpiPsGetDepthNext (NULL, Op);
      AcpiDmNamestring (NextOp->Common.Value.Name);
      AcpiOsPrintf (", ");
      NextOp->Common.DisasmFlags |= ACPI_PARSEOP_IGNORE;

      switch (Op->Common.AmlOpcode)
      {
      case AML_BANK_FIELD_OP:

        /* Namestring - Bank Name */

        NextOp = AcpiPsGetDepthNext (NULL, NextOp);
        AcpiDmNamestring (NextOp->Common.Value.Name);
        NextOp->Common.DisasmFlags |= ACPI_PARSEOP_IGNORE;
        AcpiOsPrintf (", ");

        /*
         * Bank Value. This is a TermArg in the middle of the parameter
         * list, must handle it here.
         *
         * Disassemble the TermArg parse tree. ACPI_PARSEOP_PARAMETER_LIST
         * eliminates newline in the output.
         */
        NextOp = NextOp->Common.Next;

        Info->Flags = ACPI_PARSEOP_PARAMETER_LIST;
        AcpiDmWalkParseTree (NextOp, AcpiDmDescendingOp,
            AcpiDmAscendingOp, Ctx);
        Info->Flags = 0;
        Info->Level = Level;

        NextOp->Common.DisasmFlags |= ACPI_PARSEOP_IGNORE;
        AcpiOsPrintf (", ");
        break;

      case AML_INDEX_FIELD_OP:

        /* Namestring - Data Name */

        NextOp = AcpiPsGetDepthNext (NULL, NextOp);
        AcpiDmNamestring (NextOp->Common.Value.Name);
        AcpiOsPrintf (", ");
        NextOp->Common.DisasmFlags |= ACPI_PARSEOP_IGNORE;
        break;

      default:

        break;
      }

      AcpiDmFieldFlags (NextOp);
      break;

    case AML_BUFFER_OP:

      /* The next op is the size parameter */

      NextOp = AcpiPsGetDepthNext (NULL, Op);
      if (!NextOp)
      {
        /* Single-step support */

        goto Done;
      }

      if (Op->Common.DisasmOpcode == ACPI_DASM_RESOURCE)
      {
        /*
         * We have a resource list. Don't need to output
         * the buffer size Op. Open up a new block
         */
        NextOp->Common.DisasmFlags |= ACPI_PARSEOP_IGNORE;
        ASL_CV_CLOSE_PAREN (Op, Level);

        if (Op->Asl.Parent->Common.AmlOpcode == AML_NAME_OP)
        {
          /*
           * Emit description comment showing the full ACPI name
           * of the ResourceTemplate only if it was defined using a
           * Name statement.
           */
           AcpiDmPredefinedDescription (Op->Asl.Parent);
        }

        AcpiOsPrintf ("\n");
        AcpiDmIndent (Info->Level);
        AcpiOsPrintf ("{\n");
        goto Done;
      }

      /* Normal Buffer, mark size as in the parameter list */

      NextOp->Common.DisasmFlags |= ACPI_PARSEOP_PARAMETER_LIST;
      goto Done;

    case AML_IF_OP:
    case AML_VARIABLE_PACKAGE_OP:
    case AML_WHILE_OP:

      /* The next op is the size or predicate parameter */

      NextOp = AcpiPsGetDepthNext (NULL, Op);
      if (NextOp)
      {
        NextOp->Common.DisasmFlags |= ACPI_PARSEOP_PARAMETER_LIST;
      }
      goto Done;

    case AML_PACKAGE_OP:

      /* The next op is the size parameter */

      NextOp = AcpiPsGetDepthNext (NULL, Op);
      if (NextOp)
      {
        NextOp->Common.DisasmFlags |= ACPI_PARSEOP_PARAMETER_LIST;
      }
      goto Done;

    case AML_MATCH_OP:

      AcpiDmMatchOp (Op);
      break;

    default:

      break;
    }

    if (AcpiDmBlockType (Op) & BLOCK_BRACE)
    {
      AcpiOsPrintf ("\n");
      AcpiDmIndent (Level);
      AcpiOsPrintf ("{\n");
    }
  }

Done:
  return Status;
}

/* ==================== replica of dmwalk.c AcpiDmAscendingOp ===============
   Upstream: source/components/disassembler/dmwalk.c L1042-L1296 (ACPICA
   20260408). Copied verbatim except: Context carries the wrapper ACPI_DM_CTX
   (Info = &Ctx->Walk), every early `return (AE_OK)` becomes a jump to the
   single exit point, and the row-map entry of the op is finalized at exit
   (rows written by the closing paren/brace text are attributed to the op).
   ======================================================================== */

static ACPI_STATUS
AcpiDmAscendingOp (
  ACPI_PARSE_OBJECT *Op,
  UINT32            Level,
  void              *Context
  )
{
  ACPI_DM_CTX        *Ctx = Context;
  ACPI_OP_WALK_INFO  *Info = &Ctx->Walk;
  ACPI_PARSE_OBJECT  *ParentOp;
  ACPI_STATUS        Status = AE_OK;

  /* Point the Op's filename pointer to the proper file (dmwalk.c L1052) */

  if (AcpiGbl_CaptureComments)
  {
    ASL_CV_LABEL_FILENODE (Op);

    /* Switch the output of these files if necessary */

    if (ASL_CV_FILE_HAS_SWITCHED (Op))
    {
      ASL_CV_SWITCH_FILES (Level, Op);
    }
  }

  if (Op->Common.DisasmFlags & ACPI_PARSEOP_IGNORE ||
      Op->Common.DisasmOpcode == ACPI_DASM_IGNORE_SINGLE)
  {
    /* Ignore this op -- it was handled elsewhere */

    goto Done;
  }

  if ((Level == 0) && (Op->Common.AmlOpcode == AML_SCOPE_OP))
  {
    /* Indicates the end of the current descriptor block (table) */

    ASL_CV_CLOSE_BRACE (Op, Level);

    /* Print any comments that are at the end of the file here */

    if (AcpiGbl_CaptureComments && AcpiGbl_LastListHead)
    {
      AcpiOsPrintf ("\n");
      ASL_CV_PRINT_ONE_COMMENT_LIST (AcpiGbl_LastListHead, 0);
    }
    AcpiOsPrintf ("\n\n");

    goto Done;
  }

  switch (AcpiDmBlockType (Op))
  {
  case BLOCK_PAREN:

    /* Completed an op that has arguments, add closing paren if needed */

    AcpiDmCloseOperator (Op);

    if (Op->Common.AmlOpcode == AML_NAME_OP)
    {
      /* Emit description comment for Name() with a predefined ACPI name */

      AcpiDmPredefinedDescription (Op);
    }
    else
    {
      /* For Create* operators, attempt to emit resource tag description */

      AcpiDmFieldPredefinedDescription (Op);
    }

    /* Decode Notify() values */

    if (Op->Common.AmlOpcode == AML_NOTIFY_OP)
    {
      AcpiDmNotifyDescription (Op);
    }

    AcpiDmDisplayTargetPathname (Op);

    /* Could be a nested operator, check if comma required */

    if (!AcpiDmCommaIfListMember (Op))
    {
      if ((AcpiDmBlockType (Op->Common.Parent) & BLOCK_BRACE) &&
           (!(Op->Common.DisasmFlags & ACPI_PARSEOP_PARAMETER_LIST)) &&
           (Op->Common.AmlOpcode != AML_INT_BYTELIST_OP))
      {
        /*
         * This is a first-level element of a term list
         * start a new line
         */
        if (!(Info->Flags & ACPI_PARSEOP_PARAMETER_LIST))
        {
          AcpiOsPrintf ("\n");
        }
      }
    }
    break;

  case BLOCK_BRACE:
  case (BLOCK_BRACE | BLOCK_PAREN):

    /* Completed an op that has a term list, add closing brace */

    if (Op->Common.DisasmFlags & ACPI_PARSEOP_EMPTY_TERMLIST)
    {
      ASL_CV_CLOSE_BRACE (Op, Level);
    }
    else
    {
      AcpiDmIndent (Level);
      ASL_CV_CLOSE_BRACE (Op, Level);
    }

    AcpiDmCommaIfListMember (Op);

    if (AcpiDmBlockType (Op->Common.Parent) != BLOCK_PAREN)
    {
      AcpiOsPrintf ("\n");
      if (!(Op->Common.DisasmFlags & ACPI_PARSEOP_EMPTY_TERMLIST))
      {
        if ((Op->Common.AmlOpcode == AML_IF_OP)  &&
            (Op->Common.Next) &&
            (Op->Common.Next->Common.AmlOpcode == AML_ELSE_OP))
        {
          break;
        }

        if ((AcpiDmBlockType (Op->Common.Parent) & BLOCK_BRACE) &&
            (!Op->Common.Next))
        {
          break;
        }
        AcpiOsPrintf ("\n");
      }
    }
    break;

  case BLOCK_NONE:
  default:

    /* Could be a nested operator, check if comma required */

    if (!AcpiDmCommaIfListMember (Op))
    {
      if ((AcpiDmBlockType (Op->Common.Parent) & BLOCK_BRACE) &&
           (!(Op->Common.DisasmFlags & ACPI_PARSEOP_PARAMETER_LIST)) &&
           (Op->Common.AmlOpcode != AML_INT_BYTELIST_OP))
      {
        /*
         * This is a first-level element of a term list
         * start a new line
         */
        AcpiOsPrintf ("\n");
      }
    }
    else if (Op->Common.Parent)
    {
      switch (Op->Common.Parent->Common.AmlOpcode)
      {
      case AML_PACKAGE_OP:
      case AML_VARIABLE_PACKAGE_OP:

        if (!(Op->Common.DisasmFlags & ACPI_PARSEOP_PARAMETER_LIST))
        {
          AcpiOsPrintf ("\n");
        }
        break;

      default:

        break;
      }
    }
    break;
  }

  if (Op->Common.DisasmFlags & ACPI_PARSEOP_PARAMETER_LIST)
  {
    if ((Op->Common.Next) &&
        (Op->Common.Next->Common.DisasmFlags & ACPI_PARSEOP_PARAMETER_LIST))
    {
      goto Done;
    }

    /*
     * The parent Op is guaranteed to be valid because of the flag
     * ACPI_PARSEOP_PARAMETER_LIST -- which means that this op is part of
     * a parameter list and thus has a valid parent.
     */
    ParentOp = Op->Common.Parent;

    /*
     * Just completed a parameter node for something like "Buffer (param)".
     * Close the paren and open up the term list block with a brace.
     *
     * Switch predicates don't have a Next node but require a closing paren
     * and opening brace.
     */
    if (Op->Common.Next || Op->Common.DisasmOpcode == ACPI_DASM_SWITCH_PREDICATE)
    {
      ASL_CV_CLOSE_PAREN (Op, Level);

      /*
       * Emit a description comment for a Name() operator that is a
       * predefined ACPI name. Must check the grandparent.
       */
      ParentOp = ParentOp->Common.Parent;
      if (ParentOp &&
          (ParentOp->Asl.AmlOpcode == AML_NAME_OP))
      {
        AcpiDmPredefinedDescription (ParentOp);
      }

      /* Correct the indentation level for Switch and Case predicates */

      if (Op->Common.DisasmOpcode == ACPI_DASM_SWITCH_PREDICATE)
      {
        --Level;
      }

      AcpiOsPrintf ("\n");
      AcpiDmIndent (Level - 1);
      AcpiOsPrintf ("{\n");
    }
    else
    {
      ParentOp->Common.DisasmFlags |= ACPI_PARSEOP_EMPTY_TERMLIST;
      ASL_CV_CLOSE_PAREN (Op, Level);
      AcpiOsPrintf ("{");
    }
  }

  if ((Op->Common.AmlOpcode == AML_NAME_OP) ||
      (Op->Common.AmlOpcode == AML_RETURN_OP))
  {
    Info->Level++;
  }

  /*
   * For ASL+, check for and emit a C-style symbol. If valid, the
   * symbol string has been deferred until after the first operand
   */
  if (AcpiGbl_CstyleDisassembly)
  {
    if (Op->Asl.OperatorSymbol)
    {
      AcpiOsPrintf ("%s", Op->Asl.OperatorSymbol);
      Op->Asl.OperatorSymbol = NULL;
    }
  }

Done:
  if (ACPI_SUCCESS (Status))
  {
    Status = AcpiDmFinalizeMap (Ctx);
  }
  return Status;
}

/******************************************************************************
 *
 * One full parse + disassemble pass.
 *
 * Runs the public-API AdParseTable sequence (parse pass 1, deferred
 * opcodes, resource templates) and then the wrapper's self-driven walk
 * (AcpiDmWalkParseTree with the wrapper callbacks, which also record the
 * row<->AML map into Ctx). The disassembled text lands in the OSL output
 * buffer.
 *
 * @param[in]  AmlTable  Table image (ACPI header + AML stream).
 * @param[in]  TableLen  Image size in bytes.
 * @param[in]  Ctx       Self-driven walk context (may be partially set up;
 *                       the walk fields are (re)initialized here).
 *
 * @retval EFI_SUCCESS          Pass completed.
 * @retval EFI_OUT_OF_RESOURCES Parse setup or mapping table alloc failed.
 * @retval EFI_COMPROMISED_DATA Parse/disassemble failed.
 *
 *****************************************************************************/

static EFI_STATUS
AcpicaRunPass (
  const UINT8 *AmlTable,
  UINTN       TableLen,
  ACPI_DM_CTX *Ctx
  )
{
  ACPI_TABLE_HEADER *Hdr;
  ACPI_STATUS       Status;
  ACPI_WALK_STATE   *WalkState;
  UINT8             *AmlStart;
  UINT32            AmlLength;
  EFI_STATUS        Ret;

  Hdr = (ACPI_TABLE_HEADER *) (UINTN) AmlTable;
  AcpiGbl_DisasmFlag   = TRUE;
  AcpiGbl_DmOpt_Disasm = TRUE;
  /* AcpiGbl_DmOpt_Verbose defaults to TRUE in acglobal.h; upstream iasl
     turns it off at startup (aslmain.c). Without this the named-op print
     path (dmwalk.c AcpiPsDisplayObjectPathname) fires on every named
     statement: the no-namespace lookup fails and pollutes the output with
     "ACPI Warning: Invalid character(s) in name ... [Path not found]"
     noise after every statement header (FixWave-C). */
  AcpiGbl_DmOpt_Verbose = FALSE;

  AcpiUtSetIntegerWidth (Hdr->Revision);

  AmlLength = (UINT32) (TableLen - sizeof (ACPI_TABLE_HEADER));
  AmlStart  = (UINT8 *) AmlTable + sizeof (ACPI_TABLE_HEADER);

  AcpiGbl_ParseOpRoot = AcpiPsCreateScopeOp (AmlStart);
  if (AcpiGbl_ParseOpRoot == NULL)
  {
    /* Nothing to delete: the scope op was never created. Still clear the
       disassembler globals set above (align with the normal path). */
    AcpiGbl_DisasmFlag   = FALSE;
    AcpiGbl_DmOpt_Disasm = FALSE;
    return EFI_OUT_OF_RESOURCES;
  }

  WalkState = AcpiDsCreateWalkState (0, AcpiGbl_ParseOpRoot, NULL, NULL);
  if (WalkState == NULL)
  {
    /* CreateWalkState failed - the walk state was never created, so only
       the parse tree is ours to free (mirror the InitAmlWalk failure path
       below, minus DeleteWalkState) and the globals need the same reset. */
    AcpiPsDeleteParseTree (AcpiGbl_ParseOpRoot);
    AcpiGbl_ParseOpRoot   = NULL;
    AcpiGbl_DisasmFlag    = FALSE;
    AcpiGbl_DmOpt_Disasm  = FALSE;
    return EFI_OUT_OF_RESOURCES;
  }

  Status = AcpiDsInitAmlWalk (
             WalkState,
             AcpiGbl_ParseOpRoot,
             NULL,
             AmlStart,
             AmlLength,
             NULL,
             ACPI_IMODE_LOAD_PASS1
             );
  if (ACPI_FAILURE (Status))
  {
    /* InitAmlWalk failed before the parse path took ownership of the walk
       state, so it is still ours: delete it (AcpiDsDeleteWalkState is
       NULL-safe and cleans up any partially pushed scopes). */
    AcpiDsDeleteWalkState (WalkState);
    AcpiPsDeleteParseTree (AcpiGbl_ParseOpRoot);
    AcpiGbl_ParseOpRoot = NULL;
    Ret = EFI_COMPROMISED_DATA;
    goto ResetGlobals;
  }

  WalkState->ParseFlags &= ~ACPI_PARSE_DELETE_TREE;
  Status = AcpiPsParseAml (WalkState);

  /* IMPORTANT: AcpiPsParseAml deletes the walk state itself on exit (both
     success and failure paths), so WalkState is dangling from here on and
     must not be dereferenced or freed. */

  if (ACPI_FAILURE (Status))
  {
    /* Leak the tree on the failure path, matching upstream dmtables.c (the
       parser may already have deleted subtrees of AML_REGION_OP /
       AML_DATA_REGION_OP ops that remain linked on the parent arg chain,
       so a second walk would double-free). */
    Ret = EFI_COMPROMISED_DATA;
    goto ResetGlobals;
  }

  AcpiDmParseDeferredOps (AcpiGbl_ParseOpRoot); /* control method bodies   */
  AcpiDmFindResources (AcpiGbl_ParseOpRoot);    /* ResourceTemplate decode */

  /* Self-driven walk: AcpiDmWalkParseTree with the wrapper callbacks.
     WalkState is NULL - the parse path deleted it (upstream dmtables.c
     likewise passes NULL to AcpiDmDisassemble). The walk context embeds
     the ACPI_OP_WALK_INFO as its first member because the walk function
     itself casts the context to ACPI_OP_WALK_INFO* and writes Level. */

  ZeroMem (&Ctx->Walk, sizeof (Ctx->Walk));
  Ctx->Walk.WalkState = NULL;
  Ctx->Walk.StartAml  = AcpiGbl_ParseOpRoot->Common.Aml -
                        sizeof (ACPI_TABLE_HEADER);
  Ctx->Walk.AmlOffset = (UINT32) ((UINTN)AcpiGbl_ParseOpRoot->Common.Aml -
                                  (UINTN)Ctx->Walk.StartAml);

  Ctx->StartAml   = Ctx->Walk.StartAml;
  Ctx->TableLen   = TableLen;
  Ctx->MapCount   = 0;
  Ctx->MapCap     = 0;
  Ctx->Map        = NULL;
  Ctx->PendCount  = 0;
  Ctx->PendCap    = 0;
  Ctx->Pending    = NULL;
  Ctx->MapOk      = TRUE;

  AcpiDmWalkParseTree (AcpiGbl_ParseOpRoot, AcpiDmDescendingOp,
                       AcpiDmAscendingOp, Ctx);

  if (Ctx->PendCount != 0)
  {
    /* Unbalanced pending stack - cannot happen with the upstream walk
       (every op is visited descending then ascending, incl. the nested
       bank-field walk); treat as a walk failure. */
    Ctx->MapOk = FALSE;
  }

  AcpiDmFinalizeLengths (Ctx, TableLen);

  DEBUG ((DEBUG_INFO, "[Acpica] walk rows=%u map=%u\n",
          (UINT32) AcpicaOsGetLineCount (), (UINT32) Ctx->MapCount));

  if (!Ctx->MapOk)
  {
    AcpiPsDeleteParseTree (AcpiGbl_ParseOpRoot);
    Ret = EFI_OUT_OF_RESOURCES;
    goto ResetGlobals;
  }

  Ret = EFI_SUCCESS;

  /* Free the parse tree on the SUCCESS path only (see the failure note
     above). Mirrors the upstream cleanup in common/adisasm.c. */
  AcpiPsDeleteParseTree (AcpiGbl_ParseOpRoot);

ResetGlobals:
  AcpiGbl_ParseOpRoot = NULL;
  AcpiGbl_DisasmFlag  = FALSE;
  AcpiGbl_DmOpt_Disasm = FALSE;
  AcpiGbl_DmOpt_Verbose = FALSE;   /* restored (we forced it off above) */
  return Ret;
}

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
  )
{
  ACPI_STATUS       Status;
  ACPI_DM_CTX       Ctx;
  UINT8             *Buf;
  UINTN             Cap;
  UINTN             Len;
  UINTN             OutLen;
  UINT8             *OutBuf;

  if (OutText == NULL || OutSize == NULL)
  {
    return EFI_INVALID_PARAMETER;
  }

  *OutText = NULL;
  *OutSize = 0;

  if (OutMap != NULL)
  {
    if (OutMapCount == NULL)
    {
      return EFI_INVALID_PARAMETER;
    }

    *OutMap = NULL;
    *OutMapCount = 0;
  }

  if (AmlTable == NULL || TableLen < sizeof (ACPI_TABLE_HEADER))
  {
    return EFI_INVALID_PARAMETER;
  }

  if (!gInit)
  {
    Status = AcpiInitializeSubsystem ();
    if (ACPI_FAILURE (Status))
    {
      DEBUG ((DEBUG_INFO, "[Acpica] subsystem init failed %x\n", (UINT32) Status));
      return EFI_DEVICE_ERROR;
    }

    gInit = TRUE;
  }

  /* Output buffer: 2x table size to start, floor 8KB, cap 4MB. The OSL can
     grow it further (doubling) if a disassembly exceeds the cap. */
  Cap = TableLen * 2;
  if (Cap < 8192)
  {
    Cap = 8192;
  }

  if (Cap > (4u << 20))
  {
    Cap = (4u << 20);
  }

  Buf = AllocatePool (Cap);
  if (Buf == NULL)
  {
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem (&Ctx, sizeof (Ctx));
  Ctx.Record      = (OutMap != NULL);
  Ctx.ProgressCb  = ProgressCb;
  Ctx.ProgressCtx = ProgressCtx;
  Ctx.ProgressTick = 0;

  AcpicaOsSetOutput (Buf, Cap);
  AcpicaOsClearOutput ();

  Status = AcpicaRunPass (AmlTable, TableLen, &Ctx);
  if (EFI_ERROR (Status))
  {
    /* The OSL may have grown the buffer; free the current pointer. */
    AcpicaOsGetOutput (&OutBuf, &Len);
    FreePool (OutBuf);
    if (Ctx.Map != NULL)
    {
      FreePool (Ctx.Map);
    }

    if (Ctx.Pending != NULL)
    {
      FreePool (Ctx.Pending);
    }

    DEBUG ((DEBUG_INFO, "[Acpica] disasm failed %x\n", (UINT32) Status));
    return Status;
  }

  /* The OSL may have grown the buffer; always use the current pointer. */

  AcpicaOsGetOutput (&OutBuf, &OutLen);

  /* The OSL's AsciiVSPrint translates every '\n' to "\r\n" (EDK2 PrintLib
     console semantics). ACPICA emits LF-only on every other platform, so
     normalize here: strip '\r' in place (the text only grows shorter). */
  if (OutLen > 0)
  {
    UINTN  i, o = 0;

    for (i = 0; i < OutLen; i++)
    {
      if (OutBuf[i] != '\r')
      {
        OutBuf[o++] = OutBuf[i];
      }
    }
    OutLen = o;
  }

  OutBuf[OutLen] = 0;  /* NUL-terminate; the OSL keeps >= 1 spare byte */
  *OutText = OutBuf;
  *OutSize = OutLen;

  if (OutMap != NULL)
  {
    *OutMap = Ctx.Map;
    *OutMapCount = Ctx.MapCount;
  }
  else if (Ctx.Map != NULL)
  {
    FreePool (Ctx.Map);
  }

  /* The pending stack is drained (PendCount == 0) but its buffer was
     allocated by AcpiDmPushPending when a map was requested - free it on
     every path (I-1 review fix). */
  if (Ctx.Pending != NULL)
  {
    FreePool (Ctx.Pending);
  }

  DEBUG ((DEBUG_INFO, "[Acpica] disasm ok size %u map %u\n",
          (UINT32) OutLen, (UINT32) Ctx.MapCount));
  return EFI_SUCCESS;
}
