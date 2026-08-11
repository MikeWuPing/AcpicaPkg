/** @file
  AcpicaStubs.c - ACPICA functions from components NOT compiled in this port.

  The compiled closure (utilities / parser / dswstate / namespace subset /
  disassembler) still *references* a few functions from the executer,
  events, hardware and tables components. They fall into three groups:

  1. Execution-path tripwires (STUB_WARN): control-method execution and
     predicate evaluation never happen in disassembly mode (no control
     state is created), so these must never be called. A hit is a debug
     signal for a broken port configuration.

  2. Real no-op implementations: functions the parse machinery legitimately
     calls on every run (interpreter reentrancy guard, tracer hooks,
     per-parse mutex release, per-walk scope-stack reset). They do nothing
     meaningful in a single-threaded parse-only build.

  3. Ported real implementations: AcpiEx{Integer,EisaId,PciCls}ToString are
     used by the disassembler at runtime (buffer dumps); the logic is copied
     from upstream executer/exutils.c (which is not compiled).

  Nothing in the upstream acpica/ tree is modified.

  Copyright (c) 2026, Mike Wu. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/DebugLib.h>

#include "acpi.h"
#include "accommon.h"
#include "acparser.h"
#include "acdispat.h"
#include "acinterp.h"
#include "acevents.h"
#include "achware.h"
#include "actables.h"
#include "acutils.h"
#include "acnamesp.h"
#include "acdisasm.h"
#include "amlresrc.h"
#include "acpredef.h"
#include "amlcode.h"   /* AML_NAMED (FixWave-C: name-consuming load callback) */

/* Execution-path tripwire: not expected in disassembly mode (DisasmFlag
   implies no control-state evaluation). A trigger is a port failure. */
#define STUB_WARN(fn)  DEBUG ((DEBUG_WARN, "[Acpica] stub hit: %a\n", fn))

/******************************************************************************
 *
 * Group 1: dispatcher execution-path tripwires (per acdispat.h signatures)
 *
 *****************************************************************************/

ACPI_STATUS
AcpiDsCallControlMethod (
  ACPI_THREAD_STATE *Thread,
  ACPI_WALK_STATE   *WalkState,
  ACPI_PARSE_OBJECT *Op
  )
{
  STUB_WARN ("AcpiDsCallControlMethod");
  return AE_SUPPORT;
}

ACPI_STATUS
AcpiDsRestartControlMethod (
  ACPI_WALK_STATE     *WalkState,
  ACPI_OPERAND_OBJECT *ReturnDesc
  )
{
  STUB_WARN ("AcpiDsRestartControlMethod");
  return AE_SUPPORT;
}

void
AcpiDsTerminateControlMethod (
  ACPI_OPERAND_OBJECT *MethodDesc,
  ACPI_WALK_STATE     *WalkState
  )
{
  /* Upstream guards the NULL case (method execution never started) and
     stays silent; mirror that so parse-error paths (psparse.c calls this
     with MethodDesc == NULL) do not pollute the "no stub hit" assertion.
     A non-NULL MethodDesc means real method execution, which must never
     happen in this parse-only port. */
  if (MethodDesc != NULL)
  {
    STUB_WARN ("AcpiDsTerminateControlMethod");
  }
}

ACPI_STATUS
AcpiDsBeginMethodExecution (
  ACPI_NAMESPACE_NODE *MethodNode,
  ACPI_OPERAND_OBJECT *ObjDesc,
  ACPI_WALK_STATE     *WalkState
  )
{
  STUB_WARN ("AcpiDsBeginMethodExecution");
  return AE_SUPPORT;
}

ACPI_STATUS
AcpiDsMethodError (
  ACPI_STATUS    Status,
  ACPI_WALK_STATE *WalkState
  )
{
  STUB_WARN ("AcpiDsMethodError");
  return Status;
}

ACPI_STATUS
AcpiDsGetPredicateValue (
  ACPI_WALK_STATE     *WalkState,
  ACPI_OPERAND_OBJECT *ResultObj
  )
{
  STUB_WARN ("AcpiDsGetPredicateValue");
  return AE_SUPPORT;
}

BOOLEAN
AcpiDsIsResultUsed (
  ACPI_PARSE_OBJECT *Op,
  ACPI_WALK_STATE   *WalkState
  )
{
  STUB_WARN ("AcpiDsIsResultUsed");
  return TRUE;
}

void
AcpiDsClearImplicitReturn (
  ACPI_WALK_STATE *WalkState
  )
{
  STUB_WARN ("AcpiDsClearImplicitReturn");
}

ACPI_STATUS
AcpiDsScopeStackPush (
  ACPI_NAMESPACE_NODE *Node,
  ACPI_OBJECT_TYPE    Type,
  ACPI_WALK_STATE     *WalkState
  )
{
  STUB_WARN ("AcpiDsScopeStackPush");
  return AE_SUPPORT;
}

/******************************************************************************
 *
 * Group 2: real no-ops for the parse path
 *
 *****************************************************************************/

void
AcpiExEnterInterpreter (
  VOID
  )
{
  /* Interpreter reentrancy guard; single-threaded parse has no nesting. */
}

void
AcpiExExitInterpreter (
  VOID
  )
{
}

void
AcpiExStartTraceOpcode (
  ACPI_PARSE_OBJECT *Op,
  ACPI_WALK_STATE   *WalkState
  )
{
  /* Trace support (executer/extrace.c) is not compiled; tracer is off. */
}

void
AcpiExStopTraceOpcode (
  ACPI_PARSE_OBJECT *Op,
  ACPI_WALK_STATE   *WalkState
  )
{
}

void
AcpiExTracePoint (
  ACPI_TRACE_EVENT_TYPE Type,
  BOOLEAN               Begin,
  UINT8                 *Aml,
  char                  *Pathname
  )
{
}

void
AcpiExReleaseAllMutexes (
  ACPI_THREAD_STATE *Thread
  )
{
  /* Normal exit path of AcpiPsParseAml; no mutexes are ever held. */
}

void
AcpiExUnlinkMutex (
  ACPI_OPERAND_OBJECT *ObjDesc
  )
{
  STUB_WARN ("AcpiExUnlinkMutex");
}

void
AcpiDsScopeStackClear (
  ACPI_WALK_STATE *WalkState
  )
{
  /* Real no-op, NOT a tripwire: AcpiPsParseAml calls this on the normal
     exit path of every walk (psparse.c, "Reset the current scope to the
     beginning of scope stack"). The scope stack only matters during
     execution, and our parse-only disassembly never pushes scopes. */
}

/******************************************************************************
 *
 * Group 3: ported real implementations (upstream executer/exutils.c)
 *
 *****************************************************************************/

static UINT32
AcpicaPortDigitsNeeded (
  UINT64 Value,
  UINT32 Base
  )
{
  UINT32 Count;

  Count = 1;
  while (Value >= Base)
  {
    Value /= Base;
    Count++;
  }

  return Count;
}

void
AcpiExIntegerToString (
  char   *OutString,
  UINT64 Value
  )
{
  UINT32 Count;
  UINT32 DigitsNeeded;
  UINT32 Remainder;

  DigitsNeeded = AcpicaPortDigitsNeeded (Value, 10);
  OutString[DigitsNeeded] = 0;

  for (Count = DigitsNeeded; Count > 0; Count--)
  {
    (void) AcpiUtShortDivide (Value, 10, &Value, &Remainder);
    OutString[Count - 1] = (char) ('0' + Remainder);
  }
}

void
AcpiExEisaIdToString (
  char   *OutString,
  UINT64 CompressedId
  )
{
  UINT32 SwappedId;

  /* The EISAID should be a 32-bit integer */

  if (CompressedId > ACPI_UINT32_MAX)
  {
    DEBUG ((
      DEBUG_WARN,
      "[Acpica] expected EISAID larger than 32 bits: %8.8X%8.8X, truncating\n",
      (UINT32) ((UINT64) CompressedId >> 32),
      (UINT32) CompressedId
      ));
  }

  /* Swap ID to big-endian to get contiguous bits */

  SwappedId = AcpiUtDwordByteSwap ((UINT32) CompressedId);

  /* First 3 bytes are uppercase letters. Next 4 bytes are hexadecimal */

  OutString[0] = (char) (0x40 + (((unsigned long) SwappedId >> 26) & 0x1F));
  OutString[1] = (char) (0x40 + ((SwappedId >> 21) & 0x1F));
  OutString[2] = (char) (0x40 + ((SwappedId >> 16) & 0x1F));
  OutString[3] = AcpiUtHexToAsciiChar ((UINT64) SwappedId, 12);
  OutString[4] = AcpiUtHexToAsciiChar ((UINT64) SwappedId, 8);
  OutString[5] = AcpiUtHexToAsciiChar ((UINT64) SwappedId, 4);
  OutString[6] = AcpiUtHexToAsciiChar ((UINT64) SwappedId, 0);
  OutString[7] = 0;
}

void
AcpiExPciClsToString (
  char  *OutString,
  UINT8 ClassCode[3]
  )
{
  /* All 3 bytes are hexadecimal */

  OutString[0] = AcpiUtHexToAsciiChar ((UINT64) ClassCode[0], 4);
  OutString[1] = AcpiUtHexToAsciiChar ((UINT64) ClassCode[0], 0);
  OutString[2] = AcpiUtHexToAsciiChar ((UINT64) ClassCode[1], 4);
  OutString[3] = AcpiUtHexToAsciiChar ((UINT64) ClassCode[1], 0);
  OutString[4] = AcpiUtHexToAsciiChar ((UINT64) ClassCode[2], 4);
  OutString[5] = AcpiUtHexToAsciiChar ((UINT64) ClassCode[2], 0);
  OutString[6] = 0;
}

/******************************************************************************
 *
 * Group 4: tables / events / hardware stubs (not compiled; only reachable
 * through the subsystem init/terminate entry points which the wrapper
 * never calls beyond AcpiInitializeSubsystem)
 *
 *****************************************************************************/

void
AcpiTbCheckDsdtHeader (
  VOID
  )
{
  STUB_WARN ("AcpiTbCheckDsdtHeader");
}

ACPI_STATUS
AcpiTbInitializeFacs (
  VOID
  )
{
  STUB_WARN ("AcpiTbInitializeFacs");
  return AE_SUPPORT;
}

void
AcpiTbTerminate (
  VOID
  )
{
  STUB_WARN ("AcpiTbTerminate");
}

ACPI_STATUS
AcpiEvInitializeEvents (
  VOID
  )
{
  STUB_WARN ("AcpiEvInitializeEvents");
  return AE_SUPPORT;
}

ACPI_STATUS
AcpiEvInstallXruptHandlers (
  VOID
  )
{
  STUB_WARN ("AcpiEvInstallXruptHandlers");
  return AE_SUPPORT;
}

ACPI_STATUS
AcpiEvDeleteGpeBlock (
  ACPI_GPE_BLOCK_INFO *GpeBlock
  )
{
  STUB_WARN ("AcpiEvDeleteGpeBlock");
  return AE_SUPPORT;
}

void
AcpiEvTerminate (
  VOID
  )
{
  STUB_WARN ("AcpiEvTerminate");
}

UINT32
AcpiHwGetMode (
  VOID
  )
{
  STUB_WARN ("AcpiHwGetMode");
  return ACPI_SYS_MODE_LEGACY;
}

/******************************************************************************
 *
 * Group 5: namespace / dispatcher gaps (nsalloc, nsobject, nssearch,
 * nseval, nsinit, dsutils, dswload, dbstat - none compiled here)
 *
 * The parse-only port deliberately keeps the namespace EMPTY apart from the
 * root node and the predefined names created by AcpiNsRootInitialize, so:
 *  - real ports for the three functions AcpiNsRootInitialize depends on
 *    (AcpiNsCreateNode / AcpiNsAttachObject / AcpiNsGetAttachedObject);
 *  - AcpiNsSearchAndEnter returns AE_NOT_FOUND: parse-time lookups
 *    (ACPI_IMODE_EXECUTE from psargs.c) then resolve no name, which is
 *    exactly the intended no-pass-2 "emit names as written" behavior;
 *  - everything else below is either must-call-on-parse (no-op) or only
 *    reachable from never-invoked public init/evaluate/terminate paths.
 *
 *****************************************************************************/

/* Real ports (runtime dependency of AcpiNsRootInitialize) */

ACPI_NAMESPACE_NODE *
AcpiNsCreateNode (
  UINT32 Name
  )
{
  ACPI_NAMESPACE_NODE *Node;

  /* Faithful port of upstream nsalloc.c: cache objects are zeroed (our
     cache OSL guarantees that), so only name + descriptor type are set. */
  Node = AcpiOsAcquireObject (AcpiGbl_NamespaceCache);
  if (!Node)
  {
    return NULL;
  }

  Node->Name.Integer = Name;
  ACPI_SET_DESCRIPTOR_TYPE (Node, ACPI_DESC_TYPE_NAMED);
  return Node;
}

ACPI_STATUS
AcpiNsAttachObject (
  ACPI_NAMESPACE_NODE *Node,
  ACPI_OPERAND_OBJECT *Object,
  ACPI_OBJECT_TYPE    Type
  )
{
  /* Minimal single-threaded port of upstream nsobject.c: no alias/data/
     handler bookkeeping, just the direct attachment. */
  if (!Node)
  {
    return AE_BAD_PARAMETER;
  }

  if (Node->Object)
  {
    return AE_ALREADY_EXISTS;
  }

  Node->Object = Object;
  return AE_OK;
}

ACPI_OPERAND_OBJECT *
AcpiNsGetAttachedObject (
  ACPI_NAMESPACE_NODE *Node
  )
{
  return (Node) ? Node->Object : NULL;
}

/* Must-call on the parse path: real no-ops (no DEBUG_WARN) */

void
AcpiDsMethodDataInit (
  ACPI_WALK_STATE *WalkState
  )
{
  /* AcpiDsCreateWalkState calls this for every walk state; method
     arg/local init is execution-only, nothing to do in parse mode. */
}

/* Parse-loop load callbacks (pass 1). Upstream AcpiDsLoad1BeginOp/EndOp
   (dswload.c, not compiled) create namespace nodes and push scopes during
   the walk; the parse-only design keeps the namespace EMPTY (no-pass-2).
   The parser nevertheless REQUIRES DescendingCallback != NULL:
   AcpiPsParseLoop aborts with AE_BAD_PARAMETER (0x1001) when it is NULL -
   the original "callbacks belong to the namespace-load machinery, this
   port does not use them" no-op made EVERY AcpicaDisasmAml call fail with
   0x1001 before parsing a single byte (caught by the M8 QEMU driver: the
   OVMF DSDT returned result=33).

   FixWave-C (disasm text corruption): the pure no-op BeginOp ALSO broke
   the parse-tree structure for every AML_NAMED op whose argument list
   starts with ARGP_NAME (Scope/Device/Method/Name/OperationRegion/...):
   upstream Load1BeginOp consumes that name from the parser state
   (AcpiPsGetNextNamestring); without it the name stayed in the stream,
   was re-parsed as a standalone namepath op, and the named statement
   never linked its own arguments - the tree got FLATTENED (every
   argument became a sibling of the statement under the parent scope, the
   statement headers vanished from the disassembly). Field/BankField use
   ARGP_NAMESTRING (parsed as a regular argument), which is why they were
   unaffected. The namespace work of the upstream callback (lookup, node
   creation, scope-stack push) is deliberately skipped; only the name
   consumption is needed to build the correct tree shape. */
static ACPI_STATUS
AcpicaPortLoad1BeginOp (
  ACPI_WALK_STATE *WalkState,
  ACPI_PARSE_OBJECT **OutOp
  )
{
  if (WalkState == NULL || OutOp == NULL || WalkState->OpInfo == NULL ||
      !(WalkState->OpInfo->Flags & AML_NAMED))
  {
    return AE_OK;
  }

  /* Consume the name the way upstream Load1BeginOp does (the value is
     not used - no namespace). */
  {
    char *Path = AcpiPsGetNextNamestring (&WalkState->ParserState);

    /* Create the op, link it into the parse tree and return it - the
       upstream "common exit" of Load1BeginOp. The psobject caller
       (AcpiPsBuildNamedOp) passes *OutOp unset and expects the callback
       to produce the named op (it returns AE_CTRL_PARSE_CONTINUE when
       *OutOp stays NULL, leaving the statement out of the tree - the
       flattened disassembly). The namespace work (lookup, node, scope
       push) is deliberately skipped; the external path is kept on the op
       so the disassembler can print it (AcpiDmNamestring). */
    ACPI_PARSE_OBJECT *Op = AcpiPsAllocOp (WalkState->Opcode, WalkState->Aml);

    if (Op == NULL)
    {
      return AE_NO_MEMORY;
    }

    Op->Named.Path = Path;
    AcpiPsAppendArg (AcpiPsGetParentScope (&WalkState->ParserState), Op);
    *OutOp = Op;
  }
  return AE_OK;
}

static ACPI_STATUS
AcpicaPortLoad1EndOp (
  ACPI_WALK_STATE *WalkState
  )
{
  return AE_OK;
}

ACPI_STATUS
AcpiDsInitCallbacks (
  ACPI_WALK_STATE *WalkState,
  UINT32          PassNumber
  )
{
  /* AcpiDsInitAmlWalk calls this on every parse (before AcpiPsParseAml);
     pass 2 never runs in this port, so the pass-1 callbacks are wired
     unconditionally. */
  WalkState->DescendingCallback = AcpicaPortLoad1BeginOp;
  WalkState->AscendingCallback  = AcpicaPortLoad1EndOp;
  return AE_OK;
}

ACPI_STATUS
AcpiDsMethodDataInitArgs (
  ACPI_OPERAND_OBJECT **Params,
  UINT32              MaxParamCount,
  ACPI_WALK_STATE     *WalkState
  )
{
  /* Only reached with a MethodNode (method execution), never in the
     parse-only flow. */
  return AE_OK;
}

/* Parse-error cleanup path (psobject.c AcpiPsNextParseState default
   branch; region-op error handling): no-ops, since the namespace is never
   populated during parsing (Node pointers are NULL). */

void
AcpiNsDeleteChildren (
  ACPI_NAMESPACE_NODE *Parent
  )
{
}

void
AcpiNsRemoveNode (
  ACPI_NAMESPACE_NODE *Node
  )
{
}

/* Namespace teardown (AcpiNsTerminate / object deletion), never invoked
   by the wrapper (AcpiTerminateSubsystem is not part of the closure path). */

void
AcpiNsDeleteNamespaceSubtree (
  ACPI_NAMESPACE_NODE *ParentHandle
  )
{
}

void
AcpiNsDeleteNode (
  ACPI_NAMESPACE_NODE *Node
  )
{
}

ACPI_OPERAND_OBJECT *
AcpiNsGetSecondaryObject (
  ACPI_OPERAND_OBJECT *ObjDesc
  )
{
  return NULL;
}

/* Namespace search: faithful "search-only, never-create" port of upstream
   nssearch.c (AcpiNsSearchAndEnter + its two static helpers), with the
   node-creation tail deliberately omitted. The namespace contains only the
   root node and the predefined names (AcpiNsRootInitialize), so:
   - the init-time tail lookup of "\_GPE" (nsaccess.c:402) succeeds;
   - parse-time AML name lookups (psargs.c, ACPI_IMODE_EXECUTE) still
     resolve nothing and names are emitted as written (no-pass-2 design);
   - a name can never be added to the namespace by this port. */

static ACPI_STATUS
AcpicaPortSearchOneScope (
  UINT32              TargetName,
  ACPI_NAMESPACE_NODE *ParentNode,
  ACPI_OBJECT_TYPE    Type,
  ACPI_NAMESPACE_NODE **ReturnNode
  )
{
  ACPI_NAMESPACE_NODE *Node;

  Node = ParentNode->Child;
  while (Node)
  {
    if (Node->Name.Integer == TargetName)
    {
      /* Resolve a control method alias if any */

      if (AcpiNsGetType (Node) == ACPI_TYPE_LOCAL_METHOD_ALIAS)
      {
        Node = ACPI_CAST_PTR (ACPI_NAMESPACE_NODE, Node->Object);
      }

      *ReturnNode = Node;
      return AE_OK;
    }

    Node = Node->Peer;
  }

  return AE_NOT_FOUND;
}

static ACPI_STATUS
AcpicaPortSearchParentTree (
  UINT32              TargetName,
  ACPI_NAMESPACE_NODE *Node,
  ACPI_OBJECT_TYPE    Type,
  ACPI_NAMESPACE_NODE **ReturnNode
  )
{
  ACPI_STATUS         Status;
  ACPI_NAMESPACE_NODE *ParentNode;

  ParentNode = Node->Parent;
  if (!ParentNode || AcpiNsLocal (Type))
  {
    return AE_NOT_FOUND;
  }

  while (ParentNode)
  {
    Status = AcpicaPortSearchOneScope (
               TargetName, ParentNode, ACPI_TYPE_ANY, ReturnNode);
    if (ACPI_SUCCESS (Status))
    {
      return Status;
    }

    ParentNode = ParentNode->Parent;
  }

  return AE_NOT_FOUND;
}

ACPI_STATUS
AcpiNsSearchAndEnter (
  UINT32                EntryName,
  ACPI_WALK_STATE       *WalkState,
  ACPI_NAMESPACE_NODE   *Node,
  ACPI_INTERPRETER_MODE InterpreterMode,
  ACPI_OBJECT_TYPE      Type,
  UINT32                Flags,
  ACPI_NAMESPACE_NODE   **RetNode
  )
{
  ACPI_STATUS Status;

  /* Parameter validation (upstream nssearch.c) */

  if (!Node || !EntryName || !RetNode)
  {
    return AE_BAD_PARAMETER;
  }

  AcpiUtRepairName (ACPI_CAST_PTR (char, &EntryName));

  /* Search this namespace level */

  *RetNode = ACPI_ENTRY_NOT_FOUND;
  Status = AcpicaPortSearchOneScope (EntryName, Node, Type, RetNode);
  if (Status != AE_NOT_FOUND)
  {
    if (Status == AE_OK)
    {
      if (Flags & ACPI_NS_OVERRIDE_IF_FOUND)
      {
        /* No namespace overrides in this port: drop the found node
           (AcpiNsDeleteChildren/AcpiNsRemoveNode are no-op stubs). */
        *RetNode = ACPI_ENTRY_NOT_FOUND;
      }
      else if (Flags & ACPI_NS_ERROR_IF_FOUND)
      {
        Status = AE_ALREADY_EXISTS;
      }
    }

    return Status;
  }

  /* Search parent scopes per the ACPI spec (never in pass-1 loading) */

  if ((InterpreterMode != ACPI_IMODE_LOAD_PASS1) &&
      (Flags & ACPI_NS_SEARCH_PARENT))
  {
    Status = AcpicaPortSearchParentTree (
               EntryName, Node, Type, RetNode);
    if (ACPI_SUCCESS (Status))
    {
      return Status;
    }
  }

  /* Search-only port: never create nodes, regardless of interpreter mode. */

  return AE_NOT_FOUND;
}

/* Public-API paths never invoked by the wrapper (AcpiEvaluateObject,
   AcpiInitializeObjects, AcpiEnableSubsystem): tripwires - hitting any of
   them means the port is being used beyond its parse-only contract. */

ACPI_STATUS
AcpiNsEvaluate (
  ACPI_EVALUATE_INFO *Info
  )
{
  STUB_WARN ("AcpiNsEvaluate");
  return AE_SUPPORT;
}

ACPI_STATUS
AcpiNsInitializeObjects (
  VOID
  )
{
  STUB_WARN ("AcpiNsInitializeObjects");
  return AE_SUPPORT;
}

ACPI_STATUS
AcpiNsInitializeDevices (
  UINT32 Flags
  )
{
  STUB_WARN ("AcpiNsInitializeDevices");
  return AE_SUPPORT;
}

ACPI_STATUS
AcpiEnable (
  VOID
  )
{
  STUB_WARN ("AcpiEnable");
  return AE_SUPPORT;
}

/* Disassembler-side gaps */

void
AcpiDmMarkExternalConflict (
  ACPI_NAMESPACE_NODE *Node
  )
{
  /* Reachable only if a namespace search returned AE_ALREADY_EXISTS,
     which cannot happen with the AcpiNsSearchAndEnter port above. */
}

ACPI_PARSE_OBJECT *
AcpiPsFind (
  ACPI_PARSE_OBJECT *Scope,
  char              *Path,
  UINT16            Opcode,
  UINT32            Create
  )
{
  /* Called only from AcpiDmValidateName, which has no callers in the
     compiled disassembler (dead code); NULL keeps the no-namespace
     "name not found" behavior consistent. */
  return NULL;
}

/******************************************************************************
 *
 * Group 4: M8 Task 7 link-closure gaps (first app link of AcpicaDisasmLib).
 *
 * AcpicaDisasmApi.c calls AcpiDmFindResources (upstream defines it in
 * common/dmrestag.c, not compiled here); dmresrcl2.c calls the ASL-compiler
 * resource-map helpers (compiler/aslmapenter.c, not compiled); nsaccess.c
 * and psxface.c reference debug dump helpers from nsdump.c/exdump.c (not
 * compiled); ahuuids.c needs the UUID string converter (utuuid.c's copy is
 * under the ACPI_ASL_COMPILER guard); utpredef.c needs the predefined-method
 * table (acpredef.h defines it only under ACPI_CREATE_PREDEFINED_TABLE).
 *
 *****************************************************************************/

/* Resource-template tagging pass: upstream dmrestag.c walks the parse tree
   to tag ResourceTemplate() nodes for the ASL compiler's mapfile. The
   disassembler text is produced by AcpiDmParseDeferredOps (dmdeferred.c,
   compiled) which is unaffected, so a no-op is the trim. */
void
AcpiDmFindResources (
  ACPI_PARSE_OBJECT *Root
  )
{
}

/* ASL-compiler GPIO/serial resource map storage (aslmapenter.c). The
   disassembler's resource descriptor formatting (dmresrcl2.c) calls these
   purely to record map entries for the compiler mapfile - a no-op keeps
   the ASL text output identical. */
void
MpSaveGpioInfo (
  ACPI_PARSE_OBJECT *Op,
  AML_RESOURCE      *Resource,
  UINT32            PinCount,
  UINT16            *PinList,
  char              *DeviceName
  )
{
}

void
MpSaveSerialInfo (
  ACPI_PARSE_OBJECT *Op,
  AML_RESOURCE      *Resource,
  char              *DeviceName
  )
{
}

/* Interpreter operand dump (executer/exdump.c, not compiled); called only
   under ACPI_DUMP_* debug macros. */
void
AcpiExDumpOperand (
  ACPI_OPERAND_OBJECT *ObjDesc,
  UINT32              Depth
  )
{
}

/* Namespace pathname dump helper (namespace/nsdump.c, not compiled). The
   reference sits under ACPI_DEBUG_EXEC which compiles in even with
   ACPI_DEBUG_OUTPUT=0 (defined), but the namespace pass is skipped in this
   port so it never runs; no-op matches the void prototype. */
void
AcpiNsPrintPathname (
  UINT32       NumSegments,
  const char   *Pathname
  )
{
}

/* Ported real implementation (from utilities/utuuid.c; the upstream copy
   is guarded by ACPI_ASL_COMPILER which this port does not define).
   ahuuids.c calls this at runtime to decode UUID strings from the ACPI
   UART/UUID table, so this is not a no-op. */
const UINT8 AcpiGbl_MapToUuidOffset[UUID_BUFFER_LENGTH] =
{
  6, 4, 2, 0, 11, 9, 16, 14, 19, 21, 24, 26, 28, 30, 32, 34
};

void
AcpiUtConvertStringToUuid (
  char  *InString,
  UINT8 *UuidBuffer
  )
{
  UINT32 i;

  for (i = 0; i < UUID_BUFFER_LENGTH; i++)
  {
    UuidBuffer[i] = (UINT8)(AcpiUtAsciiCharToHex (
        InString[AcpiGbl_MapToUuidOffset[i]]) << 4);
    UuidBuffer[i] |= AcpiUtAsciiCharToHex (
        InString[AcpiGbl_MapToUuidOffset[i] + 1]);
  }
}

/* Predefined-methods table: upstream defines it in acpredef.h under
   ACPI_CREATE_PREDEFINED_TABLE (iASL-only build); the compiled utpredef.c
   still references the extern. Empty table (terminator only): the
   interpreter-side predefined-name checks never run in this port (the
   namespace load pass is skipped). */
const ACPI_PREDEFINED_INFO AcpiGbl_PredefinedMethods[] =
{
  PACKAGE_INFO (0, 0, 0, 0, 0, 0)  /* Table terminator */
};

/******************************************************************************
 *
 * Group 5: M8 Task 7 - C library functions ported from upstream utclib.c.
 *
 * utclib.c is not compiled (it would define memcpy/memset/memmove/memcmp,
 * colliding with the app's CompilerIntrinsicsLib under /WHOARCHIVE).
 * The str* functions and the is* ctype table the compiled closure needs
 * are ported here verbatim (same pattern as the Group 3 AcpiEx*ToString
 * ports); mem* resolve from the app's CompilerIntrinsicsLib. The
 * declarations/macros come from acclib.h (included via accommon.h).
 *
 *****************************************************************************/

ACPI_SIZE
strlen (
    const char              *String)
{
    UINT32                  Length = 0;

    while (*String)
    {
        Length++;
        String++;
    }

    return (Length);
}

char *
strcpy (
    char                    *DstString,
    const char              *SrcString)
{
    char                    *String = DstString;

    while (*SrcString)
    {
        *String = *SrcString;

        String++;
        SrcString++;
    }

    *String = 0;
    return (DstString);
}

char *
strncpy (
    char                    *DstString,
    const char              *SrcString,
    ACPI_SIZE               Count)
{
    char                    *String = DstString;

    for (String = DstString;
        Count && (Count--, (*String++ = *SrcString++)); )
    {;}

    while (Count--)
    {
        *String = 0;
        String++;
    }

    return (DstString);
}

int
strcmp (
    const char              *String1,
    const char              *String2)
{
    for ( ; (*String1 == *String2); String2++)
    {
        if (!*String1++)
        {
            return (0);
        }
    }

    return ((unsigned char) *String1 - (unsigned char) *String2);
}

char *
strcat (
    char                    *DstString,
    const char              *SrcString)
{
    char                    *String;

    for (String = DstString; *String++; )
    { ; }

    for (--String; (*String++ = *SrcString++); )
    { ; }

    return (DstString);
}

char *
strncat (
    char                    *DstString,
    const char              *SrcString,
    ACPI_SIZE               Count)
{
    char                    *String;

    if (Count)
    {
        for (String = DstString; *String++; )
        { ; }

        for (--String; (*String++ = *SrcString++) && --Count; )
        { ; }

        if (!Count)
        {
            *String = 0;
        }
    }

    return (DstString);
}

int
toupper (
    int                     c)
{
    return (islower(c) ? ((c)-0x20) : (c));
}

int
tolower (
    int                     c)
{
    return (isupper(c) ? ((c)+0x20) : (c));
}

/* is* ctype table (upstream utclib.c, verbatim; isdigit/isspace/... are
   acclib.h macros indexing this array) */
const UINT8 AcpiGbl_Ctypes[257] = {
    _ACPI_CN,            /* 0x00     0 NUL */
    _ACPI_CN,            /* 0x01     1 SOH */
    _ACPI_CN,            /* 0x02     2 STX */
    _ACPI_CN,            /* 0x03     3 ETX */
    _ACPI_CN,            /* 0x04     4 EOT */
    _ACPI_CN,            /* 0x05     5 ENQ */
    _ACPI_CN,            /* 0x06     6 ACK */
    _ACPI_CN,            /* 0x07     7 BEL */
    _ACPI_CN,            /* 0x08     8 BS  */
    _ACPI_CN|_ACPI_SP,   /* 0x09     9 TAB */
    _ACPI_CN|_ACPI_SP,   /* 0x0A    10 LF  */
    _ACPI_CN|_ACPI_SP,   /* 0x0B    11 VT  */
    _ACPI_CN|_ACPI_SP,   /* 0x0C    12 FF  */
    _ACPI_CN|_ACPI_SP,   /* 0x0D    13 CR  */
    _ACPI_CN,            /* 0x0E    14 SO  */
    _ACPI_CN,            /* 0x0F    15 SI  */
    _ACPI_CN,            /* 0x10    16 DLE */
    _ACPI_CN,            /* 0x11    17 DC1 */
    _ACPI_CN,            /* 0x12    18 DC2 */
    _ACPI_CN,            /* 0x13    19 DC3 */
    _ACPI_CN,            /* 0x14    20 DC4 */
    _ACPI_CN,            /* 0x15    21 NAK */
    _ACPI_CN,            /* 0x16    22 SYN */
    _ACPI_CN,            /* 0x17    23 ETB */
    _ACPI_CN,            /* 0x18    24 CAN */
    _ACPI_CN,            /* 0x19    25 EM  */
    _ACPI_CN,            /* 0x1A    26 SUB */
    _ACPI_CN,            /* 0x1B    27 ESC */
    _ACPI_CN,            /* 0x1C    28 FS  */
    _ACPI_CN,            /* 0x1D    29 GS  */
    _ACPI_CN,            /* 0x1E    30 RS  */
    _ACPI_CN,            /* 0x1F    31 US  */
    _ACPI_XS|_ACPI_SP,   /* 0x20    32 ' ' */
    _ACPI_PU,            /* 0x21    33 '!' */
    _ACPI_PU,            /* 0x22    34 '"' */
    _ACPI_PU,            /* 0x23    35 '#' */
    _ACPI_PU,            /* 0x24    36 '$' */
    _ACPI_PU,            /* 0x25    37 '%' */
    _ACPI_PU,            /* 0x26    38 '&' */
    _ACPI_PU,            /* 0x27    39 ''' */
    _ACPI_PU,            /* 0x28    40 '(' */
    _ACPI_PU,            /* 0x29    41 ')' */
    _ACPI_PU,            /* 0x2A    42 '*' */
    _ACPI_PU,            /* 0x2B    43 '+' */
    _ACPI_PU,            /* 0x2C    44 ',' */
    _ACPI_PU,            /* 0x2D    45 '-' */
    _ACPI_PU,            /* 0x2E    46 '.' */
    _ACPI_PU,            /* 0x2F    47 '/' */
    _ACPI_XD|_ACPI_DI,   /* 0x30    48 '0' */
    _ACPI_XD|_ACPI_DI,   /* 0x31    49 '1' */
    _ACPI_XD|_ACPI_DI,   /* 0x32    50 '2' */
    _ACPI_XD|_ACPI_DI,   /* 0x33    51 '3' */
    _ACPI_XD|_ACPI_DI,   /* 0x34    52 '4' */
    _ACPI_XD|_ACPI_DI,   /* 0x35    53 '5' */
    _ACPI_XD|_ACPI_DI,   /* 0x36    54 '6' */
    _ACPI_XD|_ACPI_DI,   /* 0x37    55 '7' */
    _ACPI_XD|_ACPI_DI,   /* 0x38    56 '8' */
    _ACPI_XD|_ACPI_DI,   /* 0x39    57 '9' */
    _ACPI_PU,            /* 0x3A    58 ':' */
    _ACPI_PU,            /* 0x3B    59 ';' */
    _ACPI_PU,            /* 0x3C    60 '<' */
    _ACPI_PU,            /* 0x3D    61 '=' */
    _ACPI_PU,            /* 0x3E    62 '>' */
    _ACPI_PU,            /* 0x3F    63 '?' */
    _ACPI_PU,            /* 0x40    64 '@' */
    _ACPI_XD|_ACPI_UP,   /* 0x41    65 'A' */
    _ACPI_XD|_ACPI_UP,   /* 0x42    66 'B' */
    _ACPI_XD|_ACPI_UP,   /* 0x43    67 'C' */
    _ACPI_XD|_ACPI_UP,   /* 0x44    68 'D' */
    _ACPI_XD|_ACPI_UP,   /* 0x45    69 'E' */
    _ACPI_XD|_ACPI_UP,   /* 0x46    70 'F' */
    _ACPI_UP,            /* 0x47    71 'G' */
    _ACPI_UP,            /* 0x48    72 'H' */
    _ACPI_UP,            /* 0x49    73 'I' */
    _ACPI_UP,            /* 0x4A    74 'J' */
    _ACPI_UP,            /* 0x4B    75 'K' */
    _ACPI_UP,            /* 0x4C    76 'L' */
    _ACPI_UP,            /* 0x4D    77 'M' */
    _ACPI_UP,            /* 0x4E    78 'N' */
    _ACPI_UP,            /* 0x4F    79 'O' */
    _ACPI_UP,            /* 0x50    80 'P' */
    _ACPI_UP,            /* 0x51    81 'Q' */
    _ACPI_UP,            /* 0x52    82 'R' */
    _ACPI_UP,            /* 0x53    83 'S' */
    _ACPI_UP,            /* 0x54    84 'T' */
    _ACPI_UP,            /* 0x55    85 'U' */
    _ACPI_UP,            /* 0x56    86 'V' */
    _ACPI_UP,            /* 0x57    87 'W' */
    _ACPI_UP,            /* 0x58    88 'X' */
    _ACPI_UP,            /* 0x59    89 'Y' */
    _ACPI_UP,            /* 0x5A    90 'Z' */
    _ACPI_PU,            /* 0x5B    91 '[' */
    _ACPI_PU,            /* 0x5C    92 '\' */
    _ACPI_PU,            /* 0x5D    93 ']' */
    _ACPI_PU,            /* 0x5E    94 '^' */
    _ACPI_PU,            /* 0x5F    95 '_' */
    _ACPI_PU,            /* 0x60    96 '`' */
    _ACPI_XD|_ACPI_LO,   /* 0x61    97 'a' */
    _ACPI_XD|_ACPI_LO,   /* 0x62    98 'b' */
    _ACPI_XD|_ACPI_LO,   /* 0x63    99 'c' */
    _ACPI_XD|_ACPI_LO,   /* 0x64   100 'd' */
    _ACPI_XD|_ACPI_LO,   /* 0x65   101 'e' */
    _ACPI_XD|_ACPI_LO,   /* 0x66   102 'f' */
    _ACPI_LO,            /* 0x67   103 'g' */
    _ACPI_LO,            /* 0x68   104 'h' */
    _ACPI_LO,            /* 0x69   105 'i' */
    _ACPI_LO,            /* 0x6A   106 'j' */
    _ACPI_LO,            /* 0x6B   107 'k' */
    _ACPI_LO,            /* 0x6C   108 'l' */
    _ACPI_LO,            /* 0x6D   109 'm' */
    _ACPI_LO,            /* 0x6E   110 'n' */
    _ACPI_LO,            /* 0x6F   111 'o' */
    _ACPI_LO,            /* 0x70   112 'p' */
    _ACPI_LO,            /* 0x71   113 'q' */
    _ACPI_LO,            /* 0x72   114 'r' */
    _ACPI_LO,            /* 0x73   115 's' */
    _ACPI_LO,            /* 0x74   116 't' */
    _ACPI_LO,            /* 0x75   117 'u' */
    _ACPI_LO,            /* 0x76   118 'v' */
    _ACPI_LO,            /* 0x77   119 'w' */
    _ACPI_LO,            /* 0x78   120 'x' */
    _ACPI_LO,            /* 0x79   121 'y' */
    _ACPI_LO,            /* 0x7A   122 'z' */
    _ACPI_PU,            /* 0x7B   123 '{' */
    _ACPI_PU,            /* 0x7C   124 '|' */
    _ACPI_PU,            /* 0x7D   125 '}' */
    _ACPI_PU,            /* 0x7E   126 '~' */
    _ACPI_CN,            /* 0x7F   127 DEL */

    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0x80 to 0x8F    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0x90 to 0x9F    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xA0 to 0xAF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xB0 to 0xBF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xC0 to 0xCF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xD0 to 0xDF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xE0 to 0xEF    */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  /* 0xF0 to 0xFF    */
    0                                 /* 0x100 */
};
