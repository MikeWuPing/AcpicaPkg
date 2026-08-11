/** @file
  AcpicaOsUefi.c - ACPICA OSL (OS-dependent service layer) for UEFI/EDK2.

  Implements the AcpiOs* service functions used by the compiled ACPICA
  component closure (utilities / parser / dswstate / namespace subset /
  disassembler) on top of EDK2 services:

  - memory       -> AllocatePool / FreePool
  - output       -> PrintLib AsciiVSPrint appended to a growable RAM buffer
  - time/stall   -> GetPerformanceCounter / gBS->Stall
  - locks/semas  -> single-threaded model: dummy handles, no-op operations
  - cache OSL    -> plain-alloc passthrough (upstream utcache.c is NOT
                    compiled; AcpiUtCreateCaches still calls these from
                    AcpiInitializeSubsystem)
  - misc         -> physical==logical mapping, AE_SUPPORT for unsupported ops

  ACPICA internals never require a real OS here: disassembly is a single
  parse pass with no control-state execution and no hardware access.

  Copyright (c) 2026, Mike Wu. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

/* EDK2 headers MUST come before acpi.h: platform/acefi.h #defines UINTN
   (and other token aliases) as macros that would corrupt EDK2 typedefs. */
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include "acpi.h"
#include "acpiosxf.h"

/*
 * Output buffer management.
 *
 * The wrapper attaches an AllocatePool'd buffer with AcpicaOsSetOutput().
 * AcpiOsPrintf/AcpiOsVprintf append into it; when it fills up the buffer is
 * reallocated (doubling) so the *pointer the caller holds can go stale -
 * always read the current pointer via AcpicaOsGetOutput() before use.
 * The buffer always keeps >= 1 spare byte so the wrapper can NUL-terminate.
 */

static UINT8  *gOutBuf = NULL;
static UINTN  gOutLen = 0;
static UINTN  gOutCap = 0;
/* Number of '\n' characters written so far == index of the output row that
   the next appended byte will land on (M8.5 T1: the self-driven disasm walk
   uses this to attribute output rows to parse ops). Reset together with the
   output cursor; monotonic within one disassembly pass. */
static UINTN  gOutLines = 0;

/**
  Attach the initial output buffer (wrapper side).

  @param[in] Buf  AllocatePool'd buffer, >= 2 bytes.
  @param[in] Cap  Buffer size in bytes.
**/
void
AcpicaOsSetOutput (
  UINT8 *Buf,
  UINTN Cap
  )
{
  gOutBuf = Buf;
  gOutCap = Cap;
  gOutLen = 0;
  gOutLines = 0;
}

/**
  Reset the output cursor to the start of the buffer.
**/
void
AcpicaOsClearOutput (
  VOID
  )
{
  gOutLen = 0;
  gOutLines = 0;
}

/**
  Return the current output buffer pointer and text length.

  @param[out] OutBuf  Current buffer (may differ from the one attached in
                      AcpicaOsSetOutput after growth reallocations).
  @param[out] OutLen  Number of text bytes currently in the buffer.
**/
void
AcpicaOsGetOutput (
  UINT8 **OutBuf,
  UINTN  *OutLen
  )
{
  *OutBuf = gOutBuf;
  *OutLen = gOutLen;
}

/**
  Return the number of '\n' characters written so far (== the index of the
  output row the next appended byte lands on). Used by the self-driven
  disasm walk (AcpicaDisasmApi.c) to record the row range of each op.

  @return  Current output row index, 0-based.
**/
UINTN
AcpicaOsGetLineCount (
  VOID
  )
{
  return gOutLines;
}

/******************************************************************************
 *
 * OSL: Memory
 *
 *****************************************************************************/

void *
AcpiOsAllocate (
  ACPI_SIZE Size
  )
{
  return AllocatePool ((UINTN) Size);
}

void
AcpiOsFree (
  void *Memory
  )
{
  if (Memory != NULL)
  {
    FreePool (Memory);
  }
}

/******************************************************************************
 *
 * OSL: Output (all disassembler text lands in gOutBuf)
 *
 *****************************************************************************/

/* ACPICA printf-format adapter (FixWave-C root cause): EDK2 PrintLib's %s
   means a UNICODE (CHAR16*) string — in ASCII output it reads each pair of
   bytes as one CHAR16 and emits only the LOW byte, so every ACPICA string
   would lose its odd-indexed characters ("Field" -> "Fed", "NoLock" ->
   "NLc" — the whole disassembly text was corrupted). ACPICA never passes
   CHAR16*; its %s arguments are always CHAR8 strings, so the conversion
   specifier is rewritten to %a (flags/width/precision/length modifiers and
   the argument order are preserved; "%%" and every other specifier pass
   through untouched). Formats are short (< 256) in the disassembler
   closure; a longer one is truncated to the buffer (single-threaded use,
   static buffer is safe). */
#define ACPICA_FMT_BUF  256

static const CHAR8 *
AcpicaTranslateFormat (
  const CHAR8 *Format
  )
{
  static CHAR8  Buf[ACPICA_FMT_BUF];
  UINTN         i = 0;
  UINTN         o = 0;

  while (Format[i] != 0 && o < ACPICA_FMT_BUF - 1)
  {
    if (Format[i] != '%')
    {
      Buf[o++] = Format[i++];
      continue;
    }

    /* '%' — copy, then scan the specifier */
    Buf[o++] = Format[i++];
    if (Format[i] == 0)
    {
      break;                              /* trailing lone '%' */
    }
    if (Format[i] == '%')
    {
      Buf[o++] = Format[i++];             /* "%%" literal percent */
      continue;
    }

    /* flags */
    while (o < ACPICA_FMT_BUF - 1 &&
           (Format[i] == '-' || Format[i] == '+' || Format[i] == ' ' ||
            Format[i] == '#' || Format[i] == '0' || Format[i] == ','))
    {
      Buf[o++] = Format[i++];
    }
    /* width: digits or '*' */
    if (Format[i] == '*')
    {
      Buf[o++] = Format[i++];
    }
    else
    {
      while (o < ACPICA_FMT_BUF - 1 && Format[i] >= '0' && Format[i] <= '9')
      {
        Buf[o++] = Format[i++];
      }
    }
    /* precision: '.' then digits or '*' */
    if (Format[i] == '.')
    {
      Buf[o++] = Format[i++];
      if (Format[i] == '*')
      {
        Buf[o++] = Format[i++];
      }
      else
      {
        while (o < ACPICA_FMT_BUF - 1 && Format[i] >= '0' && Format[i] <= '9')
        {
          Buf[o++] = Format[i++];
        }
      }
    }
    /* length modifier */
    if (Format[i] == 'l' || Format[i] == 'L' || Format[i] == 'h' ||
        Format[i] == 'H')
    {
      Buf[o++] = Format[i++];
    }
    /* conversion: s/S -> a (ACPICA strings are always CHAR8) */
    if (Format[i] == 's' || Format[i] == 'S')
    {
      Buf[o++] = 'a';
      i++;
    }
    else if (Format[i] != 0)
    {
      Buf[o++] = Format[i++];
    }
  }
  Buf[o] = 0;
  return Buf;
}

void
AcpiOsVprintf (
  const char *Format,
  va_list    Args
  )
{
  UINTN Len;
  UINTN NewCap;
  UINT8 *NewBuf;

  if (gOutBuf == NULL)
  {
    return;
  }

  for (;;)
  {
    /* AsciiVSPrint writes at most BufferSize-1 chars + NUL and returns the
       count written. Keep 1 spare byte; if the buffer is exactly full we
       cannot tell truncation from a perfect fit, so grow and retry.
       The format is adapted for EDK2 PrintLib (%s -> %a, see above). */
    Len = AsciiVSPrint (
            (CHAR8 *)gOutBuf + gOutLen,
            gOutCap - gOutLen,
            (const CHAR8 *)AcpicaTranslateFormat (Format),
            (VA_LIST) Args
            );
    if (Len < gOutCap - gOutLen - 1)
    {
      /* M8.5 T1: count the '\n' in the newly appended range to advance the
         output row counter (PrintLib translates each '\n' to "\r\n", so
         every row ends with exactly one '\n' in the buffer). */
      UINTN NewStart = gOutLen;
      UINTN i;

      for (i = NewStart; i < NewStart + Len; i++)
      {
        if (gOutBuf[i] == '\n')
        {
          gOutLines++;
        }
      }
      gOutLen += Len;
      return;
    }

    /* Grow: double, with an overflow/sanity guard. */
    NewCap = gOutCap * 2;
    if (NewCap < gOutCap + 256)
    {
      NewCap = gOutCap + 256;
    }

    NewBuf = AllocatePool (NewCap);
    if (NewBuf == NULL)
    {
      /* Cannot grow: keep what we have (spare byte guaranteed). */
      return;
    }

    CopyMem (NewBuf, gOutBuf, gOutLen);
    FreePool (gOutBuf);
    gOutBuf = NewBuf;
    gOutCap = NewCap;
  }
}

void
AcpiOsPrintf (
  const char *Format,
  ...
  )
{
  va_list Args;

  va_start (Args, Format);
  AcpiOsVprintf (Format, Args);
  va_end (Args);
}

void
AcpiOsRedirectOutput (
  void *Destination
  )
{
  /* No-op: all output goes into the growable RAM buffer. */
}

/******************************************************************************
 *
 * OSL: Time
 *
 *****************************************************************************/

UINT64
AcpiOsGetTimer (
  VOID
  )
{
  /* Raw TSC counter; only used for relative comparisons. BaseLib
     AsmReadTsc is the TSC source - EDK2 TimerLib is deliberately not
     mapped in the app DSC (M8 Task 7). */
  return AsmReadTsc ();
}

void
AcpiOsStall (
  UINT32 Microseconds
  )
{
  gBS->Stall (Microseconds);
}

void
AcpiOsSleep (
  UINT64 Milliseconds
  )
{
  UINT64 Us;

  /* gBS->Stall takes UINTN microseconds; clamp to UINT32 range. */
  if (Milliseconds > (UINT64) (MAX_UINT32 / 1000))
  {
    Us = (UINT64) MAX_UINT32;
  }
  else
  {
    Us = Milliseconds * 1000;
  }

  gBS->Stall ((UINTN) Us);
}

/******************************************************************************
 *
 * OSL: Lifecycle
 *
 *****************************************************************************/

ACPI_STATUS
AcpiOsInitialize (
  VOID
  )
{
  return AE_OK;
}

ACPI_STATUS
AcpiOsTerminate (
  VOID
  )
{
  return AE_OK;
}

/******************************************************************************
 *
 * OSL: Memory mapping / readability
 *
 *****************************************************************************/

BOOLEAN
AcpiOsReadable (
  void *Pointer,
  ACPI_SIZE Length
  )
{
  /* Tables live in ordinary RAM; the caller validates ranges. */
  return TRUE;
}

BOOLEAN
AcpiOsWritable (
  void *Pointer,
  ACPI_SIZE Length
  )
{
  return TRUE;
}

void *
AcpiOsMapMemory (
  ACPI_PHYSICAL_ADDRESS PhysicalAddress,
  ACPI_SIZE Length
  )
{
  /* UEFI: physical addresses are already mapped 1:1. */
  return (void *) (UINTN) PhysicalAddress;
}

void
AcpiOsUnmapMemory (
  void *LogicalAddress,
  ACPI_SIZE Size
  )
{
  /* No-op: no mapping was established. */
}

ACPI_STATUS
AcpiOsGetPhysicalAddress (
  void *LogicalAddress,
  ACPI_PHYSICAL_ADDRESS *PhysicalAddress
  )
{
  *PhysicalAddress = (ACPI_PHYSICAL_ADDRESS) (UINTN) LogicalAddress;
  return AE_OK;
}

/******************************************************************************
 *
 * OSL: Threading (single-threaded disassembly - dummy handles)
 *
 *****************************************************************************/

ACPI_THREAD_ID
AcpiOsGetThreadId (
  VOID
  )
{
  return 1;
}

ACPI_STATUS
AcpiOsCreateLock (
  ACPI_SPINLOCK *OutHandle
  )
{
  UINT8 *Dummy;

  Dummy = AllocatePool (1);
  *OutHandle = (ACPI_SPINLOCK) Dummy;
  return AE_OK;
}

void
AcpiOsDeleteLock (
  ACPI_SPINLOCK Handle
  )
{
  if (Handle != NULL)
  {
    FreePool (Handle);
  }
}

ACPI_CPU_FLAGS
AcpiOsAcquireLock (
  ACPI_SPINLOCK Handle
  )
{
  return 0;
}

void
AcpiOsReleaseLock (
  ACPI_SPINLOCK Handle,
  ACPI_CPU_FLAGS Flags
  )
{
}

ACPI_STATUS
AcpiOsCreateSemaphore (
  UINT32 MaxUnits,
  UINT32 InitialUnits,
  ACPI_SEMAPHORE *OutHandle
  )
{
  UINT8 *Dummy;

  Dummy = AllocatePool (1);
  *OutHandle = (ACPI_SEMAPHORE) Dummy;
  return AE_OK;
}

ACPI_STATUS
AcpiOsDeleteSemaphore (
  ACPI_SEMAPHORE Handle
  )
{
  if (Handle != NULL)
  {
    FreePool (Handle);
  }

  return AE_OK;
}

ACPI_STATUS
AcpiOsWaitSemaphore (
  ACPI_SEMAPHORE Handle,
  UINT32 Units,
  UINT16 Timeout
  )
{
  return AE_OK;
}

ACPI_STATUS
AcpiOsSignalSemaphore (
  ACPI_SEMAPHORE Handle,
  UINT32 Units
  )
{
  return AE_OK;
}

/* Note: AcpiOsCreateMutex/DeleteMutex/AcquireMutex/ReleaseMutex are NOT
   implemented on purpose: with the default ACPI_MUTEX_TYPE ==
   ACPI_BINARY_SEMAPHORE (platform/acenv.h), actypes.h maps those names to
   the semaphore OSL above via preprocessor macros. */

/******************************************************************************
 *
 * OSL: Cache (plain-alloc passthrough; upstream utcache.c is not compiled
 * but AcpiUtCreateCaches/AcpiUtDeleteCaches call these from
 * AcpiInitializeSubsystem, so they must exist and succeed)
 *
 *****************************************************************************/

ACPI_STATUS
AcpiOsCreateCache (
  char *CacheName,
  UINT16 ObjectSize,
  UINT16 MaxDepth,
  ACPI_CACHE_T **ReturnCache
  )
{
  ACPI_MEMORY_LIST *Cache;

  Cache = AllocatePool (sizeof (ACPI_MEMORY_LIST));
  if (Cache == NULL)
  {
    return AE_NO_MEMORY;
  }

  ZeroMem (Cache, sizeof (ACPI_MEMORY_LIST));
  Cache->ListName   = CacheName;
  Cache->ObjectSize = ObjectSize;
  Cache->MaxDepth   = MaxDepth;
  *ReturnCache = Cache;
  return AE_OK;
}

ACPI_STATUS
AcpiOsDeleteCache (
  ACPI_CACHE_T *Cache
  )
{
  if (Cache != NULL)
  {
    FreePool (Cache);
  }

  return AE_OK;
}

ACPI_STATUS
AcpiOsPurgeCache (
  ACPI_CACHE_T *Cache
  )
{
  return AE_OK;
}

void *
AcpiOsAcquireObject (
  ACPI_CACHE_T *Cache
  )
{
  UINT8 *Object;

  if (Cache == NULL)
  {
    return NULL;
  }

  /* Upstream cache objects are always zeroed (free-list hits are memset,
     new objects come from AllocateZeroed); keep that contract - parse ops
     and namespace nodes rely on zeroed memory. */
  Object = AllocatePool ((UINTN) Cache->ObjectSize);
  if (Object != NULL)
  {
    ZeroMem (Object, (UINTN) Cache->ObjectSize);
  }

  return Object;
}

ACPI_STATUS
AcpiOsReleaseObject (
  ACPI_CACHE_T *Cache,
  void *Object
  )
{
  if (Object != NULL)
  {
    FreePool (Object);
  }

  return AE_OK;
}

/******************************************************************************
 *
 * OSL: Predefined names / unsupported hooks
 *
 *****************************************************************************/

ACPI_STATUS
AcpiOsPredefinedOverride (
  const ACPI_PREDEFINED_NAMES *InitVal,
  ACPI_STRING *NewVal
  )
{
  /* No override: keep the built-in predefined name list. */
  *NewVal = NULL;
  return AE_OK;
}

ACPI_STATUS
AcpiOsSignal (
  UINT32 Function,
  void *Info
  )
{
  return AE_SUPPORT;
}

ACPI_STATUS
AcpiOsExecute (
  ACPI_EXECUTE_TYPE Type,
  ACPI_OSD_EXEC_CALLBACK Function,
  void *Context
  )
{
  /* Single-threaded: no deferred execution mechanism. */
  return AE_SUPPORT;
}
