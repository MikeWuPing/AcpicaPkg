## @file
# AcpicaPkg - package DSC for building the ACPICA disassembler library.
#
# NOTE: keep this file pure ASCII - BaseTools reads meta files with the
# OS locale encoding (cp936 here), non-ASCII bytes can break the parser.

[Defines]
  PLATFORM_NAME                  = AcpicaPkg
  PLATFORM_GUID                  = 741D6D40-98FA-43AA-B670-605273F8A357
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/AcpicaPkg
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses]
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  # AcpicaLib consumes CompilerIntrinsicsLib: MSVC synthesizes memcpy/memset
  # calls for struct copies and fill loops in freestanding builds.
  CompilerIntrinsicsLib|MdePkg/Library/CompilerIntrinsicsLib/CompilerIntrinsicsLib.inf

[Components]
  AcpicaPkg/Library/AcpicaDisasmLib/AcpicaDisasmLib.inf
