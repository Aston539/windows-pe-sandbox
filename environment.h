#pragma once

#include <windows.h>
#include <vector>
#include <string>

#include "pe.h"
#include "winternls.h"

#define SBX_MAX_ENVIRONMENTS 4

typedef enum _SBX_EMULATED_PE_ENVIRONMENT_TYPE
{
	SBX_EMU_USERMODE,
	SBX_EMU_KERNELMODE,

} SBX_EMULATED_PE_ENVIRONMENT_TYPE, * PSBX_EMULATED_PE_ENVIRONMENT_TYPE;

typedef struct _SBX_MONITORED_DETOUR
{
	LPCSTR TargetLib;
	LPCSTR TargetRoutine;
	LPCWSTR TargetWRoutine;
	ULONG TargetOrdinal;

	PVOID DetourAddress;

} SBX_MONITORED_DETOUR, *PSBX_MONITORED_DETOUR;

typedef struct _SBX_MONITORED_ROUTINE
{
	std::string LibName;
	std::string RoutineName;
	ULONG RoutineOrdinal;
	PVOID RoutineAddress;
	PVOID DetourAddress;
	PVOID PointerAddress;

} SBX_MONITORED_ROUTINE, * PSBX_MONITORED_ROUTINE;

typedef struct _SBX_EMULATED_IMAGE
{
	LPCSTR Path;
	PBYTE Base;
	SBX_PE_IMAGE PE;
	BOOL ShouldConstruct;

} SBX_EMULATED_IMAGE, *PSBX_EMULATED_IMAGE;

typedef enum _SBX_EMULATED_PE_FLAGS
{
	SBX_EMU_PE_SINGLESTEP = ( 1 << 0 )

} SBX_EMULATED_PE_FLAGS, *PSBX_EMULATED_PE_FLAGS;

typedef struct _SBX_EMULATED_PE
{
	ULONG EnvironmentType;
	SBX_PE_IMAGE PE;
	ULONG Flags;
	PBYTE EmulatedBase;

	std::vector<SBX_MONITORED_ROUTINE> MonitoredRoutines;

} SBX_EMULATED_PE, * PSBX_EMULATED_PE;

#define SBX_DECLARE_MONITORED_DETOUR( Lib, RoutineName, Detour ) { Lib, #RoutineName, L#RoutineName, NULL, Detour },
#define SBX_DECLARE_MONITORED_DETOUR_ORDINAL( Lib, Ordinal, Detour ) { Lib, NULL, NULL, Ordinal, Detour },

typedef struct _SBX_ENVIRONMENT
{
	ULONG EnvironmentAccessFlags;

	std::vector< SBX_EMULATED_PE > EmulatedImages;

} SBX_ENVIRONMENT, *PSBX_ENVIRONMENT;

EXTERN std::vector<SBX_MONITORED_DETOUR> MonitoredDetours;
EXTERN SBX_ENVIRONMENT SbxEnvironment;


PSBX_EMULATED_PE
SbxAllocateImage(
	_In_ ULONG EnvironmentType,
	_In_ SBX_PE_IMAGE PEImage
);

BOOL
SbxFixEmulatedPEImports(
	_Inout_ PSBX_EMULATED_PE EmulatedPE
);

BOOL
SbxSetupMonitoredRoutines(
	_Inout_ PSBX_EMULATED_PE EmulatedPE
);

BOOL
SbxIsWithinEmulatedImage(
	_In_ UINT64 ExceptionAddress
);

PSBX_EMULATED_PE
SbxGetEmulatedPEByException(
	_In_ UINT64 ExceptionAddress
);

BOOL
SbxIsValidEnvironment(
	_In_ ULONG ID
);

BOOL
SbxSetPEProtection(
	_In_ PSBX_EMULATED_PE EmulatedPE
);