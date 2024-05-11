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

typedef struct _SBX_MONITORED_ROUTINE
{
	std::string LibName;	    // 
	std::string RoutineName;    // routine identifiers
	ULONG       RoutineOrdinal; // 

	PVOID RoutineAddress;

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
	SBX_EMU_PE_SINGLESTEP = ( 1 << 0 ),
	SBX_EMU_PE_BREAK_ON_MONITORED_ROUTINE = ( 1 << 1 ),

	SBX_EMU_LOG_MONITORED_ROUTINES = ( 1 << 2 ),
	SBX_EMU_LOG_INSTRUCTIONS = ( 1 << 3 ),

} SBX_EMULATED_PE_FLAGS, *PSBX_EMULATED_PE_FLAGS;

typedef struct _SBX_EMULATED_PE
{
	ULONG EnvironmentType;
	SBX_PE_IMAGE PE;
	ULONG Flags;
	PBYTE EmulatedBase;

} SBX_EMULATED_PE, * PSBX_EMULATED_PE;

typedef struct _SBX_ENVIRONMENT
{
	ULONG EnvironmentAccessFlags;

	std::vector< SBX_EMULATED_PE > EmulatedImages;

} SBX_ENVIRONMENT, *PSBX_ENVIRONMENT;

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

//BOOL
//SbxSetupMonitoredRoutines(
//	_Inout_ PSBX_EMULATED_PE EmulatedPE
//);

BOOL
SbxIsWithinEmulatedImage(
	_In_ UINT64 ExceptionAddress
);

PSBX_EMULATED_PE
SbxGetEmulatedPEByException(
	_In_ UINT64 ExceptionAddress
);

BOOL
SbxSetPEProtection(
	_In_ PSBX_EMULATED_PE EmulatedPE
);

ULONG
SbxHandleImageStepOut(
	_In_ PSBX_EMULATED_PE EmulatedPE,
	_In_ PVOID ExceptionAddress,
	_In_ PVOID LastExceptionAddress
);