#pragma once

#include <windows.h>

#include "pe.h"

#include "environment.h"

typedef enum _SBX_EMULATOR_FLAGS
{


} SBX_EMULATOR_FLAGS, *PSBX_EMULATOR_FLAGS;

typedef struct _SBX_DLL_START
{
	PSBX_EMULATED_PE EmulatedPE;

	ULONG ReasonForCall;

} SBX_DLL_START, *PSBX_DLL_START;

typedef struct _SBX_EXE_START
{
	PSBX_EMULATED_PE EmulatedPE;

	INT Argcount;
	PCHAR* Args;

} SBX_EXE_START, * PSBX_EXE_START;

typedef struct _SBX_SYS_START
{
	PSBX_EMULATED_PE EmulatedPE;

	LPCWSTR RegistryPath;

} SBX_SYS_START, * PSBX_SYS_START;

extern PVOID VEHHandle;

BOOL
SbxInitializeEmulator(

);

VOID SbxStartEmulatedPE(
	_In_ PSBX_EMULATED_PE EmulatedPE,
	_In_ PVOID RCX,
	_In_ PVOID RDX,
	_In_ PVOID R8,
	_In_ PVOID R9
);

VOID
SbxStartEmulatedDllPE(
	_In_ PSBX_DLL_START DynamicLinkLibraryImageStart
);

VOID
SbxStartEmulatedExePE(
	_In_ PSBX_EXE_START ExecutableImageStart
);

VOID
SbxStartEmulatedSysPE(
	_In_ PSBX_SYS_START SystemImageStart
);

BOOL
SbxEmulatePE(
	_In_ PSBX_PE_IMAGE PEImage,
	_In_ ULONG ImageEnvironmentType,
	_In_ ULONG Flags
);

ULONG
SbxExceptionHandler(
	_Inout_ PEXCEPTION_POINTERS ExceptionInfo
);