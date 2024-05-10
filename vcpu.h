#pragma once

#include <windows.h>

ULONG
SbxEmulateInstruction(
	_In_ PVOID ExceptionAddress,
	_Inout_ PCONTEXT ContextRecord
);

VOID
SbxAdvanceRIP(
	_In_ PVOID InstructionAddress,
	_Inout_ PCONTEXT ContextRecord
);