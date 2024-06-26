#include "emulator.h"

#include <iostream>
#include <intrin.h>

#include "winternls.h"

#include "hde/hde64.h"

#include "vcpu.h"
#include "monitored.h"

#pragma warning( disable : 4996 )

PVOID VEHHandle;

BOOL 
SbxInitializeEmulator(

)
{
	VEHHandle = AddVectoredExceptionHandler( 1, ( PVECTORED_EXCEPTION_HANDLER )SbxExceptionHandler );

	if ( !VEHHandle )
	{
		return FALSE;
	}

	return TRUE;
}

VOID 
SbxStartEmulatedDllPE(
	_In_ PSBX_DLL_START DynamicLinkLibraryImageStart
)
{
	SbxStartEmulatedPE(
		DynamicLinkLibraryImageStart->EmulatedPE, 
		NULL,
		( PVOID )DynamicLinkLibraryImageStart->ReasonForCall,
		NULL,
		NULL
	);

	free( DynamicLinkLibraryImageStart );
}

VOID 
SbxStartEmulatedExePE( 
	_In_ PSBX_EXE_START ExecutableImageStart
)
{
	CHAR Directory[ MAX_PATH ] = { };

	strncpy( Directory, ExecutableImageStart->EmulatedPE->PE.FilePath, ExecutableImageStart->EmulatedPE->PE.OffsetToFileName );

	SbxStartEmulatedPE( 
		ExecutableImageStart->EmulatedPE, 
		( PVOID )ExecutableImageStart->Argcount,
		( PVOID )ExecutableImageStart->Args,
		NULL, 
		NULL 
	);

	free( ExecutableImageStart );
}

VOID 
SbxStartEmulatedSysPE(
	_In_ PSBX_SYS_START SystemImageStart
)
{
	UNICODE_STRING RegistryPath = { };

	RtlInitUnicodeString( &RegistryPath, SystemImageStart->RegistryPath );

	PVOID DriverObject = malloc( 0x10000 );

	SbxStartEmulatedPE(
		SystemImageStart->EmulatedPE, 
		DriverObject,
		&RegistryPath,
		NULL, 
		NULL
	);

	free( SystemImageStart );
}

VOID 
SbxStartEmulatedPE( 
	_In_ PSBX_EMULATED_PE EmulatedPE,
	_In_ PVOID RCX,
	_In_ PVOID RDX,
	_In_ PVOID R8,
	_In_ PVOID R9
)
{
	UINT_PTR Entry = EmulatedPE->PE.LoadedBase + EmulatedPE->PE.OptionalHeader.AddressOfEntryPoint;

	SbxSetPEProtection( EmulatedPE );

	HANDLE HThread = CreateThread( NULL, PAGE_SIZE * 2, ( LPTHREAD_START_ROUTINE )Entry, NULL, CREATE_SUSPENDED, NULL );

	CONTEXT ThreadContext = { };
	
	GetThreadContext( HThread, &ThreadContext );

#ifdef _WIN64
	ThreadContext.Rcx = ( UINT_PTR )RCX;
	ThreadContext.Rdx = ( UINT_PTR )RDX;
	ThreadContext.R8  = ( UINT_PTR )R8;
	ThreadContext.R9  = ( UINT_PTR )R9;
#else
	ThreadContext.Ecx = ( UINT_PTR )RCX;
	ThreadContext.Edx = ( UINT_PTR )RDX;
	//ThreadContext.E8 = ( UINT_PTR )R8;
	//ThreadContext.E9 = ( UINT_PTR )R9;
#endif

	SetThreadContext( HThread, &ThreadContext );

	ResumeThread( HThread );

	//( ( int( __stdcall* )( PVOID, PVOID, PVOID, PVOID ) )Entry )( RCX, RDX, R8, R9 );
}

BOOL
SbxEmulatePE( 
	_In_ PSBX_PE_IMAGE PEImage,
	_In_ ULONG ImageEnvironmentType,
	_In_ ULONG Flags 
)
{
	if ( !( Flags & SBX_EMU_ONLY_MONITOR_EXTERN_LIBS ) )
	{
		//
		// will setup monitored routines for already
		// loaded libraries such as ntdll, kernelbase etc
		//
		if ( !SbxSetupMonitoredRoutines( ) )
		{
			return FALSE;
		}
	}

	PSBX_EMULATED_PE EmulatedPE = SbxAllocateImage( ImageEnvironmentType, *PEImage );

	if ( !EmulatedPE )
	{
		return FALSE;
	}

	EmulatedPE->Flags = Flags;

	if ( !SbxSetPEProtection( EmulatedPE ) )
	{
		return FALSE;
	}

	switch ( EmulatedPE->PE.PEImageType )
	{
		case SBX_EXE:
		{
			PSBX_EXE_START ExeStartParam = ( PSBX_EXE_START )malloc( sizeof( SBX_EXE_START ) );

			if ( !ExeStartParam )
			{
				return false;
			}

			ExeStartParam->EmulatedPE = EmulatedPE;
			ExeStartParam->Argcount = 1;
			ExeStartParam->Args = ( PCHAR* )malloc( 0x8 );
			ExeStartParam->Args[ NULL ] = PEImage->FilePath;

			CreateThread( 0, 0, ( LPTHREAD_START_ROUTINE )SbxStartEmulatedExePE, ExeStartParam, 0, 0 );

		} break;

		case SBX_DLL:
		{
			PSBX_DLL_START DllStartParam = ( PSBX_DLL_START )malloc( sizeof( SBX_DLL_START ) );

			if ( !DllStartParam )
			{
				return false;
			}

			DllStartParam->EmulatedPE = EmulatedPE;
			DllStartParam->ReasonForCall = DLL_PROCESS_ATTACH;

			CreateThread( 0, 0, ( LPTHREAD_START_ROUTINE )SbxStartEmulatedDllPE, DllStartParam, 0, 0 );

		} break;

		case SBX_SYS: 
		{
			PSBX_SYS_START SysStartParam = ( PSBX_SYS_START )malloc( sizeof( SBX_SYS_START ) );

			if ( !SysStartParam )
			{
				return false;
			}

			SysStartParam->EmulatedPE = EmulatedPE;
			SysStartParam->RegistryPath = L"";

			CreateThread( 0, 0, ( LPTHREAD_START_ROUTINE )SbxStartEmulatedSysPE, SysStartParam, 0, 0 );

		} break;

		default:
			return FALSE;
	}

	return TRUE;
}

#include <thread>
#include <mutex>
#include <condition_variable>
#include <stdexcept>
#include <fstream>

std::mutex ExceptionMutex;

ULONG 
SbxExceptionHandler( 
	_Inout_ PEXCEPTION_POINTERS ExceptionInfo
)
{
	thread_local static UINT_PTR LastExceptionAddress = 0;

	std::unique_lock<std::mutex> lock( ExceptionMutex );

	const auto ExceptionCode		 = ExceptionInfo->ExceptionRecord->ExceptionCode;
	const auto ExceptionAddress		 = ExceptionInfo->ExceptionRecord->ExceptionAddress;
	const auto ExceptionFlags		 = ExceptionInfo->ExceptionRecord->ExceptionFlags;
	const auto ExceptionInformation  = ExceptionInfo->ExceptionRecord->ExceptionInformation;

	if ( ExceptionCode == EXCEPTION_GUARD_PAGE )
	{
		if ( !SbxIsWithinEmulatedImage( ( UINT_PTR )ExceptionAddress ) )
		{
			//
			// this is not our exception
			//

			lock.unlock( );

			return EXCEPTION_CONTINUE_EXECUTION;
		}

		//
		// set trap flag ( single step ) to recall into our
		// handler above
		//
		ExceptionInfo->ContextRecord->EFlags |= 0x100;

		lock.unlock( );

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if ( ExceptionCode == EXCEPTION_SINGLE_STEP )
	{
		if ( !SbxIsWithinEmulatedImage( ( UINT_PTR )ExceptionAddress ) )
		{
			//
			// stepping out of image
			//

			if ( !SbxIsWithinEmulatedImage( LastExceptionAddress ) )
			{
				//
				// is something else single stepping ?
				//
				__debugbreak( );
			}

			PSBX_EMULATED_PE EmulatedPE = SbxGetEmulatedPEByException( LastExceptionAddress );

			if ( !EmulatedPE )
			{
				__debugbreak( );
			}

			//
			// re protect our emulated pe
			// as so that when we step back
			// in were notified
			//
			if ( !SbxSetPEProtection( EmulatedPE ) )
			{
				__debugbreak( );
			}

			lock.unlock( );

			return SbxHandleImageStepOut(
				EmulatedPE,
				ExceptionAddress,
				( PVOID )LastExceptionAddress
			);
		}

		LastExceptionAddress = ( UINT_PTR )ExceptionAddress; // ExceptionInfo->ContextRecord->Rip;

		PSBX_EMULATED_PE EmulatedPE = SbxGetEmulatedPEByException( ( UINT_PTR )ExceptionAddress );

		if ( !EmulatedPE )
		{
			//
			// this is not our exception
			//

			__debugbreak( );
		}
		
		if ( !SbxSetPEProtection( EmulatedPE ) )
		{
			__debugbreak( );
		}

		lock.unlock( );

		return SbxEmulateInstruction( ExceptionAddress, ExceptionInfo->ContextRecord );
	}

	lock.unlock( );

	return EXCEPTION_CONTINUE_SEARCH;
}