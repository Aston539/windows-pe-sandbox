#include "environment.h"

#include <iostream>

#include "emulator.h"
#include "monitored.h"

#pragma warning(disable : 4996)

SBX_ENVIRONMENT SbxEnvironment;

PSBX_EMULATED_PE
SbxAllocateImage(
	_In_ ULONG EnvironmentType,
	_In_ SBX_PE_IMAGE PEImage
)
{
	PSBX_ENVIRONMENT TargetEnvironment = &SbxEnvironment;

	if ( !TargetEnvironment )
	{
		//
		// litteraly cant be null
		//   ( but we love intellisense )
		//

		return NULL;
	}

	//
	// allocate new emulated pe
	//
	TargetEnvironment->EmulatedImages.push_back( { } );

	PSBX_EMULATED_PE EmulatedPE = &TargetEnvironment->EmulatedImages.front( );

	EmulatedPE->EnvironmentType = EnvironmentType;
	EmulatedPE->PE = PEImage;

	if ( !SbxFixEmulatedPEImports( EmulatedPE ) )
	{
		TargetEnvironment->EmulatedImages.pop_back( );

		return NULL;
	}

	return EmulatedPE;
}

BOOL 
SbxFixEmulatedPEImports( 
	_Inout_ PSBX_EMULATED_PE EmulatedPE 
)
{
	if ( !EmulatedPE )
	{
		return FALSE;
	}

	PSBX_ENVIRONMENT TargetEnvironment = &SbxEnvironment;

	PIMAGE_IMPORT_DESCRIPTOR HeadDescriptor = SbxGetPEImportDescriptor( &EmulatedPE->PE );

	if ( !HeadDescriptor )
	{
		return FALSE;
	}

	for (
		PIMAGE_IMPORT_DESCRIPTOR CurrDescriptor = HeadDescriptor;
								 CurrDescriptor && CurrDescriptor->Name;
								 CurrDescriptor++
		)
	{
		LPCSTR LibName = ( LPCSTR )( EmulatedPE->PE.LoadedBase + CurrDescriptor->Name );

		HMODULE Lib = GetModuleHandleA( LibName );

		if ( !Lib )
		{
			//
			// Library isnt already loaded
			//

			Lib = LoadLibraryA( LibName );

			CHAR LibPath[ MAX_PATH ] = { };

			BOOL ShouldEmulate = FALSE;

			if ( Lib )
			{
				GetModuleFileNameA( Lib, LibPath, MAX_PATH );

				if ( strstr( LibPath, "C:\\Windows\\" ) )
				{
					ShouldEmulate = FALSE;
				}
				else
				{
					ShouldEmulate = TRUE;
				}
			}
			else
			{
				//if ( GetLastError( ) != 0x007E )
				//{
					//ShouldEmulate = TRUE;

					CHAR PEDirectory[ MAX_PATH ] = { };

					strncpy( PEDirectory, EmulatedPE->PE.FilePath, EmulatedPE->PE.OffsetToFileName );
					strcat( PEDirectory, LibName );

					printf( "Couldnt load lib initially trying: \n\t%s\n", PEDirectory );

					Lib = LoadLibraryA( PEDirectory );

					if ( !Lib )
					{
						//__debugbreak( );
					}
				//}
			}

			SbxRegisterPEExportsAsMonitored( LibName, ( UINT_PTR )Lib );

			//if ( ShouldEmulate )
			//{
			//	SBX_PE_IMAGE PEImage = { };
			//	if ( !SbxLoadPE( LibName, &PEImage ) )
			//	{
			//		//
			//		// if we still couldnt find it
			//		// its likely this is not a normal module
			//		// and we need to use the parent path to load it
			//		//

			//		//
			//		// get file path to pe and try load using
			//		// path as base ( we should also emulate this module )
			//		//
			//		CHAR PEDirectory[ MAX_PATH ] = { };

			//		strncpy( PEDirectory, EmulatedPE->PE.FilePath, EmulatedPE->PE.OffsetToFileName );
			//		strcat( PEDirectory, LibName );

			//		PEImage = { };
			//		if ( !SbxLoadPE( PEDirectory, &PEImage ) )
			//		{
			//			return FALSE;
			//		}
			//	}

			//	if ( !SbxEmulatePE( &PEImage, SBX_EMU_USERMODE, NULL ) )
			//	{
			//		return FALSE;
			//	}

			//	Lib = ( HMODULE )PEImage.LoadedBase;

			//	if ( !Lib )
			//	{
			//		//
			//		// check if status indicates the module is not
			//		// allowed be loaded for example if it needs
			//		// to import from ntoskrnl.exe and we are
			//		// not handling it in our monitored routines
			//		//

			//		// return FALSE;
			//	}
			//}
		}	

		PIMAGE_THUNK_DATA IAT = ( PIMAGE_THUNK_DATA )( EmulatedPE->PE.LoadedBase + CurrDescriptor->FirstThunk );
		PIMAGE_THUNK_DATA ILT = ( PIMAGE_THUNK_DATA )( EmulatedPE->PE.LoadedBase + CurrDescriptor->OriginalFirstThunk );

		for (
				;
				IAT && ILT && ILT->u1.AddressOfData;
				ILT++, IAT++
			)
		{
			LPCSTR RoutineName = nullptr;
			
			if ( IMAGE_SNAP_BY_ORDINAL( ILT->u1.Ordinal ) )
			{
				RoutineName = ( LPCSTR )( ILT->u1.Ordinal & 0xFFF );
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME ImportName = ( PIMAGE_IMPORT_BY_NAME )( EmulatedPE->PE.LoadedBase + ILT->u1.AddressOfData );

				RoutineName = ImportName->Name;
			}

			DWORD OldProtect = { };
			if ( !VirtualProtect( IAT, sizeof( PVOID ), PAGE_READWRITE, &OldProtect ) )
			{
				return FALSE;
			}

			ULONGLONG ImportRoutineAddress = ( ULONGLONG )GetProcAddress( Lib, RoutineName );

			if ( !ImportRoutineAddress )
			{
				if ( ( UINT_PTR )RoutineName <= 0x1000 )
				{
					printf( "Failed to resolve routine: { %s, %i }\n", LibName, ( UINT16 )RoutineName );
				}
				else
				{
					printf( "Failed to resolve routine: { %s, %s }\n", LibName, RoutineName );
				}

				//__debugbreak( );
			}

			IAT->u1.AddressOfData = ImportRoutineAddress;

			VirtualProtect( IAT, sizeof( PVOID ), OldProtect, &OldProtect );
		}
	}

	return TRUE;
}

//BOOL 
//SbxSetupMonitoredRoutines(
//	_Inout_ PSBX_EMULATED_PE EmulatedPE 
//)
//{
//	if ( !EmulatedPE )
//	{
//		//
//		// should never happen
//		//
//		__debugbreak( );
//
//		return FALSE;
//	}
//
//	PSBX_ENVIRONMENT TargetEnvironment = &SbxEnvironment;
//
//	PIMAGE_IMPORT_DESCRIPTOR HeadDescriptor = SbxGetPEImportDescriptor( &EmulatedPE->PE );
//
//	if ( !HeadDescriptor )
//	{
//		//
//		// should never happen
//		//
//		__debugbreak( );
//
//		return FALSE;
//	}
//
//	for (
//		PIMAGE_IMPORT_DESCRIPTOR CurrDescriptor = HeadDescriptor;
//		CurrDescriptor && CurrDescriptor->Name;
//		CurrDescriptor++
//		)
//	{
//		LPCSTR LibName = ( LPCSTR )( EmulatedPE->PE.LoadedBase + CurrDescriptor->Name );
//
//		HMODULE Lib = GetModuleHandleA( LibName );
//
//		if ( !Lib )
//		{
//			//
//			// should never happen
//			//
//			// __debugbreak( );
//
//			// return FALSE;
//		}
//
//		PIMAGE_THUNK_DATA IAT = ( PIMAGE_THUNK_DATA )( EmulatedPE->PE.LoadedBase + CurrDescriptor->FirstThunk );
//		PIMAGE_THUNK_DATA ILT = ( PIMAGE_THUNK_DATA )( EmulatedPE->PE.LoadedBase + CurrDescriptor->OriginalFirstThunk );
//
//		for (
//			;
//			IAT && ILT && ILT->u1.AddressOfData;
//			ILT++, IAT++
//			)
//		{
//			SBX_MONITORED_ROUTINE MonitoredRoutine = { };
//
//			MonitoredRoutine.LibName = LibName;
//
//			if ( IMAGE_SNAP_BY_ORDINAL( ILT->u1.Ordinal ) )
//			{
//				MonitoredRoutine.RoutineOrdinal = ( ULONG )( ILT->u1.Ordinal & 0xFFF );
//			}
//			else
//			{
//				PIMAGE_IMPORT_BY_NAME ImportName = ( PIMAGE_IMPORT_BY_NAME )( EmulatedPE->PE.LoadedBase + ILT->u1.AddressOfData );
//
//				MonitoredRoutine.RoutineName = ImportName->Name;
//			}
//
//			MonitoredRoutine.RoutineAddress = ( PVOID )IAT->u1.AddressOfData;
//			MonitoredRoutine.PointerAddress = IAT;
//
//			EmulatedPE->MonitoredRoutines.push_back( { MonitoredRoutine } );
//
//			//EmulatedPE->MonitoredRoutines = ( PAKI_MONITORED_ROUTINE* )realloc(
//			//	EmulatedPE->MonitoredRoutines,
//			//	( EmulatedPE->MonitoredRoutinesCount * sizeof( PVOID ) ) + sizeof( PVOID )
//			//);
//			//
//			//if ( !EmulatedPE->MonitoredRoutines )
//			//{
//			//	__debugbreak( );
//			//}
//			//
//			//EmulatedPE->MonitoredRoutines[ EmulatedPE->MonitoredRoutinesCount ] = MonitoredRoutine;
//			//EmulatedPE->MonitoredRoutinesCount += 1;
//		}
//	}
//
//	return !EmulatedPE->MonitoredRoutines.empty( );
//}

BOOL 
SbxIsWithinEmulatedImage( 
	_In_ UINT_PTR ExceptionAddress 
)
{
	return SbxGetEmulatedPEByException( ExceptionAddress ) != NULL;
}

PSBX_EMULATED_PE 
SbxGetEmulatedPEByException( 
	_In_ UINT_PTR ExceptionAddress
)
{
	PSBX_ENVIRONMENT CurrentEnvironment = &SbxEnvironment;

	for ( SBX_EMULATED_PE& EmulatedPE : SbxEnvironment.EmulatedImages )
	{
		if ( ExceptionAddress >   EmulatedPE.PE.LoadedBase &&
			 ExceptionAddress < ( EmulatedPE.PE.LoadedBase + EmulatedPE.PE.OptionalHeader.SizeOfImage ) )
		{
			return &EmulatedPE;
		}
	}

	return NULL;
}

BOOL 
SbxSetPEProtection( 
	_In_ PSBX_EMULATED_PE EmulatedPE 
)
{
	if ( !EmulatedPE )
	{
		return FALSE;
	}

	for ( SBX_PE_SECTION& CodeSection : EmulatedPE->PE.CodeSections )
	{
		//
		// this is how we are able to interrupt every attempt
		// to execute an instruction 
		//
		DWORD OldProtection = { };
		if ( !VirtualProtect( ( PVOID )CodeSection.Start, CodeSection.End - CodeSection.Start, PAGE_EXECUTE_READ | PAGE_GUARD, &OldProtection ) )
		{
			return FALSE;
		}
	}

	//
	// poc code for interrupting data access
	//
	// 
	//for ( ULONG i = 0; i < EmulatedPE->PE->DataSectionsCount; i++ )
	//{
	//	PSBX_PE_SECTION DataSection = EmulatedPE->PE->DataSections[ i ];
	//
	//	if ( !DataSection )
	//	{
	//		continue;
	//	}
	//
	//	//
	//	// this is how we are able to interrupt every attempt
	//	// to access data
	//	//
	//	DWORD OldProtection = { };
	//	if ( !VirtualProtect( ( PVOID )DataSection->Start, DataSection->End - DataSection->Start, PAGE_NOACCESS, &OldProtection ) )
	//	{
	//		return FALSE;
	//	}
	//}

	return TRUE;
}

ULONG 
SbxHandleImageStepOut( 
	_In_ PSBX_EMULATED_PE EmulatedPE,
	_In_ PVOID ExceptionAddress, 
	_In_ PVOID LastExceptionAddress 
)
{
	if ( !MonitoredRoutines.contains( ( UINT_PTR )ExceptionAddress ) )
	{
		//printf( "\n[ !!! ] IMAGE STEPPING OUT TO UNKOWN ADDRESS - 0x%p [ !!! ]\n\n", ExceptionAddress );

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	//printf( "monitored routine called!\n" );

	SBX_MONITORED_ROUTINE MRoutine = MonitoredRoutines.at( ( UINT_PTR )ExceptionAddress );

	printf( "[ MRoutine ] Monitored Routine attempted to be called:\n\tRoutineLib -> %s\n\tRoutineName -> %s\n\tRoutineAddress -> 0x%p\n",

		MRoutine.LibName.c_str( ),
		MRoutine.RoutineName.c_str( ),
		MRoutine.RoutineAddress

		);

	if ( EmulatedPE->Flags & SBX_EMU_PE_BREAK_ON_MONITORED_ROUTINE )
	{
		printf( "Press any key to continue with the call...\n" );
		std::cin.get( );

		CONSOLE_SCREEN_BUFFER_INFO csbi;
		COORD cursorPosition;

		// Get the current cursor position
		GetConsoleScreenBufferInfo( GetStdHandle( STD_OUTPUT_HANDLE ), &csbi );
		cursorPosition = csbi.dwCursorPosition;

		// Move cursor to the beginning of the line
		cursorPosition.X = 0;
		cursorPosition.Y -= 1;
		SetConsoleCursorPosition( GetStdHandle( STD_OUTPUT_HANDLE ), cursorPosition );

		// Print spaces to clear the entire line
		DWORD numCharsWritten;
		DWORD consoleSize = csbi.dwSize.X;
		FillConsoleOutputCharacter( GetStdHandle( STD_OUTPUT_HANDLE ), ' ', consoleSize, cursorPosition, &numCharsWritten );
		SetConsoleCursorPosition( GetStdHandle( STD_OUTPUT_HANDLE ), cursorPosition );
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}