#include "monitored.h"

std::unordered_map<UINT64, SBX_MONITORED_ROUTINE> MonitoredRoutines;

BOOL
SbxSetupMonitoredRoutines(

)
{
	PPEB Peb = NtCurrentPeb( );

	if ( !Peb )
	{
		return FALSE;
	}

	PPEB_LDR_DATA Ldr = Peb->Ldr;

	if ( !Ldr || 
		 !Ldr->Initialized )
	{
		return FALSE;
	}

	for (
		PLIST_ENTRY CurrentListEntry = Ldr->InLoadOrderModuleList.Flink;
		CurrentListEntry&& CurrentListEntry->Flink && ( UINT64 )CurrentListEntry != ( UINT64 )Ldr->InLoadOrderModuleList.Blink;
		CurrentListEntry = CurrentListEntry->Flink
		)
	{
		PLDR_DATA_TABLE_ENTRY DataEntry = CONTAINING_RECORD( CurrentListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

		if ( !DataEntry || 
			 !DataEntry->BaseDllName.Buffer )
		{
			continue;
		}

		std::wstring WDllName = DataEntry->BaseDllName.Buffer;
		std::string DllName = std::string( WDllName.begin( ), WDllName.end( ) );

		SbxRegisterPEExportsAsMonitored( DllName, ( UINT64 )DataEntry->DllBase );
	}

	return TRUE;
}

BOOL
SbxRegisterPEExportsAsMonitored(
	_In_ std::string LibName,
	_In_ UINT64 PEBase
)
{
	if ( !PEBase )
	{
		return FALSE;
	}

	PIMAGE_DOS_HEADER Dos = ( PIMAGE_DOS_HEADER )( PEBase );
	PIMAGE_NT_HEADERS Nt = ( PIMAGE_NT_HEADERS )( PEBase + Dos->e_lfanew );

	PIMAGE_DATA_DIRECTORY ExportData = &Nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	if ( !ExportData->Size ||
		 !ExportData->VirtualAddress )
	{
		//
		// this pe likely has no exports
		//

		return TRUE;
	}

	PIMAGE_EXPORT_DIRECTORY ExportDirectory = ( PIMAGE_EXPORT_DIRECTORY )( PEBase + ExportData->VirtualAddress );

	PUINT32 AddressesTable = ( PUINT32 )( PEBase + ExportDirectory->AddressOfFunctions );
	PUINT32 NamesTable     = ( PUINT32 )( PEBase + ExportDirectory->AddressOfNames );
	PUINT16 OrdinalsTable  = ( PUINT16 )( PEBase + ExportDirectory->AddressOfNameOrdinals );

	for ( ULONG I = NULL; I < ExportDirectory->NumberOfNames; I++ )
	{
		BOOL IsNameExport = I < ExportDirectory->NumberOfNames;

		UINT16 Ordinal = OrdinalsTable[ I ];
		UINT64 Function = PEBase + AddressesTable[ Ordinal ];

		SBX_MONITORED_ROUTINE MonitoredRoutine = { };
			MonitoredRoutine.LibName        = LibName;
			MonitoredRoutine.RoutineAddress = ( PVOID )Function;
			MonitoredRoutine.RoutineOrdinal = Ordinal;

		if ( IsNameExport )
		{
			MonitoredRoutine.RoutineName = ( LPCSTR )( PEBase + NamesTable[ I ] );
		}

		SbxAddMonitoredRoutine( MonitoredRoutine );
	}

	return TRUE;
}

BOOL
SbxAddMonitoredRoutine(
	_In_ SBX_MONITORED_ROUTINE MonitoredRoutine
)
{
	if ( MonitoredRoutines.contains( ( UINT64 )MonitoredRoutine.RoutineAddress ) )
	{
		return TRUE;
	}

	MonitoredRoutines.insert( {
		( UINT64 )MonitoredRoutine.RoutineAddress,
		          MonitoredRoutine
		} );

	return TRUE;
}