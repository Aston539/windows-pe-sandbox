#include "pe.h"

#include <windows.h>
#include <iostream>

#pragma warning( disable : 4996 )

BOOL 
SbxLoadPE(
	_In_ LPCSTR Path,
	_Inout_ PSBX_PE_IMAGE PEImage
)
{
	if ( !PEImage || !Path )
	{
		return FALSE;
	}

	//
	// when the LoadLibraryEx routine is provided the optional parameter
	// DONT_RESOLVE_DLL_REFERENCES it wil omit resolving any external
	// references this may have this makes it so we have to resolve the
	// images import address table however it also doesent call the images
	// entry point allowing us time to setup its IAT and call it ourselves. 
	//
	PVOID LoadedImage = ( PVOID )LoadLibraryExA( Path, NULL, DONT_RESOLVE_DLL_REFERENCES );

	if ( !LoadedImage )
	{
		return FALSE;
	}

	//
	// at the start of a PE image is a IMAGE_DOS_HEADER structure
	// so to access this data we can cast the base of the image
	// to pointer to an IMAGE_DOS_HEADER structure
	//
	PIMAGE_DOS_HEADER Dos = ( PIMAGE_DOS_HEADER )( LoadedImage );

	//
	// the nt headers of a pe image are located at an RVA from the
	// base of image specified by the dos header in the e_lfanew 
	// data member
	//
	PIMAGE_NT_HEADERS Nt  = ( PIMAGE_NT_HEADERS )( ( UINT64 )LoadedImage + Dos->e_lfanew );

	PEImage->LoadedBase     = ( UINT64 )LoadedImage;
	PEImage->DosHeader      = *Dos;				  // make copies of the pe structures as so
	PEImage->FileHeader     = Nt->FileHeader;	  // that we can limit the amount we need to
	PEImage->OptionalHeader = Nt->OptionalHeader; // access the emulated images memory

	SbxGetFilePathInfo( Path, PEImage );

	SbxGetCodeSections( PEImage );
	SbxGetDataSections( PEImage );

	if ( _stricmp( PEImage->FilePath + PEImage->OffsetToFileExtension, ".exe" ) == 0 )
	{
		PEImage->PEImageType = SBX_EXE;
	}
	else if ( _stricmp( PEImage->FilePath + PEImage->OffsetToFileExtension, ".dll" ) == 0 )
	{
		PEImage->PEImageType = SBX_DLL;
	}
	else if ( _stricmp( PEImage->FilePath + PEImage->OffsetToFileExtension, ".sys" ) == 0 )
	{
		PEImage->PEImageType = SBX_SYS;
	}
	else
	{
		printf( "Unsupported file extension!\n" );

		return FALSE;
	}

	return TRUE;
}

PIMAGE_IMPORT_DESCRIPTOR 
SbxGetPEImportDescriptor( 
	_In_ PSBX_PE_IMAGE Image
)
{
	if ( !Image )
	{
		return NULL;
	}

	IMAGE_DATA_DIRECTORY ImportData = Image->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

	if ( !ImportData.Size || 
		 !ImportData.VirtualAddress )
	{
		return NULL;
	}

	return ( PIMAGE_IMPORT_DESCRIPTOR )( Image->LoadedBase + ImportData.VirtualAddress );
}

VOID
SbxGetFilePathInfo(
	_In_ LPCSTR Path,
	_Inout_ PSBX_PE_IMAGE PEImage
)
{
	strcpy( PEImage->FilePath, Path );

	LONG Length = strlen( Path );

	for ( ULONG i = 0; i < Length; i++ )
	{
		if ( PEImage->FilePath[ i ] == '\\' || PEImage->FilePath[ i ] == '/' )
		{
			PEImage->OffsetToFileName = i + 1;
		}
		else if ( PEImage->FilePath[ i ] == '.' )
		{
			PEImage->OffsetToFileExtension = i;
		}
	}
}

VOID 
SbxGetCodeSections( 
	_Inout_ PSBX_PE_IMAGE PEImage 
)
{
	if ( !PEImage )
	{
		return;
	}

	//
	// Get the address of the first IMAGE_SECTION_HEADER structure
	// in the pe this should be stored contiguously as an array
	// so we can just index this pointer
	//
	PIMAGE_SECTION_HEADER SectionArray = IMAGE_FIRST_SECTION( ( PIMAGE_NT_HEADERS )( PEImage->LoadedBase + PEImage->DosHeader.e_lfanew ) );

	for ( ULONG i = 0; i < PEImage->FileHeader.NumberOfSections; i++ )
	{
		PIMAGE_SECTION_HEADER CurrentSection = &SectionArray[ i ];

		if ( !CurrentSection->VirtualAddress || 
			 !CurrentSection->SizeOfRawData )
		{
			continue;
		}

		if ( CurrentSection->Characteristics & IMAGE_SCN_CNT_CODE )
		{
			SBX_PE_SECTION SbxCodeSection = { };

			SbxCodeSection.Start = PEImage->LoadedBase + CurrentSection->VirtualAddress;
			SbxCodeSection.End   = PEImage->LoadedBase + CurrentSection->VirtualAddress + CurrentSection->SizeOfRawData;
			SbxCodeSection.Name  = ( LPCSTR )CurrentSection->Name;

			PEImage->CodeSections.push_back( { SbxCodeSection } );
		}
	}
}

VOID 
SbxGetDataSections( 
	_Inout_ PSBX_PE_IMAGE PEImage 
)
{
	if ( !PEImage )
	{
		return;
	}

	//
	// Get the address of the first IMAGE_SECTION_HEADER structure
	// in the pe this should be stored contiguously as an array
	// so we can just index this pointer
	//
	PIMAGE_SECTION_HEADER SectionArray = IMAGE_FIRST_SECTION( ( PIMAGE_NT_HEADERS )( PEImage->LoadedBase + PEImage->DosHeader.e_lfanew ) );

	for ( ULONG i = 0; i < PEImage->FileHeader.NumberOfSections; i++ )
	{
		PIMAGE_SECTION_HEADER CurrentSection = &SectionArray[ i ];

		if ( !CurrentSection->VirtualAddress ||
			 !CurrentSection->SizeOfRawData )
		{
			continue;
		}

		if ( CurrentSection->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA ||
			 CurrentSection->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA )
		{
			SBX_PE_SECTION SbxDataSection = { };

			SbxDataSection.Start = PEImage->LoadedBase + CurrentSection->VirtualAddress;
			SbxDataSection.End   = PEImage->LoadedBase + CurrentSection->VirtualAddress + CurrentSection->SizeOfRawData;
			SbxDataSection.Name  = ( LPCSTR )CurrentSection->Name;

			PEImage->DataSections.push_back( { SbxDataSection } );
		}
	}
}