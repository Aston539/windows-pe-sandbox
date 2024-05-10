#pragma once

#include <windows.h>
#include <vector>
#include <string>

typedef enum _SBX_PE_IMAGE_TYPE
{
	SBX_DLL,
	SBX_EXE,
	SBX_SYS,

} SBX_PE_IMAGE_TYPE, * PSBX_PE_IMAGE_TYPE;

typedef struct _SBX_PE_SECTION
{
	std::string Name;
	UINT64 Start;
	UINT64 End;

} SBX_PE_SECTION, *PSBX_PE_SECTION;

typedef struct _SBX_PE_IMAGE
{
	UINT64 LoadedBase;

	ULONG PEImageType;

	IMAGE_DOS_HEADER DosHeader;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;

	ULONG OffsetToFileName;
	ULONG OffsetToFileExtension;

	CHAR FilePath[ MAX_PATH ];

	//ULONG CodeSectionsCount;
	//PSBX_PE_SECTION* CodeSections;

	std::vector< SBX_PE_SECTION > CodeSections;

	//ULONG DataSectionsCount;
	//PSBX_PE_SECTION* DataSections;

	std::vector< SBX_PE_SECTION > DataSections;

} SBX_PE_IMAGE, *PSBX_PE_IMAGE;

BOOL
SbxLoadPE(
	_In_ LPCSTR Path,
	_Inout_ PSBX_PE_IMAGE PEImage
);

PIMAGE_IMPORT_DESCRIPTOR
SbxGetPEImportDescriptor(
	_In_ PSBX_PE_IMAGE Image
);

VOID
SbxGetFilePathInfo(
	_In_ LPCSTR Path,
	_Inout_ PSBX_PE_IMAGE PEImage
);

VOID
SbxGetCodeSections(
	_Inout_ PSBX_PE_IMAGE PEImage
);

VOID
SbxGetDataSections(
	_Inout_ PSBX_PE_IMAGE PEImage
);