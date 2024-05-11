#include <iostream>

#include "emulator.h"

#define SBX_TARGET_IMAGE_PATH "C:\\Program Files (x86)\\Steam\\steam.exe" // "C:\\Windows\\System32\\Notepad.exe"

int
main(
    int argc,
    char** argv
) 
{
    LPCSTR TargetImagePath = NULL;

    if ( argc <= 1 )
    {
        TargetImagePath = SBX_TARGET_IMAGE_PATH;
    }
    else
    {
        TargetImagePath = argv[ 1 ];
    }

    if ( !SbxInitializeEmulator( ) )
    {
        return 0x1;
    }
    
    SBX_PE_IMAGE PEImage = { };
    if ( !SbxLoadPE( TargetImagePath, &PEImage ) )
    {
        return 0x2;
    }
    
    if ( !SbxEmulatePE( &PEImage, SBX_EMU_USERMODE,

        SBX_EMU_LOG_INSTRUCTIONS
        
        ) )
    {
        return 0x3;
    }

    while ( 1 )
    {
        Sleep( 1000 );
    }
   
    return 0;
}