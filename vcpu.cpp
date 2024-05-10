#include "vcpu.h"

#include "hde/hde64.h"

#include <iostream>

#include "emulator.h"

ULONG 
SbxEmulateInstruction( 
    _In_ PVOID ExceptionAddress, 
    _Inout_ PCONTEXT ContextRecord
)
{
    if ( SbxIsWithinEmulatedImage( ( UINT64 )ExceptionAddress ) )
    {
        PSBX_EMULATED_PE SbxPE = SbxGetEmulatedPEByException( ( UINT64 )ExceptionAddress );

        hde64s InstructionInfo = { };
        hde64_disasm( ExceptionAddress, &InstructionInfo );

        BYTE Buffer[ 0x20 ] = { };

        memcpy( Buffer, ExceptionAddress, InstructionInfo.len );

        for ( ULONG i = 0; i < InstructionInfo.len; i++ )
        {
            printf( "0x%X, ", Buffer[ i ] );
        }

        printf( "\n" );

        if ( SbxPE->Flags & SBX_EMU_PE_SINGLESTEP )
        {
            printf( "SINGLESTEP IS ACTIVE" );
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
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

VOID 
SbxAdvanceRIP( 
    _In_ PVOID InstructionAddress,
    _Inout_ PCONTEXT ContextRecord
)
{ 
    hde64s InstructionInfo = { };
    hde64_disasm( InstructionAddress, &InstructionInfo );

    printf( "SbxAdvanceRip( 0x%p ) -> %i\n", InstructionAddress, InstructionInfo.len );

    ContextRecord->Rip += InstructionInfo.len;
}