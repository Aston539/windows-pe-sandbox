#include "vcpu.h"

#include "hde/hde64.h"
#include "hde/hde32.h"

#include <iostream>

#include "emulator.h"

ULONG 
SbxEmulateInstruction( 
    _In_ PVOID ExceptionAddress, 
    _Inout_ PCONTEXT ContextRecord
)
{
    if ( SbxIsWithinEmulatedImage( ( UINT_PTR )ExceptionAddress ) )
    {
        PSBX_EMULATED_PE SbxPE = SbxGetEmulatedPEByException( ( UINT_PTR )ExceptionAddress );

        if ( SbxPE->Flags & SBX_EMU_LOG_INSTRUCTIONS )
        {
#define MAX_INSTR_LEN 20

#ifdef _WIN64
            hde64s InstructionInfo = { };
            hde64_disasm( ExceptionAddress, &InstructionInfo );
#else
            hde32s InstructionInfo = { };
            hde32_disasm( ExceptionAddress, &InstructionInfo );
#endif

            BYTE Buffer[ MAX_INSTR_LEN ] = { };

            memcpy( Buffer, ExceptionAddress, InstructionInfo.len + 1 );

            printf( "[ %p ]", ExceptionAddress );

            if ( Buffer[ NULL ] < 0x10 )
            {
                printf( "\t%X%X", NULL, Buffer[ NULL ] );
            }
            else
            {
                printf( "\t%X", Buffer[ NULL ] );
            }

            for ( ULONG I = 1; I < InstructionInfo.len; I++ )
            {
                if ( Buffer[ I ] < 0x10 )
                {
                    printf( ", %X%X", NULL, Buffer[ I ] );
                }
                else
                {
                    printf( ", %X", Buffer[ I ] );
                }
            }

            printf( "\n" );
        }

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
#ifdef _WIN64
    hde64s InstructionInfo = { };
    hde64_disasm( InstructionAddress, &InstructionInfo );
#else
    hde32s InstructionInfo = { };
    hde32_disasm( InstructionAddress, &InstructionInfo );
#endif

    printf( "SbxAdvanceRip( 0x%p ) -> %i\n", InstructionAddress, InstructionInfo.len );

#ifdef _WIN64
    ContextRecord->Rip += InstructionInfo.len;
#else
    ContextRecord->Eip += InstructionInfo.len;
#endif
}