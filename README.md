**Overview**

The Windows PE Sandbox project leverages vectored exception handling (VEH) to provide a controlled environment for single-stepping through Portable Executable (PE) files. This sandbox allows for detailed analysis and debugging of PE files by intercepting and handling exceptions, offering insights into the execution flow and behavior of the executable.

**Features**

    Single-Stepping: Allows the user to single step through instructions as the PE executes
    Api Monitoring: Provides the ability to monitor calls to code outside of the emulated PE and it will try to retrieve the
                    name of the called routine.
    Instruction Logging: Will print the current disassembly of instructions being executed
