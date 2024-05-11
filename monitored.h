#pragma once

#include <vector>
#include <unordered_map>
#include <string>

#include "winternls.h"
#include "emulator.h"

EXTERN std::unordered_map<UINT64, SBX_MONITORED_ROUTINE> MonitoredRoutines;

BOOL
SbxSetupMonitoredRoutines(

);

BOOL
SbxRegisterPEExportsAsMonitored(
	_In_ std::string LibName,
	_In_ UINT64 PEBase
);

BOOL
SbxAddMonitoredRoutine(
	_In_ SBX_MONITORED_ROUTINE MonitoredRoutine
);