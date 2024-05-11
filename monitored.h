#pragma once

#include <vector>
#include <unordered_map>
#include <string>

#include "winternls.h"
#include "emulator.h"

EXTERN std::unordered_map<UINT_PTR, SBX_MONITORED_ROUTINE> MonitoredRoutines;

BOOL
SbxSetupMonitoredRoutines(

);

BOOL
SbxRegisterPEExportsAsMonitored(
	_In_ std::string LibName,
	_In_ UINT_PTR PEBase
);

BOOL
SbxAddMonitoredRoutine(
	_In_ SBX_MONITORED_ROUTINE MonitoredRoutine
);