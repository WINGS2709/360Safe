#pragma once
#include "FilterHook.h"
#include "DebugPrint.h"
NTSTATUS NTAPI Filter_ZwLoadDriver(IN PUNICODE_STRING  DriverServiceName);