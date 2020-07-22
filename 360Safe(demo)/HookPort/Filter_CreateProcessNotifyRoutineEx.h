#pragma once
#include <ntddk.h>
#include "FilterHook.h"

#define	CreateProcessNotifyRoutineEx_FilterIndex 0x82
NTSTATUS NTAPI Filter_CreateProcessNotifyRoutineEx(IN PEPROCESS   Process, IN HANDLE	   ProcessId, IN PPS_CREATE_NOTIFY_INFO CreateInfo);