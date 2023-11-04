#pragma once
#include <ntddk.h>
#include "FilterHook.h"
#define	CreateProcessNotifyRoutine_FilterIndex	0x45
NTSTATUS NTAPI Filter_CreateProcessNotifyRoutine(IN HANDLE  ParentId, IN HANDLE  ProcessId, IN BOOLEAN  Create);