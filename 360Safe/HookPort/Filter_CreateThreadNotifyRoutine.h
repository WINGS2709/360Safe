#pragma once
#include <ntddk.h>
#include "FilterHook.h"

#define	CreateThreadNotifyRoutine_FilterIndex	0x86
NTSTATUS NTAPI Filter_CreateThreadNotifyRoutine(IN HANDLE  ParentId, IN HANDLE  ThreadId, IN BOOLEAN  Create);