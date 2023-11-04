#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Data.h"
#include "SystemProcessDataList.h"
#include "VirtualMemoryDataList.h"

NTSTATUS NTAPI After_ZwAllocateVirtualMemory_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//∑÷≈‰ƒ⁄¥Ê
NTSTATUS NTAPI Fake_ZwAllocateVirtualMemory(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);