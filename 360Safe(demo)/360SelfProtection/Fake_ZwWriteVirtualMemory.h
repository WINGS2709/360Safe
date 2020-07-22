#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Data.h"
#include "SystemProcessDataList.h"
#include "Object.h"
#include "VirtualMemoryDataList.h"
#include "SafeWarning.h"

//修改保护进程地址 or 修改PEB放行 ？？？？？？？？？？？？？
BOOLEAN NTAPI Safe_CheckWriteMemory_PEB(IN HANDLE In_Handle, IN ULONG In_BaseAddress, SIZE_T In_BufferLength);

///跨进程写内容
NTSTATUS NTAPI Fake_ZwWriteVirtualMemory(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);