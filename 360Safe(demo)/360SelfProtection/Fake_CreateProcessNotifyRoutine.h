#pragma once

#include <ntifs.h>
#include "WinKernel.h"
#include "Data.h"
#include "WhiteList.h"
#include "CreateProcessDataList.h"
#include "Xor.h"
#include "VirtualMemoryDataList.h"

NTSTATUS NTAPI Fake_CreateProcessNotifyRoutine(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg);