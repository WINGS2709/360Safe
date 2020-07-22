#pragma once
#include <ntifs.h>
#include "WinKernel.h"
#include "MemCheck.h"
#include "SafeWarning.h"


//取消映射目标进程的内存
NTSTATUS NTAPI Fake_ZwUnmapViewOfSection(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);