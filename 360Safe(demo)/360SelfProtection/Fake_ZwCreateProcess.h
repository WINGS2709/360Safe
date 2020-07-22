#pragma once
#include <ntifs.h>
#include "WinKernel.h"
#include "MemCheck.h"
#include "Data.h"
#include "x360uDataList.h"
#include "CreateProcessDataList.h"

NTSTATUS NTAPI After_ZwCreateProcess_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

NTSTATUS NTAPI After_ZwCreateProcessEx_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//创建进程Ex
NTSTATUS NTAPI Fake_ZwCreateProcessEx(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);

//创建进程
NTSTATUS NTAPI Fake_ZwCreateProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);