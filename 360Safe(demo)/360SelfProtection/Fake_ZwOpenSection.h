#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Data.h"
#include "SystemProcessDataList.h"
#include "WinBase.h"
//打开section object
//原函数执行后检查
NTSTATUS NTAPI After_ZwOpenSection_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//打开section object
NTSTATUS NTAPI Fake_ZwOpenSection(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);