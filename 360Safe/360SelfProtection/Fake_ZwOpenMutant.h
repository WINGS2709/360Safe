#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Data.h"
#include "SystemProcessDataList.h"

//打开互斥体 防多开
//原函数执行后检查
//禁止打开指定互斥体
NTSTATUS NTAPI After_ZwOpenMutant_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//打开互斥体 防多开
NTSTATUS NTAPI Fake_ZwOpenMutant(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);