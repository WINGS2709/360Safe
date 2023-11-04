#pragma once
#include <ntifs.h>
#include "WinKernel.h"
#include "MemCheck.h"
//拦截注册表注入
NTSTATUS NTAPI After_ZwOpenKey_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//打开注册表键值
NTSTATUS NTAPI Fake_ZwOpenKey(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);