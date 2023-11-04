#pragma once
#include <ntifs.h>
#include "WinKernel.h"
#include "MemCheck.h"
NTSTATUS NTAPI After_ZwUserBuildHwndList_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//枚举所有顶层窗口
NTSTATUS NTAPI Fake_ZwUserBuildHwndList(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);