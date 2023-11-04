#pragma once
#include <ntifs.h>
#include "Data.h"
#include "WinBase.h"
#include "SystemProcessDataList.h"

//遍历进程
//原函数执行后检查
//当遍历到保护进程的句柄，直接把句柄清零并且返回错误值
NTSTATUS NTAPI After_ZwGetNextProcess_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//遍历进程
NTSTATUS NTAPI Fake_ZwGetNextProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);