#pragma once
#include <ntifs.h>
#include "Data.h"
#include "SystemProcessDataList.h"
#include "WinBase.h"
//遍历线程
//原函数执行后检查
//当遍历到保护线程的句柄，直接把句柄清零并且返回错误值
NTSTATUS NTAPI After_ZwGetNextThread_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//遍历线程
NTSTATUS NTAPI Fake_ZwGetNextThread(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);