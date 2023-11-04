#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Data.h"
#include "x360uDataList.h"
#include "Object.h"
#include "Context.h"
#include "SystemProcessDataList.h"

BOOLEAN NTAPI Safe_18FDE(PDEVICE_OBJECT DeviceObject);

NTSTATUS NTAPI After_ZwCreateSection_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//根据句柄获取Dos路径
NTSTATUS NTAPI Safe_DbgFileName(IN HANDLE Handle, OUT PUNICODE_STRING FullPathNameString, IN ULONG FullPathNameSize);

//创建文件映射
NTSTATUS NTAPI Fake_ZwCreateSection(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);