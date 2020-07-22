#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Data.h"
#include "WhiteList.h"
#include "SystemProcessDataList.h"
#include "ZwNtFunc.h"
#include "NoSystemProcessDataList.h"

NTSTATUS NTAPI After_ZwCreateFile_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//创建文件
NTSTATUS NTAPI Fake_ZwCreateFile(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);