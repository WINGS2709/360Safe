#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Data.h"
#include "WhiteList.h"
#include "SystemProcessDataList.h"
#include "SrvTransactionNotImplemented.h"
#include "ZwNtFunc.h"
#include "NoSystemProcessDataList.h"


NTSTATUS NTAPI After_ZwOpenFile_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//比较OpenFile文件对象名称 == \\Device\\LanmanServer
NTSTATUS NTAPI Safe_CmpLanmanServer(POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NTAPI Fake_ZwOpenFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg);