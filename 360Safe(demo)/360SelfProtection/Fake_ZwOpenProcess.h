#pragma once
#include <ntifs.h>
#include "WinBase.h"
#include "MemCheck.h"
#include "Data.h"
#include "SystemProcessDataList.h"

NTKERNELAPI
NTSTATUS
PsLookupProcessThreadByCid(
	__in PCLIENT_ID Cid,
	__deref_opt_out PEPROCESS *Process,
	__deref_out PETHREAD *Thread
);

//函数说明：
//1、打开的是保护进程，将打开的句柄重新复制一份（降权阉割后的，原始的直接Close掉）
//2、打开的是非保护进程直接无视
NTSTATUS NTAPI After_ZwOpenProcess_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//打开进程
NTSTATUS NTAPI Fake_ZwOpenProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);