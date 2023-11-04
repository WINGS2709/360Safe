#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include "Data.h"
#include "WinKernel.h"
#include "SafeWarning.h"


//修复重定位
typedef struct _TYPE {
	USHORT Offset : 12;
	USHORT Type : 4;
}TYPE, *PTYPE;

//函数功能：
//动态定位到Srv.sys的SrvTransaction2DispatchTable地址
//返回值：SrvTransaction2DispatchTable的地址
ULONG NTAPI Safe_GetSrvTransaction2DispatchTable(IN PVOID pModuleBase, IN ULONG ModuleSize, OUT ULONG* TimeDateStamp, OUT ULONG* CheckSum);

//Mdl hook
NTSTATUS NTAPI Safe_ReplaceSrvTransaction2DispatchTable(IN PVOID pModuleBase, IN ULONG ModuleSize, IN ULONG TimeDateStamp, IN ULONG CheckSum, IN PVOID OriginalSrvTransaction2DispatchTable, IN PVOID NewOriginalSrvTransaction2DispatchTable, IN PUNICODE_STRING SrvSysPathString);

//永恒之蓝漏洞(CVE-2017-0144),替换srv!SrvTransaction2DispatchTable的0x0e
BOOLEAN NTAPI Safe_HookSrvTransactionNotImplemented();

//Fake函数
NTSTATUS NTAPI Fake_SrvTransactionNotImplemented_0xE(PVOID a1);