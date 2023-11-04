#pragma once
#include <ntddk.h>
#include "PE.h"
#include "DebugPrint.h"
//KeServiceDescriptorTable的表结构
typedef struct ServiceDescriptorEntry {
	ULONG* ServiceTableBase;		 // 服务表基址
	ULONG* ServiceCounterTableBase;	 // 计数表基址
	ULONG NumberOfServices;			 // 表中项的个数
	UCHAR *ParamTableBase;			 // 服务函数的参数个数数组的起始地址，数组的每一个成员占1字节，记录的值是对应函数的参数个数*4
} ServiceDescriptorTableEntry, *PServiceDescriptorTableEntry;

//获取SSDT基址
NTSTATUS NTAPI Safe_GetSSDTTableAddress(OUT PVOID* SSDT_KeServiceTableBase, OUT ULONG* SSDT_KeNumberOfServices, OUT PVOID* SSDT_KeParamTableBase, IN PVOID* NtImageBase);