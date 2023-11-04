#pragma once
#include <ntddk.h>
#include <ntimage.h>
#include "defs.h"

extern
PVOID NTAPI
RtlImageDirectoryEntryToData(
IN PVOID          BaseAddress,
IN BOOLEAN        ImageLoaded,
IN ULONG		   Directory,
OUT PULONG        Size);

PVOID Safe_GetSymbolAddress(PANSI_STRING SymbolName, PVOID NtImageBase);

//根据函数名和ImageBase去导出表找到对应的函数地址
PVOID NTAPI Safe_GetAndReplaceSymbol(PVOID ImageBase, PANSI_STRING SymbolName, PVOID ReplaceValue, PVOID *SymbolAddr);

//检查PE文件基本信息
BOOLEAN NTAPI Safe_CheckPeFile(IN PVOID pModuleBase);

//RVA转换成VA
ULONG NTAPI Safe_RvaToVa(IN PVOID pModuleBase, ULONG dwRva);

/************************PE结构数字签名相关*****************************/
//资源表
BOOLEAN NTAPI Safe_17C8A(IN PVOID pModuleBase, IN ULONG ModuleSize);
/************************PE结构数字签名相关*****************************/