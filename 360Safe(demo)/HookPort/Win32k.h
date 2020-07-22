#pragma once
#include	<ntifs.h>
#include    "WinKernel.h"


////ShadowSSDT
////win10_14316版本之前
//PVOID ShadowSSDT_GuiServiceTableBase ;
//ULONG ShadowSSDT_GuiNumberOfServices;
//PVOID ShadowSSDT_GuiParamTableBase;
////win10_14316版本之后
//PVOID ShadowSSDT_GuiServiceTableBase_Win10_14316;
//ULONG ShadowSSDT_GuiNumberOfServices_Win10_14316;
//PVOID ShadowSSDT_GuiParamTableBase_Win10_14316;

//KeServiceDescriptorTableShadow表结构
typedef struct _SYSTEM_SERVICE_TABLE
{
	PVOID  *ServiceTable;
	PULONG	CounterTable;
	ULONG	ServiceLimit;
	PUCHAR	ArgumentTable;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;


typedef struct _SERVICE_DESCRIPTOR_TABLE
{
	SYSTEM_SERVICE_TABLE ntoskrnl;			// ntoskrnl.exe ( native api ),其实ssdt就在这里
	SYSTEM_SERVICE_TABLE win32k;			//SSSDT
	SYSTEM_SERVICE_TABLE iis;
	SYSTEM_SERVICE_TABLE unused;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;
PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTableShadow;

//
BOOLEAN NTAPI HookPort_IsAddressExist(IN PVOID VirtualAddress, IN ULONG Size);

//通过特征码获取Shadow地址（附带win10版本）
BOOLEAN NTAPI HookPort_GetShadowTableAddress_Win10(IN PVOID ImageBase, OUT PVOID* ShadowSSDT_GuiServiceTableBase, OUT ULONG* ShadowSSDT_GuiNumberOfServices, OUT PVOID* ShadowSSDT_GuiParamTableBase, OUT PVOID* ShadowSSDT_GuiServiceTableBase_Win10_14316, OUT ULONG* ShadowSSDT_GuiNumberOfServices_Win10_14316, OUT PVOID* ShadowSSDT_GuiParamTableBase_Win10_14316, IN RTL_OSVERSIONINFOEXW osverinfo);

//通过特征码定位SSSDT表   
BOOLEAN NTAPI HookPort_GetShadowTableAddress(OUT PVOID* ShadowSSDT_GuiServiceTableBase, OUT ULONG* ShadowSSDT_GuiNumberOfServices, OUT PVOID* ShadowSSDT_GuiParamTableBase, IN PVOID* NtImageBase, IN ULONG Version_Win10_Flag, IN RTL_OSVERSIONINFOEXW osverinfo)
;