#include "Win32k.h"


//************************************     
// 函数名称: HookPort_IsAddressExist     
// 函数说明： 验证指定地址是否有效
//            检查的方法是以PAGEZ_SIZE（0x1000）为边界的指定范围内调用MmIsAddressValid验证
//            每一次检测	PAGEZ_SIZE 的范围
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值: BOOLEAN NTAPI     
// 参    数: PVOID VirtualAddress     
// 参    数: ULONG Size     
//************************************  
BOOLEAN NTAPI HookPort_IsAddressExist(IN PVOID VirtualAddress,IN ULONG Size)
{

	PVOID	Target = (PVOID)(((ULONG)((PCHAR)VirtualAddress + Size - 1) & 0xFFFFF000) + 0x1000);

	while (MmIsAddressValid(VirtualAddress))
	{
		VirtualAddress = (PVOID)(((ULONG)VirtualAddress & 0xFFFFF000) + 0x1000);
		if (VirtualAddress == Target)
			return TRUE;
	}
	return FALSE;
}

 
//************************************     
// 函数名称: HookPort_GetShadowTableAddress     
// 函数说明：通过特征码定位SSSDT表    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/03/23     
// 返 回 值: BOOLEAN     
// 参    数: OUT PVOID * ShadowSSDT_GuiServiceTableBase        [Out]ShadowSSDT_GuiServiceTableBase     
// 参    数: OUT ULONG * ShadowSSDT_GuiNumberOfServices        [Out]ShadowSSDT_GuiNumberOfServices
// 参    数: OUT PVOID * ShadowSSDT_GuiParamTableBase          [Out]ShadowSSDT_GuiNumberOfServices
// 参    数: IN PVOID * NtImageBase                            [In]Nt内核的基地址
// 参    数: IN ULONG Version_Win10_Flag                       [In]Win10标志
// 参    数: IN RTL_OSVERSIONINFOEXW osverinfo                 [In]版本信息
//************************************  
BOOLEAN NTAPI HookPort_GetShadowTableAddress(OUT PVOID* ShadowSSDT_GuiServiceTableBase, OUT ULONG* ShadowSSDT_GuiNumberOfServices, OUT PVOID* ShadowSSDT_GuiParamTableBase, IN PVOID* NtImageBase, IN ULONG Version_Win10_Flag, IN RTL_OSVERSIONINFOEXW osverinfo)
{

	PCHAR	pTemp = NULL, pAddrEnd = NULL;
	PCHAR	SymbolAddr = NULL;
	ANSI_STRING DestinationString;
	ULONG KeAddSystemServiceTableFlag = NULL;
	ULONG KeRemoveSystemServiceTableFlag = NULL;
	//KeAddSystemServiceTable
	//00582F9E 004 8D 88 80 09 56 00   lea     ecx, _KeServiceDescriptorTableShadow[eax]
	KeAddSystemServiceTableFlag = 0x888D;
	//KeRemoveSystemServiceTable
	//006C0542 004 89 88 80 09 56 00   mov     ds:_KeServiceDescriptorTableShadow[eax], ecx
	KeRemoveSystemServiceTableFlag = 0x8889;
	if (Version_Win10_Flag)                   // Win10直接退出
	{
		return 1;
	}
	if (osverinfo.dwMajorVersion == 6 && (osverinfo.dwMinorVersion == 2 || osverinfo.dwMinorVersion == 3))// Win8
	{
		KeAddSystemServiceTableFlag = 0x9189;
		KeRemoveSystemServiceTableFlag = 0x9189;
	}
	RtlInitAnsiString(&DestinationString, "KeAddSystemServiceTable");
	SymbolAddr = HookPort_GetSymbolAddress(&DestinationString,NtImageBase);

	if (!SymbolAddr || !MmIsAddressValid(SymbolAddr)) 
	{
		return (*ShadowSSDT_GuiServiceTableBase != NULL);
	}

	for (pAddrEnd = SymbolAddr + 0x300; SymbolAddr < pAddrEnd; SymbolAddr++) {
		if (!HookPort_IsAddressExist(SymbolAddr, 2))
		{
			continue;
		}
		if (*(unsigned short *)SymbolAddr != KeAddSystemServiceTableFlag)
		{
			continue;
		}

		if (!HookPort_IsAddressExist(SymbolAddr + 2, 4))
		{
			continue;
		}

		pTemp = *(PCHAR *)(SymbolAddr + 2);
		if (!HookPort_IsAddressExist(pTemp + 16, 4))
		{
			continue;
		}

		if (HookPort_IsAddressExist(pTemp + 24, 4))
		{
			break;
		}

	}
	if (SymbolAddr >= pAddrEnd)
	{
		return (*ShadowSSDT_GuiServiceTableBase != NULL);
	}
	KeServiceDescriptorTableShadow = pTemp;
	*ShadowSSDT_GuiServiceTableBase = KeServiceDescriptorTableShadow->win32k.ServiceTable;
	*ShadowSSDT_GuiNumberOfServices = KeServiceDescriptorTableShadow->win32k.ServiceLimit;
	*ShadowSSDT_GuiParamTableBase = KeServiceDescriptorTableShadow->win32k.ArgumentTable;
	return (*ShadowSSDT_GuiServiceTableBase != NULL);
}

//************************************     
// 函数名称: HookPort_GetShadowTableAddress_Win10     
// 函数说明：    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/03/24     
// 返 回 值: BOOLEAN NTAPI     
// 参    数: IN PVOID ImageBase											[In]Win32基地址  
// 参    数: OUT PVOID * ShadowSSDT_GuiServiceTableBase					[Out]ShadowSSDT_GuiServiceTableBase
// 参    数: OUT ULONG * ShadowSSDT_GuiNumberOfServices					[Out]ShadowSSDT_GuiNumberOfServices
// 参    数: OUT PVOID * ShadowSSDT_GuiParamTableBase				    [Out]ShadowSSDT_GuiParamTableBase
// 参    数: OUT PVOID * ShadowSSDT_GuiServiceTableBase_Win10_14316     [Out]ShadowSSDT_GuiServiceTableBase_Win10_14316
// 参    数: OUT ULONG * ShadowSSDT_GuiNumberOfServices_Win10_14316     [Out]ShadowSSDT_GuiNumberOfServices_Win10_14316
// 参    数: OUT PVOID * ShadowSSDT_GuiParamTableBase_Win10_14316       [Out]ShadowSSDT_GuiParamTableBase_Win10_14316
// 参    数: IN RTL_OSVERSIONINFOEXW osverinfo     					    [In]osverinfo版本信息
//************************************  
BOOLEAN NTAPI HookPort_GetShadowTableAddress_Win10(IN PVOID ImageBase, OUT PVOID* ShadowSSDT_GuiServiceTableBase, OUT ULONG* ShadowSSDT_GuiNumberOfServices, OUT PVOID* ShadowSSDT_GuiParamTableBase, OUT PVOID* ShadowSSDT_GuiServiceTableBase_Win10_14316, OUT ULONG* ShadowSSDT_GuiNumberOfServices_Win10_14316, OUT PVOID* ShadowSSDT_GuiParamTableBase_Win10_14316, IN RTL_OSVERSIONINFOEXW osverinfo)
{
	BOOLEAN Result;
	PVOID SymbolAddr;
	PVOID pGuiServiceTableBase;
	PVOID pGuiNumberOfServices;
	PVOID pGuiParamTableBase;
	PVOID pGuiServiceTableBase_Win10_14316;
	PVOID pGuiNumberOfServices_Win10_14316;
	PVOID pGuiParamTableBase_Win10_14316;
	ANSI_STRING DestinationString;
	ULONG BuildNumber = osverinfo.dwBuildNumber;
	ULONG MinorVersion = osverinfo.dwMinorVersion;
	ULONG MajorVersion = osverinfo.dwMajorVersion;
	//根据特征码获取低版本的ShadowSSDT信息
	RtlInitAnsiString(&DestinationString, "SysEntryGetW32pServiceTable");
	pGuiServiceTableBase = HookPort_GetAndReplaceSymbol(ImageBase, &DestinationString, NULL, &SymbolAddr);
	RtlInitAnsiString(&DestinationString, "SysEntryGetW32pServiceLimit");
	pGuiNumberOfServices = HookPort_GetAndReplaceSymbol(ImageBase, &DestinationString, NULL, &SymbolAddr);
	RtlInitAnsiString(&DestinationString, "SysEntryGetW32pArgumentTable");
	pGuiParamTableBase = HookPort_GetAndReplaceSymbol(ImageBase, &DestinationString, NULL, &SymbolAddr);

	if (pGuiServiceTableBase &&
		pGuiNumberOfServices &&
		pGuiParamTableBase
		)
	{
		*ShadowSSDT_GuiServiceTableBase = pGuiServiceTableBase;
		*ShadowSSDT_GuiNumberOfServices = pGuiNumberOfServices;
		*ShadowSSDT_GuiParamTableBase = pGuiParamTableBase;
		//版本大于Win10_14316
		if (BuildNumber >= 14316)
		{
			//根据特征码获取高版本的ShadowSSDT信息
			RtlInitAnsiString(&DestinationString, "SysEntryGetW32pServiceTableFilter");
			pGuiServiceTableBase_Win10_14316 = HookPort_GetAndReplaceSymbol(ImageBase, &DestinationString, NULL, &SymbolAddr);
			RtlInitAnsiString(&DestinationString, "SysEntryGetW32pServiceLimitFilter");
			pGuiNumberOfServices_Win10_14316 = HookPort_GetAndReplaceSymbol(ImageBase, &DestinationString, NULL, &SymbolAddr);
			RtlInitAnsiString(&DestinationString, "SysEntryGetW32pArgumentTableFilter");
			pGuiParamTableBase_Win10_14316 = HookPort_GetAndReplaceSymbol(ImageBase, &DestinationString, NULL, &SymbolAddr);
			if (pGuiServiceTableBase_Win10_14316 &&
				pGuiNumberOfServices_Win10_14316 &&
				pGuiParamTableBase_Win10_14316
				)
			{
				*ShadowSSDT_GuiServiceTableBase_Win10_14316 = pGuiServiceTableBase_Win10_14316;
				*ShadowSSDT_GuiNumberOfServices_Win10_14316 = pGuiNumberOfServices_Win10_14316;
				*ShadowSSDT_GuiParamTableBase_Win10_14316   = pGuiParamTableBase_Win10_14316;
			}
		}
		Result = 1;
	}
	else
	{
		Result = 0;
	}
	return Result;
}