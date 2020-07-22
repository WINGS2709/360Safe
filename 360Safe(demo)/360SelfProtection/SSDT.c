#include "SSDT.h"

//************************************     
// 函数名称: SafePort_GetSSDTTableAddress     
// 函数说明：获取SSDT基址    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/03/23     
// 返 回 值: NTSTATUS NTAPI     
// 参    数: OUT PVOID * SSDT_KeServiceTableBase     //[Out]SSDT_KeServiceTableBase
// 参    数: OUT ULONG * SSDT_KeNumberOfServices     //[Out]SSDT_KeNumberOfServices
// 参    数: OUT PVOID * SSDT_KeParamTableBase       //[Out]SSDT_KeParamTableBase
// 参    数: IN PVOID * NtImageBase					 //[In]Nt内核的基地址
//************************************  
NTSTATUS NTAPI Safe_GetSSDTTableAddress(OUT PVOID* SSDT_KeServiceTableBase, OUT ULONG* SSDT_KeNumberOfServices, OUT PVOID* SSDT_KeParamTableBase, IN PVOID* NtImageBase)
{
	NTSTATUS                     Status = STATUS_UNSUCCESSFUL;
	ANSI_STRING					 KeServiceDescriptorTableString;
	PCHAR						 SymbolAddr = NULL;
	PServiceDescriptorTableEntry KeServiceDescriptorTable = NULL;
	//3、获取SSDT基址
	RtlInitAnsiString(&KeServiceDescriptorTableString, "KeServiceDescriptorTable");
	SymbolAddr = Safe_GetSymbolAddress(&KeServiceDescriptorTableString, NtImageBase);
	if (SymbolAddr)
	{
		KeServiceDescriptorTable = (PServiceDescriptorTableEntry)SymbolAddr;
		*SSDT_KeServiceTableBase = KeServiceDescriptorTable->ServiceTableBase;
		*SSDT_KeNumberOfServices = KeServiceDescriptorTable->NumberOfServices;
		*SSDT_KeParamTableBase = KeServiceDescriptorTable->ParamTableBase;
		if (!KeServiceDescriptorTable && MmIsAddressValid(KeServiceDescriptorTable))
		{
			HookPort_RtlWriteRegistryValue(3);
			return STATUS_UNSUCCESSFUL;
		}
		if (!*SSDT_KeNumberOfServices)
		{
			HookPort_RtlWriteRegistryValue(5);
			return STATUS_UNSUCCESSFUL;
		}
		if (!*SSDT_KeServiceTableBase || !*SSDT_KeParamTableBase)
		{
			HookPort_RtlWriteRegistryValue(6);
			return STATUS_UNSUCCESSFUL;
		}
		Status = STATUS_SUCCESS;
	}
	else
	{
		//查找SSDT表失败
		Status = STATUS_UNSUCCESSFUL;
	}
	return Status;
}