#include "Fake_ZwCreateProcess.h"

//************************************     
// 函数名称: After_ZwCreateProcess_Func     
// 函数说明：原始函数执行后检查，保护进程路径则禁止用户打开（将句柄清零，看你怎么打开）  
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/03/31     
// 返 回 值: NTSTATUS NTAPI     
// 参    数: IN ULONG FilterIndex      [In]After_ZwOpenFileIndex序号
// 参    数: IN PVOID ArgArray         [In]ZwOpenFile参数的首地址
// 参    数: IN NTSTATUS Result        [In]调用原始ZwOpenFile返回值
// 参    数: IN PULONG RetFuncArgArray [In]返回被删除的SafeMon列表数组下标
//************************************  
NTSTATUS NTAPI After_ZwCreateProcess_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{

	NTSTATUS       Status, result;
	PEPROCESS pPeprocess = NULL;
	result = STATUS_SUCCESS;
	//0、获取ZwCreateProcess原始参数
	PHANDLE  ProcessHandle = *(ULONG*)((ULONG)ArgArray);

	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	if (myProbeRead(ProcessHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(After_ZwCreateProcess_Func：ProcessHandle) error \r\n"));
		return result;
	}
	if (ObReferenceObjectByHandle(*(ULONG*)ProcessHandle, NULL, PsProcessType, KernelMode, &pPeprocess, 0) >= 0)
	{
		Safe_InsertCreateProcessDataList(pPeprocess, *(ULONG*)RetFuncArgArray);
		ObfDereferenceObject((PVOID)pPeprocess);
		pPeprocess = 0;
	}
	return result;
}

//************************************     
// 函数名称: After_ZwCreateProcessEx_Func     
// 函数说明：原始函数执行后检查，保护进程路径则禁止用户打开（将句柄清零，看你怎么打开）  
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/03/31     
// 返 回 值: NTSTATUS NTAPI     
// 参    数: IN ULONG FilterIndex      [In]After_ZwOpenFileIndex序号
// 参    数: IN PVOID ArgArray         [In]ZwOpenFile参数的首地址
// 参    数: IN NTSTATUS Result        [In]调用原始ZwOpenFile返回值
// 参    数: IN PULONG RetFuncArgArray [In]与返回的函数指针对应的一个参数,在调用RetFuncArray中的一个函数时需要传递在本参数中对应的参数
//************************************  
NTSTATUS NTAPI After_ZwCreateProcessEx_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS  Status, result;
	PROCESS_BASIC_INFORMATION PBI = { 0 };
	ULONG ReturnLength = NULL;
	PEPROCESS pPeprocess = NULL;
	result = STATUS_SUCCESS;
	//0、获取ZwCreateProcess原始参数
	PHANDLE  ProcessHandle = *(ULONG*)((ULONG)ArgArray);

	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	if (myProbeRead(ProcessHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(Address) error \r\n"));
		return result;
	}
	//GetProcessPid
	Status = Safe_ZwQueryInformationProcess(*(ULONG*)ProcessHandle, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
	if (NT_SUCCESS(Status))
	{
		if (PBI.UniqueProcessId)
		{
			Safe_InsertWhiteList_PID_Win2003(PBI.UniqueProcessId, *(ULONG*)RetFuncArgArray);
		}
	}
	return result;
}

//创建进程Ex
NTSTATUS NTAPI Fake_ZwCreateProcessEx(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       Status, Result;
	Result = STATUS_SUCCESS;
	//0、获取ZwCreateProcess原始参数
	HANDLE  SectionHandle = *(ULONG*)((ULONG)ArgArray + 0x14);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		ULONG SafeModIndex = Safe_DeleteSafeMonDataList(*(HANDLE*)SectionHandle);
		if (SafeModIndex)
		{
			*(ULONG*)ret_func = After_ZwCreateProcessEx_Func;
			*(ULONG*)ret_arg = SafeModIndex;
		}
	}
	return Result;
}

//创建进程
NTSTATUS NTAPI Fake_ZwCreateProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       Status, result;
	result = STATUS_SUCCESS;
	//0、获取ZwCreateProcess原始参数
	HANDLE  SectionHandle = *(ULONG*)((ULONG)ArgArray + 0x14);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		ULONG SafeModIndex = Safe_DeleteSafeMonDataList(*(HANDLE*)SectionHandle);
		if (SafeModIndex)
		{
			*(ULONG*)ret_func = After_ZwCreateProcess_Func;
			*(ULONG*)ret_arg = SafeModIndex;
		}
	}
	return result;
}