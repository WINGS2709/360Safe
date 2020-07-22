#include "Fake_ZwWriteVirtualMemory.h"

//修改保护进程地址 or 修改PEB放行 ？？？？？？？？？？？？？
BOOLEAN NTAPI Safe_CheckWriteMemory_PEB(IN HANDLE In_Handle, IN ULONG In_BaseAddress, SIZE_T In_BufferLength)
{
	BOOLEAN        result = FALSE;
	NTSTATUS       Status = STATUS_SUCCESS;
	ULONG          ReturnLength = NULL;
	ULONG          Peb_Offset = NULL;
	ULONG          Peb_ProcessParameters_Offset = 0x10;			//Peb->ProcessParameters(包含进程名等重要信息，可以隐藏进程之类的)
	ULONG          Peb_pShimData_Offset = 0x1E8;				//Peb->pShimData(利用Shim Engine来Dll劫持)
	ULONG          Peb_pContextData_Offset = 0x238;				//Peb->ProcessParameters(知识盲区不清楚，知道的大佬告诉下)
	PROCESS_BASIC_INFORMATION ProcessInformation = { 0 };
	//1、获取PEB信息
	Status = Safe_ZwQueryInformationProcess(In_Handle, ProcessBasicInformation, &ProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
	if (NT_SUCCESS(Status))
	{
		if (In_BaseAddress + In_BufferLength >= In_BaseAddress)
		{
			if (Safe_QueryVirtualMemoryDataList(In_BaseAddress, In_BufferLength, ProcessInformation.UniqueProcessId, PsGetCurrentProcessId())// 判断写的空间是否在列表空间之间
				|| In_BaseAddress > ProcessInformation.PebBaseAddress								//大于PebBase都算Peb地址（有点不严谨，不过不影响）
				&& ((Peb_Offset = In_BaseAddress - (ULONG)(ProcessInformation.PebBaseAddress),		
				   Peb_Offset == Peb_ProcessParameters_Offset)										// Peb->ProcessParameters
				|| Peb_Offset == Peb_pShimData_Offset												// Peb->pShimData
				|| Peb_Offset == Peb_pContextData_Offset)											// Peb->pContextData 
				&& In_BufferLength == sizeof(ULONG))												// 4个字节
			{
				result = TRUE;
			}
		}
	}
	else
	{
		result = TRUE;
	}
	return result;
}

NTSTATUS NTAPI Fake_ZwWriteVirtualMemory(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	//0、获取ZwWriteVirtualMemory原始参数
	HANDLE  In_ProcessHandle = *(ULONG*)((ULONG)ArgArray);
	PVOID   In_BaseAddress =*(ULONG*)((ULONG)ArgArray+4);
	PVOID   In_Buffer =*(ULONG*)((ULONG)ArgArray+8);
	ULONG   In_BufferLength = *(ULONG*)((ULONG)ArgArray+0xC);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//若句柄值!=当前进程的句柄（-1），特殊处理
		if (In_ProcessHandle != NtCurrentProcess())
		{
			//自身非白名单进程
			if (!Safe_QueryWhitePID(PsGetCurrentProcessId()))
			{
				// 查找指定的Object类型
				if (Safe_QueryObjectType(In_ProcessHandle, L"Process"))
				{
					if (!Safe_QueryWintePID_ProcessHandle(In_ProcessHandle)
						|| Safe_QuerySystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_CSRSS_EXE,g_VersionFlag)
						|| Safe_QuerySystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_DLLHOST_EXE, g_VersionFlag)
						|| Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_CSRSS_EXE, g_VersionFlag)
						|| Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_DLLHOST_EXE, g_VersionFlag))
					{
						//非保护进程走这里
						if (Safe_CheckSysProcess_Csrss_Lsass(In_ProcessHandle) &&		//过滤掉进程名为：csrss.exe和lsass.exe
							!Safe_FindEprocessThreadCount(In_ProcessHandle, 0))			//检查进程线程个数
						{
							//调用者为coherence.exe返回1，否则0
							return Safe_CheckSysProcess_Coherence() != FALSE ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
						}
					}
					//执行到这里都是受保护白名单进程
					//修改保护进程内存地址 or 修改PEB放行 ？？？？？？？？？？？？？
					else if (!Safe_CheckWriteMemory_PEB(In_ProcessHandle, In_BaseAddress, In_BufferLength))
					{
						//触发拦截还是放行
						Safe_18A72_SendR3(PsGetCurrentProcessId(), PsGetCurrentProcessId(), 2);
						return STATUS_CALLBACK_BYPASS;
					}
				}
			}
		}
	}

	return result;
}