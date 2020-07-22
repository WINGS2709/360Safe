#include "Fake_ZwAllocateVirtualMemory.h"

//************************************     
// 函数名称: After_ZwAllocateVirtualMemory_Func     
// 函数说明：原始函数执行后检查
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
NTSTATUS NTAPI After_ZwAllocateVirtualMemory_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS       Status, result;
	PROCESS_BASIC_INFORMATION PBI = { 0 };
	ULONG          ReturnLength = NULL;
	result = STATUS_SUCCESS;
	//0、获取ZwAllocateVirtualMemory原始参数
	HANDLE  In_ProcessHandle = *(ULONG*)((ULONG)ArgArray);
	PVOID   In_pBaseAddress = *(ULONG*)((ULONG)ArgArray + 4); //指针
	PSIZE_T RegionSize = *(ULONG*)((ULONG)ArgArray + 0xC);    //指针
	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	//2、GetProcessPid
	Status = Safe_ZwQueryInformationProcess(In_ProcessHandle, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
	if (NT_SUCCESS(Status))
	{
		//判断参数合法性
		if (myProbeRead(In_pBaseAddress, sizeof(PVOID), sizeof(CHAR)) && myProbeRead(RegionSize, sizeof(ULONG), sizeof(CHAR)))
		{
			KdPrint(("ProbeRead(After_ZwAllocateVirtualMemory_Func：In_pBaseAddress、RegionSize) error \r\n"));
			return result;
		}
		//保存进程分配的内存信息
		if (!Safe_InsertVirtualMemoryDataList(*(PVOID*)In_pBaseAddress, *(ULONG*)RegionSize, PBI.UniqueProcessId, PsGetCurrentProcessId()))
		{
			//添加失败：将参数清零，并返回错误值
			if (g_HighgVersionFlag)
			{
				ZwFreeVirtualMemory(In_ProcessHandle, &In_pBaseAddress, &RegionSize, MEM_RELEASE);
			}
			else
			{
				NtFreeVirtualMemory(In_ProcessHandle, &In_pBaseAddress, &RegionSize, MEM_RELEASE);
			}
			*(PVOID*)In_pBaseAddress = 0;
			*(ULONG*)RegionSize = 0;
			result = STATUS_ACCESS_DENIED;
		}
	}

	return result;
}


//分配内存
NTSTATUS NTAPI Fake_ZwAllocateVirtualMemory(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	BOOLEAN        Flag = FALSE;
	//0、获取ZwAllocateVirtualMemory原始函数
	HANDLE In_ProcessHandle = *(ULONG*)((ULONG)ArgArray);
	//1、必须是应用层调用
	if (ExGetPreviousMode())                 
	{
		//若句柄值!=当前进程的句柄（-1），特殊处理
		if (In_ProcessHandle != NtCurrentProcess())
		{
			//自身非白名单进程
			if (!Safe_QueryWhitePID(PsGetCurrentProcessId()))
			{
				//判断要打开的是不是保护进程,是继续判断，不是直接成功退出
				if (Safe_QueryWintePID_ProcessHandle(In_ProcessHandle))	
				{
					if (!Safe_QuerySystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_CSRSS_EXE))
					{
						if (!Safe_QuerySystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_DLLHOST_EXE))
						{
							if (!Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_CSRSS_EXE, g_VersionFlag))
							{
								if (!Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_DLLHOST_EXE, g_VersionFlag))
								{
									if (g_Win2K_XP_2003_Flag)
									{
										Flag = TRUE;
									}
									//进程线程个数等于1时候（刚创建时候就满足）
									//注入保护进程的在这里就已经GG了，因为跑起来的进程的线程个数不可能等于1
									result = Safe_FindEprocessThreadCount(In_ProcessHandle, Flag);
									if (!result)
									{
										result = STATUS_ACCESS_DENIED;
										return result;
									}
									*(ULONG*)ret_func = After_ZwAllocateVirtualMemory_Func;
									*(ULONG*)ret_arg = 0;
								}
							}
						}
					}
				}
			}
		}
	}
	return result;
}