#include "WhiteList.h"

//判断是不是白名单进程
//1：如果是：将白名单进程信息从数组中抹除
//2、如果不是：直接退出
BOOLEAN Safe_DeleteWhiteList_PID(_In_ HANDLE ProcessId)
{
	KIRQL NewIrql;
	ULONG Index = 0;						//下标索引
	NewIrql = KfAcquireSpinLock(&g_White_List.SpinLock);
	//判断白名单个数
	if (g_White_List.WhiteListNumber)
	{
		for (ULONG Index = 0; Index < g_White_List.WhiteListNumber; Index++)
		{
			//判断句柄合法性（句柄是4的倍数）
			//0x00,0x04,0x08,0x10,0x14等等的二进制既然低2位永远为0，那么微软就利用了这两位做一个标志位，用来指示当前句柄值所代表的内核对象到那个表项数组中找到。
			if ((((ULONG)ProcessId | 3) ^ 3) == ((g_White_List.WhiteListPID[Index] | 3) ^ 3))
			{
				//清空退出进程的信息(后一个往前挪)
				for (ULONG i = Index; i <= g_White_List.WhiteListNumber; i++)
				{
					g_White_List.WhiteListPID[i] = g_White_List.WhiteListPID[i + 1];			//进程PID
					g_White_List.SafeModIndex[i] = g_White_List.SafeModIndex[i + 1];			//未知
				}
				//保护进程个数-1
				--g_White_List.WhiteListNumber;
				break;
			}
		}
	}
	KfReleaseSpinLock(&g_White_List.SpinLock, NewIrql);
	return TRUE;
}

//根据ProcessId和SessionId删除
//1：如果是：将白名单进程信息从数组中抹除
//2、如果不是：直接退出
BOOLEAN Safe_DeleteWhiteList_PID_SessionId(_In_ HANDLE ProcessId)
{
	KIRQL NewIrql;
	ULONG Index = 0;						//下标索引
	NewIrql = KfAcquireSpinLock(&g_White_List.SpinLock);
	//判断白名单个数
	if (g_White_List.WhiteListNumber)
	{
		for (ULONG Index = 0; Index < g_White_List.WhiteListNumber; Index++)
		{
			//判断句柄合法性（句柄是4的倍数）
			//0x00,0x04,0x08,0x10,0x14等等的二进制既然低2位永远为0，那么微软就利用了这两位做一个标志位，用来指示当前句柄值所代表的内核对象到那个表项数组中找到。
			if (((((ULONG)ProcessId | 3) ^ 3) == ((g_White_List.WhiteListPID[Index] | 3) ^ 3)) && g_White_List.SafeModIndex[Index])
			{
				//清空退出进程的信息(后一个往前挪)
				for (ULONG i = Index; i <= g_White_List.WhiteListNumber; i++)
				{
					g_White_List.WhiteListPID[i] = g_White_List.WhiteListPID[i + 1];			//进程PID
					g_White_List.SafeModIndex[i] = g_White_List.SafeModIndex[i + 1];	//未知
				}
				//保护进程个数-1
				--g_White_List.WhiteListNumber;
				break;
			}
		}
	}
	KfReleaseSpinLock(&g_White_List.SpinLock, NewIrql);
	return TRUE;
}


//根据SessionId删除
//1：如果是：将白名单进程信息从数组中抹除
//2、如果不是：直接退出
BOOLEAN Safe_DeleteWhiteList_SessionId(_In_ HANDLE SessionId)
{
	KIRQL NewIrql;
	ULONG Index = 0;						//下标索引
	NewIrql = KfAcquireSpinLock(&g_White_List.SpinLock);
	//判断白名单个数
	if (g_White_List.WhiteListNumber)
	{
		for (ULONG Index = 0; Index < g_White_List.WhiteListNumber; Index++)
		{
			
			if ((ULONG)SessionId == g_White_List.SafeModIndex[Index])
			{
				//清空退出进程的信息(后一个往前挪)
				for (ULONG i = Index; i <= g_White_List.WhiteListNumber; i++)
				{
					g_White_List.WhiteListPID[i] = g_White_List.WhiteListPID[i + 1];			//进程PID
					g_White_List.SafeModIndex[i] = g_White_List.SafeModIndex[i + 1];		    //未知
				}
				//保护进程个数-1
				--g_White_List.WhiteListNumber;
				break;
			}
		}
	}
	KfReleaseSpinLock(&g_White_List.SpinLock, NewIrql);
	return TRUE;
}

//Win2K
// 添加白名单进程信息
// 成功返回1，失败返回0
BOOLEAN  Safe_InsertWhiteList_PID_Win2003(_In_ HANDLE ProcessId, _In_ ULONG SafeModIndex)
{
	PEPROCESS	ProcObject;
	KIRQL NewIrql;
	ULONG Index = 0;						//下标索引
	UCHAR ImageFileNameBuff[0x256] = { 0 };
	NTSTATUS	status,result;
	result = TRUE;							//默认返回值
	status = PsLookupProcessByProcessId(ProcessId, &ProcObject);
	if (NT_SUCCESS(status))
	{
		Safe_PsGetProcessImageFileName(ProcObject, &ImageFileNameBuff, sizeof(ImageFileNameBuff));
		if (!_stricmp(&ImageFileNameBuff, "360Safeup.exe") || !_stricmp(&ImageFileNameBuff, "Safeboxup.exe"))
		{
			SafeModIndex = 0;
		}
		ObfDereferenceObject(ProcObject);
	}
	NewIrql = KfAcquireSpinLock(&g_White_List.SpinLock);
	//判断白名单个数
	if (g_White_List.WhiteListNumber)
	{
		//1、新增插入  白名单个数+1，成功返回TRUE（个数<=0xFE），失败FALSE（个数>0xFE）
		//2、已存在    无视，默认返回TRUE（成功）
		while ((((ULONG)ProcessId | 3) ^ 3) != ((g_White_List.WhiteListPID[Index] | 3) ^ 3))
		{
			//假设是新的白名单信息就插入
			if (++Index >= g_White_List.WhiteListNumber)
			{
				//白名单进程个数<=0xFE
				if (g_White_List.WhiteListNumber <= WHITELISTNUMBER)
				{
					g_White_List.WhiteListPID[g_White_List.WhiteListNumber] = ProcessId;
					g_White_List.SafeModIndex[g_White_List.WhiteListNumber] = SafeModIndex;		//保存SafeMon,查找该dos路径在列表第几项，ret_arg = 返回数组下标
					//白名单个数自增1
					g_White_List.WhiteListNumber++;
					//成功返回
					result = TRUE;
					break;
				}
				else
				{
					//失败返回
					result = FALSE;
					break;
				}
			}
		}
	}
	KfReleaseSpinLock(&g_White_List.SpinLock, NewIrql);
	return result;
}


// 添加白名单进程信息
// 成功返回1，失败返回0
BOOLEAN  Safe_InsertWhiteList_PID(_In_ HANDLE ProcessId, _In_ ULONG SafeModIndex)
{
	KIRQL NewIrql;
	ULONG Index = 0;						//下标索引
	UCHAR ImageFileNameBuff[0x256] = { 0 };
	NTSTATUS	status, result;
	ULONG GotoFalg;							//不想同goto设置的Falg
	GotoFalg = 1;
	NewIrql = KfAcquireSpinLock(&g_White_List.SpinLock);
	//判断白名单个数
	if (g_White_List.WhiteListNumber)
	{
		//1、新增插入  白名单个数+1，成功返回TRUE（个数<=0xFE），失败FALSE（个数>0xFE）
		while ((((ULONG)ProcessId | 3) ^ 3) != ((g_White_List.WhiteListPID[Index] | 3) ^ 3))
		{
			//假设是新的白名单信息就插入
			if (++Index >= g_White_List.WhiteListNumber)
			{
				//取消条件2
				GotoFalg = 0;
				//白名单进程个数<=0xFE
				if (g_White_List.WhiteListNumber <= WHITELISTNUMBER)
				{
					g_White_List.WhiteListPID[g_White_List.WhiteListNumber] = ProcessId;
					g_White_List.SafeModIndex[g_White_List.WhiteListNumber] = SafeModIndex;
					//白名单个数自增1
					g_White_List.WhiteListNumber++;
					//成功返回
					result = TRUE;
					break;
				}
				else
				{
					//失败返回
					result = FALSE;
					break;
				}
			}
		}
		//2、已存在    只添加SafeModIndex部分
		if (GotoFalg)
		{
			g_White_List.SafeModIndex[Index] = SafeModIndex;
			result = TRUE;
		}
	}
	KfReleaseSpinLock(&g_White_List.SpinLock, NewIrql);
	return result;
}

//判断是不是白名单_EPROCESS
//返回值：是1，不是0
BOOLEAN Safe_QueryWhiteEProcess(_In_ PEPROCESS Process)
{
	ULONG result;
	PEPROCESS	ProcObject;
	NTSTATUS	status;
	result = FALSE;
	//判断白名单个数
	if (g_White_List.WhiteListNumber)
	{
		for (ULONG Index = 0; Index < g_White_List.WhiteListNumber; Index++)
		{
			status = PsLookupProcessByProcessId(g_White_List.WhiteListPID[Index], &ProcObject);
			if (NT_SUCCESS(status))
			{
				ObfDereferenceObject(ProcObject);
				//判断Process是否跟白名单的相同
				if (Process == ProcObject)
				{
					result = TRUE;
					break;
				}

			}
		}
	}
	else
	{
		result = FALSE;
	}
	return result;
}


//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWhitePID(_In_ HANDLE ProcessId)
{
	ULONG result;
	PEPROCESS	ProcObject;
	result = FALSE;
	//判断白名单个数
	if (g_White_List.WhiteListNumber)
	{
		for (ULONG Index = 0; Index < g_White_List.WhiteListNumber; Index++)
		{
			//判断是不是白名单进程
			if ((((ULONG)ProcessId | 3) ^ 3) == ((g_White_List.WhiteListPID[Index] | 3) ^ 3))
			{
				//如果是返回TRUE
				result = TRUE;
				break;
			}
		}
	}
	else
	{
		result = FALSE;
	}
	return result;
}


//函数功能：
//判断特殊白名单进程SessionId是否等于当前进程的SessionId
//返回值：
//返回值：是1，不是0
BOOLEAN Safe_QuerySpecialWhiteSessionId()
{
	ULONG SelfSessionId, SpecialWhiteSessionId;
	PVOID pSessionIDAddress = 0xFFDF02D8;	//Win10_14393以下版本一个固定地址可以获取到SessionId
	KIRQL NewIrql;
	ULONG result;
	ULONG Index = 0;						//下标索引
	//WINDOWS_VERSION_2K
	if (g_VersionFlag == WINDOWS_VERSION_2K)
	{
		result = TRUE;
		return result;
	}
	//Win10_14393以上获取方式
	if (g_dynData->pRtlGetActiveConsoleId_Win10_14393)     
	{
		SelfSessionId = g_dynData->pRtlGetActiveConsoleId_Win10_14393();		//获取自身SessionId
	}
	else
	{
		if (!MmIsAddressValid(pSessionIDAddress))
		{
			result = TRUE;
			return result;
		}
		SelfSessionId = *(ULONG*)pSessionIDAddress;								//获取自身SessionId
	}
	//上锁操作
	NewIrql = KfAcquireSpinLock(&g_SpecialWhite_List.SpinLock);
	//判断特殊白名单个数
	if (g_SpecialWhite_List.SpecialWhiteListNumber)
	{
		for (ULONG Index = 0; Index < g_SpecialWhite_List.SpecialWhiteListNumber; Index++)
		{
			SpecialWhiteSessionId = g_SpecialWhite_List.SpecialWhiteListSessionId;
			if (SelfSessionId == SpecialWhiteSessionId || SpecialWhiteSessionId == SPECIALSIGN)
			{
				result = TRUE;
				break;
			}
		}
	}
	else
	{
		result = FALSE;
	}
	//解锁操作
	KfReleaseSpinLock(&g_SpecialWhite_List.SpinLock, NewIrql);
	return result;
}

//Eprocess_UniqueProcessId
//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWhitePID_PsGetProcessId(IN PEPROCESS pPeprocess)
{
	BOOLEAN        Result = FALSE;
	HANDLE         ProcessId = NULL;
	ProcessId = Safe_pPsGetProcessId(pPeprocess);
	if (ProcessId)
	{
		Result = Safe_QueryWhitePID(ProcessId);
	}
	return Result;
}

//根据ProcessHandle转换成Eprocess，然后调用Safe_QueryWhitePID_PsGetProcessId
//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWintePID_ProcessHandle(IN HANDLE ProcessHandle)
{
	NTSTATUS       Status;
	BOOLEAN        Result = FALSE;
	Status = STATUS_SUCCESS;
	PEPROCESS pPeprocess = NULL;
	if (ProcessHandle && (Status = ObReferenceObjectByHandle(ProcessHandle, NULL, PsProcessType, UserMode, &pPeprocess, NULL), NT_SUCCESS(Status)))
	{
		Result = Safe_QueryWhitePID_PsGetProcessId(pPeprocess);
		ObfDereferenceObject((PVOID)pPeprocess);
	}
	else
	{
		Result = FALSE;
	}
	return Result;
}

//根据ThreadHandle获取当前进程PID
BOOLEAN  Safe_QueryWhitePID_PsGetThreadProcessId(PVOID VirtualAddress)
{
	BOOLEAN        Result = FALSE;
	HANDLE         ProcessId = NULL;
	if (!MmIsAddressValid(VirtualAddress))
	{
		return Result;
	}
	//只有win2K才会有，应该是ETHREAD某个偏移
	if (g_dynData->Eprocess_Offset.dword_34DF4)
	{
		if (!MmIsAddressValid((CHAR *)VirtualAddress + g_dynData->Eprocess_Offset.dword_34DF4))
		{
			return Result;
		}
		Result = Safe_QueryWhitePID_PsGetProcessId(*(PVOID *)((CHAR *)VirtualAddress + g_dynData->Eprocess_Offset.dword_34DF4));
	}
	else
	{
		ProcessId = g_dynData->pPsGetThreadProcessId(VirtualAddress);
		Result = Safe_QueryWhitePID(ProcessId);
	}
	return Result;
}

//根据线程句柄获取PID，然后判断PID是否是保护进程
//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWintePID_ThreadHandle(IN HANDLE ThreadHandle)
{
	NTSTATUS       Status;
	BOOLEAN        Result = FALSE;
	Status = STATUS_SUCCESS;
	PETHREAD ThreadObject = NULL;
	if (ThreadHandle && (Status = ObReferenceObjectByHandle(ThreadHandle, NULL, PsThreadType, UserMode, &ThreadObject, NULL), NT_SUCCESS(Status)))
	{
		Result = Safe_QueryWhitePID_PsGetThreadProcessId(ThreadObject);
		ObfDereferenceObject((PVOID)ThreadObject);
	}
	else
	{
		Result = FALSE;
	}
	return Result;
}