#include "Fake_ZwOpenThread.h"

//打开线程
//原函数执行后检查
//当打开到保护线程的句柄，直接把句柄清零并且返回错误值
NTSTATUS NTAPI After_ZwOpenThread_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	//0、获取ZwOpenThread原始参数
	PHANDLE ThreadHandle = *(ULONG*)((ULONG)ArgArray);			//输出句柄结果
	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	//检查地址合法性
	if (myProbeRead(ThreadHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(After_ZwOpenThread_Func：ThreadHandle) error \r\n"));
		return result;
	}
	//防止打开受保护线程
	if (Safe_QueryWintePID_ThreadHandle(*(HANDLE*)ThreadHandle))
	{
		//保护线程直接句柄清零，禁止访问
		Safe_ZwNtClose(*(HANDLE*)ThreadHandle, g_VersionFlag);
		*(HANDLE*)ThreadHandle = 0;
		result = STATUS_ACCESS_DENIED;
	}
	return result;
}

//打开线程
NTSTATUS NTAPI Fake_ZwOpenThread(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	ACCESS_MASK    DesiredAccess_Flag =														   //0x520D00B7
		(GENERIC_WRITE | GENERIC_ALL) |                                                        //0x50000000 = GENERIC_WRITE | GENERIC_ALL
		(MAXIMUM_ALLOWED) |                                                                    //0x02000000 = MAXIMUM_ALLOWED
		(WRITE_OWNER | WRITE_DAC | DELETE) |   	                                               //0x000D0000 = WRITE_OWNER | WRITE_DAC | DELETE
		(THREAD_SET_THREAD_TOKEN | THREAD_SET_INFORMATION | THREAD_SET_CONTEXT) |			   //0x000000B0 = THREAD_SET_THREAD_TOKEN | THREAD_SET_INFORMATION | THREAD_SET_CONTEXT															   //0x000000B0 = 
		(THREAD_SUSPEND_RESUME | THREAD_ALERT | THREAD_TERMINATE);							   //0x00000007 = THREAD_SUSPEND_RESUME | THREAD_ALERT | THREAD_TERMINATE

	//0、获取ZwOpenThread原始参数
	ACCESS_MASK	   In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//检查高权限操作的
		if (In_DesiredAccess & DesiredAccess_Flag)
		{
			//调用者非保护进程，需要二次判断
			if (!Safe_QueryWhitePID(PsGetCurrentProcessId()))
			{
				if (!g_Win2K_XP_2003_Flag || (!Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_CSRSS_EXE, g_VersionFlag)))
				{
					*(ULONG*)ret_func = After_ZwOpenThread_Func;
				}
			}
		}
	}
	return result;
}