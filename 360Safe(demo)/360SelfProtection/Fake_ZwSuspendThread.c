#include "Fake_ZwSuspendThread.h"


//线程挂起
NTSTATUS NTAPI Fake_ZwSuspendThread(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    result;
	result = STATUS_SUCCESS;
	//0、获取ZwSuspendProcess原始参数
	IN HANDLE   In_ThreadHandle = *(ULONG*)((ULONG)ArgArray);
	//1、内核模式、自身是保护进程直接放行
	if (!ExGetPreviousMode() || (Safe_QueryWhitePID(PsGetCurrentProcessId())))
	{
		result = STATUS_SUCCESS;
	}
	else
	{
		//2、用户模式
		//2、1检查参数
		if (myProbeRead(In_ThreadHandle, sizeof(ULONG), sizeof(CHAR)))
		{
			KdPrint(("ProbeRead(Fake_ZwSuspendThread：In_ThreadHandle) error \r\n"));
			return result;
		}
		//根据线程获取PID
		//假设是打开保护进程直接返回错误值
		result = Safe_QueryWintePID_ThreadHandle(In_ThreadHandle) != 0 ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
	}
	return result;
}

