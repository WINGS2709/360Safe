/*
说明：
傀儡进程就是使用ZwUnmapViewOfSection这个函数
*/
#include "Fake_ZwUnmapViewOfSection.h"

//取消映射目标进程的内存
NTSTATUS NTAPI Fake_ZwUnmapViewOfSection(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	PROCESS_BASIC_INFORMATION PBI = { 0 };
	ULONG ReturnLength = NULL;
	result = STATUS_SUCCESS;
	//0、获取ZwUnmapViewOfSection参数
	HANDLE In_ProcessHandle = *(ULONG*)((ULONG)ArgArray);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//假设是取消映射的是白名单进程直接错误返回，并通知用户拦截还是放行
		if ((In_ProcessHandle != NtCurrentProcess()) &&
			(!Safe_QueryWhitePID(PsGetCurrentProcessId())) &&			//判断是不是白名单调用，如果是放行 不是继续判断		
			(NT_SUCCESS(Safe_ZwQueryInformationProcess(In_ProcessHandle, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength))) &&	//获取进程PID
			Safe_QueryWhitePID(PBI.UniqueProcessId)						//判断要操作的PID是不是白名单，如果是拦截 不是放行
			)
		{
			//触发拦截还是放行
			Safe_18A72_SendR3(PsGetCurrentProcessId(), PsGetCurrentThreadId(), 2);
			//失败返回
			result = STATUS_ACCESS_DENIED;
		}
		else
		{
			result = STATUS_SUCCESS;
		}
	}
	return result;
}