#include "Fake_ZwGetNextProcess.h"

//遍历进程
//原函数执行后检查
//当遍历到保护进程的句柄，直接把句柄清零并且返回错误值
NTSTATUS NTAPI After_ZwGetNextProcess_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	//0、获取ZwGetNextProcess原始参数
	PHANDLE NewProcessHandle = *(ULONG*)((ULONG)ArgArray + 0x10);			//输出句柄结果
	//1、原函数正常执行 and 遍历到保护进程
	if (NT_SUCCESS(InResult) && Safe_QueryWintePID_ProcessHandle(*(HANDLE*)NewProcessHandle))
	{
		//保护进程直接句柄清零，禁止访问
		Safe_ZwNtClose(*(HANDLE*)NewProcessHandle, g_VersionFlag);
		*(HANDLE*)NewProcessHandle = 0;
		result = STATUS_ACCESS_DENIED;
	}
	else
	{
		result = STATUS_SUCCESS;
	}
	return result;
}
//遍历进程
NTSTATUS NTAPI Fake_ZwGetNextProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	ACCESS_MASK    DesiredAccess_Flag =															   //0x720D0BAF
		(GENERIC_WRITE | GENERIC_ALL | GENERIC_EXECUTE) |										   //0x70000000 = GENERIC_WRITE | GENERIC_ALL | GENERIC_EXECUTE
		(MAXIMUM_ALLOWED) |                                                                        //0x02000000 = MAXIMUM_ALLOWED
		(WRITE_OWNER | WRITE_DAC | DELETE) |   	                                                   //0x000D0000 = WRITE_OWNER | WRITE_DAC | DELETE
		(PROCESS_SUSPEND_RESUME | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION) |                   //0x00000B00 = PROCESS_SUSPEND_RESUME | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION
		(PROCESS_CREATE_PROCESS | PROCESS_VM_WRITE) |							                   //0x000000A0 = PROCESS_CREATE_PROCESS(Required to create a process) | PROCESS_VM_WRITE(WriteProcessMemory)
		(PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION);//0x0000000F = PROCESS_TERMINATE |PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION			

	//0、获取ZwGetNextProcess原始参数
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
				*(ULONG*)ret_func = After_ZwGetNextProcess_Func;
			}
		}
	}
	return result;
}