#include "Fake_ZwTerminateProcess.h"

//结束进程
NTSTATUS NTAPI Fake_ZwTerminateProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	ACCESS_MASK    Out_GrantedAccess = NULL;
	ULONG          ReturnLength = NULL;
	PEPROCESS      pPeprocess = NULL;
	BOOLEAN        ObfDereferenceObjectFlag = FALSE;		//真调用ObfDereferenceObject  假则不需要
	PROCESS_BASIC_INFORMATION ProcessInfo = { 0 };
	//0、获取ZwTerminateProcess原始函数
	HANDLE   In_ProcessHandle = *(ULONG*)((ULONG)ArgArray);
	NTSTATUS In_ExitStatus = *(ULONG*)((ULONG)ArgArray + 4);
	//第一种R3调用ZwTerminateProcess结束保护进程的防御措施
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//2、获取要结束进程的句柄权限
		Status = Safe_GetGrantedAccess(In_ProcessHandle, &Out_GrantedAccess);
		//3、被结束进程不包含PROCESS_TERMINATE权限
		if (NT_SUCCESS(Status) && !(Out_GrantedAccess & PROCESS_TERMINATE))
		{
			//3、1 结束目标句柄是：保护进程     需要进一步判断，非保护进程无视
			if (Safe_QueryWintePID_ProcessHandle(In_ProcessHandle))
			{
				//3、2 判断调用者是不是保护进程：
				//非保护进程调用拦截
				//保护进程调用放行
				if (!Safe_QueryWhitePID(PsGetCurrentProcessId()))
				{
					ULONG uGetCurrentProcessId = PsGetCurrentProcessId();
					ULONG uUniqueProcessId = Safe_GetUniqueProcessId(In_ProcessHandle);
					//3、3 判断是否用Dos命令结束进程，如果是获取父进程PID
					//taskkill /f /im PID 这个命令来杀掉这个进程
					if (Safe_CmpImageFileName("taskkill.exe"))
					{
						//3、4 获取进程信息
						Status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, (PVOID)&ProcessInfo, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
						if (NT_SUCCESS(Status))
						{
							//获取父进程的PID
							uGetCurrentProcessId = ProcessInfo.InheritedFromUniqueProcessId;
						}
					}
					//触发拦截还是放行
					//sub_188E8(uGetCurrentProcessId, PsGetCurrentThreadId(),uUniqueProcessId);
					result = STATUS_ACCESS_DENIED;
					return result;
				}
			}
		}
	}
	//第二种由csrss.exe进程结束保护进程防范措施，高版本
	if (!Safe_QueryWhitePID(PsGetCurrentProcessId()) &&	   //调用者非保护进程
		Safe_CmpImageFileName("csrss.exe") &&			   //调用者是csrss.exe进程
		g_Win2K_XP_2003_Flag			   &&			   //高版本(非Win2K、Xp、2003)
		!In_ExitStatus					   &&			   //这个有撒含义？？？？？？
		Safe_QueryWintePID_ProcessHandle(In_ProcessHandle) //结束的目标是保护进程
		)
	{
		result = STATUS_ACCESS_DENIED;
		return result;
	}
	//第三种正常流程的
	if ((In_ProcessHandle != NtCurrentProcess()) ||			//非自身
		(KeGetCurrentIrql() == APC_LEVEL) ||				//IRQL中断等级
		(!Safe_QueryWhitePID_PsGetThreadProcessId(KeGetCurrentThread()))	//调用者非保护进程
		)
	{
		//4、判断In_ProcessHandle ==0 and In_ProcessHandle != 当前进程
		if (In_ProcessHandle && In_ProcessHandle != NtCurrentProcess())
		{
			//4、1 句柄非Process类型退出
			if (!Safe_QueryObjectType(In_ProcessHandle, L"Process"))
			{
				result = STATUS_SUCCESS;
				return result;
			}
			//4、2 获取Eprocess结构
			//注意ObReferenceObjectByHandle获取的Eprocess结构需要解引用
			Status = ObReferenceObjectByHandle(In_ProcessHandle, NULL, PsProcessType, ExGetPreviousMode(), &pPeprocess, 0);
			if (!NT_SUCCESS(Status))
			{
				//获取失败直接退出
				result = STATUS_SUCCESS;
				return result;
			}
			else
			{
				//表示ObReferenceObjectByHandle函数调用成功，后续需要释放
				ObfDereferenceObjectFlag = TRUE;
			}
		}
		else
		{
			//In_ProcessHandle == 0表示本进程除当前线程外的线程都给杀掉
			//注意IoGetCurrentProcess方式获取Eprocess结构不需要解引用
			pPeprocess = IoGetCurrentProcess();
			ObfDereferenceObjectFlag = FALSE;
		}
		//5、前面第一步不是已经过滤了吗？这里存在的意义有点疑惑，希望有大佬能解释下
		if (Safe_QueryWhitePID_PsGetProcessId(pPeprocess) &&			//保护进程
			(KeGetCurrentIrql() == APC_LEVEL ||							//IRQL中断等级
			!ExGetPreviousMode())										//R0调用
			)
		{
			//失败返回
			result = STATUS_ACCESS_DENIED;
		}
		else
		{
			//成功返回
			result = STATUS_SUCCESS;
		}
		//6、ObfDereferenceObjectFlag为真才需要释放，区别ObReferenceObjectByHandle or IoGetCurrentProcess方式获取的Eprocess结构
		if (ObfDereferenceObjectFlag)
		{
			ObfDereferenceObject(pPeprocess);
		}
	}
	return result;
}