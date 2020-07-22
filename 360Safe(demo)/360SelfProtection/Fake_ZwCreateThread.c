#include "Fake_ZwCreateThread.h"

//看不懂的函数
//WINDOWS_VERSION_XP与Win2K生效
BOOLEAN NTAPI Safe_19AFC(IN HANDLE In_ProcessHandle, IN ULONG In_Eip, IN ULONG In_Eax, IN ULONG In_Esp, IN ULONG In_ExpandableStackBottom, IN ULONG In_ExpandableStackSize)
{

	BOOLEAN		   result = TRUE;
	NTSTATUS	   Status = STATUS_SUCCESS;
	PEPROCESS      pPeprocess = NULL;
	HANDLE		   SectionHandle = NULL;
	HANDLE		   Out_SectionHandle = NULL;
	KAPC_STATE 	   ApcState;
	ULONG          ResultLength = NULL;
	ULONG          UniqueProcessId = NULL;
	PVOID          SectionObject = NULL;
	ULONG          WinXP_EPROCESS_SectionObjectIndex = 0x138;    //+0x138 SectionObject
	ULONG          WinXP_EPROCESS_UniqueProcessIdIndex = 0x84;   //+0x84  void *UniqueProcessId
	ULONG          Win2k_EPROCESS_SectionHandleIndex = 0x1AC;    //+1xac  void *SectionHandle
	ULONG          Win2k_EPROCESS_UniqueProcessIdIndex = 0x9C;   //+0x9c  void *UniqueProcessId
	SECTION_IMAGE_INFORMATION ImageInformation = { 0 };
	Status = ObReferenceObjectByHandle(In_ProcessHandle, NULL, PsProcessType, UserMode, &pPeprocess, 0);
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	//1、根据版本获取:Win2K
	if (g_VersionFlag == WINDOWS_VERSION_2K)
	{
		//获取Section句柄
		SectionHandle = *(HANDLE*)((ULONG)pPeprocess + Win2k_EPROCESS_SectionHandleIndex);
		//获取PID
		UniqueProcessId = *(HANDLE*)((ULONG)pPeprocess + Win2k_EPROCESS_UniqueProcessIdIndex);
		//附加
		KeStackAttachProcess(In_ProcessHandle, &ApcState);
		Status = ZwQuerySection(SectionHandle, SectionImageInformation, &ImageInformation, sizeof(SECTION_IMAGE_INFORMATION), &ResultLength);
		//解除附加
		KeUnstackDetachProcess(&ApcState);
		if (!NT_SUCCESS(Status))
		{
			goto _FunctionRet;
		}
	}
	//1、1 根据版本获取:WINDOWS_VERSION_XP
	else if (g_VersionFlag == WINDOWS_VERSION_XP)
	{
		SectionObject = *(PVOID*)((ULONG)pPeprocess + WinXP_EPROCESS_SectionObjectIndex);
		//附加
		KeStackAttachProcess(In_ProcessHandle, &ApcState);
		Status = ObOpenObjectByPointer(SectionObject, NULL, NULL, 1, MmSectionObjectType, KernelMode, &Out_SectionHandle);
		//判断函数返回值
		if (!NT_SUCCESS(Status))
		{
			//解除附加
			KeUnstackDetachProcess(&ApcState);
			goto _FunctionRet;
		}
		Status = ZwQuerySection(Out_SectionHandle, SectionImageInformation, &ImageInformation, sizeof(SECTION_IMAGE_INFORMATION), &ResultLength);
		//解除附加
		KeUnstackDetachProcess(&ApcState);
		//判断函数返回值
		if (!NT_SUCCESS(Status))
		{
			goto _FunctionRet;
		}
		//获取PID
		UniqueProcessId = *(HANDLE*)((ULONG)pPeprocess + WinXP_EPROCESS_UniqueProcessIdIndex);
	}
	//其他版本直接退出即可
	else
	{
		goto _FunctionRet;
	}
	//2、判断部分
	if (In_Eax == ImageInformation.TransferAddress && In_Eip == g_Thread_Information.ThreadContext_Eip)
	{
		if (In_ExpandableStackSize >= 0x100000)
		{
			In_ExpandableStackSize = 0x100000;
		}
		//删除指定内存数据
		Safe_DeleteVirtualMemoryDataList_XP_WIN2K(UniqueProcessId, PsGetCurrentProcessId(), In_Esp, In_ExpandableStackBottom, In_ExpandableStackSize);
	}
_FunctionRet:
	if (Out_SectionHandle)
	{
		ZwClose(Out_SectionHandle);
		Out_SectionHandle = NULL;
	}
	if (pPeprocess)
	{
		ObfDereferenceObject(pPeprocess);
		pPeprocess = NULL;
	}
	return result;
}
//创建线程
NTSTATUS NTAPI Fake_ZwCreateThread(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       Status = STATUS_SUCCESS;
	NTSTATUS       result = STATUS_SUCCESS;
	PEPROCESS      pPeprocess = NULL;
	ULONG          ReturnLength = NULL;
	ULONG          ExpandableStackBottom = NULL;
	ULONG          ExpandableStackSize = NULL;		 // ExpandableStackBase - ExpandableStackBottom	
	PROCESS_BASIC_INFORMATION ProcessInformation = { 0 };
	//0、获取ZwCreateThread原始参数
	PHANDLE     In_ThreadHandle = *(ULONG*)((ULONG)ArgArray);
	ACCESS_MASK In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	HANDLE       In_ProcessHandle = *(ULONG*)((ULONG)ArgArray + 0xC);
	PCLIENT_ID   In_PCLIENT_ID = *(ULONG*)((ULONG)ArgArray + 0x10);
	PCONTEXT     In_ThreadContext = *(ULONG*)((ULONG)ArgArray + 0x14);
	PUSER_STACK  In_UserStack = *(ULONG*)((ULONG)ArgArray + 0x18);
	//1、若句柄值!=当前进程的句柄（-1），特殊处理
	if (In_ProcessHandle == NtCurrentProcess())
	{
		return result;
	}
	//2、过滤条件
	if (Safe_QueryWhitePID(PsGetCurrentProcessId())						//保护进程调用直接退出
		|| !ExGetPreviousMode()											//用户模式调用直接退出
		|| !Safe_QueryObjectType(In_ProcessHandle, L"Process")			//句柄非Process类型退出
		|| ObReferenceObjectByHandle(In_ProcessHandle, 2u, PsProcessType, UserMode, &pPeprocess, 0) < 0)
	{
		return result;
	}
	if (pPeprocess != IoGetCurrentProcess())
	{
		ObfDereferenceObject(pPeprocess);
		return result;
	}
	//引用计数-1
	ObfDereferenceObject(pPeprocess);
	if (!Safe_CheckSysProcess_Csrss_Lsass(In_ProcessHandle) || Safe_FindEprocessThreadCount(In_ProcessHandle, 0))
	{
		//判断要目标进程是不是保护进程
		if (Safe_QueryWintePID_ProcessHandle(In_ProcessHandle))
		{
			//低版本
			if (!g_Win2K_XP_2003_Flag || Safe_FindEprocessThreadCount(In_ProcessHandle, 0))
			{
				//判断参数合法性
				if (myProbeRead(In_ThreadContext, sizeof(In_ThreadContext), 1) && myProbeRead(In_UserStack, sizeof(USER_STACK), 4))
				{
					KdPrint(("ProbeRead(Fake_ZwCreateThread：In_ThreadContext or In_UserStack) error \r\n"));
					return result;
				}
				ExpandableStackBottom = In_UserStack->ExpandableStackBottom;
				ExpandableStackSize = (ULONG)In_UserStack->ExpandableStackBase - ExpandableStackBottom;
				//获取EIP
				if (!g_Thread_Information.ThreadContext_Eip)
				{
					g_Thread_Information.ThreadContext_Eip = In_ThreadContext->Eip;
					return result;
				}
				//WINDOWS_VERSION_XP与Win2K生效
				if (Safe_19AFC(In_ProcessHandle, In_ThreadContext->Eip, In_ThreadContext->Eax, In_ThreadContext->Esp, ExpandableStackBottom, ExpandableStackSize))
				{
					return result;
				}
			}
			//通知用户层R3 拦截还是放行
			Safe_18A72_SendR3(PsGetCurrentProcessId(), PsGetCurrentThreadId(), 2);
			result = STATUS_ACCESS_DENIED;
		}
		return result;
	}
	//coherence.exe是什么鬼进程？？？？？ 平时没关注过有明白的老哥告诉下
	if (Safe_CheckSysProcess_Coherence())
	{
		//获取进程PID
		Status = Safe_ZwQueryInformationProcess(In_ProcessHandle, ProcessBasicInformation, &ProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
		if (NT_SUCCESS(Status))
		{
			g_Thread_Information.UniqueProcessId = ProcessInformation.UniqueProcessId;
		}
		return result;
	}
	result = STATUS_ACCESS_DENIED;
	return result;
}