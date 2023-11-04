/*
说明：
主要拦截注册表注入
核心：
1、拦截HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion \Windows\AppInit_DLLs（注册表注入，详情参考资料1）
2、拦截\\SHELLEXECUTEHOOKS（自启动）
3、拦截\\SAFER\\CODEIDENTIFIERS（软件限制策略，平时没接触过属于知识盲区，详情参考资料2）
如果是以上几种行为直接拦截，将句柄清零，并返回STATUS_ACCESS_DENIED
参考资料：
1、几种常见的注入姿势
网址：https://bbs.pediy.com/thread-227075.htm
2、Determine Allow-Deny List and Application Inventory for Software Restriction Policies
网址：https://docs.microsoft.com/en-us/windows-server/identity/software-restriction-policies/determine-allow-deny-list-and-application-inventory-for-software-restriction-policies
*/
#include "Fake_ZwOpenKey.h"


//************************************     
// 函数名称: After_ZwOpenKey_Func     
// 函数说明：原始函数执行后检查，拦截注册表注入 
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
NTSTATUS NTAPI After_ZwOpenKey_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS  Status, result;
	PEPROCESS pPeprocess = NULL;
	HANDLE   Object = NULL;
	POBJECT_NAME_INFORMATION pFileNameInfo = NULL;
	ULONG NumberOfBytes = 0x1024;
	ULONG ReturnLength = NULL;
	ULONG Tag = 0x206B6444u;
	BOOLEAN ErrorFlag = TRUE;				//成功1，失败0
	result = STATUS_SUCCESS;
	//0、获取ZwOpenKey原始参数
	PHANDLE   In_KeyHandle = *(ULONG*)((ULONG)ArgArray);
	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	//检查地址合法性
	if (myProbeRead(In_KeyHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(After_ZwOpenKey_Func：In_KeyHandle) error \r\n"));
		return result;
	}
	Status = ObReferenceObjectByHandle(*(ULONG*)In_KeyHandle, 0, 0, UserMode, &Object, 0);
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	pFileNameInfo = (POBJECT_NAME_INFORMATION)Safe_AllocBuff(NonPagedPool, NumberOfBytes, Tag);
	if (!pFileNameInfo)
	{
		ObfDereferenceObject(Object);
		return result;
	}
	//2、驱动层通过注册表_OBJECT指针查询注册表路径ObQueryNameString
	Status = ObQueryNameString(Object, pFileNameInfo, NumberOfBytes, &ReturnLength);
	//解引用
	ObfDereferenceObject(Object);
	if (!NT_SUCCESS(Status) || !pFileNameInfo->Name.Buffer || !pFileNameInfo->Name.Length)
	{
		ExFreePool(pFileNameInfo);
		return result;
	}
	//3、判断各种违规路径
	// 自启动
	if (wcsstr(pFileNameInfo->Name.Buffer, L"\\SHELLEXECUTEHOOKS"))
	{
		//自启动
		ErrorFlag = FALSE;
		result = STATUS_ACCESS_DENIED;
	}
	//利用AppCertDlls注册表，将HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls下写入dll的路径，可以将此注册表项下的DLL加载到调用CreateProcess，CreateProcessAsUser，CreateProcessWithLogonW，CreateProcessWithTokenW和WinExec的每个进程中。值得注意的是win xp - win 10 默认不存在这个注册表项
	else if (wcsstr(pFileNameInfo->Name.Buffer, L"CONTROL\\SESSION MANAGER\\APPCERTDLLS"))
	{
		 //AppCertDlls注入
		ErrorFlag = FALSE;
		result = STATUS_OBJECT_NAME_NOT_FOUND;
	}
	//软件限制策略（平时没关注过）
	else if (wcsstr(pFileNameInfo->Name.Buffer, L"\\SAFER\\CODEIDENTIFIERS"))
	{
		//软件限制策略
		ErrorFlag = FALSE;
		result = STATUS_ACCESS_DENIED;
	}
	else
	{
		//合法返回
		ErrorFlag = TRUE;
		result = STATUS_SUCCESS;
	}
	//失败返回要清空句柄
	if (!ErrorFlag)
	{
		Safe_ZwNtClose(*(ULONG*)In_KeyHandle, g_VersionFlag);
		*(ULONG*)In_KeyHandle = 0;
	}
	//释放nre空间
	ExFreePool(pFileNameInfo);
	pFileNameInfo = NULL;
	return result;
}

//打开注册表键值
NTSTATUS NTAPI Fake_ZwOpenKey(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	result = STATUS_SUCCESS;
	//0、获取ZwOpenKey的原始参数
	ACCESS_MASK    DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//2、高权限启动函数执行后检查
		if (KEY_READ == DesiredAccess || MAXIMUM_ALLOWED == DesiredAccess)
		{
			//判断是不是保护进程，是返回：1  不是返回0
			if (Safe_QueryWhitePID(PsGetCurrentProcessId()))
			{
				//3、启动调用后检查
				*(ULONG*)ret_func = After_ZwOpenKey_Func;
			}
		}
	}
	return result;
}
