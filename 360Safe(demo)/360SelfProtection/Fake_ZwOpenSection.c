/*
说明：
重点照顾对象叫做\\Device\\PhysicalMemory和\\KnownDlls\\
检查1：
访问\\Device\\PhysicalMemory直接句柄清零，错误返回
检查2：
访问\\KnownDlls\\
句柄copy成功，降权去除DELETE权限并与R3通讯，成功返回
句柄copy失败，句柄清零，错误返回
参考资料：
1、续PhysicalMemory攻击 						   
网址：https://bbs.pediy.com/thread-94203.htm
2、分析了一下360安全卫士的HOOK(二)——架构与实现   
网址：https://bbs.pediy.com/thread-99460.htm?source=1
*/
#include "Fake_ZwOpenSection.h"


//打开section object
//原函数执行后检查
NTSTATUS NTAPI After_ZwOpenSection_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	SIZE_T         PhysicalMemorySize = 0x16;					//\\Device\\PhysicalMemory字符串大小
	SIZE_T         KnownDllsSize = 0xB;						   //\\KnownDlls\\字符串大小
	CHAR		   ObjectInformation[0x500] = { 0 };
	ULONG          ReturnLength = NULL;
	HANDLE         TargetHandle = NULL;
	ACCESS_MASK    Out_GrantedAccess = NULL;
	PPUBLIC_OBJECT_TYPE_INFORMATION	pPubObjTypeInfo = NULL;
	//0、获取ZwOpenSection原始参数
	PHANDLE SectionHandle = *(ULONG*)((ULONG)ArgArray);			//输出句柄结果
	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	//检查地址合法性
	if (myProbeRead(SectionHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(After_ZwOpenSection_Func：SectionHandle) error \r\n"));
		return result;
	}
	//2、检查敏感路径
	Status = Safe_UserMode_ZwQueryObject(g_HighgVersionFlag, *(HANDLE*)SectionHandle, ObjectNameInformation, ObjectInformation, sizeof(ObjectInformation), &ReturnLength);
	pPubObjTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)ObjectInformation;
	if (!NT_SUCCESS(Status) ||
		!pPubObjTypeInfo->TypeName.Length
		)
	{
		return result;
	}
	//2、1 PhysicalMemory检查
	if (!_wcsnicmp(pPubObjTypeInfo->TypeName.Buffer, L"\\Device\\PhysicalMemory", PhysicalMemorySize))
	{
		//句柄清零，禁止访问
		Safe_ZwNtClose(*(HANDLE*)SectionHandle, g_VersionFlag);
		*(HANDLE*)SectionHandle = 0;
		//Safe_18A72_SendR3(PsGetCurrentProcessId(), PsGetCurrentThreadId(),0x8);
		result = STATUS_ACCESS_DENIED;
	}
	//2、2 KnownDlls检查
	else if (!_wcsnicmp(pPubObjTypeInfo->TypeName.Buffer, L"\\KnownDlls\\", KnownDllsSize))
	{
		//2、3 获取该句柄原始权限
		Status  = Safe_GetGrantedAccess(*(HANDLE*)SectionHandle, &Out_GrantedAccess);
		if (NT_SUCCESS(Status))
		{
			//2、4 拷贝句柄并且降权,删掉DELETE权限
			//0xFFFEFFFF = 16  DELETE  Delete access.
			Status = ZwDuplicateObject(
				NtCurrentProcess(),						//__in HANDLE SourceProcessHandle,
				*(HANDLE*)SectionHandle,				//__in HANDLE SourceHandle,
				NtCurrentProcess(),						//__in_opt HANDLE TargetProcessHandle,
				&TargetHandle,							//__out_opt PHANDLE TargetHandle,
				Out_GrantedAccess,						//__in ACCESS_MASK DesiredAccess,
				NULL,									//__in ULONG HandleAttributes,
				NULL									//__in ULONG Options
				);
			if (NT_SUCCESS(Status))
			{
				//替换掉阉割后的句柄
				Safe_ZwNtClose(*(HANDLE*)SectionHandle, g_VersionFlag);
				*(HANDLE*)SectionHandle = TargetHandle;
				//Safe_18A72_SendR3(PsGetCurrentProcessId(), PsGetCurrentThreadId(),0x9);
				result = STATUS_SUCCESS;
			}
			else
			{
				//拷贝不成功直接清除原始句柄
				Safe_ZwNtClose(*(HANDLE*)SectionHandle, g_VersionFlag);
				*(HANDLE*)SectionHandle = 0;
				result = STATUS_ACCESS_DENIED;
			}
		}
	}
	return result;
}

//打开section object
NTSTATUS NTAPI Fake_ZwOpenSection(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	//Section Access Rights
	ACCESS_MASK    DesiredAccess_Flag =														   //0x52010002
		(GENERIC_WRITE | GENERIC_ALL) |                                                        //0x50000000 = GENERIC_WRITE | GENERIC_ALL
		(MAXIMUM_ALLOWED) |                                                                    //0x02000000 = MAXIMUM_ALLOWED
		(DELETE) |   																		   //0x00010000 = DELETE
		(SECTION_MAP_WRITE);																   //0x00000002 = SECTION_MAP_WRITE
	
	//0、获取ZwOpenSection原始参数
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
				//触发调用后检查
				*(ULONG*)ret_func = After_ZwOpenSection_Func;
			}
		}
	}
	return result;
}