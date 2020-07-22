#include "Fake_ZwOpenMutant.h"

//打开互斥体 防多开
//原函数执行后检查
//禁止打开指定互斥体
NTSTATUS NTAPI After_ZwOpenMutant_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	CHAR		   ObjectInformation[0x500] = { 0 };
	ULONG          ReturnLength = NULL;
	UNICODE_STRING Q360dsmainmuteString = { 0 };
	PPUBLIC_OBJECT_TYPE_INFORMATION	pPubObjTypeInfo = NULL;
	RtlInitUnicodeString(&Q360dsmainmuteString, L"Q360dsmainmute");
	//0、获取ZwOpenMutant原始参数
	PHANDLE        In_MutantHandle = *(ULONG*)((ULONG)ArgArray);
	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	//检查地址合法性
	if (myProbeRead(In_MutantHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(After_ZwOpenMutant_Func：In_MutantHandle) error \r\n"));
		return result;
	}
	Status = Safe_UserMode_ZwQueryObject(g_HighgVersionFlag, *(HANDLE*)In_MutantHandle, ObjectNameInformation, ObjectInformation, sizeof(ObjectInformation), &ReturnLength);
	pPubObjTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)ObjectInformation;
	if (NT_SUCCESS(Status) && pPubObjTypeInfo->TypeName.Length)
	{
		//防多开，防止打开指定互斥体
		if (RtlEqualUnicodeString(&pPubObjTypeInfo->TypeName, &Q360dsmainmuteString, TRUE))
		{
			//句柄清零，禁止访问
			Safe_ZwNtClose(*(HANDLE*)In_MutantHandle, g_VersionFlag);
			*(HANDLE*)In_MutantHandle = 0;
			//Safe_18A72_SendR3(PsGetCurrentProcessId(), PsGetCurrentThreadId(),0xF);
			result = STATUS_ACCESS_DENIED;
		}
	}
	
	return result;
}

//打开互斥体 防多开
NTSTATUS NTAPI Fake_ZwOpenMutant(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//调用者非保护进程，需要二次判断
		if (!Safe_QueryWhitePID(PsGetCurrentProcessId()))
		{
			*(ULONG*)ret_func = After_ZwOpenMutant_Func;
		}
	}
	return result;
}