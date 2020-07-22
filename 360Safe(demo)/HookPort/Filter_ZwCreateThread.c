#include "Filter_ZwCreateThread.h"

//线程创建
NTSTATUS NTAPI Filter_ZwCreateThread(OUT PHANDLE  ThreadHandle, IN ACCESS_MASK  DesiredAccess, IN POBJECT_ATTRIBUTES  ObjectAttributes, IN HANDLE  ProcessHandle, OUT PCLIENT_ID  ClientId, IN PCONTEXT  ThreadContext, IN PUSER_STACK  UserStack, IN BOOLEAN  CreateSuspended)
{
	NTSTATUS Result, OutResult;

	PULONG FuncTable[16] = { 0 };
	PULONG ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &ThreadHandle;//参数数组，指向栈中属于本函数的所有参数
	//KdPrint(("Filter_ZwCreateThread\t\n"));

	NTSTATUS(NTAPI *ZwCreateThreadPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PUSER_STACK, BOOLEAN);
	Result = HookPort_DoFilter(ZwCreateThread_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwCreateThreadPtr = HookPort_GetOriginalServiceRoutine(g_SSDT_Func_Index_Data.ZwCreateThreadIndex);

		//调用原始函数
		Result = ZwCreateThreadPtr(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, UserStack, CreateSuspended);
		if (NT_SUCCESS(Result))
		{
			//原始函数执行后检查
			Result = HookPort_ForRunFuncTable(ZwCreateThread_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;
}

//线程创建
NTSTATUS NTAPI Filter_ZwCreateThreadEx(OUT PHANDLE  ThreadHandle, IN ACCESS_MASK  DesiredAccess, IN POBJECT_ATTRIBUTES  ObjectAttributes, IN HANDLE  ProcessHandle, OUT PCLIENT_ID  ClientId, IN PCONTEXT  ThreadContext, IN PUSER_STACK  UserStack, IN BOOLEAN  CreateSuspended, IN PVOID  Arg9, IN PVOID  Arg10, IN PVOID  Arg11)
{
	NTSTATUS Result, OutResult;

	PULONG FuncTable[16] = { 0 };
	PULONG ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &ThreadHandle;//参数数组，指向栈中属于本函数的所有参数
	KdPrint(("Filter_ZwCreateThreadEx\t\n"));

	NTSTATUS(NTAPI *ZwCreateThreadExPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PUSER_STACK, BOOLEAN, PVOID, PVOID, PVOID);
	Result = HookPort_DoFilter(ZwCreateThread_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwCreateThreadExPtr = HookPort_GetOriginalServiceRoutine(g_SSDT_Func_Index_Data.ZwCreateThreadExIndex);

		//调用原始函数
		Result = ZwCreateThreadExPtr(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, UserStack, CreateSuspended, Arg9, Arg10, Arg11);
		if (NT_SUCCESS(Result))
		{
			Result = HookPort_ForRunFuncTable(ZwCreateThread_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;
}