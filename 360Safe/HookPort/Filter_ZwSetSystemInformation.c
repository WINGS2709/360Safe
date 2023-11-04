#include "Filter_ZwSetSystemInformation.h"

NTSTATUS NTAPI Filter_ZwSetSystemInformation(IN SYSTEM_INFORMATION_CLASS  SystemInformationClass,IN OUT PVOID  SystemInformation,IN ULONG  SystemInformationLength)
{
	NTSTATUS Result = STATUS_SUCCESS;
	NTSTATUS OutResult = STATUS_SUCCESS;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;							//一共有多少组Fake函数
	PVOID	 pArgArray = &SystemInformationClass;		//参数数组，指向栈中属于本函数的所有参数
	NTSTATUS(NTAPI *ZwSetSystemInformationPtr)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG);
	//原始函数执行前检查
	Result = HookPort_DoFilter(ZwCreateFile_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwSetSystemInformationPtr = HookPort_GetOriginalServiceRoutine(g_SSDT_Func_Index_Data.ZwCreateFileIndex);

		//调用原始函数
		Result = ZwSetSystemInformationPtr(SystemInformationClass, SystemInformation, SystemInformationLength);
		if (NT_SUCCESS(Result))
		{
			//原始函数执行后检查
			Result = HookPort_ForRunFuncTable(ZwCreateFile_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;
}