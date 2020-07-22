#include "Filter_ZwLoadDriver.h"

NTSTATUS NTAPI Filter_ZwLoadDriver(IN PUNICODE_STRING  DriverServiceName)
{
	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &DriverServiceName;//参数数组，指向栈中属于本函数的所有参数
	NTSTATUS(NTAPI *ZwLoadDriverPtr)(PUNICODE_STRING);
	//KdPrint(("Filter_ZwLoadDriver\t\n"));
	Result = HookPort_DoFilter(ZwLoad_Un_Driver_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwLoadDriverPtr = HookPort_GetOriginalServiceRoutine(g_SSDT_Func_Index_Data.ZwLoadDriverIndex);
		//调用原始函数
		Result = ZwLoadDriverPtr(DriverServiceName);
		if (NT_SUCCESS(Result))
		{
			Result = HookPort_ForRunFuncTable(ZwLoad_Un_Driver_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;
}