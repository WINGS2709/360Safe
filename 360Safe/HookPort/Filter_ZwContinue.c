#include "Filter_ZwContinue.h"

//这个没有对应的Fake函数
NTSTATUS NTAPI Filter_ZwContinue(PCONTEXT Context, BOOLEAN TestAlert)
{
	NTSTATUS Result, OutResult;
	PVOID	 pArgArray = &Context;//参数数组，指向栈中属于本函数的所有参数

	//HOOKPORT_DEBUG_PRINT(HOOKPORT_DISPLAY_INFO, "Filter_ZwContinue");
	NTSTATUS(NTAPI *ZwContinuePtr)(PCONTEXT, BOOLEAN);
	Result = HookPort_DoFilter(ZwContinue_FilterIndex, pArgArray, 0, 0, 0, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwContinuePtr = HookPort_GetOriginalServiceRoutine(g_SSDT_Func_Index_Data.ZwContinueIndex);

		//调用原始函数
		Result = ZwContinuePtr(Context, TestAlert);
	}
	return Result;
}