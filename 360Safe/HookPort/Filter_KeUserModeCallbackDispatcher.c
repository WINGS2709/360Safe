#include "Filter_KeUserModeCallbackDispatcher.h"

//加载DLL的
NTSTATUS NTAPI Filter_ClientLoadLibrary(IN ULONG ApiNumber, IN PVOID InputBuffer, IN ULONG InputLength, OUT PVOID *OutputBuffer, IN PULONG OutputLength)
{
	NTSTATUS Result, OutResult;
	Result = STATUS_UNSUCCESSFUL;
	PVOID		pArgArray = &ApiNumber;//参数数组，指向栈中属于本函数的所有参数

	//HOOKPORT_DEBUG_PRINT(HOOKPORT_DISPLAY_INFO, "Filter_ClientLoadLibrary");
	if (HookPort_DoFilter(ClientLoadLibrary_FilterIndex, pArgArray, 0, 0, 0, &OutResult))
	{
		Result = OriginalKeUserModeCallback(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength);
	}
	else
	{
		Result = OutResult;
	}
	return Result;
}

//未完待续
NTSTATUS NTAPI Filter_fnHkOPTINLPEVENTMSG(IN ULONG ApiNumber, IN PVOID InputBuffer, IN ULONG InputLength, OUT PVOID *OutputBuffer, IN PULONG OutputLength)
{
	//HOOKPORT_DEBUG_PRINT(HOOKPORT_DISPLAY_INFO, "Filter_fnHkOPTINLPEVENTMSG");
	//v5 = a2;
	//if (*(_WORD *)(a2 + 2)
	//	|| (v8 = *(_DWORD *)(a2 + 8),
	//	v6 = HookPort_DoFilter(0x7Au, (ULONG)&v8, 0, 0, 0, (NTSTATUS *)&a2) == 0,
	//	result = a2,
	//	!v6)
	//	&& a2 >= 0)
	//{
	//	a2 = OriginalKeUserModeCallback(a1, v5, a3, a4, a5);
	//	result = sub_11CF6(a1, v5, a3, (ULONG *)a4, (_DWORD *)a5, a2);
	//}
	//return result;
	return OriginalKeUserModeCallback(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength);
}

//未完待续
NTSTATUS NTAPI Filter_fnHkINLPKBDLLHOOKSTRUCT(IN ULONG ApiNumber, IN PVOID InputBuffer, IN ULONG InputLength, OUT PVOID *OutputBuffer, IN PULONG OutputLength)
{
	//HOOKPORT_DEBUG_PRINT(HOOKPORT_DISPLAY_INFO, "Filter_fnHkINLPKBDLLHOOKSTRUCT");
	/*v8 = *(_DWORD *)(a2 + 4);
	v7 = a2 + 0x10;
	if (!HookPort_DoFilter(0x7Bu, (ULONG)&v7, 0, 0, 0, 0))
	{
	*(_DWORD *)(a2 + 0x10) = 0;
	*(_DWORD *)(a2 + 20) = 0;
	*(_DWORD *)(a2 + 24) = 0;
	v5 = a2 + 0x1C;
	*(_DWORD *)v5 = 0;
	*(_DWORD *)(v5 + 4) = 0;
	*(_DWORD *)(a2 + 4) = 0;
	}*/
	return OriginalKeUserModeCallback(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength);
}

//未完待续
NTSTATUS NTAPI Filter_ClientImmLoadLayout(IN ULONG ApiNumber, IN PVOID InputBuffer, IN ULONG InputLength, OUT PVOID *OutputBuffer, IN PULONG OutputLength, PULONG Result)
{
	//HOOKPORT_DEBUG_PRINT(HOOKPORT_DISPLAY_INFO, "Filter_ClientImmLoadLayout");
	return 0;
}


NTSTATUS NTAPI Filter_KeUserModeCallbackDispatcher(ULONG ApiNumber, PVOID InputBuffer, ULONG InputLength, PVOID *OutputBuffer, PULONG OutputLength)
{
	NTSTATUS result;
	result = STATUS_UNSUCCESSFUL;
	//拦截DLL注入的
	if (ApiNumber == g_ShadowSSDT_Func_Index_Data.KeUserModeCallback_ClientLoadLibrary_Index)
	{
		result = Filter_ClientLoadLibrary(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength);// ClientLoadLibrary
	}
	else if (ApiNumber == g_ShadowSSDT_Func_Index_Data.KeUserModeCallback_fnHkOPTINLPEVENTMSG_Index)
	{
		//未完待续
		result = Filter_fnHkOPTINLPEVENTMSG(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength);
	}
	else if (ApiNumber == g_ShadowSSDT_Func_Index_Data.KeUserModeCallback_fnHkINLPKBDLLHOOKSTRUCT_Index)//拦截键盘消息
	{
		result = Filter_fnHkINLPKBDLLHOOKSTRUCT(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength);
	}
	else if (ApiNumber == g_ShadowSSDT_Func_Index_Data.KeUserModeCallback_ClientImmLoadLayout_Index)
	{
		//未完待续
		result = OriginalKeUserModeCallback(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength);
		if (NT_SUCCESS(result))
		{
			result = Filter_ClientImmLoadLayout(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength, result);
		}
	}
	else
	{
		//调用原始的
		result = OriginalKeUserModeCallback(ApiNumber, InputBuffer, InputLength, OutputBuffer, OutputLength);
	}
	return result;
}