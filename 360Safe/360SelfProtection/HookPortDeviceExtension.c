#include "HookPortDeviceExtension.h"

//设置过滤函数
ULONG Safe_Initialize_SetFilterSwitchFunction()
{
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwWriteFile_FilterIndex, (ULONG)Fake_ZwWriteFile);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, CreateProcessNotifyRoutine_FilterIndex, (ULONG)Fake_CreateProcessNotifyRoutine);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwOpenFile_FilterIndex, (ULONG)Fake_ZwOpenFile);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwCreateFile_FilterIndex, (ULONG)Fake_ZwCreateFile);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwCreateSection_FilterIndex, (ULONG)Fake_ZwCreateSection);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwDeleteFile_FilterIndex, (ULONG)Fake_ZwDeleteFile);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwCreateProcess_FilterIndex, (ULONG)Fake_ZwCreateProcess);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwCreateProcess_FilterIndex, (ULONG)Fake_ZwCreateProcessEx);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwUnmapViewOfSection_FilterIndex, (ULONG)Fake_ZwUnmapViewOfSection);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwUnmapViewOfSectionIndex_Win8_Win10_FilterIndex, (ULONG)Fake_ZwUnmapViewOfSection);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwSuspendProcess_FilterIndex, (ULONG)Fake_ZwSuspendProcess);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwSuspendThread_FilterIndex, (ULONG)Fake_ZwSuspendThread);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwAllocateVirtualMemory_FilterIndex, (ULONG)Fake_ZwAllocateVirtualMemory);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwOpenProcess_FilterIndex, (ULONG)Fake_ZwOpenProcess);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwWriteVirtualMemory_FilterIndex, (ULONG)Fake_ZwWriteVirtualMemory);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwCreateThread_FilterIndex, (ULONG)Fake_ZwCreateThread);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwSetSystemTime_FilterIndex, (ULONG)Fake_ZwSetSystemTime);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwCreateSymbolicLinkObject_FilterIndex, (ULONG)Fake_ZwCreateSymbolicLinkObject);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwGetNextThread_FilterIndex, (ULONG)Fake_ZwGetNextThread);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwGetNextProcess_FilterIndex, (ULONG)Fake_ZwGetNextProcess);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwOpenMutant_FilterIndex, (ULONG)Fake_ZwOpenMutant);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwOpenThread_FilterIndex, (ULONG)Fake_ZwOpenThread);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ess_FilterIndex, (ULOZwOpenSection_FilterIndex, (ULONG)Fake_ZwOpenSection);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwTerminateProcNG)Fake_ZwTerminateProcess);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwZwDuplicateObject_FilterIndex, (ULONG)Fake_ZwDuplicateObject);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwMakeTemporaryObject_FilterIndex, (ULONG)Fake_ZwMakeTemporaryObject);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwEnumerateValueKey_FilterIndex, (ULONG)Fake_ZwEnumerateValueKey);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwAlpcSendWaitReceivePort_FilterIndex, (ULONG)Fake_ZwAlpcSendWaitReceivePort);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwLoad_Un_Driver_FilterIndex, (ULONG)Fake_ZwLoadDriver);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ClientLoadLibrary_FilterIndex, (ULONG)Fake_ClientLoadLibrary);					//拦截DLL注入的
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwSetSystemInformation_FilterIndex, (ULONG)Fake_ZwSetSystemInformation);			//加载驱动XP生效


	/*************************************注册表*************************************/
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwDeleteKey_FilterIndex, (ULONG)Fake_ZwDeleteKey);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwReplaceKey_FilterIndex, (ULONG)Fake_ZwReplaceKey);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwRenameKey_FilterIndex, (ULONG)Fake_ZwRenameKey);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwRestoreKey_FilterIndex, (ULONG)Fake_ZwRestoreKey);
	//Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, ZwOpenKey_FilterIndex, (ULONG)Fake_ZwOpenKey);
	/*************************************注册表*************************************/
	return TRUE;
}

//设置过滤函数开关
VOID NTAPI Safe_Initialize_SetFilterRule(PDEVICE_OBJECT pHookPortDeviceObject)
{
	if (pHookPortDeviceObject->DeviceExtension)
	{
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwWriteFile_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, CreateProcessNotifyRoutine_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwOpenFile_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwCreateFile_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwCreateSection_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwDeleteFile_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwCreateProcess_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwCreateProcessEx_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwUnmapViewOfSection_FilterIndex, 1);					
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwUnmapViewOfSectionIndex_Win8_Win10_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwSuspendProcess_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwSuspendThread_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwAllocateVirtualMemory_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwOpenProcess_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwWriteVirtualMemory_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwCreateThread_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwSetSystemTime_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwCreateSymbolicLinkObject_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwGetNextThread_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwGetNextProcess_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwOpenMutant_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwOpenThread_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwOpenSection_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwTerminateProcess_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwZwDuplicateObject_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwMakeTemporaryObject_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwEnumerateValueKey_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwAlpcSendWaitReceivePort_FilterIndex, 1);	//拦截服务方式加载
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwLoad_Un_Driver_FilterIndex, 1);			//拦截驱动
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ClientLoadLibrary_FilterIndex, 1);			//全局钩子拦截DLL注入
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwSetSystemInformation_FilterIndex, 1);	//加载驱动XP生效

		/*************************************注册表*************************************/
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwOpenKey_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwDeleteKey_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwReplaceKey_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwRenameKey_FilterIndex, 1);
		//Safe_Run_SetFilterRule(g_FilterFun_Rule_table_head_Temp, ZwRestoreKey_FilterIndex, 1);
		/*************************************注册表*************************************/
	}
}


//检查HookPort_SetFilterSwitchFunction函数是否获取成功
//有点多余的检查
ULONG NTAPI Safe_Run_SetFilterSwitchFunction(PFILTERFUN_RULE_TABLE After_rule, ULONG index, PVOID func_addr)
{
	ULONG result; // eax@2

	if (HookPort_SetFilterSwitchFunction)
		result = HookPort_SetFilterSwitchFunction(After_rule, index, func_addr);
	else
		result = 0;
	return result;
}

//检查HookPort_SetFilterRule是否获取成功
//有点多余的检查
ULONG NTAPI Safe_Run_SetFilterRule(PFILTERFUN_RULE_TABLE	After_rule, ULONG index, ULONG	rule)
{
	ULONG result; // eax@2
	result = 0;
	if (HookPort_SetFilterRule)
	{
		HookPort_SetFilterRule(After_rule, index, rule);
		result = 1;
	}
	return result;
}
