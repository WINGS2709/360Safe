#include "FilterHook.h"


//
// 
// 这个函数根据调用号调用过滤函数并返回一个状态值供调用者判断结果
// 参数:
//	CallIndex			[INT]系统服务调用号
//	ArgArray			[INT]原函数的参数数组，其中包含了栈中保存的该服务函数所有的参数			
//	RetFuncArray		[OUT]函数返回函数指针的数组,最多为16个函数指针
//	RetFuncArgArray		[OUT]与返回的函数指针对应的一个参数,在调用RetFuncArray中的一个函数时需要传递在本参数中对应的参数
//  PULONG RetNumber    [OUT]返回值，当!gFilterFun_Rule_table_head则置0
//	Result				[OUT]返回值
// 返回值:
//	使用 NT_SUCCESS 宏进行测试
//
//sub_10DAC
NTSTATUS NTAPI HookPort_DoFilter(ULONG CallIndex, PHANDLE ArgArray, PULONG *RetFuncArray, PULONG *RetFuncArgArray, PULONG RetNumber, PULONG Result)
{

	ULONG		Index = 0;
	PULONG		ret_func;
	PULONG		ret_arg;
	ULONG       ServiceIndex = 0;
	NTSTATUS	status;
	ULONG       ebp_value, Rtn_Address;
	PFILTERFUN_RULE_TABLE	ptemp_rule;

	NTSTATUS(NTAPI *FilterFunc)(ULONG, PHANDLE, PULONG, PULONG);

	//调用号超过了最大过滤函数数量
	if (CallIndex >= FILTERFUNCNT)
	{
		return 1;
	}

	////通过ebp获取retn返回值
	//_asm
	//{
	//	MOV  ebp_value, EBP
	//}
	//Rtn_Address = (PVOID)*(ULONG *)((CHAR *)ebp_value + 4);
	Rtn_Address = _ReturnAddress();
	//过滤规则信息不存在
	if (!g_FilterFun_Rule_table_head)
	{
	LABEL_17:
		if (filter_function_table[CallIndex] != g_SSDTServiceLimit
			&& CallIndex != ZwSetValueKey_FilterIndex			//ZwSetValueKeyIndex
			&& CallIndex != ZwContinue_FilterIndex				//ZwContinueIndex
			&& Rtn_Address != g_call_ring0_rtn_address)
		{
			dword_1B114 = 1;
		}
		if (RetNumber)
		{
			*RetNumber = Index;
		}
		return 1;
	}

	ptemp_rule = g_FilterFun_Rule_table_head;
	//ULONG Number = RetFuncArray - RetFuncArgArray;
	//执行自己构造的虚构API函数，直到成功(一共有0x10次机会)
	while (1)
	{
		// 查找对应的过滤函数，并调用之
		if (ptemp_rule->IsFilterFunFilledReady
			&& ptemp_rule->FakeServiceRoutine[CallIndex])
		{

			ret_func = ret_arg = NULL;

			FilterFunc = (NTSTATUS(NTAPI *)(ULONG, PHANDLE, PULONG, PULONG))ptemp_rule->FakeServiceRoutine[CallIndex];

			status = FilterFunc(CallIndex, ArgArray, (PULONG)&ret_func, (PULONG)&ret_arg);

			if (ret_func && RetFuncArray && Index < 0x10)
			{
				++Index;
				*RetFuncArray++ = ret_func;
				*RetFuncArgArray++ = ret_arg;
			}
			//判断构造的hook函数是否执行成功
			if (status)
			{
				//失败返回（error）
				break;
			}
		}
		ptemp_rule = ptemp_rule->Next;
		//假设是空则退出，非空继续（一共0x10次机会）
		if (!(ULONG)ptemp_rule)
		{
			//退出（特殊情况例外）
			goto LABEL_17;
		}
	}
	//针对部分不感兴趣的函数进行特殊返回
	ServiceIndex = filter_function_table[CallIndex];
	if (status == STATUS_HOOKPORT_FILTER_RULE_ERROR)
	{
		if (Result)
		{
			if (ServiceIndex == g_SSDTServiceLimit)
			{
				*Result = STATUS_HOOKPORT_FILTER_RULE_ERROR;
			}
			else
			{
				*Result = _CHECK_IS_SHADOW_CALL(ServiceIndex) && CallIndex != ZwUserBuildHwndList_FilterIndex && CallIndex != ZwUserSetInformationThread_FilterIndex;
			}
		}
	}
	else
	{
		if (ServiceIndex != g_SSDTServiceLimit && _CHECK_IS_SHADOW_CALL(ServiceIndex))
		{
			if (CallIndex != ZwUserBuildHwndList_FilterIndex && CallIndex != ZwUserSetInformationThread_FilterIndex)
			{
				if (Result)
				{
					*Result = 0;
				}
			}
			else if (Result)
			{
				*Result = status;
			}
		}
		else if (Result)
		{
			*Result = status;
		}
	}
	return STATUS_SUCCESS;

}

// 根据FilterFunRuleTable表中的Rule((根据PreviousMode有进一步判断))来判断是否需要Hook
BOOLEAN	NTAPI HookPort_HookOrNot(ULONG ServiceIndex, BOOLEAN GuiServiceCall)
{

	KPROCESSOR_MODE kpm;
	PFILTERFUN_RULE_TABLE	prule_table;
	ULONG	rule;

	//作用不明
	if (dword_1B110 == 1)
	{
		return FALSE;
	}

	if (ServiceIndex == g_SSDT_Func_Index_Data.ZwSetSystemInformationIndex)
	{
		return TRUE;
	}

	if (!g_FilterFun_Rule_table_head)
		return FALSE;

	kpm = ExGetPreviousMode();

	// GUI系统调用
	if (GuiServiceCall)
	{
		prule_table = g_FilterFun_Rule_table_head;
		do {
			rule = prule_table->ShadowSSDTRuleTableBase[ServiceIndex];
			if (RULE_MUST_HOOK == rule)
				return TRUE;
			if ((RULE_KERNEL_HOOK == rule && KernelMode == kpm)
				|| (RULE_GUI_HOOK == rule && UserMode == kpm)
				) {
				return TRUE;
			}
			prule_table = prule_table->Next;
		} while (prule_table);
		return 	FALSE;
	}

	// Ki系统调用	
	prule_table = g_FilterFun_Rule_table_head;
	do {
		rule = prule_table->SSDTRuleTableBase[ServiceIndex];
		if (RULE_MUST_HOOK == rule)
			return TRUE;
		if ((RULE_KERNEL_HOOK == rule && KernelMode == kpm)
			|| (RULE_GUI_HOOK == rule && UserMode == kpm)
			) {
			return TRUE;
		}
		prule_table = prule_table->Next;
	} while (prule_table);
	return FALSE;

}

//获取原始的SSDT与ShadowSSDT地址
ULONG NTAPI HookPort_GetOriginalServiceRoutine(IN ULONG ServiceIndex)
{
	ULONG Index;
	ULONG ServiceTableBase = 0;
	ULONG Result =0;
	ULONG BuildNumber = Global_osverinfo.dwBuildNumber;
	ULONG MinorVersion = Global_osverinfo.dwMinorVersion;
	ULONG MajorVersion = Global_osverinfo.dwMajorVersion;
	Index = ServiceIndex;
	//SSSDT
	if (ServiceIndex & 0x1000)
	{
		if (BuildNumber < 14316)
		{
			ServiceTableBase = g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiServiceTableBase;
			Index = ServiceIndex & 0xFFF;
		}
		else
		{
			ServiceTableBase = *(ULONG *)(*((ULONG *)KeGetCurrentThread() + 0xF) + 0x10);
			Index = ServiceIndex & 0xFFF;
		}
		Result = *(ULONG*)(ServiceTableBase + 4 * Index);
	}
	//SSDT
	else
	{
		ServiceTableBase = g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeServiceTableBase;
		Result = *(ULONG*)(ServiceTableBase + 4 * Index);
	}
	return Result;
}

//
// 
// 
// 参数:
//	CallIndex			[INT]系统服务调用号
//	ArgArray			[INT]原函数的参数数组，其中包含了栈中保存的该服务函数所有的参数		
//	InResult			[INT]调用原始函数的返回值
//	RetFuncArray		[INT]函数返回函数指针的数组,最多为16个函数指针
//	RetFuncArgArray		[INT]与返回的函数指针对应的一个参数,在调用RetFuncArray中的一个函数时需要传递在本参数中对应的参数
//	RetCount			[INT]重复调用了几次，一般都是1次，默认pFilterFun_Rule_table_head->Next是空的
// 返回值:
//	使用 NT_SUCCESS 宏进行测试
//
ULONG NTAPI HookPort_ForRunFuncTable(IN ULONG CallIndex, IN PHANDLE ArgArray, IN NTSTATUS InResult, IN PULONG *RetFuncArray, IN PULONG *RetFuncArgArray, IN ULONG  RetCount)
{
	NTSTATUS Status;
	NTSTATUS(NTAPI *pPostProcessPtr)(ULONG,		// 参    数: IN ULONG FilterIndex        [In]Filter_ZwOpenFileIndex序号
		PHANDLE,								// 参    数: IN PVOID ArgArray           [In]ZwOpenFile参数的首地址
		NTSTATUS,								// 参    数: IN NTSTATUS Result          [In]调用原始ZwOpenFile返回值
		ULONG									// 参    数: IN PULONG RetFuncArgArray   [In]]与返回的函数指针对应的一个参数,在调用RetFuncArray中的一个函数时需要传递在本参数中对应的参数
		);
	Status = InResult;
	for (ULONG i = 0; i < RetCount; i++)
	{
		pPostProcessPtr = RetFuncArray[i];
		if (pPostProcessPtr && MmIsAddressValid(pPostProcessPtr)) 
		{
			Status = pPostProcessPtr(CallIndex, ArgArray, InResult, RetFuncArgArray[i]);
			if (!NT_SUCCESS(Status))
			{
				break;
			}
		}
	}
	return Status;
}

//************************************     
// 函数名称: HookPort_KiFastCallEntryFilterFunc     
// 函数说明：次函数在JMPSTUB中被调用，根据规则判断是否过滤此次调用    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值: PULONG NTAPI     
// 参    数: ULONG ServiceIndex     
// 参    数: PULONG OriginalServiceRoutine     
// 参    数: PULONG ServiceTable     
//************************************  
PULONG NTAPI HookPort_KiFastCallEntryFilterFunc(ULONG ServiceIndex, PULONG OriginalServiceRoutine, PULONG ServiceTable)
{
	ULONG BuildNumber = Global_osverinfo.dwBuildNumber;
	ULONG MinorVersion = Global_osverinfo.dwMinorVersion;
	ULONG MajorVersion = Global_osverinfo.dwMajorVersion;
	//判断是否是SSDT中的调用 
	if (ServiceTable == g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeServiceTableBase && ServiceIndex <= g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeNumberOfServices)
	{
		if (g_SS_Filter_Table->SwitchTableForSSDT[ServiceIndex] && HookPort_HookOrNot(ServiceIndex, FALSE))
		{
			g_SS_Filter_Table->SavedSSDTServiceAddress[ServiceIndex] = OriginalServiceRoutine;		//返回我们原始函数的地址 
			return g_SS_Filter_Table->ProxySSDTServiceAddress[ServiceIndex];						//返回我们代理函数的地址 
		}
		return OriginalServiceRoutine;
	}
	//判断是否是ShadowSSDT中的调用,过程同上(判断win10_14316之前后版本两种) 
	if ((ServiceTable == g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiServiceTableBase && ServiceIndex <= g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiNumberOfServices)
		|| (BuildNumber >= 14316
		&& ServiceTable == g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiServiceTableBase_Win10_14316
		&& ServiceIndex < g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiNumberOfServices_Win10_14316)
		)
	{
		if (g_SS_Filter_Table->SwitchTableForShadowSSDT[ServiceIndex] && HookPort_HookOrNot(ServiceIndex, TRUE))
		{
			g_SS_Filter_Table->SavedShadowSSDTServiceAddress[ServiceIndex] = OriginalServiceRoutine;		//返回我们原始函数的地址 
			return g_SS_Filter_Table->ProxyShadowSSDTServiceAddress[ServiceIndex];
		}
	}
	return OriginalServiceRoutine; // 不明调用,就直接返回原始例程 
}

//************************************     
// 函数名称: HookPort_FilterHook     
// 函数说明：不感兴趣的hook函数都由这个通用处理，检查下就直接完事
//           有4处地方需要动态修复
//           sub     esp, 0BBBBBBBBh    需要开辟多大空间               
//			 push    0AAAAAAAAh         调用HookPort_DoFilter参数
//           mov     ecx, 0CCCCCCCCh    调用memcpy参数需要new多大空间
//           push    0DDDDDDDDh         调用sub_10A38参数
//           push    0AAAAAAAAh         调用DbgPrint_17DA4参数
//           retn    0EEEEh             需要释放空间
// IDA地址 ：sub_18082
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值:      
//************************************ 
__declspec(naked) __cdecl HookPort_FilterHook()
{

	/*
	动态修复的指令介绍:
	1、sub		esp, 0xbbbbbbbb与retn 0xeeee是一对
	修复方式：  根据SSDT、SSSDT的第四个ParamTableBase里面记录的值是对应函数的参数个数
	2、push     0xAAAAAAA
	修复方式：变成push Index
	3、mov		ecx, 0xCCCCCCCC
	修复方式：  根据SSDT、SSSDT的第四个ParamTableBase里面记录的值是对应函数的参数个数
	*/
	_asm{
			mov     edi, edi
			push    ebp
			mov		ebp, esp
			sub		esp, 0xBBBBBBBB							//动态修复
			mov		[ebp - 0x4], esi
			mov		[ebp - 0x8], edi
			mov		[ebp - 0xC], ecx
			mov		[ebp - 0x10], edx
			lea		eax, [ebp - 0x14]
			push	eax
			lea		eax, [ebp - 0x18]
			push	eax
			lea		eax, [ebp - 0x58]
			push	eax
			lea		eax, [ebp - 0x98]
			push	eax
			lea		eax, [ebp + 0x8]
			push	eax
			push	0xAAAAAAAA								//动态修复
			call    HookPort_DoFilter						//这个函数根据调用号调用过滤函数并返回一个状态值供调用者判断结果
			test	eax, eax
			mov		eax, [ebp - 0x14]
			jz      short Quit
			mov		edi, esp
			lea		esi, [ebp + 0x8]
			mov		ecx, 0xCCCCCCCC							//动态修复
			rep		movsd
			push	0xDDDDDDDD								//动态修复
			call    HookPort_GetOriginalServiceRoutine
			mov		esi, [ebp + 0x4]
			cmp     esi, g_call_ring0_rtn_address
			jnz     short loc_1810D
			mov     esi, dword_1B130
			test    esi, esi
			jz      short loc_1810D
			mov     esi, offset HookPort_FilterHook
			mov	    [ebp + 0x4], esi
			mov		esi, [ebp - 0x4]
			mov		edi, [ebp - 0x8]
			mov		ecx, [ebp - 0xC]
			mov		edx, [ebp - 0x10]
			call	eax
			mov     esi, g_call_ring0_rtn_address
			mov		[ebp + 0x4], esi
			jmp     short loc_1811B
		loc_1810D :
			mov		esi, [ebp - 0x4]
			mov		edi, [ebp - 0x8]
			mov		ecx, [ebp - 0xC]
			mov		edx, [ebp - 0x10]
			call	eax
		loc_1811B :
			mov     [ebp - 0x14], eax
			push    [ebp - 0x18]
			lea		eax, [ebp - 0x58]
			push	eax
			lea		eax, [ebp - 0x98]
			push	eax
			push    [ebp - 0x14]
			lea		eax, [ebp + 0x8]
			push	eax
			push	0xAAAAAAAA								//动态修复
			call	HookPort_ForRunFuncTable
		Quit :
			mov		esi, [ebp - 0x4]
			mov		edi, [ebp - 0x8]
			mov		ecx, [ebp - 0xC]
			mov		edx, [ebp - 0x10]
			Leave											//Leave的作用相当==mov esp,ebp和pop ebp
			retn	0xEEEE									//动态修复
			nop												//结尾标识符
			nop
			nop
			nop
			push	0x4536251
			nop
			nop
			nop
			nop
	}
}

//自己写的函数获取HookPort_FilterHook函数总大小
ULONG HookPort_PredictBlockEnd(ULONG uAddress, ULONG uSearchLength, UCHAR *Signature, ULONG SignatureLen)
{
	ULONG	Index;
	UCHAR	*p;
	ULONG	uRetAddress;

	if (uAddress == 0)
	{
		return 0;
	}
	p = (UCHAR*)uAddress;
	for (Index = 0; Index < uSearchLength; Index++)
	{
		if (memcmp(p, Signature, SignatureLen) == 0)
		{
			return p;
		}
		p++;
	}
	return 0;
}

//************************************     
// 函数名称: HookPort_InitFilterTable     
// 函数说明：初始化过滤数组    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/18     
// 返 回 值: ULONG     
//************************************  
ULONG HookPort_InitFilterTable()
{
	ULONG result; // eax@1

	filter_function_table[0] = g_SSDT_Func_Index_Data.ZwCreateKeyIndex;
	filter_function_table[1] = g_SSDT_Func_Index_Data.ZwQueryValueKeyIndex;
	filter_function_table[2] = g_SSDT_Func_Index_Data.ZwDeleteKeyIndex;
	filter_function_table[3] = g_SSDT_Func_Index_Data.ZwDeleteValueKeyIndex;
	filter_function_table[4] = g_SSDT_Func_Index_Data.ZwRenameKeyIndex;
	filter_function_table[5] = g_SSDT_Func_Index_Data.ZwReplaceKeyIndex;
	filter_function_table[6] = g_SSDT_Func_Index_Data.ZwRestoreKeyIndex;
	filter_function_table[7] = g_SSDT_Func_Index_Data.ZwSetValueKeyIndex;
	filter_function_table[8] = g_SSDT_Func_Index_Data.ZwCreateFileIndex;
	filter_function_table[9] = g_SSDT_Func_Index_Data.ZwFsControlFileIndex;
	filter_function_table[10] = g_SSDT_Func_Index_Data.ZwSetInformationFileIndex;
	filter_function_table[11] = g_SSDT_Func_Index_Data.ZwWriteFileIndex;
	filter_function_table[13] = g_SSDT_Func_Index_Data.ZwCreateProcessIndex;
	filter_function_table[14] = g_SSDT_Func_Index_Data.ZwCreateProcessExIndex;
	filter_function_table[15] = g_SSDT_Func_Index_Data.ZwCreateUserProcessIndex;
	filter_function_table[16] = g_SSDT_Func_Index_Data.ZwCreateThreadIndex;
	filter_function_table[17] = g_SSDT_Func_Index_Data.ZwOpenThreadIndex;
	filter_function_table[18] = g_SSDT_Func_Index_Data.ZwDeleteFileIndex;
	filter_function_table[19] = g_SSDT_Func_Index_Data.ZwOpenFileIndex;
	filter_function_table[20] = g_SSDT_Func_Index_Data.ZwReadVirtualMemoryIndex;
	filter_function_table[21] = g_SSDT_Func_Index_Data.ZwTerminateProcessIndex;
	filter_function_table[22] = g_SSDT_Func_Index_Data.ZwQueueApcThreadIndex;
	filter_function_table[23] = g_SSDT_Func_Index_Data.ZwSetContextThreadIndex;
	filter_function_table[24] = g_SSDT_Func_Index_Data.ZwSetInformationThreadIndex;
	filter_function_table[25] = g_SSDT_Func_Index_Data.ZwProtectVirtualMemoryIndex;
	filter_function_table[26] = g_SSDT_Func_Index_Data.ZwWriteVirtualMemoryIndex;
	filter_function_table[27] = g_SSDT_Func_Index_Data.ZwAdjustGroupsTokenIndex;
	filter_function_table[28] = g_SSDT_Func_Index_Data.ZwAdjustPrivilegesTokenIndex;
	filter_function_table[29] = g_SSDT_Func_Index_Data.ZwRequestWaitReplyPortIndex;
	filter_function_table[30] = g_SSDT_Func_Index_Data.ZwCreateSectionIndex;
	filter_function_table[31] = g_SSDT_Func_Index_Data.ZwOpenSectionIndex;
	filter_function_table[32] = g_SSDT_Func_Index_Data.ZwCreateSymbolicLinkObjectIndex;
	filter_function_table[33] = g_SSDT_Func_Index_Data.ZwOpenSymbolicLinkObjectIndex;
	filter_function_table[34] = g_SSDT_Func_Index_Data.ZwLoadDriverIndex;
	filter_function_table[35] = g_SSDT_Func_Index_Data.ZwQuerySystemInformationIndex;
	filter_function_table[36] = g_SSDT_Func_Index_Data.ZwSetSystemInformationIndex;
	filter_function_table[37] = g_SSDT_Func_Index_Data.ZwSetSystemTimeIndex;
	filter_function_table[38] = g_SSDT_Func_Index_Data.ZwSystemDebugControlIndex;
	filter_function_table[39] = g_ShadowSSDT_Func_Index_Data.ZwUserBuildHwndListIndex;
	filter_function_table[40] = g_ShadowSSDT_Func_Index_Data.ZwUserQueryWindowIndex;
	filter_function_table[41] = g_ShadowSSDT_Func_Index_Data.ZwUserFindWindowExIndex;
	filter_function_table[42] = g_ShadowSSDT_Func_Index_Data.ZwUserWindowFromPointIndex;
	filter_function_table[43] = g_ShadowSSDT_Func_Index_Data.ZwUserMessageCallIndex;
	filter_function_table[44] = g_ShadowSSDT_Func_Index_Data.ZwUserPostMessageIndex;
	filter_function_table[45] = g_ShadowSSDT_Func_Index_Data.ZwUserSetWindowsHookExIndex;
	filter_function_table[46] = g_ShadowSSDT_Func_Index_Data.ZwUserPostThreadMessageIndex;
	filter_function_table[47] = g_SSDT_Func_Index_Data.ZwOpenProcessIndex;
	filter_function_table[48] = g_SSDT_Func_Index_Data.ZwDeviceIoControlFileIndex;
	filter_function_table[49] = g_ShadowSSDT_Func_Index_Data.ZwUserSetParentIndex;
	filter_function_table[51] = g_SSDT_Func_Index_Data.ZwDuplicateObjectIndex;
	filter_function_table[50] = g_SSDT_Func_Index_Data.ZwOpenKeyIndex;
	filter_function_table[52] = g_SSDT_Func_Index_Data.ZwResumeThreadIndex;
	filter_function_table[53] = g_ShadowSSDT_Func_Index_Data.ZwUserChildWindowFromPointExIndex;
	filter_function_table[54] = g_ShadowSSDT_Func_Index_Data.ZwUserDestroyWindowIndex;
	filter_function_table[55] = g_ShadowSSDT_Func_Index_Data.ZwUserInternalGetWindowTextIndex;
	filter_function_table[56] = g_ShadowSSDT_Func_Index_Data.ZwUserMoveWindowIndex;
	filter_function_table[57] = g_ShadowSSDT_Func_Index_Data.ZwUserRealChildWindowFromPointIndex;
	filter_function_table[58] = g_ShadowSSDT_Func_Index_Data.ZwUserSetInformationThreadIndex;
	filter_function_table[70] = g_SSDT_Func_Index_Data.ZwUnmapViewOfSectionIndex;
	filter_function_table[59] = g_ShadowSSDT_Func_Index_Data.ZwUserSetInternalWindowPosIndex;
	filter_function_table[71] = g_ShadowSSDT_Func_Index_Data.ZwUserSetWinEventHookIndex;
	filter_function_table[60] = g_ShadowSSDT_Func_Index_Data.ZwUserSetWindowLongIndex;
	filter_function_table[72] = g_SSDT_Func_Index_Data.ZwSetSecurityObjectIndex;
	filter_function_table[61] = g_ShadowSSDT_Func_Index_Data.ZwUserSetWindowPlacementIndex;
	filter_function_table[73] = g_ShadowSSDT_Func_Index_Data.ZwUserCallHwndParamLockIndex;
	filter_function_table[62] = g_ShadowSSDT_Func_Index_Data.ZwUserSetWindowPosIndex;
	filter_function_table[74] = g_ShadowSSDT_Func_Index_Data.ZwUserRegisterUserApiHookIndex;
	filter_function_table[63] = g_ShadowSSDT_Func_Index_Data.ZwUserSetWindowRgnIndex;
	filter_function_table[76] = g_ShadowSSDT_Func_Index_Data.NtUserRegisterWindowMessageIndex;
	filter_function_table[64] = g_ShadowSSDT_Func_Index_Data.ZwUserShowWindowIndex;
	filter_function_table[77] = g_ShadowSSDT_Func_Index_Data.NtUserCallNoParamIndex;
	filter_function_table[65] = g_ShadowSSDT_Func_Index_Data.ZwUserShowWindowAsyncIndex;
	filter_function_table[78] = g_SSDT_Func_Index_Data.ZwAllocateVirtualMemoryIndex;
	filter_function_table[66] = g_SSDT_Func_Index_Data.ZwQueryAttributesFileIndex;
	filter_function_table[79] = g_ShadowSSDT_Func_Index_Data.NtUserCallOneParamIndex;
	filter_function_table[67] = g_ShadowSSDT_Func_Index_Data.ZwUserSendInputIndex;
	filter_function_table[80] = g_SSDT_Func_Index_Data.ZwCreateMutantIndex;
	filter_function_table[68] = g_SSDT_Func_Index_Data.ZwAlpcSendWaitReceivePortIndex;
	filter_function_table[81] = g_SSDT_Func_Index_Data.ZwOpenMutantIndex;
	filter_function_table[69] = g_SSDTServiceLimit;
	filter_function_table[75] = g_SSDTServiceLimit;
	filter_function_table[82] = g_SSDT_Func_Index_Data.ZwVdmControlIndex;
	filter_function_table[84] = g_SSDT_Func_Index_Data.ZwGetNextProcessIndex;
	filter_function_table[83] = g_SSDT_Func_Index_Data.ZwGetNextThreadIndex;
	filter_function_table[85] = g_SSDT_Func_Index_Data.ZwRequestPortIndex;
	filter_function_table[86] = g_SSDT_Func_Index_Data.ZwFreeVirtualMemoryIndex;
	filter_function_table[87] = g_ShadowSSDT_Func_Index_Data.NtUserCallTwoParamIndex;
	filter_function_table[88] = g_ShadowSSDT_Func_Index_Data.NtUserCallHwndLockIndex;
	filter_function_table[89] = g_SSDT_Func_Index_Data.ZwEnumerateValueKeyIndex;
	filter_function_table[90] = g_SSDT_Func_Index_Data.ZwQueryKeyIndex;
	filter_function_table[91] = g_SSDT_Func_Index_Data.ZwEnumerateKeyIndex;
	filter_function_table[92] = g_SSDT_Func_Index_Data.ZwConnectPortIndex;
	filter_function_table[93] = g_SSDT_Func_Index_Data.ZwSecureConnectPortIndex;
	filter_function_table[94] = g_SSDT_Func_Index_Data.ZwAlpcConnectPortIndex;
	filter_function_table[95] = g_ShadowSSDT_Func_Index_Data.NtUserUnhookWindowsHookExIndex;
	filter_function_table[98] = g_SSDT_Func_Index_Data.ZwSetTimerIndex;
	filter_function_table[99] = g_ShadowSSDT_Func_Index_Data.NtUserClipCursorIndex;
	filter_function_table[100] = g_SSDT_Func_Index_Data.ZwSetInformationProcessIndex;
	filter_function_table[101] = g_ShadowSSDT_Func_Index_Data.NtUserGetKeyStateIndex;
	filter_function_table[102] = g_ShadowSSDT_Func_Index_Data.NtUserGetKeyboardStateIndex;
	filter_function_table[103] = g_ShadowSSDT_Func_Index_Data.NtUserGetAsyncKeyStateIndex;
	filter_function_table[104] = g_ShadowSSDT_Func_Index_Data.NtUserAttachThreadInputIndex;
	filter_function_table[105] = g_ShadowSSDT_Func_Index_Data.NtUserRegisterHotKeyIndex;
	filter_function_table[106] = g_ShadowSSDT_Func_Index_Data.NtUserRegisterRawInputDevicesIndex;
	filter_function_table[107] = g_ShadowSSDT_Func_Index_Data.NtGdiBitBltIndex;
	filter_function_table[108] = g_ShadowSSDT_Func_Index_Data.NtGdiStretchBltIndex;
	filter_function_table[109] = g_ShadowSSDT_Func_Index_Data.NtGdiMaskBltIndex;
	filter_function_table[110] = g_ShadowSSDT_Func_Index_Data.NtGdiPlgBltIndex;
	filter_function_table[111] = g_ShadowSSDT_Func_Index_Data.NtGdiTransparentBltIndex;
	filter_function_table[112] = g_ShadowSSDT_Func_Index_Data.NtGdiAlphaBlendIndex;
	filter_function_table[113] = g_ShadowSSDT_Func_Index_Data.NtGdiGetPixelIndex;
	filter_function_table[114] = g_SSDT_Func_Index_Data.ZwMapViewOfSectionIndex;
	filter_function_table[115] = g_SSDT_Func_Index_Data.ZwTerminateThreadIndex;
	filter_function_table[117] = g_SSDT_Func_Index_Data.ZwTerminateJobObjectIndex;
	filter_function_table[116] = g_SSDT_Func_Index_Data.ZwAssignProcessToJobObjectIndex;
	filter_function_table[118] = g_SSDT_Func_Index_Data.ZwDebugActiveProcessIndex;
	filter_function_table[119] = g_SSDT_Func_Index_Data.ZwSetInformationJobObjectIndex;
	filter_function_table[121] = g_ShadowSSDT_Func_Index_Data.NtUserGetRawInputDataIndex;
	filter_function_table[120] = g_ShadowSSDT_Func_Index_Data.NtUserGetRawInputBufferIndex;
	filter_function_table[96] = g_SSDTServiceLimit;
	filter_function_table[97] = g_SSDTServiceLimit;
	filter_function_table[122] = g_SSDTServiceLimit;
	filter_function_table[123] = g_SSDTServiceLimit;
	filter_function_table[124] = g_ShadowSSDT_Func_Index_Data.NtUserSetImeInfoExIndex;
	filter_function_table[129] = g_SSDTServiceLimit;
	filter_function_table[130] = g_SSDTServiceLimit;
	filter_function_table[134] = g_SSDTServiceLimit;
	filter_function_table[135] = g_SSDT_Func_Index_Data.ZwContinueIndex;
	filter_function_table[136] = g_SSDT_Func_Index_Data.ZwAccessCheckIndex;
	filter_function_table[137] = g_SSDT_Func_Index_Data.ZwAccessCheckAndAuditAlarmIndex;
	filter_function_table[139] = g_SSDT_Func_Index_Data.ZwQueryInformationProcessIndex;
	filter_function_table[138] = g_SSDT_Func_Index_Data.ZwQueryInformationThreadIndex;
	filter_function_table[140] = g_SSDT_Func_Index_Data.ZwQueryIntervalProfileIndex;
	filter_function_table[141] = g_SSDT_Func_Index_Data.ZwSetIntervalProfileIndex;
	filter_function_table[142] = g_SSDT_Func_Index_Data.ZwCreateProfileIndex;
	filter_function_table[143] = g_ShadowSSDT_Func_Index_Data.NtUserLoadKeyboardLayoutExIndex;
	filter_function_table[145] = g_ShadowSSDT_Func_Index_Data.NtGdiAddFontMemResourceExIndex;
	filter_function_table[146] = g_ShadowSSDT_Func_Index_Data.NtGdiAddRemoteFontToDCIndex;
	filter_function_table[144] = g_ShadowSSDT_Func_Index_Data.NtGdiAddFontResourceWIndex;
	filter_function_table[148] = g_SSDT_Func_Index_Data.ZwSuspendProcessIndex;
	filter_function_table[147] = g_SSDT_Func_Index_Data.ZwSuspendThreadIndex;
	filter_function_table[149] = g_SSDT_Func_Index_Data.ZwApphelpCaCheControlIndex;
	filter_function_table[151] = g_SSDT_Func_Index_Data.ZwLoadKeyIndex;
	filter_function_table[126] = g_SSDT_Func_Index_Data.ZwAlpcConnectPortExIndex;
	filter_function_table[153] = g_SSDT_Func_Index_Data.ZwLoadKeyExIndex;
	filter_function_table[125] = g_SSDT_Func_Index_Data.ZwQueueApcThreadExIndex;
	filter_function_table[152] = g_SSDT_Func_Index_Data.ZwLoadKey2Index;
	filter_function_table[127] = g_SSDT_Func_Index_Data.ZwMakeTemporaryObjectIndex;
	filter_function_table[150] = g_SSDT_Func_Index_Data.ZwUnmapViewOfSectionIndex_Win8_Win10;
	filter_function_table[128] = g_SSDT_Func_Index_Data.ZwDisplayStringIndex;
	filter_function_table[154] = g_SSDT_Func_Index_Data.ZwOpenKeyExIndex;
	filter_function_table[131] = g_ShadowSSDT_Func_Index_Data.NtGdiOpenDCWIndex;
	filter_function_table[155] = g_SSDT_Func_Index_Data.dword_1BAA0;
	filter_function_table[132] = g_ShadowSSDT_Func_Index_Data.NtGdiDeleteObjectAppIndex;
	filter_function_table[156] = g_SSDT_Func_Index_Data.dword_1BB08;
	result = g_SSDT_Func_Index_Data.dword_1BA98;
	filter_function_table[133] = g_ShadowSSDT_Func_Index_Data.NtUserBlockInputIndex;
	filter_function_table[157] = g_SSDT_Func_Index_Data.dword_1BA98;
	return result;
}


//************************************     
// 函数名称: HookPort_InitProxyAddress     
// 函数说明：填充g_SS_Filter_Table->SSDT、SSSDT代理函数
//			处理过滤函数部分分为两种方式：
//			1、感兴趣的单独处理（有针对性的Fake_XXXX函数）
//			2、不感兴趣的通用处理（修复HookPort_FilterHook函数）
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/18     
// 返 回 值: ULONG NTAPI     
// 参    数: ULONG Flag          0 == SSDT、1 == shadowSSDT（切换到GUI线程）
//************************************  
ULONG NTAPI HookPort_InitProxyAddress(ULONG Flag)
{
	ULONG FunSize = 0; // ebx@1
	ULONG Number = 0; // esi@4
	ULONG Index = 0; // edx@32
	ULONG v13 = 0;
	PVOID pBuff_v5;
	//特征码
	UCHAR	cDbgObjSign[] = { 0x90, 0x90, 0x90, 0x90, 0x68, 0x51, 0x62, 0x53, 0x04, 0x90, 0x90, 0x90, 0x90, 0x00 };
	//获取HookPort_FilterHook函数大小
	FunSize = HookPort_PredictBlockEnd((ULONG)HookPort_FilterHook, 0x100, cDbgObjSign, strlen(cDbgObjSign));
	//故意写长几个字节（ + strlen(cDbgObjSign)）
	FunSize = (FunSize - (ULONG)HookPort_FilterHook) + strlen(cDbgObjSign);
	//2、new出对应的空间存放，filter_function_table_Size_temp保存后续所有通用不感兴趣的SSDT、SSSDT调用代码都在这张表里
	if (!filter_function_table_Size_temp)
	{
		filter_function_table_Size_temp = ExAllocatePoolWithTag(NonPagedPool, FILTERFUNCNT * FunSize, HOOKPORT_POOLTAG1);
		RtlZeroMemory(filter_function_table_Size_temp, FILTERFUNCNT * FunSize);
		if (!filter_function_table_Size_temp)
			return 0;
	}
	Number = 0;
	v13 = 0;
	//3、处理SSDT、SSSDTFake_Hook函数分为两种：
	//1:感兴趣的（单独写个Fake_xxxx函数处理）
	//2:不感兴趣的（使用通用Hook函数HookPort_FilterHook，并且针对不同的NT函数修复HookPort_FilterHook）
	do
	{
		if (Number == 0xC)							//这一项是空的				ZwSetEvnet
		{
			goto Next;
		}
		if (Number == ZwWriteFile_FilterIndex)		//filter_function_table[11] = ZwWriteFileIndex;
		{
			g_SS_Filter_Table->ProxySSDTServiceAddress[g_SSDT_Func_Index_Data.ZwWriteFileIndex] = Filter_ZwWriteFile;
			g_SS_Filter_Table->ProxySSDTServiceAddress[g_SSDT_Func_Index_Data.ZwWriteFileGatherIndex] = Filter_ZwWriteFileGather;
			goto Next;
		}
		if (Number == ZwCreateThread_FilterIndex)		//filter_function_table[16] = ZwCreateThreadIndex;
		{
			g_SS_Filter_Table->ProxySSDTServiceAddress[g_SSDT_Func_Index_Data.ZwCreateThreadIndex] = Filter_ZwCreateThread;
			g_SS_Filter_Table->ProxySSDTServiceAddress[g_SSDT_Func_Index_Data.ZwCreateThreadExIndex] = Filter_ZwCreateThreadEx;
			goto Next;
		}
		if (Number == ZwLoad_Un_Driver_FilterIndex)         // filter_function_table[34] = ZwLoadDriverIndex;
		{
			g_SS_Filter_Table->ProxySSDTServiceAddress[g_SSDT_Func_Index_Data.ZwLoadDriverIndex] = Filter_ZwLoadDriver;
			g_SS_Filter_Table->ProxySSDTServiceAddress[g_SSDT_Func_Index_Data.ZwUnloadDriverIndex] = Filter_ZwUnloadDriver;
			goto Next;
		}
		if (Number == ZwOpenFile_FilterIndex)           // filter_function_table[19] = ZwOpenFileIndex;
		{
			g_SS_Filter_Table->ProxySSDTServiceAddress[g_SSDT_Func_Index_Data.ZwOpenFileIndex] = Filter_ZwOpenFile;
			goto Next;
		}
		if (Number == ZwCreateFile_FilterIndex)         // filter_function_table[8] = ZwCreateFileIndex;
		{
			g_SS_Filter_Table->ProxySSDTServiceAddress[g_SSDT_Func_Index_Data.ZwCreateFileIndex] = Filter_ZwCreateFile;
			goto Next;
		}
		if (Number == ZwSetSystemInformation_FilterIndex) // filter_function_table[36] = ZwSetSystemInformationIndex;
		{
			g_SS_Filter_Table->ProxySSDTServiceAddress[g_SSDT_Func_Index_Data.ZwSetSystemInformationIndex] = Filter_ZwSetSystemInformation;
			goto Next;
		}
		if (Number == NtUserSetImeInfoEx_FilterIndex)                       // filter_function_table[124] = NtUserSetImeInfoExIndex;
		{
			if (Flag)
			{
				//g_SS_Filter_Table->ProxyShadowSSDTServiceAddress[g_ShadowSSDT_Func_Index_Data.NtUserSetImeInfoExIndex & 0xFFF] = &off_114B8;
				goto Next;
			}
		}
		else
		{
			if (Number	  == CreateProcessNotifyRoutine_FilterIndex    //这部分是HookPort自身就携带的Fake函数，其他Fake函数都是通过360SafeProtection赋值的
				|| Number == ClientLoadLibrary_FilterIndex
				|| Number == fnHkOPTINLPEVENTMSG_XX2_FilterIndex
				|| Number == ClientImmLoadLayout_XX1_FilterIndex
				|| Number == fnHkOPTINLPEVENTMSG_XX1_FilterIndex
				|| Number == fnHkINLPKBDLLHOOKSTRUCT_FilterIndex
				|| Number == LoadImageNotifyRoutine_FilterIndex
				|| Number == CreateProcessNotifyRoutineEx_FilterIndex
				|| Number == CreateThreadNotifyRoutine_FilterIndex)
			{
				goto Next;
			}
			if (Number == ZwContinue_FilterIndex)         // filter_function_table[135] = ZwContinueIndex;
			{
				g_SS_Filter_Table->ProxySSDTServiceAddress[g_SSDT_Func_Index_Data.ZwContinueIndex] = Filter_ZwContinue;
			}
		}
		Index = filter_function_table[Number];
		if (Index == g_SSDTServiceLimit)               // 判断是否无效值
		{
			goto Next;
		}
		if (Index & 0x1000)                          // 判断是不是SSSDT
		{
			if (!Flag
				|| g_SS_Filter_Table->ProxyShadowSSDTServiceAddress[(Index & 0xFFF)]
				|| !g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiParamTableBase)
			{
				goto Next;
			}
		}
		else if (Flag == 1 || g_SS_Filter_Table->ProxySSDTServiceAddress[Index])
		{
			goto Next;
		}
		//不感兴趣的通用处理部分
		//修复下HookPort_FilterHook结构然后就往g_SS_Filter_Table->SSDT、SSSDT[Index]塞即可
		//每一个过滤函数对应一个HookPort_FilterHook，一共有FILTERFUNCNT个
		pBuff_v5 = (UCHAR *)filter_function_table_Size_temp + FunSize * Number;
		RtlCopyMemory(pBuff_v5, HookPort_FilterHook, FunSize);
		//修复HookPort_FilterHook函数
		for (ULONG i_v9 = 0; i_v9 < FunSize; i_v9++)
		{
			PVOID v10 = (PVOID)((PCHAR)pBuff_v5 + i_v9);
			//1:修复HookPort_DoFilter函数的参数1
			//push 0xAAAAA  ->  push Index
			if (*(ULONG *)v10 == 0xAAAAAAAA)
			{
				*(ULONG *)v10 = Number;
				//判断是不是call
				if (*(UCHAR *)((PCHAR)v10 + 4) == 0xE8u)
				{
					//修复：call xxxx（重定位到new出来空间里）
					*(ULONG *)((PCHAR)v10 + 5) += (ULONG)HookPort_FilterHook - (ULONG)pBuff_v5;
				}
			}
			//2:判断要使用多大空间，然后修复sub esp, 0BBBBBBBBh->sub esp,XXXh
			//获取SSDT、SSSDT的ParamTableBase就可以确认参数个数
			if (*(ULONG *)v10 == 0xBBBBBBBB)
			{
				//判断SSDT还是SSSDT
				if (Index & 0x1000)
				{
					*(ULONG *)v10 = *(UCHAR*)((Index & 0xFFF) + (PCHAR)g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiParamTableBase) + 0x98;
				}
				else
				{

					*(ULONG *)v10 = *(UCHAR*)((PCHAR)g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeParamTableBase + Index) + 0x98;
				}
			}
			//3:判断要memcpy多大空间，然后修复qmemcpy(&savedregs, &a1, 0x33333330u)->qmemcpy(&savedregs, &a1, 0xXXXu);
			if (*(ULONG *)v10 == 0xCCCCCCCC)
			{
				//判断SSDT还是SSSDT
				if (Index & 0x1000)
				{
					*(ULONG *)v10 = *(UCHAR*)((Index & 0xFFF) + (PCHAR)g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiParamTableBase) >> 2;
				}
				else
				{
					*(ULONG *)v10 = *(UCHAR*)((PCHAR)g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeParamTableBase + Index) >> 2;
				}
			}
			//4:修复sub_10A38函数函数的参数1			调用原始函数
			//push 0xAAAAA  ->  push Index
			if (*(ULONG *)v10 == 0xDDDDDDDD)
			{
				*(ULONG *)v10 = Index;
				//判断是不是call
				if (*(UCHAR *)((PCHAR)v10 + 4) == 0xE8u)
				{
					//修复：call xxxx（重定位到new出来空间里）
					*(ULONG *)((PCHAR)v10 + 5) += (ULONG)HookPort_FilterHook - (ULONG)pBuff_v5;
				}
			}
			//5:修复retn
			if (*(ULONG *)v10 == 0xEEEEC2C9)
			{
				//判断SSDT还是SSSDT
				if (Index & 0x1000)
				{
					*(USHORT *)((PCHAR)v10 + 2) = *(UCHAR*)((Index & 0xFFF) + (PCHAR)g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiParamTableBase);
				}
				else
				{
					*(USHORT *)((PCHAR)v10 + 2) = *(UCHAR*)((PCHAR)g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeParamTableBase + Index);
				}
			}
		}
		//修复完毕将首地址赋值到我们的HOOK链中
		//判断SSDT还是SSSDT
		if (Index & 0x1000)
		{
			g_SS_Filter_Table->ProxyShadowSSDTServiceAddress[Index] = pBuff_v5;
		}
		else
		{
			g_SS_Filter_Table->ProxySSDTServiceAddress[Index] = pBuff_v5;
		}
	Next:
		v13 = ++Number;
	} while (Number < FILTERFUNCNT);

	return 1;
}