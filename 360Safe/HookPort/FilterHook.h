#pragma once
#include <ntddk.h>
#include "Data.h"
#include "Filter_CreateProcessNotifyRoutine.h"
#include "Filter_LoadImageNotifyRoutine.h"
#include "Filter_CreateThreadNotifyRoutine.h"
#include "Filter_ZwOpenFile.h"
#include "Filter_CreateProcessNotifyRoutineEx.h"
#include "Filter_ZwContinue.h"
#include "Filter_KeUserModeCallbackDispatcher.h"
#include "Filter_ZwCreateThread.h"
#include "Filter_ZwWriteFile.h"
#include "Filter_ZwCreateFile.h"
#include "Filter_ZwLoadDriver.h"
#include "Filter_ZwUnloadDriver.h"
#include "Filter_ZwSetSystemInformation.h"

/**************************过滤函数（外壳）***************************/
//说明：
//R3 == File_XXXX               检查参数各种乱七八糟的
//R0 == FakeHook_XXXX           真正工作的
//类似于应用层与内核层的区别 

#define ZwLoad_Un_Driver_FilterIndex	0x22 

#define ZwSetSystemInformation_FilterIndex	0x24 

#define NtUserSetImeInfoEx_FilterIndex	0x7C 

#define ZwSetValueKey_FilterIndex 0x7

#define ZwSetInformationFile_FilterIndex 0xA

#define ZwUserBuildHwndList_FilterIndex 0x27

#define ZwUserSetInformationThread_FilterIndex 0x3A
/**************************过滤函数（外壳）***************************/

//自己写的函数获取HookPort_FilterHook函数总大小
ULONG HookPort_PredictBlockEnd(ULONG uAddress, ULONG uSearchLength, UCHAR *Signature, ULONG SignatureLen);

//填充g_SS_Filter_Table->SSDT、SSSDT代理函数
ULONG NTAPI HookPort_InitProxyAddress(ULONG Flag);

// 根据FilterFunRuleTable表中的Rule((根据PreviousMode有进一步判断))来判断是否需要Hook
BOOLEAN	NTAPI HookPort_HookOrNot(ULONG ServiceIndex, BOOLEAN GuiServiceCall);

//次函数在JMPSTUB中被调用，根据规则判断是否过滤此次调用
PULONG NTAPI HookPort_KiFastCallEntryFilterFunc(ULONG ServiceIndex, PULONG OriginalServiceRoutine, PULONG ServiceTable);

//这个函数根据调用号调用过滤函数并返回一个状态值供调用者判断结果
NTSTATUS NTAPI HookPort_DoFilter(ULONG CallIndex, PHANDLE ArgArray, PULONG *RetFuncArray, PULONG *RetFuncArgArray, PULONG RetNumber, PULONG Result);

//初始化过滤数组
ULONG HookPort_InitFilterTable();

//获取原始的SSDT与ShadowSSDT地址
ULONG NTAPI HookPort_GetOriginalServiceRoutine(IN ULONG ServiceIndex);

//核心部分待分析
ULONG NTAPI HookPort_ForRunFuncTable(IN ULONG CallIndex, IN PHANDLE ArgArray, IN NTSTATUS InResult, IN PULONG *RetFuncArray, IN PULONG *RetFuncArgArray, IN ULONG  RetCount);





#define	_CHECK_IS_SHADOW_CALL( index )	( (index) & (0x1000) )
#define	_HOOKPORT_GET_SERVICE_PTR(service_index) \
	_CHECK_IS_SHADOW_CALL( (service_index) ) ? 	\
		( MmIsAddressValid( g_SS_Filter_Table->SavedShadowSSDTServiceAddress[(service_index) & (0xFFF)])?	\
			(g_SS_Filter_Table->SavedShadowSSDTServiceAddress[(service_index) & (0xFFF)]) \
			:(*(PVOID*)((PULONG)g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiServiceTableBase + ( (service_index) & (0xFFF) ))) ) \
		:( MmIsAddressValid( g_SS_Filter_Table->SavedSSDTServiceAddress[(service_index)])? \
			(g_SS_Filter_Table->SavedSSDTServiceAddress[(service_index)]) \
			:(*(PVOID*)((PULONG)g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeServiceTableBase + (service_index) )))	