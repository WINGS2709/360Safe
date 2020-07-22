#pragma once
#include <ntddk.h>
#include "defs.h"
//全局DriverObject
PDRIVER_OBJECT Global_DriverObject;

//作用不明
ULONG dword_1B110;					//标志位，开关
ULONG dword_1B130;					//作用不明，HookPort_FilterHook
ULONG dword_1B114;					//返回给3环FakeXXX_函数失败

//各种加密后的哈希值(未知)
ULONG Global_Hash_1;
ULONG Global_Hash_2;
ULONG Global_Hash_3;
ULONG Global_Hash_4;

ULONG dword_1B134_ModuleBase;		//Global_Hash_1的基址
ULONG dword_1B138_ModuleSize;		//Global_Hash_1的基址大小

ULONG dword_1B13C_ModuleBase;		//Global_Hash_2的基址
ULONG dword_1B140_ModuleSize;		//Global_Hash_2的基址大小

ULONG dword_1B14C_ModuleBase;      //Global_Hash_3的基址
ULONG dword_1B150_ModuleSize;      //Global_Hash_3的基址大小

ULONG dword_1B144_ModuleBase;      //Global_Hash_4的基址
ULONG dword_1B148_ModuleSize;      //Global_Hash_4的基址大小

ULONG dword_1B120;					//未知 开关
ULONG dword_1B124;					//控制Global_Hash_2~Global_Hash_4的开关Flag
ULONG dword_1B128;					//未知 开关
ULONG dword_1B12C;					//未知 开关

////Win32k标记，获取Win32k内核成功置1
ULONG				 Global_Win32kFlag;
ULONG                Global_Version_Win10_Flag;		//Win10标识
RTL_OSVERSIONINFOEXW Global_osverinfo;				//后面需要使用直接定义成全局的

//Fake_ZwSetEvent函数使用的变量
PVOID g_call_ring0_rtn_address;												//从栈回溯中获得的KiFastCallEntry返回地址

/**************************宏定义***************************/
#define	HookPort_DeviceName		L"\\Device\\360HookPort"
#define	HookPort_LinkName		L"\\DosDevices\\360HookPort"
#define HookPort_Minimal        L"\\SafeBoot\\Minimal\\HookPort"
#define HookPort_Network        L"\\SafeBoot\\Network\\HookPort"


#define	WIN32KSYS				"win32k.sys"
#define	WIN32KFULLSYS			"win32kfull.sys"
#define	NTOSKERNL				"ntoskrnl.exe"


#define	HOOKPORT_POOLTAG1		'HPPX'
#define	HOOKPORT_POOLTAG2	    'JMPP'
#define	HOOKPORT_POOLTAG3	    'HPIT'
#define	HOOKPORT_POOLTAG4	    'SMAP'
#define	HOOKPORT_POOLTAG5	    'SSMA'
#define HOOKPORT_POOLTAG6       'NMU '
#define HOOKPORT_POOLTAG7       'HPOR'


#define STATUS_HOOKPORT_FILTER_RULE_ERROR  ((NTSTATUS)0xC0000503L)


/**************************宏定义***************************/


#define	g_SSDTServiceLimit 2000

typedef struct _SYSTEM_SERVICE_FILTER_TABLE{
	PULONG ProxySSDTServiceAddress[g_SSDTServiceLimit + 1];			 //起始偏移0000*4,保存被Hook的SSDT函数对应的代理函数的地址 
	PULONG ProxyShadowSSDTServiceAddress[g_SSDTServiceLimit + 1];    //起始偏移2001*4,保存被Hook的ShadowSSDT函数对应的代理函数的地址 
	ULONG SwitchTableForSSDT[g_SSDTServiceLimit + 1];                //起始偏移4002*4,保存SSDT Hook开关,决定该函数是否会被Hook 
	ULONG SwitchTableForShadowSSDT[g_SSDTServiceLimit + 1];          //起始偏移6003*4,保存ShadowSSDT Hook开关,决定该函数是否会被Hook 
	PULONG SavedSSDTServiceAddress[g_SSDTServiceLimit + 1];			 //起始偏移8004*4,保存被Hook的原始SSDT函数的地址            作废
	PULONG SavedShadowSSDTServiceAddress[g_SSDTServiceLimit + 1];    //起始偏移A005*4,保存被Hook的原始ShadowSSDT函数的地址      作废
}SYSTEM_SERVICE_FILTER_TABLE, *PSYSTEM_SERVICE_FILTER_TABLE;

PSYSTEM_SERVICE_FILTER_TABLE	g_SS_Filter_Table;								//Hook框架的结构体
// 
// 根据某人的逆向认为这个结构尺寸为0x51C，过滤函数的个数0x9E
// 

#define FILTERFUNCNT 0x9E //过滤函数的个数 

typedef struct _FILTERFUN_RULE_TABLE{
	ULONG 	Size; 									//本结构的大小,为0x51C	 
	struct _FILTERFUN_RULE_TABLE 	*Next; 			//偏移为0x4,指向下一个节点 
	ULONG 	IsFilterFunFilledReady;             	//偏移为0x8,标志,表明过滤函数表是否准备好 
	PULONG 	SSDTRuleTableBase;                  	//偏移为0xC,是SSDT函数的过滤规则表,表的大小为SSDTCnt*4 
	PULONG 	ShadowSSDTRuleTableBase;         		//偏移为0x10,是ShadowSSDT函数的过滤规则表,表的大小为ShadowSSDTCnt*4
	UCHAR	FilterRuleName[16];						//偏移为0x14~0x20规则的名字
	PVOID   pModuleBase;							//偏移为0x24,基地址
	ULONG   ModuleSize;								//偏移为0x28,基地址大小
	PULONG 	FakeServiceRoutine[FILTERFUNCNT];    	//偏移为0x2C,过滤函数数组,共有过滤函数0x9E个  (函数)
	PULONG 	FakeServiceRuleFlag[FILTERFUNCNT];    	//偏移为0x2A4,过滤函数数组,共有过滤函数0x9E个 (开关)
}FILTERFUN_RULE_TABLE, *PFILTERFUN_RULE_TABLE;

PFILTERFUN_RULE_TABLE	        g_FilterFun_Rule_table_head;
PFILTERFUN_RULE_TABLE	        g_FilterFun_Rule_table_head_Temp;			    //备份

//dword_1A940
//这里保存这过滤函数地址 
ULONG	filter_function_table[FILTERFUNCNT];
PVOID	filter_function_table_Size_temp;    //临时new出来的变量，大小是：filter_function_table数组大小 * 某个函数大小

#define RULE_MUST_HOOK				1
#define RULE_KERNEL_HOOK			2
#define RULE_GUI_HOOK				3

/*
// sizeof(HOOKPORT_EXTENSION) = 0x18
设备扩展包含了添加规则的接口
1、其他驱动需要增加规则时只需要获取Hookport的驱动扩展访问里面的HookPort_FilterRule_Init初始化一条规则
2、HookPort_SetFilterSwitchFunction 设置规则过滤函数
3、HookPort_SetFilterRuleFlag 设置开关表示启动 or 关闭
State							 启动标识
HookPort_FilterRule_Init		 初始化规则，新建规则会加到规则链中
HookPort_SetFilterSwitchFunction 设置规则过滤函数
HookPort_SetFilterRuleFlag       设置规则开关
HookPort_SetFilterRuleName       设置规则名字
Value3F1						 该驱动版本
*/
typedef struct _HOOKPORT_EXTENSION
{
	_DWORD State;
	_DWORD HookPort_FilterRule_Init;
	_DWORD HookPort_SetFilterSwitchFunction;
	_DWORD HookPort_SetFilterRule;
	_DWORD HookPort_SetFilterRuleName;
	_DWORD Value3F1;
}HOOKPORT_EXTENSION, *PHOOKPORT_EXTENSION;



//nt内核与win32k基地址
typedef struct _HOOKPORT_NT_WIN32K_DATA
{
	//NT内核基地址与大小
	struct
	{
		PVOID NtImageBase;
		ULONG NtImageSize;
	}NtData;
	//ShadowSSDT表信息
	struct
	{
	//win10_14316版本之前
	PVOID ShadowSSDT_GuiServiceTableBase;
	ULONG ShadowSSDT_GuiNumberOfServices;
	PVOID ShadowSSDT_GuiParamTableBase;
	//win10_14316版本之后
	PVOID ShadowSSDT_GuiServiceTableBase_Win10_14316;
	ULONG ShadowSSDT_GuiNumberOfServices_Win10_14316;
	PVOID ShadowSSDT_GuiParamTableBase_Win10_14316;
	}ShadowSSDTTable_Data;
	//SSDT表信息
	struct
	{
		PVOID SSDT_KeServiceTableBase;
		ULONG SSDT_KeNumberOfServices;
		PVOID SSDT_KeParamTableBase;
	}SSDTTable_Data;
}HOOKPORT_NT_WIN32K_DATA, *PHOOKPORT_NT_WIN32K_DATA;

//SSDT表函数地址和索引
typedef struct _SSDT_FUNC_INDEX_DATA
{
	PVOID pZwSetEvent;									//HOOK KiFastCallEntry
	ULONG ZwSetEventIndex;

	PVOID pZwAccessCheckAndAuditAlarm  ;
	ULONG ZwAccessCheckAndAuditAlarmIndex  ;

	PVOID pZwAdjustPrivilegesToken  ;
	ULONG ZwAdjustPrivilegesTokenIndex  ;

	PVOID pZwAllocateVirtualMemory  ;
	ULONG ZwAllocateVirtualMemoryIndex  ;

	PVOID pZwAlpcConnectPort  ;
	ULONG ZwAlpcConnectPortIndex  ;

	PVOID pZwAlpcConnectPortEx  ;
	ULONG ZwAlpcConnectPortExIndex  ;

	PVOID pZwConnectPort  ;
	ULONG ZwConnectPortIndex  ;

	PVOID pZwCreateFile  ;
	ULONG ZwCreateFileIndex  ;

	PVOID pZwCreateKey  ;
	ULONG ZwCreateKeyIndex  ;

	PVOID pZwCreateSection  ;
	ULONG ZwCreateSectionIndex  ;

	PVOID pZwCreateSymbolicLinkObject  ;
	ULONG ZwCreateSymbolicLinkObjectIndex  ;

	PVOID pZwDeleteFile  ;
	ULONG ZwDeleteFileIndex  ;

	PVOID pZwDeleteKey  ;
	ULONG ZwDeleteKeyIndex  ;

	PVOID pZwDeleteValueKey  ;
	ULONG ZwDeleteValueKeyIndex  ;

	PVOID pZwDeviceIoControlFile  ;
	ULONG ZwDeviceIoControlFileIndex  ;

	PVOID pZwDisplayString  ;
	ULONG ZwDisplayStringIndex  ;

	PVOID pZwDuplicateObject  ;
	ULONG ZwDuplicateObjectIndex  ;

	PVOID pZwEnumerateKey  ;
	ULONG ZwEnumerateKeyIndex  ;

	PVOID pZwEnumerateValueKey  ;
	ULONG ZwEnumerateValueKeyIndex  ;

	PVOID pZwFreeVirtualMemory  ;
	ULONG ZwFreeVirtualMemoryIndex  ;

	PVOID pZwFsControlFile  ;
	ULONG ZwFsControlFileIndex  ;

	PVOID pZwLoadDriver  ;
	ULONG ZwLoadDriverIndex  ;

	PVOID pZwLoadKey;
	ULONG ZwLoadKeyIndex;

	PVOID pZwMapViewOfSection  ;
	ULONG ZwMapViewOfSectionIndex  ;

	PVOID pZwMakeTemporaryObject  ;
	ULONG ZwMakeTemporaryObjectIndex  ;
 
	PVOID pZwOpenFile  ;
	ULONG ZwOpenFileIndex  ;

	PVOID pZwOpenKey  ;
	ULONG ZwOpenKeyIndex  ;

	PVOID pZwOpenKeyEx  ;
	ULONG ZwOpenKeyExIndex  ;

	PVOID pZwOpenProcess  ;
	ULONG ZwOpenProcessIndex  ;

	PVOID pZwOpenThread  ;
	ULONG ZwOpenThreadIndex  ;

	PVOID pZwOpenSection  ;
	ULONG ZwOpenSectionIndex  ;

	PVOID pZwOpenSymbolicLinkObject  ;
	ULONG ZwOpenSymbolicLinkObjectIndex  ;

	PVOID pZwQueryKey  ;
	ULONG ZwQueryKeyIndex  ;

	PVOID pZwQueryInformationProcess  ;
	ULONG ZwQueryInformationProcessIndex  ;

	PVOID pZwQueryInformationThread  ;
	ULONG ZwQueryInformationThreadIndex  ;

	PVOID pZwQueryValueKey  ;
	ULONG ZwQueryValueKeyIndex  ;

	PVOID pZwQuerySystemInformation  ;
	ULONG ZwQuerySystemInformationIndex  ;
 
	PVOID pZwReplaceKey  ;
	ULONG ZwReplaceKeyIndex  ;

	PVOID pZwRequestWaitReplyPort  ;
	ULONG ZwRequestWaitReplyPortIndex  ;

	PVOID pZwRestoreKey  ;
	ULONG ZwRestoreKeyIndex  ;
 
	PVOID pZwSecureConnectPort  ;
	ULONG ZwSecureConnectPortIndex  ;

	PVOID pZwSetInformationProcess  ;
	ULONG ZwSetInformationProcessIndex  ;

	PVOID pZwSetInformationFile  ;
	ULONG ZwSetInformationFileIndex  ;

	PVOID pZwSetInformationThread  ;
	ULONG ZwSetInformationThreadIndex  ;

	PVOID pZwSetTimer  ;
	ULONG ZwSetTimerIndex  ;

	PVOID pZwSetSecurityObject  ;
	ULONG ZwSetSecurityObjectIndex  ;

	PVOID pZwSetSystemInformation  ;
	ULONG ZwSetSystemInformationIndex  ;

	PVOID pZwSetSystemTime  ;
	ULONG ZwSetSystemTimeIndex  ;

	PVOID pZwSetValueKey  ;
	ULONG ZwSetValueKeyIndex  ;

	PVOID pZwTerminateProcess  ;
	ULONG ZwTerminateProcessIndex  ;

	PVOID pZwWriteFile  ;
	ULONG ZwWriteFileIndex  ;

	PVOID pZwUnloadDriver  ;
	ULONG ZwUnloadDriverIndex  ;

	PVOID pZwUnmapViewOfSection;
	ULONG ZwUnmapViewOfSectionIndex;
	ULONG ZwUnmapViewOfSectionIndex_Win8_Win10;		//Win7版本基础上这个不知道是什么？

	ULONG ZwRenameKey;

	ULONG ZwRenameKeyIndex;

	ULONG ZwCreateProcessIndex;

	ULONG ZwCreateProcessExIndex;

	ULONG ZwCreateUserProcessIndex;

	ULONG ZwCreateThreadIndex;

	ULONG ZwRequestPortIndex;

	ULONG ZwGetNextProcessIndex;

	ULONG ZwGetNextThreadIndex;

	ULONG ZwVdmControlIndex;

	ULONG ZwCreateMutantIndex;

	ULONG ZwOpenMutantIndex;

	ULONG ZwSystemDebugControlIndex;

	ULONG ZwReadVirtualMemoryIndex;

	ULONG ZwWriteVirtualMemoryIndex;

	ULONG ZwQueueApcThreadIndex;

	ULONG ZwSetContextThreadIndex;

	ULONG ZwProtectVirtualMemoryIndex;

	ULONG ZwAdjustGroupsTokenIndex;

	ULONG ZwWriteFileGatherIndex;

	ULONG ZwResumeThreadIndex;

	ULONG ZwAlpcSendWaitReceivePortIndex;

	ULONG ZwCreateThreadExIndex;

	ULONG ZwQueryAttributesFileIndex;

	ULONG ZwTerminateThreadIndex;

	ULONG ZwAssignProcessToJobObjectIndex;

	ULONG ZwTerminateJobObjectIndex;

	ULONG ZwDebugActiveProcessIndex;

	ULONG ZwSetInformationJobObjectIndex;

	ULONG ZwQueueApcThreadExIndex;

	ULONG ZwContinueIndex;

	ULONG ZwAccessCheckIndex;

	ULONG ZwQueryIntervalProfileIndex;

	ULONG ZwSetIntervalProfileIndex;

	ULONG ZwCreateProfileIndex;

	ULONG ZwSuspendThreadIndex;

	ULONG ZwSuspendProcessIndex;

	ULONG ZwApphelpCaCheControlIndex;

	ULONG ZwLoadKey2Index;

	ULONG ZwLoadKeyExIndex;

	//三个未知的
	ULONG dword_1BAA0;
	ULONG dword_1BB08;
	ULONG dword_1BA98;
}SSDT_FUNC_INDEX_DATA, *PSSDT_FUNC_INDEX_DATA;

//ShadowSSDT表函数地址和索引
typedef struct _SHADOWSSDT_FUNC_INDEX_DATA
{
	ULONG ZwUnmapViewOfSectionIndex;
	ULONG ZwUserSetWinEventHookIndex;
	ULONG ZwUserCallHwndParamLockIndex;
	ULONG ZwUserRegisterUserApiHookIndex;
	ULONG ZwUserSetParentIndex;
	ULONG ZwUserChildWindowFromPointExIndex;
	ULONG ZwUserDestroyWindowIndex;
	ULONG ZwUserInternalGetWindowTextIndex;
	ULONG ZwUserMoveWindowIndex;
	ULONG ZwUserRealChildWindowFromPointIndex;
	ULONG ZwUserSetInformationThreadIndex;
	ULONG ZwUserSetInternalWindowPosIndex;
	ULONG ZwUserSetWindowLongIndex;
	ULONG ZwUserSetWindowPlacementIndex;
	ULONG ZwUserSetWindowPosIndex;
	ULONG ZwUserSetWindowRgnIndex;
	ULONG ZwUserShowWindowIndex;
	ULONG ZwUserShowWindowAsyncIndex;
	ULONG ZwUserSendInputIndex;
	ULONG NtUserCallOneParamIndex;
	ULONG NtUserRegisterWindowMessageIndex;
	ULONG NtUserCallNoParamIndex;
	ULONG NtUserCallTwoParamIndex;
	ULONG NtUserCallHwndLockIndex;
	ULONG NtUserUnhookWindowsHookExIndex;
	ULONG NtUserClipCursorIndex;
	ULONG NtUserGetKeyStateIndex;
	ULONG NtUserGetKeyboardStateIndex;
	ULONG NtUserGetAsyncKeyStateIndex;
	ULONG NtUserAttachThreadInputIndex;
	ULONG NtUserRegisterHotKeyIndex;
	ULONG NtUserRegisterRawInputDevicesIndex;
	ULONG NtGdiBitBltIndex;
	ULONG NtGdiStretchBltIndex;
	ULONG NtGdiMaskBltIndex;
	ULONG NtGdiPlgBltIndex;
	ULONG NtGdiTransparentBltIndex;
	ULONG NtGdiAlphaBlendIndex;
	ULONG NtGdiGetPixelIndex;
	ULONG NtUserGetRawInputDataIndex;
	ULONG NtUserGetRawInputBufferIndex;
	ULONG NtUserSetImeInfoExIndex;
	ULONG NtGdiOpenDCWIndex;
	ULONG NtGdiDeleteObjectAppIndex;
	ULONG NtUserBlockInputIndex;
	ULONG NtUserLoadKeyboardLayoutExIndex;
	ULONG NtGdiAddFontResourceWIndex;
	ULONG NtGdiAddFontMemResourceExIndex;
	ULONG NtGdiAddRemoteFontToDCIndex;
	ULONG ZwUserBuildHwndListIndex;
	ULONG ZwUserQueryWindowIndex;
	ULONG ZwUserFindWindowExIndex;
	ULONG ZwUserWindowFromPointIndex;
	ULONG ZwUserMessageCallIndex;
	ULONG ZwUserPostMessageIndex;
	ULONG ZwUserSetWindowsHookExIndex;
	ULONG ZwUserPostThreadMessageIndex;
	ULONG KeUserModeCallback_ClientLoadLibrary_Index;
	ULONG KeUserModeCallback_ClientImmLoadLayout_Index;
	ULONG KeUserModeCallback_fnHkOPTINLPEVENTMSG_Index;
	ULONG KeUserModeCallback_fnHkINLPKBDLLHOOKSTRUCT_Index;
}SHADOWSSDT_FUNC_INDEX_DATA, *PSHADOWSSDT_FUNC_INDEX_DATA;

HOOKPORT_NT_WIN32K_DATA         g_HookPort_Nt_Win32k_Data;				//保存SSDT和ShadowSSDT和Nt内核基地信息（基址和大小之类的）
SHADOWSSDT_FUNC_INDEX_DATA      g_ShadowSSDT_Func_Index_Data;			//保存shadowSSDT的所有函数与下表索引信息
SSDT_FUNC_INDEX_DATA            g_SSDT_Func_Index_Data;			        //保存SSDT的所有函数与下表索引信息 