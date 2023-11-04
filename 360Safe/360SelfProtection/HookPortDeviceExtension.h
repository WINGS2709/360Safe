#pragma once
#include <ntifs.h>
#include "Fake_KeUserModeCallback.h"
#include "Fake_CreateProcessNotifyRoutine.h"
#include "Fake_ZwOpenMutant.h"
#include "Fake_ZwWriteFile.h"
#include "Fake_ZwOpenFile.h"
#include "Fake_ZwOpenThread.h"
#include "Fake_ZwSetSystemInformation.h"
#include "Fake_ZwAlpcSendWaitReceivePort.h"
#include "Fake_ZwOpenSection.h"
#include "Fake_ZwCreateFile.h"
#include "Fake_ZwGetNextProcess.h"
#include "Fake_ZwGetNextThread.h"
#include "Fake_ZwCreateSection.h"
#include "Fake_ZwDeleteFile.h"
#include "Fake_ZwCreateProcess.h"
#include "Fake_ZwOpenKey.h"
#include "Fake_ZwUnmapViewOfSection.h"
#include "Fake_ZwSuspendProcess.h"
#include "Fake_ZwSuspendThread.h"
#include "Fake_ZwAllocateVirtualMemory.h"
#include "Fake_ZwLoadDriver.h"
#include "Fake_ZwOpenProcess.h"
#include "Fake_ZwWriteVirtualMemory.h"
#include "Fake_ZwCreateThread.h"
#include "Fake_ZwSetSystemTime.h"
#include "Fake_ZwCreateSymbolicLinkObject.h"
#include "Fake_ZwTerminateProcess.h"
#include "Fake_ZwDuplicateObject.h"
#include "Fake_ZwMakeTemporaryObject.h"
#include "Fake_ZwEnumerateValueKey.h"
#include "Fake_ZwDeleteKey.h"
#include "Fake_ZwReplaceKey.h"
#include "Fake_ZwRenameKey.h"
#include "Fake_ZwRestoreKey.h"
#include "Fake_ZwUserBuildHwndList.h"
/**************************Fake函数（核心）***************************/
//删除注册表项
#define ZwDeleteKey_FilterIndex								0x2

//重命名
#define ZwRenameKey_FilterIndex								0x4

//取代注册表项
#define ZwReplaceKey_FilterIndex							0x5

//恢复注册表项
#define ZwRestoreKey_FilterIndex							0x6

//创建文件
#define ZwCreateFile_FilterIndex							0x8

//写文件
#define	ZwWriteFile_FilterIndex								0xB

//创建进程
#define	ZwCreateProcess_FilterIndex							0xD

//创建进程Ex
#define	ZwCreateProcessEx_FilterIndex						0xE

//创建进程
#define	ZwCreateUserProcess_FilterIndex						0xF

//创建线程
#define ZwCreateThread_FilterIndex							0x10 

//打开线程
#define ZwOpenThread_FilterIndex							0x11

//删除文件
#define ZwDeleteFile_FilterIndex							0x12

//打开文件
#define ZwOpenFile_FilterIndex								0x13 

//结束进程
#define ZwTerminateProcess_FilterIndex						0x15 

//跨进程写内容
#define ZwWriteVirtualMemory_FilterIndex	                0x1A

//
#define ZwRequestWaitReplyPort_FilterIndex                  0x1D

//创建文件映射
#define ZwCreateSection_FilterIndex							0x1E

//打开section object
#define ZwOpenSection_FilterIndex							0x1F

//创建符号链接
#define ZwCreateSymbolicLinkObject_FilterIndex				0x20

//加载驱动
#define ZwLoad_Un_Driver_FilterIndex						0x22

//
#define ZwQuerySystemInformation_FilterIndex				0x23

//加载驱动
#define ZwSetSystemInformation_FilterIndex					0x24

//设置时间
#define ZwSetSystemTime_FilterIndex                         0x25

//枚举所有顶层窗口
#define ZwUserBuildHwndList_FilterIndex                     0x27

//打开进程
#define ZwOpenProcess_FilterIndex							0x2F

//打开注册表键值
#define ZwOpenKey_FilterIndex								0x32

//拷贝句柄
#define ZwZwDuplicateObject_FilterIndex						0x33

//RPC通讯
#define ZwAlpcSendWaitReceivePort_FilterIndex               0x44

//进程回调
#define	CreateProcessNotifyRoutine_FilterIndex				0x45

//取消映射目标进程的内存
#define ZwUnmapViewOfSection_FilterIndex					0x46

//拦截DLL注入的
#define	ClientLoadLibrary_FilterIndex						0x4B

//分配空间
#define ZwAllocateVirtualMemory_FilterIndex					0x4E

//打开互斥体
#define ZwOpenMutant_FilterIndex							0x51

//遍历线程
#define ZwGetNextThread_FilterIndex							0x53

//遍历进程
#define ZwGetNextProcess_FilterIndex						0x54

//枚举valuekey
#define ZwEnumerateValueKey_FilterIndex						0x59

//永久对象转化成临时对象
#define ZwMakeTemporaryObject_FilterIndex                   0x7F

//线程挂起
#define ZwSuspendThread_FilterIndex							0x93

//进程挂起
#define	ZwSuspendProcess_FilterIndex					    0x94

//取消映射目标进程的内存 Win8~Win10
#define ZwUnmapViewOfSectionIndex_Win8_Win10_FilterIndex	0x96
/**************************Fake函数（核心）***************************/

#define FILTERFUNCNT 0x9E //过滤函数的个数 

typedef struct _FILTERFUN_RULE_TABLE {
	ULONG 	Size; 									//本结构的大小,为0x51C	 
	struct _FILTERFUN_RULE_TABLE 	*Next; 			//偏移为0x4,指向下一个节点 
	ULONG 	IsFilterFunFilledReady;             	//偏移为0x8,标志,表明过滤函数表是否准备好 
	PULONG 	SSDTRuleTableBase;                  	//偏移为0xC,是SSDT函数的过滤规则表,表的大小为SSDTCnt*4 
	PULONG 	ShadowSSDTRuleTableBase;         		//偏移为0x10,是ShadowSSDT函数的过滤规则表,表的大小为ShadowSSDTCnt*4
	UCHAR	FilterRuleName[16];						//偏移为0x14~0x20规则的名字
	PVOID   pModuleBase;							//偏移为0x24,未明确
	ULONG   ModuleSize;								//偏移为0x28,未明确
	PULONG 	FakeServiceRoutine[FILTERFUNCNT];    	//偏移为0x2C,过滤函数数组,共有过滤函数0x9E个  (函数)
	PULONG 	FakeServiceRuleFlag[FILTERFUNCNT];    	//偏移为0x2A4,过滤函数数组,共有过滤函数0x9E个 (开关)
}FILTERFUN_RULE_TABLE, *PFILTERFUN_RULE_TABLE;

/*
// sizeof(HOOKPORT_EXTENSION) = 18u
设备扩展包含了添加规则的接口，其他驱动需要增加规则时只需要获取Hookport的驱动扩展访问里面的HookPort_FilterRule_Init初始化一条规则，HookPort_SetFilterSwitchFunction 设置规则过滤函数。
HookPort_FilterRule_Init		 初始化规则，新建规则会加到规则链中
HookPort_SetFilterSwitchFunction 设置规则过滤函数
HookPort_SetFilterRuleFlag       设置规则开关
HookPort_SetFilterRuleName       设置规则名字
*/
typedef struct _HOOKPORT_EXTENSION
{
	ULONG State;
	ULONG HookPort_FilterRule_Init;
	ULONG HookPort_SetFilterSwitchFunction;
	ULONG HookPort_SetFilterRule;
	ULONG HookPort_SetFilterRuleName;
	ULONG Value3F1;
}HOOKPORT_EXTENSION, *PHOOKPORT_EXTENSION;

//dword_1B10C
//PFILTERFUN_RULE_TABLE	g_FilterFun_Rule_table_head;

//dword_1B11C
PFILTERFUN_RULE_TABLE	g_FilterFun_Rule_table_head_Temp;	//备份

															//初始化规则，新建规则会加到规则链中
ULONG(NTAPI *HookPort_AllocFilterRuleTable)(ULONG);

//设置规则名字
ULONG(NTAPI *HookPort_SetFilterRuleName)(PFILTERFUN_RULE_TABLE, CHAR*);

//设置规则开关
VOID(NTAPI *HookPort_SetFilterRule)(PFILTERFUN_RULE_TABLE	After_rule, ULONG index, ULONG	rule);

//设置规则过滤函数
BOOLEAN(NTAPI *HookPort_SetFilterSwitchFunction)(PFILTERFUN_RULE_TABLE After_rule, ULONG index, PVOID func_addr);

//初始化所有规则过滤函数
ULONG Safe_Initialize_SetFilterSwitchFunction();

//初始化所有规则开关
VOID NTAPI Safe_Initialize_SetFilterRule(PDEVICE_OBJECT pHookPortDeviceObject);

//检查HookPort_SetFilterSwitchFunction是否获取成功
ULONG NTAPI Safe_Run_SetFilterSwitchFunction(PFILTERFUN_RULE_TABLE After_rule, ULONG index, PVOID func_addr);

//检查HookPort_SetFilterRule是否获取成功
ULONG NTAPI Safe_Run_SetFilterRule(PFILTERFUN_RULE_TABLE After_rule, ULONG index, ULONG	rule);