#pragma once
#include	<ntifs.h>
#include	"defs.h"
#include	"Data.h"
#include    "System.h"
#include    "WinKernel.h"
#include    "DebugPrint.h"
#include    "Win32k.h"
#include	"SSDT.h"
#include    "FilterHook.h"
#include    "KiFastCallEntry.h"
#include    "Filter_ZwDisplayString.h"

extern PULONG InitSafeBootMode;

#define ObjectNameInformation		1	

//通讯命令
#define HOOKPORT_GETVER            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0801, METHOD_BUFFERED, FILE_ANY_ACCESS)	    //返回HookPort版本号
#define HOOKPORT_DEBUGMEASSAGE1    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0802, METHOD_BUFFERED, FILE_ANY_ACCESS)		//输出Debug信息开关（无用）DbgPrintf_dword_1B174
#define HOOKPORT_DEBUGMEASSAGE2    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0803, METHOD_BUFFERED, FILE_ANY_ACCESS)		//输出Debug信息开关（无用）DbgPrintf_dword_1AFA0
#define HOOKPORT_DEBUGMEASSAGE3    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0804, METHOD_BUFFERED, FILE_ANY_ACCESS)		//输出Debug信息开关（无用）DbgPrintf_dword_1B178
#define HOOKPORT_DEBUGMEASSAGE4    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0805, METHOD_BUFFERED, FILE_ANY_ACCESS)		//R3传递一个时间，A点到B点执行代码时间必须小于该时间才打印调试信息，难道防止被调试（无用）

ULONG     DbgPrintf_dword_1B174 = NULL;		//无用
ULONG     DbgPrintf_dword_1AFA0 = NULL;     //无用
ULONG     DbgPrintf_dword_1B178 = NULL;     //无用
ULONGLONG DbgPrintf_qdword_1AFB0 = NULL;	//检查代码执行时间

//我逆向的版本是0x3F1
#define HOOKPORT_VERSION                    0x3F1	

//自旋锁的参数
KSPIN_LOCK	g_Filter_Rule_SpinLock;

typedef NTSTATUS(NTAPI *pPsAcquireProcessExitSynchronization)(__in PEPROCESS Process);
//dword_1A710
pPsAcquireProcessExitSynchronization	PsAcquireProcessExitSynchronization;
#define		PsAcquireProcessExitSynchronizationName  L"PsAcquireProcessExitSynchronization"


typedef NTSTATUS(NTAPI *pPsReleaseProcessExitSynchronization)(__in PEPROCESS Process);
//dword_1A714PsReleaseProcessExitSynchronization
pPsReleaseProcessExitSynchronization	PsReleaseProcessExitSynchronization;
#define		PsReleaseProcessExitSynchronizationName  L"PsReleaseProcessExitSynchronization"

////获取csrss的进程id
HANDLE	HookPort_GetApiPortProcessId(IN RTL_OSVERSIONINFOEXW osverinfo);

//IAT hook KeUserModeCallback
VOID HookPort_HookKeUserModeCallback(IN ULONG Version_Win10_Flag);

//初始化SSDT、ShadowSSDT等部分
NTSTATUS NTAPI HookPort_InitSDT();

//获取SSDT与ShadowSSDT原始地址和索引
BOOLEAN  NTAPI HookPort_GetAllNativeFunAddress(PVOID* NtImageBase, IN RTL_OSVERSIONINFOEXW osverinfo);

//获取指定函数基址
BOOLEAN NTAPI HookPort_GetNativeFunAddress(PVOID* NtImageBase);

//初始化Nt内核函数索引 
BOOLEAN HookPort_InitializeIndex();

//初始化过滤数组
ULONG HookPort_InitFilterTable();

//解密哈希
BOOLEAN  HookPort_GetModuleBaseAddress_EncryptHash(IN ULONG Hash, OUT PVOID *pModuleBase, OUT ULONG *ModuleSize, OUT ULONG *LoadOrderIndex);

//Filter_LoadImageNotifyRoutine对应的Fake函数
ULONG Fake_LoadImageNotifyRoutine(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg);

//不知道具体用途
ULONG Fake_VacancyFunc(ULONG a1, ULONG a2, ULONG a3, ULONG a4);

//函数功能：
//1、根据条件判断是否启用FakeKiSystemService的hook
//2、初始化扩展结构，导出给另外一个sys使用
PVOID HookPort_19230();

//获取驱动的启动加载顺序 
ULONG HookPort_1858E(OUT ULONG *Flag_1, OUT ULONG *Flag_2, OUT PVOID *ValueDataBuff);

//准备缓冲区存放HOOK需要用的数据
BOOLEAN  HookPort_AllocFilterTable();

//初始化导出接口
ULONG NTAPI HookPort_InitDeviceExtInterface(IN PDEVICE_OBJECT DeviceObject);

//初始化规则，新建规则会加到规则链中
PVOID NTAPI HookPort_AllocFilterRuleTable(IN ULONG NumberOfBytes);

//设置规则名字
ULONG NTAPI HookPort_SetFilterRuleName(IN PFILTERFUN_RULE_TABLE FilterFun_Rule_table_head, IN CHAR *FilterRuleName);

//设置规则开关
VOID NTAPI HookPort_SetFilterRule(IN PFILTERFUN_RULE_TABLE	filter_rule, IN ULONG index, IN ULONG rule);

//设置规则过滤函数
BOOLEAN NTAPI HookPort_SetFilterSwitchFunction(IN PFILTERFUN_RULE_TABLE filter_rule, IN ULONG index_a2, OUT PVOID func_addr);
