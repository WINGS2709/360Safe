#pragma once
#include <ntddk.h>
#include <ntimage.h>
#include "defs.h"
#define	SELFPROTECTION_POOLTAG		'INFT'

ULONG dword_1B170;					//sub_193F2用来计数，结果是：取值0~2之间

typedef struct tagSYSTEM_MODULE_INFORMATION {
	ULONG Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

//
// System Information Classes.
//
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,              // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,                //系统进程信息
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,				//系统模块
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadImage,					   //26 加载驱动
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemLoadAndCallImage,					//38 加载驱动
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass   // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

extern
NTSTATUS
ZwQuerySystemInformation(
IN ULONG SystemInformationClass,
IN PVOID SystemInformation,
IN ULONG SystemInformationLength,
OUT PULONG ReturnLength);

NTSTATUS
NTAPI
ZwQueryInformationProcess(
IN HANDLE ProcessHandle,
IN PROCESSINFOCLASS ProcessInformationClass,
OUT PVOID ProcessInformation,
IN ULONG ProcessInformationLength,
OUT PULONG ReturnLength OPTIONAL
);

extern
PVOID NTAPI
RtlImageDirectoryEntryToData(
IN PVOID          BaseAddress,
IN BOOLEAN        ImageLoaded,
IN ULONG		   Directory,
OUT PULONG        Size);

typedef struct _SYSTEM_HANDLE_INFORMATION{
	ULONG ProcessID;                //进程的标识ID 
	UCHAR ObjectTypeNumber;         //对象类型 
	UCHAR Flags;					//0x01 = PROTECT_FROM_CLOSE,0x02 = INHERIT 
	USHORT Handle;					//对象句柄的数值 
	PVOID  Object;					//对象句柄所指的内核对象地址 
	ACCESS_MASK GrantedAccess;      //创建句柄时所准许的对象的访问权 
}SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

PVOID HookPort_GetSymbolAddress(PANSI_STRING SymbolName, PVOID NtImageBase);

PVOID NTAPI HookPort_GetAndReplaceSymbol(PVOID ImageBase, PANSI_STRING SymbolName, PVOID ReplaceValue, PVOID *SymbolAddr);

PVOID NTAPI HookPort_QuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass);

BOOLEAN  HookPort_FindModuleBaseAddress(ULONG func_addr, PVOID *pModuleBase_a2, ULONG *ModuleSize_a3, PVOID *FilterRuleName, ULONG RuleNameLen);


// 此函数查找或修改ModuleName指定的模块中的FunctionName指定的函数
PULONG  HookPort_HookImportedFunction(PVOID pModuleBase, ULONG ModuleSize, CONST CHAR *FunctionName, CONST CHAR *ModuleName, PVOID *RetValue);

//恢复内存保护 
VOID PageProtectOn();

////去掉内存保护
VOID PageProtectOff();

//释放MDL
VOID  HookPort_RemoveLockMemory(PMDL pmdl);
//映射MDL
PVOID HookPort_LockMemory(PVOID VirtualAddress, ULONG Length, PVOID *Mdl_a3, ULONG Version_Win10_Flag);

//获取CPU数目
ULONG HookPort_CheckCpuNumber(IN RTL_OSVERSIONINFOEXW osverinfo);

//获取csrss的进程id
HANDLE	HookPort_GetApiPortProcessId(IN RTL_OSVERSIONINFOEXW osverinfo);

//根据本驱动对象的成员(DriverObject->DriverStart)获取自身LoadOrderIndex 
BOOLEAN  HookPort_GetModuleLoadOrderIndex(IN PVOID pModuleBase, OUT ULONG *LoadOrderIndex);

//根据函数名获取指定内核基址
BOOLEAN NTAPI HookPort_GetModuleBaseAddress(IN CONST CHAR *ModuleName, OUT PVOID *pModuleBase, OUT ULONG *ModuleSize, OUT USHORT *LoadOrderIndex);

//检查合法版本号
ULONG HookPort_CheckSysVersion(IN RTL_OSVERSIONINFOEXW osverinfo, IN PVOID *NtImageBase);