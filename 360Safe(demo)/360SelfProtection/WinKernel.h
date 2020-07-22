#pragma once
#include <ntifs.h>
#include "Xor.h"
#include "NoSystemProcessDataList.h"
#include "WhiteList.h"
#include "Data.h"
#include "PE.h"
#define	SELFPROTECTION_POOLTAG		'INFT'


#define ObjectNameInformation		1	

#ifdef _X86_
#define PEB_LDR_DATA_OFFSET           0xC
#elif _AMD64_
#endif

typedef struct _PEB_LDR_DATA
{
	ULONG		Length;
	ULONG		Initialized;
	PVOID		SsHandle;
	LIST_ENTRY	InLoadOrderModuleList; // ref. to PLDR_DATA_TABLE_ENTRY->InLoadOrderModuleList
	LIST_ENTRY	InMemoryOrderModuleList; // ref. to PLDR_DATA_TABLE_ENTRY->InMemoryOrderModuleList
	LIST_ENTRY	InInitializationOrderModuleList; // ref. to PLDR_DATA_TABLE_ENTRY->InInitializationOrderModuleList
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY		InLoadOrderLinks;
	LIST_ENTRY		InMemoryOrderLinks;
	LIST_ENTRY		InInitializationOrderLinks;
	PVOID			DllBase;
	PVOID			EntryPoint;
	ULONG			SizeOfImage;	// in bytes
	UNICODE_STRING	FullDllName;
	UNICODE_STRING	BaseDllName;
	ULONG			Flags;			// LDR_*
	USHORT			LoadCount;
	USHORT			TlsIndex;
	LIST_ENTRY		HashLinks;
	PVOID			SectionPointer;
	ULONG			CheckSum;
	ULONG			TimeDateStamp;
	//    PVOID			LoadedImports;					// seems they are exist only on XP !!!
	//    PVOID			EntryPointActivationContext;	// -same-
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

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

typedef struct _SYSTEM_LOAD_AND_CALL_IMAGE{
	UNICODE_STRING ModuleName;
} SYSTEM_LOAD_AND_CALL_IMAGE, *PSYSTEM_LOAD_AND_CALL_IMAGE;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER   KernelTime;
	LARGE_INTEGER   UserTime;
	LARGE_INTEGER   CreateTime;
	ULONG           WaitTime;
	PVOID           StartAddress;
	CLIENT_ID       ClientId;
	KPRIORITY       Priority;
	KPRIORITY       BasePriority;
	ULONG           ContextSwitchCount;
	LONG            State;// 状态,是THREAD_STATE枚举类型中的一个值
	LONG            WaitReason;//等待原因, KWAIT_REASON中的一个值
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFRMATION
{
	ULONG           NextEntryDelta;//指向下一个结构体的指针
	ULONG           ThreadCount;//本进程的总线程数
	ULONG           Reserved1[6];//保留
	LARGE_INTEGER   CreateTime;//进程创建的时间
	LARGE_INTEGER   UserTime;//在用户层的使用时间
	LARGE_INTEGER   KernelTime;//在内核层的使用时间
	UNICODE_STRING  ProcessName; // 进程名
	KPRIORITY       BasePriority;
	ULONG           ProcessId;//进程ID
	ULONG           InheritedFromProcessId;
	ULONG           HandleCount; // 进程的句柄总数
	ULONG           Reserved2[2]; // 保留
	VM_COUNTERS     VmCounters;
	IO_COUNTERS     IoCounters;
	SYSTEM_THREAD_INFORMATION Threads[1]; // 子线程信息数组
}SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

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

NTSTATUS ZwQueryDirectoryObject(
	IN HANDLE       DirectoryHandle,
	OUT PVOID       Buffer,
	IN ULONG        Length,
	IN BOOLEAN      ReturnSingleEntry,
	IN BOOLEAN      RestartScan,
	IN OUT PULONG   Context,
	OUT PULONG      ReturnLength OPTIONAL
	);

NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID *Object
);

// 基本信息定义  
typedef struct _DIRECTORY_BASIC_INFORMATION {
	UNICODE_STRING ObjectName;
	UNICODE_STRING ObjectTypeName;
} DIRECTORY_BASIC_INFORMATION, *PDIRECTORY_BASIC_INFORMATION;

//根据函数名获取指定内核基址
BOOLEAN NTAPI Safe_GetModuleBaseAddress(IN PUNICODE_STRING ModuleName, OUT PVOID *pModuleBase, OUT ULONG *ModuleSize, OUT USHORT *LoadOrderIndex);

//PsGetProcessImageFileName函数
ULONG NTAPI Safe_PsGetProcessImageFileName(PEPROCESS Process, UCHAR* ImageFileName, ULONG ImageFileNameLen);

//比较ImageFileName
//相同返回1，不同返回非0
BOOLEAN NTAPI Safe_CmpImageFileName(UCHAR *ImageFileName);

//通过编程方式使用 MDL 绕过 KiServiceTable 的只读属性
PVOID Safe_LockMemory(PVOID VirtualAddress, ULONG Length, PVOID *Mdl_a3);

//释放MDL空间
PVOID  Safe_RemoveLockMemory(PMDL pmdl);

//new空间
PVOID Safe_AllocBuff(POOL_TYPE PoolType, ULONG Size, ULONG Tag);

//释放空间
PVOID Safe_ExFreePool(IN PVOID pBuff);

//获取ZwOpenSymbolicLinkObject函数地址并执行
NTSTATUS NTAPI Safe_RunZwOpenSymbolicLinkObject(OUT PHANDLE LinkHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG Version_Flag, IN PVOID ServiceTableBase, IN ULONG NumberOfServices);

// 查询对象
BOOLEAN NTAPI Safe_ZwQueryDirectoryObject(IN PUNICODE_STRING CmpString_a1, IN HANDLE DirectoryHandle, IN PUNICODE_STRING CmpString_a3);

//PsGetProcessId函数
ULONG NTAPI Safe_pPsGetProcessId(PVOID VirtualAddress);

//通过Handle获取Eprocess->UniqueProcessId
HANDLE NTAPI Safe_GetUniqueProcessId(HANDLE Handle);

//查找符号链接（带Open）
BOOLEAN NTAPI Safe_ZwQuerySymbolicLinkObject_Open(IN PUNICODE_STRING ObjectName, IN HANDLE DirectoryHandle, OUT PUNICODE_STRING Out_LinkTarget);

//查找符号链接(不带Open)
BOOLEAN NTAPI Safe_ZwQuerySymbolicLinkObject(IN HANDLE LinkHandle, OUT PUNICODE_STRING Out_LinkTarget);

//ZwCreateFile和ZwOpenFile使用的
//禁止用户打开受保护路径
BOOLEAN NTAPI Safe_CheckProtectPath(IN HANDLE FileHandle, IN KPROCESSOR_MODE AccessMode);

//获取句柄权限
NTSTATUS NTAPI Safe_GetGrantedAccess(IN HANDLE Handle, OUT PACCESS_MASK Out_GrantedAccess);

//根据LDR链获取该DLL导入表信息
ULONG NTAPI Safe_PeLdrFindExportedRoutineByName(IN PCHAR In_SourceAPINameBuff, IN ULONG In_Flag);

//查找ProcessHandleCount、ProcessHandleTracing、ProcessBasicInformation
NTSTATUS NTAPI Safe_ZwQueryInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT ULONG ReturnLength);

//这个函数我没看懂，获取句柄个数失败
BOOLEAN NTAPI Safe_QueryProcessHandleOrHandleCount(IN HANDLE ProcessHandle);

//查询线程信息的
//遍历进程PID，找到继续判断进程线程个数等于1时候（刚创建时候就满足）
BOOLEAN NTAPI Safe_FindEprocessThreadCount(IN HANDLE In_ProcessHandle, IN BOOLEAN In_Flag);

/************************PE结构数字签名相关(废弃)*****************************/
BOOLEAN NTAPI Safe_CheckProcessNameSign(IN UNICODE_STRING SourceString);
BOOLEAN NTAPI Safe_18108(IN PCWSTR SourceString);
/************************PE结构数字签名相关(废弃)*****************************/









