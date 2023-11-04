#pragma once
#include <ntifs.h>
#include "WinKernel.h"
#include "Data.h"
#include "DebugPrint.h"
#include "IDT.h"
#include "FilterHook.h"

#define CPUNUMBERMAX  0x32													//CPU个数最大不超过32
//Fake_ZwSetEvent函数相关的标志位
HANDLE Global_Fake_ZwSetEvent_Handle;										//虚假的ZwSetEvent句柄（暗号）
ULONG  Global_ZwSetEventHookFlag;											//判断Fake_ZwSetEvent函数是否执行成功
ULONG  Global_IdtHook_Or_InlineHook;										//判断采用IDT或则传统InlineHook方式

//Fake_ZwSetEvent函数使用的变量
PVOID p_jmpstub_code;														//new空间存储构造的跳转指令
ULONG p_jmpstub_codeLen ;													//new空间长度
ULONG g_DpcFlag_dword_1B41C;
KSPIN_LOCK g_SpinLock_WhiteList;

// 这是从伪KiFastCallEntry的返回地址
// dword_1A6F4
PVOID g_KiFastCallEntry_Fake_rtn_address;


KDPC g_Dpc[CPUNUMBERMAX];

//360HOOK点
PVOID g_KiFastCallEntry_360HookPoint;										//高版本>2003
PVOID g_Fake_KiSystemServiceFuncAddress;									//低版本<2003
//IDT方式的hook
ULONG Global_KiTrap04;

//HookPort_Hook_153D0函数使用的，用来Dpc计数的
typedef struct _TsFlt_DPC
{
	PKSPIN_LOCK pSpinLock;
	PULONG pFlag;
}TsFlt_DPC, *PTsFlt_DPC;

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


//不带浮点5字节hook
VOID NTAPI HookPort_InlineHook5Byte_1521C(ULONG JmpAddress_a1, ULONG MdlAddress_a2, ULONG a3, ULONG a4);

//带浮点5字节hook
VOID NTAPI HookPort_InterlockedCompareExchange64_15236(ULONG* a1, ULONG a2, ULONG a3, ULONG a4);

/**********通过hook ZwSetEvent函数方式来修改KiFastCallEntry***********/
//高版本>2003 KiFastCallEntry

NTSTATUS NTAPI HookPort_InstallZwSetEventHook();
NTSTATUS NTAPI Fake_ZwSetEvent(HANDLE EventHandle, PULONG PreviousState);
ULONG sub_1567A(IN RTL_OSVERSIONINFOEXW osverinfo);															//完全没看明白这个函数在干嘛？？？？？？
/**********通过hook ZwSetEvent函数方式来修改KiFastCallEntry***********/

/**********Hook KiSystemService**************************************/
//低版本<2003 KiSystemService

//InlineHook hook掉KiSystemService
BOOLEAN HookPort_SetFakeKiSystemServiceAddress();

//获取KiSystemService的Hook点
ULONG HookPort_GetKiSystemService_HookPoint(IN ULONG MmUserProbeAddress, IN ULONG NtImageBase, IN ULONG NtImageSize, OUT ULONG *Index);

//有空再逆把
//跟Fake_ZwSetEvent基本一致
ULONG HookPort_SetFakeKiSystemServiceData(ULONG ImageBase_a1, ULONG ImageSize_a2);
/**********Hook KiSystemService**************************************/
