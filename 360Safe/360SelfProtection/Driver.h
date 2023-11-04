#pragma once
#include <ntifs.h>
#include "HookPortDeviceExtension.h"
#include "defs.h"
#include "System.h"
#include "WinKernel.h"
#include "Regedit.h"
#include "DebugPrint.h"
#include "SSDT.h"
#include "Command.h"
#include "VirtualMemoryDataList.h"

//设备名称与符号名称
#define	SpShadow_DeviceName			L"\\Device\\360SpShadow0"
#define	SpShadow_LinkName			L"\\DosDevices\\360SpShadow0"

#define	SelfProtection_DeviceName	L"\\Device\\360SelfProtection"
#define	SelfProtection_LinkName		L"\\DosDevices\\360SelfProtection"

#define	HookPort_DeviceName			L"\\Device\\360HookPort"

#define	WIN32KSYS					L"win32k.sys"
#define	SELFPROTECTION_POOLTAG		'King'


//得到设备对象信息
BOOLEAN Safe_GetSymbolicLinkObjectData();

//根据版本获取偏移值
BOOLEAN NTAPI Safe_Initialize_Data();

//Win10未检查的函数
PVOID Safe_1391C_Win10();


//得到SSDT与SSSDT的基地址
NTSTATUS NTAPI Safe_GetSSDTorSSSDTData();

//初始化360Safe特殊进程
VOID NTAPI Safe_InitializeSafeWhiteProcessList();

/**************************开关作用的变量****************************/
//Safe_Initialize_Data
//dword_34E64
ULONG Global_InitializeDataFlag;		//防止二次初始化，置1（函数已执行） 置0（函数未执行）
/**************************开关作用的变量****************************/