#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>
#include "Data.h"
#include "DrvmkDataList.h"
#include "WinKernel.h"
#include "SafeWarning.h"
#include "WinBase.h"
#include "MemCheck.h"
#include "Object.h"

//全局变量
UNICODE_STRING g_ControlSet00XPath;				//保存\\Registry\\Machine\\SYSTEM\\ControlSet00%d\\services路径
WCHAR g_RegServicePath[0x256];
ULONG g_ObjectType;								//_OBJECT_TYPE			

//服务的类型
typedef enum SERVICE_TYPE {
	CLOSESERVICEHANDLE_TYPE,		//CloseServiceHandle
	CONTROLSERVICE_TYPE,			//ControlService
	DELETESERVICE_TYPE,				//DeleteService
	UNKNOWN_SERVICETYPE_3,
	UNKNOWN_SERVICETYPE_4,
	UNKNOWN_SERVICETYPE_5,
	QUERYSERVICESTATUS_TYPE,		//QueryServiceStatus(0x6)		
	UNKNOWN_SERVICETYPE_7,
	UNKNOWN_SERVICETYPE_8,
	UNKNOWN_SERVICETYPE_9,			
	UNKNOWN_SERVICETYPE_A,
	CHANGESERVICECONFIGW_TYPE,		//ChangeServiceConfigW
	CREATESERVICEW_TYPE,			//CreateServiceW
	UNKNOWN_SERVICETYPE_D,
	UNKNOWN_SERVICETYPE_E,
	OPENSCMANAGERW_TYPE,			//OpenSCManagerW
	OPENSERVICEW_TYPE,				//OpenServiceW(0x10)
	UNKNOWN_SERVICETYPE_11,
	UNKNOWN_SERVICETYPE_12,
	STARTSERVICEW_TYPE,				//StartServiceW(0x13)
	UNKNOWN_SERVICETYPE_14,
	UNKNOWN_SERVICETYPE_15,
	UNKNOWN_SERVICETYPE_16,
	CHANGESERVICECONFIGA_TYPE,		//ChangeServiceConfigA
	CREATESERVICEA_TYPE,			//CreateServiceA
	UNKNOWN_SERVICETYPE_19,
	UNKNOWN_SERVICETYPE_1A,
	OPENSCMANAGERA_TYPE,			//OpenSCManagerA
	OPENSERVICEA_TYPE,				//OpenServiceA(0x1C)
	UNKNOWN_SERVICETYPE_1D,
	UNKNOWN_SERVICETYPE_1E,
	STARTSERVICEA_TYPE,			    //StartServiceA(0x1F)
	UNKNOWN_SERVICETYPE_20,
	UNKNOWN_SERVICETYPE_21,
	UNKNOWN_SERVICETYPE_22,
	UNKNOWN_SERVICETYPE_23,
	UNKNOWN_SERVICETYPE_24,
	UNKNOWN_SERVICETYPE_25,
	UNKNOWN_SERVICETYPE_26,
	UNKNOWN_SERVICETYPE_27,
	QUERYSERVICESTATUSEX_TYPE,		//QueryServiceStatusEx
	UNKNOWN_SERVICETYPE_29,
	UNKNOWN_SERVICETYPE_2A,
	UNKNOWN_SERVICETYPE_2B,
	UNKNOWN_SERVICETYPE_2C,
	UNKNOWN_SERVICETYPE_2D,
	UNKNOWN_SERVICETYPE_2E,
	UNKNOWN_SERVICETYPE_2F,
	UNKNOWN_SERVICETYPE_30,
	UNKNOWN_SERVICETYPE_31,
	CONTROLSERVICEEXA_TYPE,			//ControlServiceExA
	CONTROLSERVICEEXW_TYPE,			//ControlServiceExW
	UNKNOWN_SERVICETYPE_34,
	UNKNOWN_SERVICETYPE_35,
	UNKNOWN_SERVICETYPE_36,
	UNKNOWN_SERVICETYPE_37,
	UNKNOWN_SERVICETYPE_38,
	UNKNOWN_SERVICETYPE_39,
	UNKNOWN_SERVICETYPE_3A,
	UNKNOWN_SERVICETYPE_3B,
	UNKNOWN_SERVICETYPE_3C,
	UNKNOWN_SERVICETYPE_3D,
	UNKNOWN_SERVICETYPE_3E,
	UNKNOWN_SERVICETYPE_3F
} SERVICE_TYPE;

//检查文件对象指针是不是分页文件
BOOLEAN NTAPI Safe_RunFsRtlIsPagingFile(IN PFILE_OBJECT In_FileObject);

//查询注册表HIVELIST
BOOLEAN NTAPI Safe_QuerHivelist(IN ACCESS_MASK GrantedAccess, IN HANDLE In_SourceHandle, IN HANDLE In_SourceProcessHandle);

//获取指定路径的文件信息与传入文件信息比较，相等返回1
BOOLEAN Safe_QueryValueKeyInformation(IN HANDLE In_KeyHandle, IN PUNICODE_STRING In_TargetString, IN PSYSTEM_INFORMATIONFILE_XOR In_System_Information);

//开关置g_HookSrvTransactionNotImplementedFlag
NTSTATUS NTAPI Safe_SetRegedit_DisableDPHotPatch(IN ULONG *Data, IN ULONG Type, IN ULONG DataLength, IN ULONG Flag);

//这个->Data读取的是REG_SZ类型的
NTSTATUS NTAPI Safe_SetRegedit_RULE_360Safe(IN PCWSTR Data, IN ULONG Type, IN ULONG DataLength, IN ULONG Flag);

//这个->Data读取的是REG_SZ类型的
NTSTATUS NTAPI Safe_SetRegedit_TextOutCache(IN PCWSTR Data, IN ULONG Type, IN ULONG DataLength, IN ULONG Flag);

//这个->Data读取的是REG_DWORD类型的
NTSTATUS NTAPI Safe_SetRegedit_SpShadow0(IN ULONG *Data, IN ULONG Type, IN ULONG DataLength, IN ULONG Flag);

//这个->Data读取的是REG_DWORD类型的
NTSTATUS NTAPI Safe_SetRegedit_i18h(IN ULONG *Data, IN ULONG Type, IN ULONG DataLength, IN ULONG Flag);

//查询注册表键值
BOOLEAN NTAPI Safe_QuerRegedit(IN PUNICODE_STRING ObjectName, IN PCWSTR ValueName,IN ULONG Func,IN ULONG Flag);

//初始化注册表信息的
BOOLEAN NTAPI Safe_Initialize_RegeditData(IN PUNICODE_STRING ObjectName, IN ULONG Flag);

//获取到\\Registry\\Machine\\SYSTEM\\ControlSet00%d\\services路径
NTSTATUS NTAPI Safe_GetControlSet00XPath();

//获取注册表KeyValueFullInformation信息
//返回值：KeyValueFullInformation地址
PVOID NTAPI Safe_GetKeyValueFullInformation(IN HANDLE In_KeyHandle, IN PUNICODE_STRING ValueName);

//查询各种白名单注册表键值是否存在例如各种：RULE_360xxxx之类的
NTSTATUS NTAPI Safe_EnumerateValueKey(IN PUNICODE_STRING ObjectName, IN ULONG Flag);

//判断拦截还是放行加载驱动
NTSTATUS NTAPI Safe_CheckSys(IN HANDLE KeyHandle, IN HANDLE CurrentProcessId, IN HANDLE CurrentThreadId, IN ULONG Flag);

//判断当前驱动加载路径 == ControlSet001
BOOLEAN NTAPI Safe_CheckControlSetPath(IN HANDLE KeyHandle, IN ULONG NameLength);

//设置驱动路径
NTSTATUS NTAPI Safe_SetImagePathString(IN PUNICODE_STRING In_SysString, IN HANDLE KeyHandle, OUT PUNICODE_STRING Ou_ImagePathString);

//字符串后面添加上.sys
BOOLEAN NTAPI Safe_AppendString_Sys(IN PUNICODE_STRING SysNameString);

//根据服务类型做不同的处理
NTSTATUS NTAPI Safe_RPCDispatcher(IN PVOID In_SendMessage, IN HANDLE In_PortHandle);

//比较指定Port名字的object，相同1，不同0
BOOLEAN NTAPI Safe_CmpObReferenceObjectByName(PUNICODE_STRING In_CmpPortName, PVOID In_Object);

//比较Port名字，相同1，不同0    
BOOLEAN NTAPI Safe_CmpPortName(IN HANDLE In_PortHandle, IN PUNICODE_STRING In_CmpPortName);

//获取当前用户的SID
NTSTATUS NTAPI Safe_RunRtlFormatCurrentUserKeyPath(OUT PUNICODE_STRING CurrentUserKeyPath);

