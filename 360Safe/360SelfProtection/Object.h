#pragma once
#include <ntifs.h>
#include "Data.h"
#include "WinKernel.h"

NTSTATUS(NTAPI *pSeDeleteObjectAuditAlarmWithTransaction)(PVOID, HANDLE, ULONG);

//根据Object查询注册表路径
NTSTATUS NTAPI Safe_ObGetObjectNamePath(IN HANDLE In_ObjectHandle, OUT POBJECT_NAME_INFORMATION Out_ObjectNameInfo, IN ULONG In_Length);

//查找指定的Object类型
//成功返回：1
//失败返回：0
BOOLEAN NTAPI Safe_QueryObjectType(IN HANDLE ObjectHandle, IN PWCHAR pObjectTypeName);

NTSTATUS NTAPI Safe_Run_SeDeleteObjectAuditAlarm(IN HANDLE In_Handle);



