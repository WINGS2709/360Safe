#pragma once
#include <ntddk.h>
#include "Data.h"
//获取系统版本信息
ULONG HookPort_PsGetVersion();

typedef NTSTATUS(NTAPI * PFN_RtlGetVersion)(OUT PRTL_OSVERSIONINFOW lpVersionInformation);

