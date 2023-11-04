#pragma once
#include <ntddk.h>
#include "Data.h"

//获取系统版本信息
ULONG Safe_PsGetVersion();

RTL_OSVERSIONINFOEXW osverinfo;

typedef NTSTATUS(NTAPI * PFN_RtlGetVersion)(OUT PRTL_OSVERSIONINFOW lpVersionInformation);


