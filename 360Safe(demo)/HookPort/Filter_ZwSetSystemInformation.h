#pragma once
#include <ntddk.h>
#include "WinKernel.h"
#include "FilterHook.h"

#define	ZwSetSystemInformation_FilterIndex	0x24
NTSTATUS NTAPI Filter_ZwSetSystemInformation(IN SYSTEM_INFORMATION_CLASS  SystemInformationClass, IN OUT PVOID  SystemInformation, IN ULONG  SystemInformationLength);