#pragma once
#include <ntifs.h>
#include "Data.h"
#include "WinKernel.h"
#include "SafeWarning.h"

//获取IoGetDiskDeviceObject函数地址，并调用该函数
NTSTATUS NTAPI Safe_IoGetDiskDeviceObjectPrt( PDEVICE_OBJECT FileSystemDeviceObject,  PDEVICE_OBJECT* DiskDeviceObject);

NTSTATUS NTAPI Fake_ZwWriteFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg);