#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Data.h"
#include "Regedit.h"
#include "SystemProcessDataList.h"

//¼ÓÔØÇý¶¯
NTSTATUS NTAPI Fake_ZwLoadDriver(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);