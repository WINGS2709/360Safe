#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Data.h"
#include "WhiteList.h"
#include "SafeWarning.h"

NTSTATUS NTAPI After_ZwSetSystemInformation_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//ZwSetSystemInformation
NTSTATUS NTAPI Fake_ZwSetSystemInformation(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);