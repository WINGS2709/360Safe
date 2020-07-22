#pragma once
#include <ntifs.h>
#include "WinKernel.h"
#include "Regedit.h"
#include "MemCheck.h"

NTSTATUS NTAPI After_ZwEnumerateValueKey_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray);

//Ã¶¾Ùvaluekey
NTSTATUS NTAPI Fake_ZwEnumerateValueKey(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);