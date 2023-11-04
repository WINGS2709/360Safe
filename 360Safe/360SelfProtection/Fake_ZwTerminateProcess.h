#pragma once
#include <ntifs.h>
#include "WinBase.h"
#include "Object.h"
#include "Data.h"
//½áÊø½ø³Ì
NTSTATUS NTAPI Fake_ZwTerminateProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);