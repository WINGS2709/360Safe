#pragma once
#include <ntifs.h>
#include "MemCheck.h"

//É¾³ý×¢²á±íÖµ¼ü
NTSTATUS NTAPI Fake_ZwDeleteKey(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);