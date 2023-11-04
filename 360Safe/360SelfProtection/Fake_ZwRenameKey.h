#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Regedit.h"
//重命名注册表值键
NTSTATUS NTAPI Fake_ZwRenameKey(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);