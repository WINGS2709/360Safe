#pragma once
#include <ntifs.h>
#include "Object.h"

//永久对象转化成临时对象
NTSTATUS NTAPI Fake_ZwMakeTemporaryObject(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);