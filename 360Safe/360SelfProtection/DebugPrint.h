#pragma once
#include <ntddk.h>


//Hook失败往注册表写的失败标记

NTSTATUS NTAPI HookPort_RtlWriteRegistryValue(CHAR ValueData);




