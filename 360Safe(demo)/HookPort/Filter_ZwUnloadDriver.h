#pragma once
#include <ntddk.h>
#include "FilterHook.h"


NTSTATUS NTAPI Filter_ZwUnloadDriver(IN PUNICODE_STRING  DriverServiceName);