#pragma once
#include <ntifs.h>
ULONG   NTAPI ExSystemExceptionFilter();
NTSTATUS NTAPI myProbeRead(PVOID Address, SIZE_T Size, ULONG Alignment);
NTSTATUS NTAPI myProbeWrite(PVOID Address, SIZE_T Size, ULONG Alignment);