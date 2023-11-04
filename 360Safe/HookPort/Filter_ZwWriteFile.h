#pragma once
#include <ntddk.h>
#include "FilterHook.h"

//Ð´ÎÄ¼þ
#define	ZwWriteFile_FilterIndex	0xB    
NTSTATUS NTAPI Filter_ZwWriteFile(IN HANDLE  FileHandle, IN HANDLE  Event  OPTIONAL, IN PIO_APC_ROUTINE  ApcRoutine  OPTIONAL, IN PVOID  ApcContext  OPTIONAL, OUT PIO_STATUS_BLOCK  IoStatusBlock, IN PVOID  Buffer, IN ULONG  Length, IN PLARGE_INTEGER  ByteOffset  OPTIONAL, IN PULONG  Key  OPTIONAL);
NTSTATUS NTAPI Filter_ZwWriteFileGather(IN HANDLE  FileHandle, IN HANDLE  Event  OPTIONAL, IN PIO_APC_ROUTINE  ApcRoutine  OPTIONAL, IN PVOID  ApcContext  OPTIONAL, OUT PIO_STATUS_BLOCK  IoStatusBlock, IN PVOID  Buffer, IN ULONG  Length, IN PLARGE_INTEGER  ByteOffset  OPTIONAL, IN PULONG  Key  OPTIONAL);
