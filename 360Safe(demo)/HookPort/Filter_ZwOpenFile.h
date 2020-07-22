#pragma once
#include <ntddk.h>
#include "FilterHook.h"

//打开文件
#define ZwOpenFile_FilterIndex	0x13 
NTSTATUS NTAPI Filter_ZwOpenFile(OUT PHANDLE  FileHandle, IN ACCESS_MASK  DesiredAccess, IN POBJECT_ATTRIBUTES  ObjectAttributes, OUT PIO_STATUS_BLOCK  IoStatusBlock, IN ULONG  ShareAccess, IN ULONG  OpenOptions);
