#pragma once
#include <ntddk.h>
#include "FilterHook.h"


//创建文件
#define ZwCreateFile_FilterIndex	0x8 
NTSTATUS NTAPI Filter_ZwCreateFile(OUT PHANDLE  FileHandle, IN ACCESS_MASK  DesiredAccess, IN POBJECT_ATTRIBUTES  ObjectAttributes, OUT PIO_STATUS_BLOCK  IoStatusBlock, IN PLARGE_INTEGER  AllocationSize  OPTIONAL, IN ULONG  FileAttributes, IN ULONG  ShareAccess, IN ULONG  CreateDisposition, IN ULONG  CreateOptions, IN PVOID  EaBuffer  OPTIONAL, IN ULONG  EaLength);
