#pragma once
#include <ntifs.h>
#include "Data.h"

//阉割版函数：只支持TargetProcessHandle == NtCurrentProcess()的调用
NTSTATUS NTAPI Safe_ZwIoDuplicateObject(IN HANDLE  SourceProcessHandle, IN HANDLE  SourceHandle, IN HANDLE  TargetProcessHandle, IN PHANDLE  TargetHandle, IN ACCESS_MASK  DesiredAccess, IN ULONG  HandleAttributes, IN ULONG  Options, IN BOOLEAN HighVersion_Flag, IN ULONG Version_Flag);

NTSTATUS NTAPI Safe_IoCreateFile(_In_ POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PHANDLE FileHandle);

//释放句柄
NTSTATUS NTAPI Safe_ZwNtClose(IN HANDLE Handle, IN BOOLEAN HighVersion_Flag);

//当AccessMode == 1，UserMode模式
NTSTATUS NTAPI Safe_UserMode_ZwQueryObject(_In_ BOOLEAN HighVersion_Flag, _In_ HANDLE ObjectHandle, _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass, _Out_opt_  PVOID ObjectInformation, _In_ ULONG ObjectInformationLength, _Out_opt_  PULONG ReturnLength);

//当AccessMode == 1，UserMode模式
NTSTATUS NTAPI Safe_UserMode_ZwQueryVolumeInformationFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FsInformation, _In_ ULONG Length, _In_ FS_INFORMATION_CLASS FsInformationClass, IN BOOLEAN HighVersion_Flag);

//当AccessMode == 1，UserMode模式
NTSTATUS NTAPI Safe_UserMode_ZwQueryInformationFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass, IN BOOLEAN HighVersion_Flag);
