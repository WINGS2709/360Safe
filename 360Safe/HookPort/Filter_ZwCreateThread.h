#pragma once
#include <ntddk.h>
#include "FilterHook.h"

//线程创建
typedef struct _USER_STACK {
	PVOID  FixedStackBase;
	PVOID  FixedStackLimit;
	PVOID  ExpandableStackBase;
	PVOID  ExpandableStackLimit;
	PVOID  ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;
#define	ZwCreateThread_FilterIndex 0x10  

NTSTATUS NTAPI Filter_ZwCreateThread(OUT PHANDLE  ThreadHandle, IN ACCESS_MASK  DesiredAccess, IN POBJECT_ATTRIBUTES  ObjectAttributes, IN HANDLE  ProcessHandle, OUT PCLIENT_ID  ClientId, IN PCONTEXT  ThreadContext, IN PUSER_STACK  UserStack, IN BOOLEAN  CreateSuspended);

NTSTATUS NTAPI Filter_ZwCreateThreadEx(OUT PHANDLE  ThreadHandle, IN ACCESS_MASK  DesiredAccess, IN POBJECT_ATTRIBUTES  ObjectAttributes, IN HANDLE  ProcessHandle, OUT PCLIENT_ID  ClientId, IN PCONTEXT  ThreadContext, IN PUSER_STACK  UserStack, IN BOOLEAN  CreateSuspended, IN PVOID  Arg9, IN PVOID  Arg10, IN PVOID  Arg11);