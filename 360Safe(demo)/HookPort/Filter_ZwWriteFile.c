#include "Filter_ZwWriteFile.h"

NTSTATUS NTAPI Filter_ZwWriteFileGather(IN HANDLE  FileHandle, IN HANDLE  Event  OPTIONAL, IN PIO_APC_ROUTINE  ApcRoutine  OPTIONAL, IN PVOID  ApcContext  OPTIONAL, OUT PIO_STATUS_BLOCK  IoStatusBlock, IN PVOID  Buffer, IN ULONG  Length, IN PLARGE_INTEGER  ByteOffset  OPTIONAL, IN PULONG  Key  OPTIONAL)
{
	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &FileHandle;//参数数组，指向栈中属于本函数的所有参数
	//KdPrint(("Filter_ZwWriteFileGather\t\n"));

	NTSTATUS(NTAPI *ZwWriteFileGatherPtr)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
	Result = HookPort_DoFilter(ZwWriteFile_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwWriteFileGatherPtr = HookPort_GetOriginalServiceRoutine(g_SSDT_Func_Index_Data.ZwWriteFileGatherIndex);
		//调用原始函数
		Result = ZwWriteFileGatherPtr(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
		if (NT_SUCCESS(Result))
		{
			Result = HookPort_ForRunFuncTable(ZwWriteFile_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;
}

NTSTATUS NTAPI Filter_ZwWriteFile(IN HANDLE  FileHandle, IN HANDLE  Event  OPTIONAL, IN PIO_APC_ROUTINE  ApcRoutine  OPTIONAL, IN PVOID  ApcContext  OPTIONAL, OUT PIO_STATUS_BLOCK  IoStatusBlock, IN PVOID  Buffer, IN ULONG  Length, IN PLARGE_INTEGER  ByteOffset  OPTIONAL, IN PULONG  Key  OPTIONAL)
{
	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber;
	PVOID    pArgArray = &FileHandle;//参数数组，指向栈中属于本函数的所有参数
	NTSTATUS(NTAPI *ZwWriteFilePtr)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
	Result = HookPort_DoFilter(ZwWriteFile_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwWriteFilePtr = HookPort_GetOriginalServiceRoutine(g_SSDT_Func_Index_Data.ZwWriteFileIndex);

		//调用原始函数
		Result = ZwWriteFilePtr(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	}
	else
	{
		Result = OutResult;
	}
	return Result;
}