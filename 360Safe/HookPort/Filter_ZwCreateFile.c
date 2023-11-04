#include "Filter_ZwCreateFile.h"


NTSTATUS NTAPI Filter_ZwCreateFile(OUT PHANDLE  FileHandle, IN ACCESS_MASK  DesiredAccess, IN POBJECT_ATTRIBUTES  ObjectAttributes, OUT PIO_STATUS_BLOCK  IoStatusBlock, IN PLARGE_INTEGER  AllocationSize  OPTIONAL, IN ULONG  FileAttributes, IN ULONG  ShareAccess, IN ULONG  CreateDisposition, IN ULONG  CreateOptions, IN PVOID  EaBuffer  OPTIONAL, IN ULONG  EaLength)
{
	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &FileHandle;//参数数组，指向栈中属于本函数的所有参数
	//KdPrint(("Filter_ZwCreateFile\t\n"));

	NTSTATUS(NTAPI *ZwCreateFilePtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
	//原始函数执行前检查
	Result = HookPort_DoFilter(ZwCreateFile_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwCreateFilePtr = HookPort_GetOriginalServiceRoutine(g_SSDT_Func_Index_Data.ZwCreateFileIndex);

		//调用原始函数
		Result = ZwCreateFilePtr(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
		if (NT_SUCCESS(Result))
		{
			//原始函数执行后检查
			Result = HookPort_ForRunFuncTable(ZwCreateFile_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;

}