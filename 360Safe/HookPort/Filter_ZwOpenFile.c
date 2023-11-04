#include "Filter_ZwOpenFile.h"


NTSTATUS NTAPI Filter_ZwOpenFile(OUT PHANDLE  FileHandle, IN ACCESS_MASK  DesiredAccess, IN POBJECT_ATTRIBUTES  ObjectAttributes, OUT PIO_STATUS_BLOCK  IoStatusBlock, IN ULONG  ShareAccess, IN ULONG  OpenOptions)
{
	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &FileHandle;//参数数组，指向栈中属于本函数的所有参数
	//KdPrint(("Filter_ZwOpenFile\t\n"));
	NTSTATUS(NTAPI *ZwOpenFilePtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
	Result = HookPort_DoFilter(ZwOpenFile_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwOpenFilePtr = HookPort_GetOriginalServiceRoutine(g_SSDT_Func_Index_Data.ZwOpenFileIndex);

		//调用原始函数
		Result = ZwOpenFilePtr(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
		if (NT_SUCCESS(Result))
		{
			Result = HookPort_ForRunFuncTable(ZwOpenFile_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;
}