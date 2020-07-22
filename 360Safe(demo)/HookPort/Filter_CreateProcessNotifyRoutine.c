#include "Filter_CreateProcessNotifyRoutine.h"

//NotifyRoutine
NTSTATUS NTAPI Filter_CreateProcessNotifyRoutine(IN HANDLE  ParentId, IN HANDLE  ProcessId, IN BOOLEAN  Create)
{
	NTSTATUS result;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };

	ULONG		RetCount;
	PVOID		pArgArray = &ParentId;//参数数组，指向栈中属于本函数的所有参数

	result = HookPort_DoFilter(CreateProcessNotifyRoutine_FilterIndex, pArgArray, 0, 0, 0, 0);
	return result;
}