#include "Fake_ZwAlpcSendWaitReceivePort.h"

//RPC通讯在各个平台上依赖的API各不相同，基本上
//win2000 : NtFsControlFile
//xp, 2003 : NtRequestWaitReplyPort
//vista, 2008.win7 : NtAlpcSendWaitReceivePort
NTSTATUS NTAPI Fake_ZwAlpcSendWaitReceivePort(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS	Result = STATUS_SUCCESS;
	//0、获取ZwAllocateVirtualMemory原始函数
	HANDLE In_PortHandle = *(ULONG*)((ULONG)ArgArray);
	PVOID  In_SendMessage = *(ULONG*)((ULONG)ArgArray + 8);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		Result = Safe_RPCDispatcher(In_SendMessage, In_PortHandle);
	}
	return Result;
}