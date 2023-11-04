#include "Fake_CreateProcessNotifyRoutine.h"

NTSTATUS NTAPI Fake_CreateProcessNotifyRoutine(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg)
{
	PEPROCESS	Process;
	NTSTATUS	status;
	HANDLE      ProcessHandle;
	CLIENT_ID   ClientId;
	ULONG       SafeModIndex = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	//PROCESS_SESSION_INFORMATION SessionInfo;
	UCHAR ImageFileNameBuff[0x256] = { 0 };
	ProcessHandle = NULL;
	IN HANDLE In_ParentId = *(ULONG*)((ULONG)ArgArray);
	IN HANDLE In_ProcessId = *(ULONG*)((ULONG)ArgArray + 4);
	IN BOOLEAN In_Create = *(ULONG*)((ULONG)ArgArray + 8);
	//当Create为True时，例程在新创建的进程（ProcessId句柄指定）的初始化线程被创建后被调用。
	if (In_Create)
	{
		status = PsLookupProcessByProcessId(In_ProcessId, &Process);
		if (NT_SUCCESS(status))
		{
			//Win2K
			if (g_VersionFlag == WINDOWS_VERSION_2K)
			{
				SafeModIndex = Safe_DeleteCreateProcessDataList(Process);
				if (SafeModIndex)
				{
					Safe_InsertWhiteList_PID_Win2003(In_ProcessId, SafeModIndex);
				}
			}
			Safe_PsGetProcessImageFileName(Process, &ImageFileNameBuff, sizeof(ImageFileNameBuff));
			ObfDereferenceObject(Process);
			if (!_stricmp(&ImageFileNameBuff, "userinit.exe"))
			{
				//设置开关
				g_dynData->SystemInformation.Userinit_Flag = 1;
			}
			if (!g_dynData->SystemInformation.Explorer_Flag && !_stricmp(&ImageFileNameBuff, "explorer.exe"))
			{
				//设置开关与保存explorer.exePID
				g_dynData->SystemInformation.Explorer_Flag = 1;
				g_dynData->SystemInformation.Explorer_ProcessId = In_ProcessId;
				ClientId.UniqueProcess = In_ProcessId;
				ClientId.UniqueThread = NULL;
				InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
				if (!NT_SUCCESS(ZwOpenProcess(&ProcessHandle, 0x400u, &ObjectAttributes, &ClientId)))
				{
					ZwQueryInformationProcess(ProcessHandle, ProcessSessionInformation, &g_dynData->SystemInformation.Explorer_SessionId, sizeof(PROCESS_SESSION_INFORMATION), 0);
					ZwClose(ProcessHandle);
				}
			}
			if (!g_dynData->SystemInformation.Winlogon_ProcessId && !_stricmp(&ImageFileNameBuff, "winlogon.exe"))
			{
				g_dynData->SystemInformation.Winlogon_ProcessId = In_ProcessId;
			}
			if (g_Win2K_XP_2003_Flag && !g_dynData->SystemInformation.Wininit_ProcessId && !_stricmp(&ImageFileNameBuff, "wininit.exe"))
			{
				g_dynData->SystemInformation.Wininit_ProcessId = In_ProcessId;
			}
		}
	}
	//当Create为False时，例程在进程的最后一个线程被关闭，进程的地址空间将被释放时调用。 
	else
	{
		if (g_dynData->SystemInformation.Explorer_ProcessId && g_dynData->SystemInformation.Explorer_ProcessId == In_ProcessId)
		{
			g_dynData->SystemInformation.Explorer_ProcessId = 0;
		}
		//判断是不是白名单进程
		//1：如果是：将白名单进程信息从数组中抹除
		//2、如果不是：直接退出
		Safe_DeleteWhiteList_PID(In_ProcessId);
		//删除内存信息
		Safe_DeleteVirtualMemoryDataList(In_ProcessId);
		//清空特殊进程（未知）
		if (In_ProcessId == g_dynData->dword_34EA0[9])
		{
			g_dynData->dword_34EA0[9] = 0;
		}
		if (In_ProcessId == g_dynData->dword_34EA0[10])
		{
			g_dynData->dword_34EA0[10] = 0;
		}
		if (In_ProcessId == g_dynData->dword_34DAC[11])
		{
			g_dynData->dword_34DAC[11] = 0;
		}
		if (In_ProcessId == g_dynData->dword_34DAC[12])
		{
			g_dynData->dword_34DAC[12] = 0;
		}
		if (In_ProcessId == g_dynData->dword_34DAC[0])
		{
			g_dynData->dword_34DAC[0] = 0;
		}
		if (In_ProcessId == g_dynData->dword_34DAC[1])
		{
			g_dynData->dword_34DAC[1] = 0;
		}
		if (In_ProcessId == g_dynData->dword_34DAC[4])
		{
			g_dynData->dword_34DAC[4] = 0;
		}
		if (In_ProcessId == g_dynData->dword_34DAC[5])
		{
			g_dynData->dword_34DAC[5] = 0;
		}
		if (In_ProcessId == g_dynData->dword_34DAC[7])
		{
			g_dynData->dword_34DAC[7] = 0;
		}
		if (In_ProcessId == g_dynData->dword_34DAC[6])
		{
			g_dynData->dword_34DAC[6] = 0;
		}
		if (g_dynData->dword_34D64 == In_ProcessId)
		{
			g_dynData->dword_34D64 = 0;
		}
		//清空列表
		for (ULONG i = 0; i < SYSTEMNUMBER; i++)
		{
			//如果是系统进程就清空列表
			if (g_dynData->SystemInformationList.SystemListPID[i] == In_ProcessId)
			{
				g_dynData->SystemInformationList.SystemListEprocess[i] = 0;
				g_dynData->SystemInformationList.SystemListPID[i] = 0;
			}
		}
	}
	return STATUS_SUCCESS;
}