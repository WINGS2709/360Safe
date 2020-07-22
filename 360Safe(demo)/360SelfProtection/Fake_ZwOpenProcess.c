#include "Fake_ZwOpenProcess.h"

#define WHILEPROCESSNAMENUMBER_ZWOPENPROCESS 0x4
//要放行的白名单进程名称
PWCHAR g_WhiteProcessName_ZwOpenProcess[WHILEPROCESSNAMENUMBER_ZWOPENPROCESS + 1] = {
	0			//自定义
};

//函数说明：
//1、打开的是保护进程，将打开的句柄重新复制一份（降权阉割后的，原始的直接Close掉）
//2、打开的是非保护进程直接无视
NTSTATUS NTAPI After_ZwOpenProcess_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS       Status = STATUS_SUCCESS;
	NTSTATUS       result = STATUS_SUCCESS;
	ACCESS_MASK    DesiredAccess_Flag =															   //0x520D0BAF
		(GENERIC_WRITE | GENERIC_ALL) |                                                            //0x50000000 = GENERIC_WRITE | GENERIC_ALL
		(MAXIMUM_ALLOWED) |                                                                        //0x02000000 = MAXIMUM_ALLOWED
		(WRITE_OWNER | WRITE_DAC | DELETE) |   	                                                   //0x000D0000 = WRITE_OWNER | WRITE_DAC | DELETE
		(PROCESS_SUSPEND_RESUME | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION) |                   //0x00000B00 = PROCESS_SUSPEND_RESUME | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION
		(PROCESS_CREATE_PROCESS | PROCESS_VM_WRITE) |							                   //0x000000A0 = PROCESS_CREATE_PROCESS(Required to create a process) | PROCESS_VM_WRITE(WriteProcessMemory)
		(PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION);//0x0000000F = PROCESS_TERMINATE |PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION			
	HANDLE         Handle_v5 = NULL;
	PEPROCESS      pPeprocess = NULL;
	BOOLEAN        Terminate_Flag = FALSE;			//真设置PROCESS_TERMINATE
	HANDLE         TargetHandle = NULL;
	UCHAR          ImageFileNameBuff[0x1000] = { 0 };
	ACCESS_MASK    TestDesiredAccess = NULL;		//临时
	//0、获取ZwOpenProcess原始函数
	PHANDLE		   In_ProcessHandle = *(ULONG*)((ULONG)ArgArray);
	ACCESS_MASK	   In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	PCLIENT_ID	   In_ClientId = *(ULONG*)((ULONG)ArgArray + 0xC);
	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	//2、低版本权限
	if (!g_Win2K_XP_2003_Flag)
	{
		DesiredAccess_Flag |= GENERIC_EXECUTE;  //0x720D0BAF;
	}
	DesiredAccess_Flag = ~DesiredAccess_Flag;
	//取反的话失去了比较重要的权限如下：
	//DesiredAccess_Flag=0xADF2F450
	//1、PROCESS_VM_OPERATION       //操作进程内存空间的权限(可用VirtualProtectEx和WriteProcessMemory) 
	//2、PROCESS_VM_WRITE           //读取进程内存空间的权限，可使用WriteProcessMemory
	//3、创建线程、进程之类的

	//2、1判断参数合法性
	if (myProbeRead(In_ProcessHandle, sizeof(CLIENT_ID), sizeof(ULONG)))
	{
		KdPrint(("ProbeRead(After_ZwOpenProcess_Func：In_ProcessHandle) error \r\n"));
		return result;
	}
	Handle_v5 = *(HANDLE*)In_ProcessHandle;
	//3、判断要打开的句柄是不是白名单进程，如果是继续判断，不是直接退出
	if (Safe_QueryWintePID_ProcessHandle(Handle_v5) &&
		!Safe_CheckSysProcess()					//核对csrss.exe、svchost.exe、dllhost.exe
		)
	{
		//防止父进程
		if (Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_SVCHOST_EXE,g_VersionFlag))
		{
		_FunctionRet:				//正常退出，阉割受保护进程句柄权限
			if (Terminate_Flag)
			{
				//大数字特殊进程保留PROCESS_TERMINATE属性
				Terminate_Flag = FALSE;
				TestDesiredAccess = In_DesiredAccess & DesiredAccess_Flag | PROCESS_TERMINATE;
			}
			else
			{
				//受保护白名单进程
				TestDesiredAccess = In_DesiredAccess & DesiredAccess_Flag;
			}
			//拷贝句柄并且降权
			Status = ZwDuplicateObject(
				NtCurrentProcess(),						//__in HANDLE SourceProcessHandle,
				Handle_v5,								//__in HANDLE SourceHandle,
				NtCurrentProcess(),						//__in_opt HANDLE TargetProcessHandle,
				&TargetHandle,							//__out_opt PHANDLE TargetHandle,
				TestDesiredAccess,						//__in ACCESS_MASK DesiredAccess,
				NULL,									//__in ULONG HandleAttributes,
				NULL									//__in ULONG Options
				);
			if (NT_SUCCESS(Status))
			{
				//结束掉原始的句柄
				if (Handle_v5)
				{
					Safe_ZwNtClose(Handle_v5, g_VersionFlag);
				}
				//这个句柄权限是阉割后的
				*(HANDLE*)In_ProcessHandle = TargetHandle;
				result = STATUS_SUCCESS;
			}
			else
			{
				_InvalidRet:		//错误退出：Copy句柄失败、程序非正常退出
				//复制失败句柄直接清零，返回个错误值
				Safe_ZwNtClose(Handle_v5, g_VersionFlag);
				*(HANDLE*)In_ProcessHandle = 0;
				result = STATUS_ACCESS_DENIED;

			}
			return result;
		}
		//最大权限不应该是PROCESS_ALL_ACCESS =0x001fffff ？？？？？？
		else if (In_DesiredAccess == 0x1F0FFF && Safe_CmpImageFileName("Mcshield.exe"))
		{
			goto _FunctionRet;
		}
		//保护进程 or 带有结束进程标志
		else if (RetFuncArgArray == TRUE || DesiredAccess_Flag & PROCESS_TERMINATE)
		{
			//判断父进程是不是特殊进程：任务管理器
			if (Safe_CmpImageFileName("taskmgr.exe"))
			{
				Status = ObReferenceObjectByHandle(Handle_v5, NULL, PsProcessType, KernelMode, &pPeprocess, 0);
				if (NT_SUCCESS(Status))
				{
					//获取要打开句柄的路径，判断是不是大数字的
					Safe_PsGetProcessImageFileName(pPeprocess, &ImageFileNameBuff, sizeof(ImageFileNameBuff));
					//遇到360*****跟360*****的进程设置对应的权限(阉割)，唯一区别保留PROCESS_TERMINATE
					for (ULONG i = 0; i < WHILEPROCESSNAMENUMBER_ZWOPENPROCESS; i++)
					{
						if (_stricmp(&ImageFileNameBuff, g_WhiteProcessName_ZwOpenProcess[i]) == 0)
						{
							//特殊进程设置标志位，保留PROCESS_TERMINATE属性
							Terminate_Flag = TRUE;
							break;
						}
					}
					//引用计数-1
					if (pPeprocess)
					{
						ObfDereferenceObject(pPeprocess);
						pPeprocess = NULL;
					}
				}
			}
			//跳到Copy句柄（阉割）
			goto _FunctionRet;
		}
		else
		{
			//一般不会执行到这里
			//无效退出，句柄直接清零错误返回
			goto _InvalidRet;
		}
	}
	else
	{
		//非保护进程，直接返回 保留原始权限
		result = STATUS_SUCCESS;
	}
	return result;
}

//打开进程
NTSTATUS NTAPI Fake_ZwOpenProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       Status = STATUS_SUCCESS;
	NTSTATUS       result = STATUS_SUCCESS;
	ACCESS_MASK    DesiredAccess_Flag =															   //0x520D0BAF
		(GENERIC_WRITE | GENERIC_ALL) |                                                            //0x50000000 = GENERIC_WRITE | GENERIC_ALL
		(MAXIMUM_ALLOWED) |                                                                        //0x02000000 = MAXIMUM_ALLOWED
		(WRITE_OWNER | WRITE_DAC | DELETE) |   	                                                   //0x000D0000 = WRITE_OWNER | WRITE_DAC | DELETE
		(PROCESS_SUSPEND_RESUME | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION) |                   //0x00000B00 = PROCESS_SUSPEND_RESUME | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION
		(PROCESS_CREATE_PROCESS | PROCESS_VM_WRITE) |							                   //0x000000A0 = PROCESS_CREATE_PROCESS(Required to create a process) | PROCESS_VM_WRITE(WriteProcessMemory)
		(PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION);//0x0000000F = PROCESS_TERMINATE |PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION			
	PEPROCESS      ClientProcess = NULL;
	PETHREAD       ClientThread = NULL;
	BOOLEAN        Protection_Flag = FALSE;						//访问的是受保护进程置1
	UCHAR          ImageFileNameBuff[0x256] = { 0 };
	//0、获取ZwOpenProcess原始函数
	PHANDLE     In_ProcessHandle = *(ULONG*)((ULONG)ArgArray);
	ACCESS_MASK In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	PCLIENT_ID  In_ClientId = *(ULONG*)((ULONG)ArgArray + 0xC);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//2、低版本权限
		if (!g_Win2K_XP_2003_Flag)
		{
			DesiredAccess_Flag |= GENERIC_EXECUTE;  //0x720D0BAF
		}
		//3、判断权限
		if (DesiredAccess_Flag & In_DesiredAccess)
		{
			//判断是不是保护进程调用ZwOpenProcess，如果是直接返回，不是继续判断
			if (!Safe_QueryWhitePID(PsGetCurrentProcessId()))
			{
				if (In_DesiredAccess & PROCESS_TERMINATE)
				{
					if (In_ClientId)
					{
						//判断参数合法性
						if (myProbeRead(In_ClientId, sizeof(CLIENT_ID), sizeof(ULONG)))
						{
							KdPrint(("ProbeRead(Fake_ZwOpenProcess：In_ClientId) error \r\n"));
							return result;
						}
						//获取ETHREAD / EPROCESS
						if (In_ClientId->UniqueThread)
						{
							//千万别忘记释放ObfDereferenceObject(ClientProcess)和ObfDereferenceObject(ClientThread)
							Status = PsLookupProcessThreadByCid(&In_ClientId, &ClientProcess, &ClientThread);
						}
						else
						{
							Status = PsLookupProcessByProcessId(In_ClientId->UniqueProcess, &ClientProcess);
						}
						//获取失败直接退出
						if (!NT_SUCCESS(Status))
						{
							*(ULONG*)ret_func = After_ZwOpenProcess_Func;
							return result;
						}
						//判断你打开的进程是不是保护进程，不是退出  是继续判断
						if (!Safe_QueryWhitePID_PsGetProcessId(ClientProcess))
						{
							//非白名单进程直接退出了
							if (ClientThread)
							{
								ObfDereferenceObject(ClientThread);
							}
							ObfDereferenceObject(ClientProcess);
							*(ULONG*)ret_func = After_ZwOpenProcess_Func;
							return result;
						}
						//受保护进程有几个需要单独处理权限(这几个进程不在白名单列表中)				
						if (ClientThread)
						{
							ObfDereferenceObject(ClientThread);
						}
						if (!Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_CSRSS_EXE, g_VersionFlag))
						{
							//获取要打开句柄的路径，判断是不是大数字的
							Safe_PsGetProcessImageFileName(ClientProcess, &ImageFileNameBuff, sizeof(ImageFileNameBuff));
							//遇到360*****跟360*****的进程直接放行,其他保护进程设置对应的权限
							for (ULONG i = 0; i < WHILEPROCESSNAMENUMBER_ZWOPENPROCESS; i++)
							{
								if (_stricmp(&ImageFileNameBuff, g_WhiteProcessName_ZwOpenProcess[i]) == 0)
								{
									//特殊进程直接放行
									break;
								}
								else
								{
									//保护进程进行阉割权限

									//判断是不是想结束OpenPorcess(PROCESS_TERMINATE,xx,PID)然后调用TerminateProcess结束进程
									ULONG Flag = *(ULONG*)((ULONG)ArgArray + 4) & PROCESS_TERMINATE == 0;
									//取消掉结束进程的权限
									*(ULONG*)((ULONG)ArgArray + 4) &= PROCESS_TERMINATE;
									//仅有PROCESS_TERMINATE权限，就给设置个默认权限
									if (Flag)
									{
										*(ULONG*)((ULONG)ArgArray + 4) = PROCESS_QUERY_INFORMATION;
									}
									Protection_Flag = TRUE;
								}
							}
						}
						ObfDereferenceObject(ClientProcess);
					}
				}
				*(ULONG*)ret_func = After_ZwOpenProcess_Func;
				*(ULONG*)ret_arg = Protection_Flag;						//访问的是受保护进程置1
			}
		}
	}
	return result;
}