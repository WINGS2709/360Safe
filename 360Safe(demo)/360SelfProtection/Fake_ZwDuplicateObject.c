#include "Fake_ZwDuplicateObject.h"

#define WHILEDRIVERNAMENUMBER_ZWDUPLICATEOBJECT 0xA
//要拦截的白名单驱动名称
PWCHAR g_WhiteDriverName_ZwDuplicateObject[WHILEDRIVERNAMENUMBER_ZWDUPLICATEOBJECT + 1] = {
	0				//自定义
};

//判断DuplicateObject函数执行后的错误码
BOOLEAN NTAPI CheckResult_After_DuplicateObject(NTSTATUS In_Status)
{
	BOOLEAN        Result = TRUE;
	ULONG          ReturnLength = NULL;
	ULONG          HandleCount = NULL;			//句柄个数
	NTSTATUS       Status = STATUS_SUCCESS;
	Status = Safe_ZwQueryInformationProcess(NtCurrentProcess() , ProcessHandleCount, &HandleCount, sizeof(HandleCount), &ReturnLength);
	Result = (In_Status == STATUS_INSUFFICIENT_RESOURCES) && (!NT_SUCCESS(Status) || HandleCount == g_dynData->dword_3323C);
	return Result;
}

//没看懂
BOOLEAN NTAPI Safe_26794(IN HANDLE In_TargetProcessHandle)
{
	BOOLEAN        Result = TRUE;
	NTSTATUS       Status = STATUS_SUCCESS;
	PEPROCESS      TargetProcess = NULL;
	if (In_TargetProcessHandle)
	{
		//获取目标进程的Eprocess结构
		Status = ObReferenceObjectByHandle(In_TargetProcessHandle,NULL,PsProcessType,UserMode,&TargetProcess,NULL);
		if (NT_SUCCESS(Status))
		{
			if (Safe_QuerySystemInformationList(TargetProcess, SYSTEMROOT_SYSTEM32_CSRSS_EXE))
			{
				Result = TRUE;
			}
			else if ((g_Win2K_XP_2003_Flag && Safe_QuerySystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_SVCHOST_EXE)) ||	//判断是否存在
				(Safe_InsertSystemInformationList(TargetProcess, SYSTEMROOT_SYSTEM32_CSRSS_EXE,g_VersionFlag)) ||								//不存在则添加
				(g_Win2K_XP_2003_Flag && Safe_QuerySystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_SVCHOST_EXE))           //添加不成那就查询是否已存在
				)
			{
				Result = TRUE;
			}
			ObfDereferenceObject(TargetProcess);
		}
	}
	else
	{
		Result = FALSE;
	}
	return Result;
}
//里面细化处理各种类型：File、Process、Section、Thread敏感操作
//File：   违规操作：访问句柄是指定的白名单驱动对象
//Process：违规操作：访问句柄是指定的白名单、自身进程是IE
//Section：违规操作：路径是\\Device\\PhysicalMemory和\\KnownDlls\\ 
//Thread： 违规操作：访问句柄是指定的白名单、自身进程是IE
NTSTATUS NTAPI Safe_26C42(IN HANDLE In_SourceHandle, IN ULONG In_Options, IN ACCESS_MASK In_DesiredAccess, IN HANDLE In_TargetProcessHandle, IN HANDLE In_SourceProcessHandle)
{
	NTSTATUS                   result = STATUS_SUCCESS;
	NTSTATUS                   Status = STATUS_SUCCESS;
	ACCESS_MASK                Local_DesiredAccess_Process =										//0x520D0BAF
		(GENERIC_WRITE | GENERIC_ALL) |                                                            //0x50000000 = GENERIC_WRITE | GENERIC_ALL
		(MAXIMUM_ALLOWED) |                                                                        //0x02000000 = MAXIMUM_ALLOWED
		(WRITE_OWNER | WRITE_DAC | DELETE) |   	                                                   //0x000D0000 = WRITE_OWNER | WRITE_DAC | DELETE
		(PROCESS_SUSPEND_RESUME | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION) |                   //0x00000B00 = PROCESS_SUSPEND_RESUME | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION
		(PROCESS_CREATE_PROCESS | PROCESS_VM_WRITE) |							                   //0x000000A0 = PROCESS_CREATE_PROCESS(Required to create a process) | PROCESS_VM_WRITE(WriteProcessMemory)
		(PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION);//0x0000000F = PROCESS_TERMINATE |PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION	
	ACCESS_MASK                Local_DesiredAccess_File = 0x520D0156;
	ACCESS_MASK                Local_DesiredAccess_Section =										//0x52010002
		(GENERIC_WRITE | GENERIC_ALL) |																//0x50000000 = GENERIC_WRITE | GENERIC_ALL
		(MAXIMUM_ALLOWED) |																			//0x02000000 = MAXIMUM_ALLOWED
		(DELETE) |   																				//0x00010000 = DELETE
		(SECTION_MAP_WRITE);																		//0x00000002 = SECTION_MAP_WRITE
	ACCESS_MASK                Local_DesiredAccess_Thread = 										//0x520D00B7
		(GENERIC_WRITE | GENERIC_ALL) |																//0x50000000 = GENERIC_WRITE | GENERIC_ALL
		(MAXIMUM_ALLOWED) |																			//0x02000000 = MAXIMUM_ALLOWED
		(WRITE_OWNER | WRITE_DAC | DELETE) |   														//0x000D0000 = WRITE_OWNER | WRITE_DAC | DELETE
		(THREAD_SET_THREAD_TOKEN | THREAD_SET_INFORMATION | THREAD_SET_CONTEXT) |					//0x000000B0 = THREAD_SET_THREAD_TOKEN | THREAD_SET_INFORMATION | THREAD_SET_CONTEXT															   //0x000000B0 = 
		(THREAD_SUSPEND_RESUME | THREAD_ALERT | THREAD_TERMINATE);									//0x00000007 = THREAD_SUSPEND_RESUME | THREAD_ALERT | THREAD_TERMINATE

	PFILE_OBJECT               FileObject = NULL;
	CHAR		               ObjectInformation[0x500] = { 0 };
	ULONG                      ReturnLength = NULL;
	SIZE_T				       PhysicalMemorySize = 0x16;		        //\\Device\\PhysicalMemory字符串大小
	SIZE_T				       KnownDllsSize = 0xB;						//\\KnownDlls\\字符串大小
	PDRIVER_OBJECT             pDeviceObject = NULL;
	UNICODE_STRING             TempString1 = { 0 };
	BOOLEAN                    In_Options_Flag = TRUE;					//判断In_Options & 2
	ACCESS_MASK                Out_GrantedAccess = NULL;
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile = { 0 };			//文件信息
	PPUBLIC_OBJECT_TYPE_INFORMATION	pPubObjTypeInfo = NULL;
	In_Options_Flag = In_Options & DUPLICATE_SAME_ACCESS;
	//1、获取你要拷贝句柄的权限（源进程的对象句柄，句柄是以4开始，以4为单位递增）
	Status = Safe_GetGrantedAccess(In_SourceHandle, &Out_GrantedAccess);
	if (!NT_SUCCESS(Status))
	{
		result = STATUS_SUCCESS;
		return  result;
	}
	//2、低版本权限
	if (!g_Win2K_XP_2003_Flag)
	{
		Local_DesiredAccess_Process |= GENERIC_EXECUTE;  //0x720D0BAF;
	}
	//3、查询注册表HiveList结构
	if (Safe_QuerHivelist(Out_GrantedAccess, In_SourceHandle, In_SourceProcessHandle))
	{
		result = STATUS_ACCESS_DENIED;
		return  result;
	}
	//4、根据句柄类型为File
	if (Safe_QueryObjectType(In_SourceHandle, L"File"))
	{
		//4、1 得到文件对象指针
		Status = ObReferenceObjectByHandle(In_SourceHandle, FILE_ANY_ACCESS, *IoFileObjectType, UserMode, (PVOID*)&FileObject, NULL);
		if (!NT_SUCCESS(Status) && !FileObject && !FileObject->DeviceObject)
		{
		_Fun_Exit:
			//DUPLICATE_SAME_ACCESS权限
			if (In_Options_Flag)
			{
				//判断当前对象句柄的原始权限
				if (!(Out_GrantedAccess & Local_DesiredAccess_File))
				{
					result = STATUS_SUCCESS;
					return  result;
				}
			}
			//判断新的句柄权限
			else if (!(In_DesiredAccess & Local_DesiredAccess_File))
			{
				result = STATUS_SUCCESS;
				return  result;
			}
			//获取文件基本信息
			Status = Safe_GetInformationFile(In_SourceHandle, (ULONG)&System_InformationFile, UserMode);
			if (!NT_SUCCESS(Status))
			{
				result = STATUS_SUCCESS;
				return result;
			}
			//查找该信息是否在列表中，找到返回1，失败返回0
			Status = Safe_QueryInformationFileList(System_InformationFile.IndexNumber_LowPart,
				System_InformationFile.u.IndexNumber_HighPart,
				System_InformationFile.VolumeSerialNumber);
			if (Status == 0)
			{
				//不在列表中正常返回
				result = STATUS_SUCCESS;
			}
			else
			{
				//在列表中错误返回
				result = STATUS_ACCESS_DENIED;
			}
			return  result;
		}
		//4、2 判断是不是打开了受保护的驱动对象路径
		//源目标进程的句柄是保护进程：  进行判断
		//源目标进程的句柄是非保护进程：直接无视
		pDeviceObject = FileObject->DeviceObject;
		if (Safe_QueryWintePID_ProcessHandle(In_SourceProcessHandle))
		{
			if (pDeviceObject && pDeviceObject->Flags)
			{
				//防止恶意打开受保护的驱动对象
				for (ULONG i = 0; i < WHILEDRIVERNAMENUMBER_ZWDUPLICATEOBJECT; i++)
				{
					//因为DriverName是UUNICODE_STRING类型所以我们要转换下
					RtlInitUnicodeString(&TempString1, g_WhiteDriverName_ZwDuplicateObject[i]);
					if (RtlEqualUnicodeString(&pDeviceObject->DeviceObject->DriverObject->DriverName,&TempString1, TRUE))
					{
						//找到了直接错误返回
						ObfDereferenceObject(FileObject);
						result = STATUS_ACCESS_DENIED;
						return  result;
					}
				}
			}
		}
		//4、3 这部分没看明白，DriverInit == 0x14 ？？？？？？？
		if (pDeviceObject)
		{
			if (pDeviceObject->DriverInit == 0x14 &&			//指向DriverEntry函数的，这还有入口函数等于0x14的？？？？
				In_Options_Flag								    // 新句柄拥有与原始句柄相同的安全访问特征
				)
			{
				//正确返回
				ObfDereferenceObject(FileObject);
				result = STATUS_SUCCESS;
				return  result;
			}
		}
		ObfDereferenceObject(FileObject);
		goto _Fun_Exit;
	}
	//5、根据句柄类型为Process
	if (Safe_QueryObjectType(In_SourceHandle, L"Process"))
	{
		//源目标进程的对象句柄是保护进程：  进行判断
		//源目标进程的对象句柄是非保护进程：直接无视
		if (!Safe_QueryWintePID_ProcessHandle(In_SourceHandle))
		{
			result = STATUS_SUCCESS;
			return  result;
		}
		//DUPLICATE_SAME_ACCESS权限
		if (In_Options_Flag)
		{
			//判断当前对象句柄的原始权限
			if (!(Out_GrantedAccess & Local_DesiredAccess_Process))
			{
				result = STATUS_SUCCESS;
				return  result;
			}
		}
		//判断新的句柄权限
		else if (!(In_DesiredAccess & Local_DesiredAccess_Process))
		{
			result = STATUS_SUCCESS;
			return  result;
		}
		//这一句实在没看懂，判断目标进程句柄
		if (Safe_26794(In_TargetProcessHandle))
		{
			result = STATUS_SUCCESS;
			return  result;
		}
		//自身进程非IE
		if (Safe_CmpImageFileName("iexplore.exe"))
		{
			result = STATUS_CALLBACK_BYPASS;
			return  result;
		}
		//通知用户层R3 拦截还是放行
		Safe_18A72_SendR3(PsGetCurrentProcessId(), PsGetCurrentThreadId(), 0xD);
		result = STATUS_ACCESS_DENIED;
		return  result;

	}
	//6、根据句柄类型为Thread,处理方式与Process一致
	if (Safe_QueryObjectType(In_SourceHandle, L"Thread"))
	{
		//源目标进程的对象句柄是保护进程：  进行判断
		//源目标进程的对象句柄是非保护进程：直接无视
		if (!Safe_QueryWintePID_ThreadHandle(In_SourceHandle))
		{
			result = STATUS_SUCCESS;
			return  result;
		}
		//DUPLICATE_SAME_ACCESS权限
		if (In_Options_Flag)
		{
			//判断当前对象句柄的原始权限
			if (!(Out_GrantedAccess & Local_DesiredAccess_Thread))
			{
				result = STATUS_SUCCESS;
				return  result;
			}
		}
		//判断新的句柄权限
		else if (!(In_DesiredAccess & Local_DesiredAccess_Thread))
		{
			result = STATUS_SUCCESS;
			return  result;
		}
		//这一句实在没看懂，判断目标进程句柄
		if (Safe_26794(In_TargetProcessHandle))
		{
			result = STATUS_SUCCESS;
			return  result;
		}
		//自身进程非IE
		if (Safe_CmpImageFileName("iexplore.exe"))
		{
			result = STATUS_CALLBACK_BYPASS;
			return  result;
		}
		//与process不用的是没有通知R3用户层
		result = STATUS_ACCESS_DENIED;
		return  result;
	}
	//7、根据句柄类型为Section
	if (Safe_QueryObjectType(In_SourceHandle, L"Section"))
	{
		//DUPLICATE_SAME_ACCESS权限
		if (In_Options_Flag)
		{
			//判断当前对象句柄的原始权限
			if (!(Out_GrantedAccess & Local_DesiredAccess_Section))
			{
				result = STATUS_SUCCESS;
				return  result;
			}
		}
		//判断新的句柄权限
		else if (!(In_DesiredAccess & Local_DesiredAccess_Section))
		{
			result = STATUS_SUCCESS;
			return  result;
		}
		//获取句柄路径，防止打开敏感路径：KnownDlls和KnownDlls
		Status = Safe_UserMode_ZwQueryObject(g_HighgVersionFlag, *(HANDLE*)In_SourceHandle, ObjectNameInformation, ObjectInformation, sizeof(ObjectInformation), &ReturnLength);
		pPubObjTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)ObjectInformation;
		if (!NT_SUCCESS(Status) ||
			!pPubObjTypeInfo ||
			!pPubObjTypeInfo->TypeName.Length
			)
		{
			result = STATUS_SUCCESS;
			return result;
		}
		//PhysicalMemory检查    相等返回0，不等返回非0
		if (!_wcsnicmp(pPubObjTypeInfo->TypeName.Buffer, L"\\Device\\PhysicalMemory", PhysicalMemorySize))
		{
			result = STATUS_ACCESS_DENIED;
		}
		// KnownDlls检查        相等返回0，不等返回非0
		else if (!_wcsnicmp(pPubObjTypeInfo->TypeName.Buffer, L"\\KnownDlls\\", KnownDllsSize))
		{
			result = STATUS_ACCESS_DENIED;
		}
		else
		{
			//正常返回（非敏感路径）
			result = STATUS_SUCCESS;
		}
		return result;
	}
	//8、其他类型直接正常返回 不作处理
	result = STATUS_SUCCESS;
	return result;
}

//复制句柄
NTSTATUS NTAPI Fake_ZwDuplicateObject(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	ULONG          HandleCount = NULL;			//句柄个数
	ULONG          MaxHandleCount = 0xF8000;	//这是什么意思？？？？？？？
	ULONG          ReturnLength = NULL;
	PEPROCESS      SourceProcess = NULL;
	PEPROCESS      TargetProcess = NULL;
	PEPROCESS      Temp_Eprocess = NULL;		//临时使用
	PETHREAD       Temp_Thread = NULL;			//临时使用
	HANDLE         Temp_TargetHandle = NULL;	//临时使用，调用原始ZwDuplicateObject时候接收返回值
	//0、获取ZwDuplicateObject原始参数
	HANDLE  In_SourceProcessHandle = *(ULONG*)((ULONG)ArgArray);		//源进程PID
	HANDLE  In_SourceHandle = *(ULONG*)((ULONG)ArgArray + 4);			//要拷贝哪个句柄
	HANDLE  In_TargetProcessHandle = *(ULONG*)((ULONG)ArgArray + 0x8);	//目标进程PID
	PHANDLE In_TargetHandle = *(ULONG*)((ULONG)ArgArray + 0xC);			//指针,输出句柄
	ACCESS_MASK In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 0x10);	//权限
	ULONG In_Attributes = *(ULONG*)((ULONG)ArgArray + 0x14);
	ULONG In_Options = *(ULONG*)((ULONG)ArgArray + 0x18);
	//1、必须是应用层调用
	if (!ExGetPreviousMode())
	{
		return result;
	}
	//2、调用者是保护进程放行
	if (Safe_QueryWhitePID(PsGetCurrentProcessId()))
	{
		return result;
	}
	//3 句柄非Process类型退出
	if (Safe_QueryObjectType(In_SourceProcessHandle, L"Process"))
	{
		//4、没有DUPLICATE_CLOSE_SOURCE 权限,选择DUPLICATE_CLOSE_SOURCE时,源句柄就会自动关闭了
		if (!(In_Options & DUPLICATE_CLOSE_SOURCE))
		{
		_CheckParameter:
			//4、1 过滤掉非PROCESS类型
			if (!Safe_QueryObjectType(In_TargetProcessHandle, L"Process")
				|| Safe_QueryProcessHandleOrHandleCount(In_SourceProcessHandle)		//这一步意义是什么呢？获取句柄个数？检查是否合法句柄？？？
				|| Safe_QueryProcessHandleOrHandleCount(In_TargetProcessHandle))    //这一步意义是什么呢？获取句柄个数？检查是否合法句柄？？？
			{
				return result;
			}
			//4、2 假设TargetProcessHandle是保护进程则进行拦截
			if (Safe_QueryWintePID_ProcessHandle(In_TargetProcessHandle))
			{
				//4、3 获取句柄个数
				Status = Safe_ZwQueryInformationProcess(In_TargetProcessHandle, ProcessHandleCount, &HandleCount, sizeof(HandleCount), &ReturnLength);
				if (!NT_SUCCESS(Status))
				{
					//获取失败句柄个数为0
					HandleCount = 0;
				}
				//4、4 蜜汁比较？？？？？
				//dword_3323C默认是0x0FF8000有何意义？？？
				if ((g_dynData->dword_3323C >= HandleCount) && (g_dynData->dword_3323C - HandleCount <= MaxHandleCount))
				{
					result = STATUS_ACCESS_DENIED;
					return result;
				}
			}
			//4、5 自身句柄copy
			if ((In_SourceProcessHandle == NtCurrentProcess() &&
				In_TargetProcessHandle == NtCurrentProcess() &&
				(In_Options & DUPLICATE_SAME_ACCESS) && // 新句柄拥有与原始句柄相同的安全访问特征
				!(In_Attributes & OBJ_INHERIT))		  //这一个判断有何意义呢？没看明白
				)
			{
				result = STATUS_SUCCESS;
				return  result;
			}
			//4、6 分别获取SourceProcessHandle和TargetProcessHandle的Eprocess
			Status = ObReferenceObjectByHandle(In_SourceProcessHandle,
				PROCESS_DUP_HANDLE,
				PsProcessType,
				UserMode,
				&SourceProcess,
				NULL);
			if (!NT_SUCCESS(Status))
			{
				result = STATUS_SUCCESS;
				return  result;
			}
			Status = ObReferenceObjectByHandle(In_TargetProcessHandle,
				PROCESS_DUP_HANDLE,
				PsProcessType,
				UserMode,
				&TargetProcess,
				NULL);
			if (!NT_SUCCESS(Status))
			{
				ObfDereferenceObject(SourceProcess);
				result = STATUS_SUCCESS;
				return  result;
			}
			//4、8 源和目的句柄是一样的
			if (TargetProcess == SourceProcess &&
				In_Options & DUPLICATE_SAME_ACCESS && // 新句柄拥有与原始句柄相同的安全访问特征
				!(In_Attributes & OBJ_INHERIT)		  //这一个判断有何意义呢？没看明白
				)
			{
				ObfDereferenceObject(SourceProcess);
				ObfDereferenceObject(TargetProcess);
				result = STATUS_SUCCESS;
				return  result;
			}
			//解引用后面不需要使用了
			ObfDereferenceObject(SourceProcess);
			ObfDereferenceObject(TargetProcess);
			SourceProcess = NULL;
			TargetProcess = NULL;
			//4、7 SourceProcess为自身
			if (In_SourceProcessHandle == NtCurrentProcess())
			{
				//里面细化处理各种类型：File、Process、Section、Thread敏感操作
				//File：   违规操作：访问句柄是指定的白名单驱动对象
				//Process：违规操作：访问句柄是指定的白名单、自身进程是IE
				//Section：违规操作：路径是\\Device\\PhysicalMemory和\\KnownDlls\\ 
				//Thread： 违规操作：访问句柄是指定的白名单、自身进程是IE
				return Safe_26C42(In_SourceHandle, In_Options, In_DesiredAccess, In_TargetProcessHandle, In_SourceProcessHandle);
			}
			//4、8 SourceProcess非自身
			Status = ObReferenceObjectByHandle(In_SourceProcessHandle,
				PROCESS_DUP_HANDLE,
				PsProcessType,
				UserMode,
				&SourceProcess,
				NULL);
			if (NT_SUCCESS(Status))
			{
				//目标进程句柄 == 调用者
				if (SourceProcess == IoGetCurrentProcess())
				{
					ObfDereferenceObject(SourceProcess);
					//里面细化处理各种类型：File、Process、Section、Thread敏感操作
					//File：   违规操作：访问句柄是指定的白名单驱动对象
					//Process：违规操作：访问句柄是指定的白名单、自身进程是IE
					//Section：违规操作：路径是\\Device\\PhysicalMemory和\\KnownDlls\\ 
					//Thread： 违规操作：访问句柄是指定的白名单、自身进程是IE
					return Safe_26C42(In_SourceHandle, In_Options, In_DesiredAccess, In_TargetProcessHandle, In_SourceProcessHandle);
				}
				ObfDereferenceObject(SourceProcess);
			}
			//4、9  调用原始ZwDuplicateObject函数，进行函数调用后判断
			Status = Safe_ZwIoDuplicateObject(In_SourceProcessHandle, In_SourceHandle, NtCurrentProcess(), &Temp_TargetHandle, NULL, NULL, DUPLICATE_SAME_ACCESS, g_HighgVersionFlag, g_VersionFlag);
			//4、10 将拷贝后的对象句柄作为参数
			if (NT_SUCCESS(Status))
			{
				//里面细化处理各种类型：File、Process、Section、Thread敏感操作
				//File：   违规操作：访问句柄是指定的白名单驱动对象
				//Process：违规操作：访问句柄是指定的白名单、自身进程是IE
				//Section：违规操作：路径是\\Device\\PhysicalMemory和\\KnownDlls\\ 
				//Thread： 违规操作：访问句柄是指定的白名单、自身进程是IE
				result = Safe_26C42(Temp_TargetHandle, In_Options, In_DesiredAccess, In_TargetProcessHandle, In_SourceProcessHandle);
				Safe_ZwNtClose(Temp_TargetHandle, g_HighgVersionFlag);
				return result;
			}
			//4、11 失败返回：根据错误码返回不同的值
			return CheckResult_After_DuplicateObject(Status) != FALSE ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
		}
		//5、源目标进程句柄是保护进程直接拉闸
		if (Safe_QueryWintePID_ProcessHandle(In_SourceProcessHandle))
		{
			Safe_18A72_SendR3(PsGetCurrentProcessId(), PsGetCurrentThreadId(), 0xC);
			result = STATUS_ACCESS_DENIED;
			return result;
		}
		//6、......
		if (In_TargetProcessHandle && !Safe_CheckSysProcess_Csrss_Lsass(In_SourceProcessHandle) ||
			In_SourceProcessHandle == NtCurrentProcess())
		{
			//来源于Windows情景分析上4.8
			//In_TargetProcessHandle为0并不意味着目标进程就是源进程，而意味着不进行复制
			if (!In_TargetProcessHandle)		
			{
				result = STATUS_SUCCESS;
				return result;
			}
			else
			{
				goto _CheckParameter;
			}
		}
		//7、根据进程线程句柄得到对应Eprocess或则PETHREAD结构，防止访问了保护白名单进程
		//7、1 调用原始ZwDuplicateObject函数，进行函数调用后判断
		Status = Safe_ZwIoDuplicateObject(In_SourceProcessHandle, In_SourceHandle, NtCurrentProcess(), &Temp_TargetHandle, NULL, NULL, DUPLICATE_SAME_ACCESS, g_HighgVersionFlag, g_VersionFlag);
		if (!NT_SUCCESS(Status))
		{
			//失败错误返回
			return CheckResult_After_DuplicateObject(Status) != FALSE ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
		}
		//7、2 获取对应的Eprocess or PETHREAD结构
		Status = ObReferenceObjectByHandle(Temp_TargetHandle, NULL, PsProcessType, UserMode, &Temp_Eprocess, NULL);//获取Eprocess
		if (NT_SUCCESS(Status))
		{
			//通过Eprocess方式查找，假设是保护进程错误返回
			if (Safe_QueryWhitePID_PsGetProcessId(Temp_Eprocess))
			{
				result = STATUS_ACCESS_DENIED;
			}
			ObfDereferenceObject(Temp_Eprocess);
			Safe_ZwNtClose(Temp_TargetHandle, g_HighgVersionFlag);
			return result;
		}
		else
		{
			//非进程那就是线程了，获取PETHREAD
			Status = ObReferenceObjectByHandle(Temp_TargetHandle, NULL, PsThreadType, UserMode, &Temp_Thread, NULL);//获取PETHREAD
			if (NT_SUCCESS(Status))
			{
				//通过PETHREAD方式查找，假设是保护进程错误返回
				if (Safe_QueryWhitePID_PsGetThreadProcessId(Temp_Thread))
				{
					result = STATUS_ACCESS_DENIED;
				}
				ObfDereferenceObject(Temp_Thread);
				Safe_ZwNtClose(Temp_TargetHandle, g_HighgVersionFlag);
				return result;
			}
		}
		//记得释放句柄
		if (Temp_TargetHandle)
		{
			Safe_ZwNtClose(Temp_TargetHandle, g_HighgVersionFlag);
			Temp_TargetHandle = NULL;
		}
		//来源于Windows情景分析上4.8
		//8、In_TargetProcessHandle为0并不意味着目标进程就是源进程，而意味着不进行复制
		if (!In_TargetProcessHandle)		
		{
			result = STATUS_SUCCESS;
			return result;
		}
		else
		{
			goto _CheckParameter;
		}
	}
	return result;
}