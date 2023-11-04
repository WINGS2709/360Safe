#include <WinKernel.h>

//查询线程信息的
BOOLEAN NTAPI Safe_FindEprocessThreadCount(IN HANDLE In_ProcessHandle, IN BOOLEAN In_Flag)
{
	NTSTATUS Status; // eax@5
	BOOLEAN result = TRUE;
	PROCESS_BASIC_INFORMATION PBI = { 0 };
	ULONG ReturnLength = NULL;
	PSYSTEM_PROCESS_INFORMATION pInfo = NULL;
	size_t	BufLen = 4096; 
	//1、获取进程PID
	Status = Safe_ZwQueryInformationProcess(In_ProcessHandle, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
	if (!NT_SUCCESS(Status) || !PBI.UniqueProcessId)
	{
		return result;
	}
	//2、调用API获取信息
	do
	{
		if (pInfo)
		{
			ExFreePool(pInfo);
		}
		pInfo = Safe_AllocBuff(NonPagedPool, BufLen, SELFPROTECTION_POOLTAG);
		if (!pInfo)
		{

			return result;

		}
		Status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, BufLen, &ReturnLength);
		if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(pInfo);
			return result;
		}
		BufLen += 4096;
	} while (!NT_SUCCESS(Status));
	//3、找到进程并遍历所有线程
	while (1)
	{
		//判断是否还有下一个进程
		if (pInfo->NextEntryDelta == 0)
		{
			break;
		}
		//判断是否找到了进程ID
		if (pInfo->ProcessId == PBI.UniqueProcessId)
		{
			//线程个数
			if (pInfo->ThreadCount)
			{
				//进程线程个数等于1时候（刚创建时候就满足）,所以那些注入保护进程的在这里就已经GG了，因为跑起来的进程的线程个数不可能等于1
				if (!In_Flag || (pInfo->ThreadCount != 1) || pInfo->Threads->UserTime.QuadPart)
				{
					result = FALSE;
					break;
				}
			}
		}
		//换下一个节点
		pInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryDelta);
	}
	if (pInfo)
	{
		ExFreePool(pInfo);
	}
	return result;
}

//这个函数我没看懂，获取句柄个数失败
BOOLEAN NTAPI Safe_QueryProcessHandleOrHandleCount(IN HANDLE ProcessHandle)
{
	BOOLEAN result = TRUE;
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG  HandleCount = NULL;			//句柄个数
	ULONG  ReturnLength = NULL;
	PROCESS_HANDLE_TRACING_QUERY Pht = { 0 };	//这个结构没使用？？？？？？？？
	//1、获取句柄个数
	Status = Safe_ZwQueryInformationProcess(ProcessHandle, ProcessHandleCount, &HandleCount, sizeof(HandleCount), &ReturnLength);
	if (NT_SUCCESS(Status))
	{
		//2、这一步的意义是什么呢？Pht并没有使用？？？？？？？？？？？？？
		Status = Safe_ZwQueryInformationProcess(ProcessHandle, ProcessHandleTracing, &Pht, sizeof(PROCESS_HANDLE_TRACING_QUERY), &ReturnLength);
		if (HandleCount ||								//正常进程句柄个数不可能 == 0吧？？？？？
			NT_SUCCESS(Status) ||						
			Status != STATUS_PROCESS_IS_TERMINATING
			)
		{
			result = FALSE;
		}

	}
	return result;
}
NTSTATUS NTAPI Safe_ZwQueryInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT ULONG ReturnLength)
{
	NTSTATUS Status, result; // eax@5
	UNICODE_STRING32 DestinationString;
	PEPROCESS pPeprocess = NULL;
	HANDLE Handle = NULL;
	result = STATUS_SUCCESS;
	//win7或则Win7以上版本成立
	if (g_HighgVersionFlag)
	{ 
		if (ProcessInformationClass)
		{ 
			if (ProcessInformationClass == ProcessHandleCount || ProcessInformationClass == ProcessHandleTracing)
			{
				Status = ObReferenceObjectByHandle(ProcessHandle, NULL, PsProcessType, UserMode, &pPeprocess, 0);
				if (NT_SUCCESS(Status))
				{
					Status = ObOpenObjectByPointer(pPeprocess, OBJ_FORCE_ACCESS_CHECK, NULL, PROCESS_ALL_ACCESS, PsProcessType, KernelMode, &Handle);
					{
						if (NT_SUCCESS(Status))
						{
							Status = ZwQueryInformationProcess(Handle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
							ZwClose(Handle);
						}
					}
					ObfDereferenceObject((PVOID)pPeprocess);
				}
				result = Status;
			}
			else
			{
				result = STATUS_SUCCESS;
			}
		}
		else if (ProcessInformationLength == sizeof(PROCESS_BASIC_INFORMATION))
		{
			//查找ProcessBasicInformation
			if (!g_dynData->pPsGetProcessInheritedFromUniqueProcessId)
			{
				RtlInitUnicodeString(&DestinationString, L"PsGetProcessInheritedFromUniqueProcessId");
				g_dynData->pPsGetProcessInheritedFromUniqueProcessId = MmGetSystemRoutineAddress(&DestinationString);
			}
			if (!g_dynData->pPsGetProcessPeb)
			{
				RtlInitUnicodeString(&DestinationString, L"PsGetProcessPeb");
				g_dynData->pPsGetProcessPeb = MmGetSystemRoutineAddress(&DestinationString);
			}
			if (!g_dynData->pPsGetProcessExitStatus)
			{
				RtlInitUnicodeString(&DestinationString, L"PsGetProcessExitStatus");
				g_dynData->pPsGetProcessExitStatus = MmGetSystemRoutineAddress(&DestinationString);
			}
			Status = ObReferenceObjectByHandle(ProcessHandle, NULL, PsProcessType, UserMode, &pPeprocess, 0);
			if (NT_SUCCESS(Status))
			{
				PROCESS_BASIC_INFORMATION* PBI = ProcessInformation;
				PBI->BasePriority = 0;												//接收进程的优先级类
				if (g_dynData->pPsGetProcessExitStatus)								//接收进程终止状态
				{
					PBI->ExitStatus = g_dynData->pPsGetProcessExitStatus(pPeprocess);
				}
				if (g_dynData->pPsGetProcessInheritedFromUniqueProcessId)			//接收父进程ID
				{
					PBI->InheritedFromUniqueProcessId = g_dynData->pPsGetProcessInheritedFromUniqueProcessId(pPeprocess);
				}
				if (g_dynData->pPsGetProcessPeb)									//接收进程环境块地址
				{
					PBI->PebBaseAddress = (PPEB)g_dynData->pPsGetProcessPeb(pPeprocess);
				}
				if (g_dynData->pPsGetProcessId)										//接收进程ID
				{
					PBI->UniqueProcessId = g_dynData->pPsGetProcessId(pPeprocess);
				}
				ObfDereferenceObject((PVOID)pPeprocess);
				if (ReturnLength)
					*(ULONG*)ReturnLength = sizeof(PROCESS_BASIC_INFORMATION);

			}
			result = Status;
		}
		else
		{
			*(ULONG*)ReturnLength = sizeof(PROCESS_BASIC_INFORMATION);
			result = STATUS_BUFFER_TOO_SMALL;
			return result;
		}
	}
	else
	{
		Status = ZwQueryInformationProcess(
			ProcessHandle,
			ProcessInformationClass,
			ProcessInformation,
			ProcessInformationLength,
			ReturnLength);
	}
	return result;
}

//************************************     
// 函数名称: Safe_GetModuleBaseAddress     
// 函数说明：根据函数名获取指定内核基址    
// IDA地址 ：sub_16E2C
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/05     
// 返 回 值: BOOLEAN NTAPI     
// 参    数: PUNICODE_STRING ModuleName ModuleName    模块名 
// 参    数: PVOID * pModuleBase					  模块基址
// 参    数: ULONG * ModuleSize						  模块大小
// 参    数: USHORT * LoadOrderIndex    
//************************************  
BOOLEAN NTAPI Safe_GetModuleBaseAddress(IN PUNICODE_STRING ModuleName, OUT PVOID *pModuleBase, OUT ULONG *ModuleSize, OUT USHORT *LoadOrderIndex)
{

	NTSTATUS status; // eax@5

	ULONG    uCount; // eax@8  
	PSYSTEM_MODULE_INFORMATION    pSysModule;
	STRING DestinationString;
	UNICODE_STRING CmpString2;
	ULONG ReturnLength; // [sp+Ch] [bp-14h]@5  
	PCHAR  pModuleInfo = NULL; // [sp+10h] [bp-10h]@8
	size_t	BufLen = 4096; // [sp+14h] [bp-Ch]@12
	BOOLEAN Result = FALSE;
	PCHAR            pName = NULL;
	ULONG            ui;

	do {

		if (pModuleInfo)
			ExFreePool(pModuleInfo);

		pModuleInfo = ExAllocatePoolWithTag(NonPagedPool, BufLen, 0x12331231);

		if (!pModuleInfo)
		{
			Result = FALSE;
			return Result;

		}

		status = ZwQuerySystemInformation(SystemModuleInformation, pModuleInfo, BufLen, &ReturnLength);
		if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(pModuleInfo);
			Result = FALSE;
			return Result;
		}

		BufLen += 4096;

	} while (!NT_SUCCESS(status));


	uCount = (ULONG)*(ULONG *)pModuleInfo;
	pSysModule = (PSYSTEM_MODULE_INFORMATION)(pModuleInfo + sizeof(ULONG));

	if (!ModuleName)
	{

		*pModuleBase = pSysModule->Base;
		*ModuleSize = pSysModule->Size;
		ExFreePool(pModuleInfo);
		Result = TRUE;
		return Result;
	}

	for (ui = 0; ui < uCount; ui++)
	{

		pName = strrchr(pSysModule->ImageName, '\\');
		if (pName) {
			++pName;
		}
		else {
			pName = pSysModule->ImageName;
		}
		RtlInitAnsiString(&DestinationString, pName);
		status = RtlAnsiStringToUnicodeString(&CmpString2, &DestinationString, TRUE);
		if (!NT_SUCCESS(status))
		{
			Result = FALSE;
			break;
		}
		//相等退出
		if (RtlEqualUnicodeString(ModuleName, &CmpString2, TRUE))
		{
			Result = TRUE;
			break;
		}
		RtlFreeUnicodeString(&CmpString2);
		pSysModule++;

	}
	if (ui >= uCount)
	{
		ExFreePool(pModuleInfo);
		Result = FALSE;
		return Result;
	}
	if (pModuleBase)
	{
		*pModuleBase = pSysModule->Base;
	}
	if (ModuleSize)
	{
		*ModuleSize = pSysModule->Size;
	}
	if (LoadOrderIndex)
	{
		*LoadOrderIndex = pSysModule->LoadOrderIndex;
	}
	RtlFreeUnicodeString(&CmpString2);
	ExFreePool(pModuleInfo);
	return Result;
}


//PsGetProcessImageFileName函数
ULONG NTAPI Safe_PsGetProcessImageFileName(PEPROCESS Process, UCHAR* ImageFileName, ULONG ImageFileNameLen)
{
	ULONG Result = 0;
	UCHAR ErrorBuff[] = {"unknow_proc"};
	PVOID *pImageFileName = NULL;
	RtlZeroMemory(ImageFileName, ImageFileNameLen);
	//低版本代替PsGetProcessImageFileName
	if (g_dynData->Eprocess_Offset._Eprocess_ImageFileNameIndex)
	{
		pImageFileName = (ULONG *)(g_dynData->Eprocess_Offset._Eprocess_ImageFileNameIndex + (ULONG)Process);
		RtlCopyMemory(ImageFileName, pImageFileName, strlen(pImageFileName));
	}
	//高版本使用PsGetProcessImageFileName
	else if (g_dynData->pPsGetProcessImageFileName)
	{
		pImageFileName = (ULONG)g_dynData->pPsGetProcessImageFileName(Process);
		RtlCopyMemory(ImageFileName, pImageFileName, strlen(pImageFileName));
	}
	//都不存在直接写个失败值
	else
	{
		RtlCopyMemory(ImageFileName, ErrorBuff, strlen(ErrorBuff));
	}
	return Result;
}

//比较ImageFileName
//相同返回1，不同返回非0
BOOLEAN NTAPI Safe_CmpImageFileName(UCHAR *ImageFileName)
{
	UCHAR ImageFileNameBuff[0x256] = { 0 };
	Safe_PsGetProcessImageFileName(IoGetCurrentProcess(), &ImageFileNameBuff, sizeof(ImageFileNameBuff));
	return _stricmp(&ImageFileNameBuff, ImageFileName) == 0;
}

//************************************     
// 函数名称: Safe_LockMemory     
// 函数说明：通过编程方式使用 MDL 绕过 KiServiceTable 的只读属性，需要借助 Windows 执行体组件中的 I/O 管理器以及
//			 内存管理器导出的一些函数，大致流程如下：
//           IoAllocateMdl() 分配一个 MDL 来描述 KiServiceTable->MmProbeAndLockPages() 把该 MDL 描述的 KiServiceTable 所
//           属物理页锁定在内存中，并赋予对这张页面的读写访问权限（实际是将描述该页面的 PTE 内容中的 “R” 标志位修改成 “W”）
//           ->MmGetSystemAddressForMdlSafe() 将 KiServiceTable 映射到另一片内核虚拟地址区域（一般而言，位于 rootkit 被加载
//           到的内核地址范围内）。
// IDA地址 ：sub_15A28
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/25     
// 返 回 值: PVOID     
// 参    数: PVOID VirtualAddress     
// 参    数: ULONG Length     
// 参    数: PVOID *Mdl_a3     
//************************************  
PVOID Safe_LockMemory(PVOID VirtualAddress, ULONG Length, PVOID *Mdl_a3)
{
	PMDL Mdl_v3; // eax@1
	PMDL Mdl_v4; // eax@2
	PVOID result; // eax@3

	Mdl_v3 = IoAllocateMdl(VirtualAddress, Length, 0, FALSE, NULL);
	*Mdl_a3 = Mdl_v3;
	if (Mdl_v3)
	{
		MmProbeAndLockPages(Mdl_v3, KernelMode, IoModifyAccess);
		Mdl_v4 = Mdl_v3;
		if (Mdl_v3->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL))		//仅当 _MDL 的 MdlFlags 字段内设置了 MDL_MAPPED_TO_SYSTEM_VA 或  MDL_SOURCE_IS_NONPAGED_POOL 比特位，MappedSystemVa 字段才有效。
			result = Mdl_v4->MappedSystemVa;
		else
			result = MmMapLockedPagesSpecifyCache(Mdl_v4, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	}
	else
	{
		result = 0;
	}
	return result;
}


//释放MDL空间
PVOID  Safe_RemoveLockMemory(PMDL pmdl)
{
	MmUnlockPages(pmdl);
	IoFreeMdl(pmdl);
}

//查找符号链接(不带Open)
BOOLEAN NTAPI Safe_ZwQuerySymbolicLinkObject(IN HANDLE LinkHandle, OUT PUNICODE_STRING Out_LinkTarget)
{
	NTSTATUS Status;
	ULONG Tag = 0x206B6444;
	ULONG ReturnedLength = 1024;
	UNICODE_STRING LinkTarget;
	//1、动态分配内存的方式初始化
	LinkTarget.Length = 0;
	LinkTarget.MaximumLength = ReturnedLength;
	LinkTarget.Buffer = ExAllocatePoolWithTag(NonPagedPool, ReturnedLength, Tag);
	if (!LinkTarget.Buffer)
	{
		return FALSE;
	}
	//通过符号链接得到设备名
	Status = ZwQuerySymbolicLinkObject(LinkHandle, &LinkTarget, &ReturnedLength);
	if (NT_SUCCESS(Status))
	{
		*Out_LinkTarget = LinkTarget;
		return TRUE;
	}
	//释放旧分配内存
	ExFreePool(LinkTarget.Buffer);
	//再来一次,进行第二次判断：是否空间给小了？
	if (Status == STATUS_BUFFER_TOO_SMALL && Status == STATUS_BUFFER_OVERFLOW)
	{
		//重复操作再来一次
		LinkTarget.Length = 0;
		LinkTarget.MaximumLength = ReturnedLength;
		LinkTarget.Buffer = ExAllocatePoolWithTag(NonPagedPool, ReturnedLength, Tag);
		if (LinkTarget.Buffer)
		{
			//成功
			if (NT_SUCCESS(Status))
			{
				Out_LinkTarget = &LinkTarget;
				return TRUE;
			}
			//再次失败没办法了直接退出把
			else
			{
				//释放动态分配内存
				ExFreePool(LinkTarget.Buffer);
				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
	}
	return FALSE;
}

//查找符号链接
BOOLEAN NTAPI Safe_ZwQuerySymbolicLinkObject_Open(IN PUNICODE_STRING ObjectName, IN HANDLE DirectoryHandle, OUT PUNICODE_STRING Out_LinkTarget)
{
	NTSTATUS Status;
	ULONG Tag = 0x206B6444;
	ULONG ReturnedLength = 1024;
	UNICODE_STRING LinkTarget;
	HANDLE LinkHandle = NULL;
	// 1. 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	InitializeObjectAttributes(&ObjectAttributes, ObjectName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, DirectoryHandle, NULL);
	//得到符号链接句柄
	Status = ZwOpenSymbolicLinkObject(&LinkHandle, FILE_ALL_ACCESS, &ObjectAttributes);
	if (!NT_SUCCESS(Status))
	{
		return 0;
	}
	//2、动态分配内存的方式初始化
	LinkTarget.Length = 0;
	LinkTarget.MaximumLength = ReturnedLength;
	LinkTarget.Buffer = ExAllocatePoolWithTag(NonPagedPool, ReturnedLength, Tag);
	if (!LinkTarget.Buffer)
	{
		ZwClose(LinkHandle);
		return 0;
	}
	//通过符号链接得到设备名
	Status = ZwQuerySymbolicLinkObject(LinkHandle, &LinkTarget, &ReturnedLength);
	if (NT_SUCCESS(Status))
	{
		*Out_LinkTarget = LinkTarget;
		ZwClose(LinkHandle);
		return 1;
	}
	//释放动态分配内存
	ExFreePool(LinkTarget.Buffer);
	//再来一次，感觉没必要把？
	if (Status == STATUS_BUFFER_TOO_SMALL && Status == STATUS_BUFFER_OVERFLOW)
	{
		//重复操作再来一次
		//动态分配内存的方式初始化
		LinkTarget.Length = 0;
		LinkTarget.MaximumLength = ReturnedLength;
		LinkTarget.Buffer = ExAllocatePoolWithTag(NonPagedPool, ReturnedLength, Tag);
		if (LinkTarget.Buffer)
		{
			Status = ZwOpenSymbolicLinkObject(&LinkHandle, FILE_ALL_ACCESS, &ObjectAttributes);
			//成功
			if (NT_SUCCESS(Status))
			{
				Out_LinkTarget = &LinkTarget;
				ZwClose(LinkHandle);
				return 1;
			}
			//再次失败没办法了直接退出把
			else
			{
				ZwClose(LinkHandle);
				//释放动态分配内存
				ExFreePool(LinkTarget.Buffer);
				return 0;
			}
		}
		else
		{
			ZwClose(LinkHandle);
			return 0;
		}
	}
	ZwClose(LinkHandle);
	return 0;
}


// 查询对象
BOOLEAN NTAPI Safe_ZwQueryDirectoryObject(IN PUNICODE_STRING CmpString_a1, IN HANDLE DirectoryHandle, IN PUNICODE_STRING CmpString_a3)
{
	BOOLEAN Result;
	NTSTATUS Status;
	ULONG Tag = 0x206B6444;
	ULONG ReturnedLength = NULL;
	ULONG NewSize = 1024 * 2;
	UNICODE_STRING LinkTarget;
	HANDLE LinkHandle = NULL;
	ULONG Context;
	PDIRECTORY_BASIC_INFORMATION   pBuffer = NULL;			//后面释放，原始的不进行操作
	PDIRECTORY_BASIC_INFORMATION   pBuffer2 = NULL;			//备份的随便整
	UNICODE_STRING OutDestinationString;					//Safe_ZwQuerySymbolicLinkObject_Open函数的返回值
	UNICODE_STRING SymbolicLinkString;
	Result = FALSE;
	RtlInitUnicodeString(&SymbolicLinkString, L"SymbolicLink");
	//1、动态分配内存
	pBuffer = (PDIRECTORY_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, NewSize, Tag);
	if (!pBuffer)
	{
		//kdprintf("内存分配失败\t\n");
		return Result;
	}
	//2、查询对象
	Status = ZwQueryDirectoryObject(DirectoryHandle, pBuffer, NewSize, 0, 0, &Context, &ReturnedLength);
	if (NT_SUCCESS(Status))
	{
		//保留备份，方便后面释放
		pBuffer2 = pBuffer;
		if (Context)
		{
			while ((pBuffer2->ObjectName.Length != 0) && (pBuffer2->ObjectTypeName.Length != 0))
			{
				if (RtlEqualUnicodeString(&pBuffer2->ObjectTypeName, &SymbolicLinkString, TRUE)
					&& RtlPrefixUnicodeString(&pBuffer2->ObjectName, &CmpString_a3, TRUE)
					&& Safe_ZwQuerySymbolicLinkObject_Open(&pBuffer2->ObjectName, DirectoryHandle, &OutDestinationString)
					)
				{
					if (RtlEqualUnicodeString(&OutDestinationString, CmpString_a1, TRUE))
					{
						ExFreePool(OutDestinationString.Buffer);
						Result = TRUE;
						break;
					}
					ExFreePool(OutDestinationString.Buffer);
				}
				//偏移到下一个
				pBuffer2++;
				//没有就退出
				if (!--Context)
				{
					break;
				}
			}
		}
	}
	if (pBuffer)
	{
		ExFreePool(pBuffer);
	}
	return Result;
}

//************************************     
// 函数名称: Safe_RunZwOpenSymbolicLinkObject     
// 函数说明：获取ZwOpenSymbolicLinkObject函数地址并执行    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/03/30     
// 返 回 值: NTSTATUS NTAPI     
// 参    数: OUT PHANDLE LinkHandle					 [Out]句柄
// 参    数: IN ACCESS_MASK DesiredAccess			 [In]权限
// 参    数: IN POBJECT_ATTRIBUTES ObjectAttributes  [In]   
// 参    数: IN ULONG g_VersionFlag                    [In]版本
// 参    数: IN PVOID ServiceTableBase               [In]SSDT表基地址
// 参    数: IN ULONG NumberOfServices               [In]SSDT表个数
//************************************  
NTSTATUS NTAPI Safe_RunZwOpenSymbolicLinkObject(OUT PHANDLE LinkHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG Version_Flag, IN PVOID ServiceTableBase, IN ULONG NumberOfServices)
{
	ULONG ZwOpenSymbolicLinkObjectIndex = NULL;
	NTSTATUS Status;
	Status = STATUS_UNSUCCESSFUL;
	//extern
	//NTSTATUS ZwOpenSymbolicLinkObject(
	//	_Out_ PHANDLE            LinkHandle,
	//	_In_  ACCESS_MASK        DesiredAccess,
	//	_In_  POBJECT_ATTRIBUTES ObjectAttributes
	//	 ;
	NTSTATUS(NTAPI *ZwOpenSymbolicLinkObjectPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
	//1、SSDT表基地址和SSDT表个数不能为空
	if (!ServiceTableBase || !NumberOfServices)
	{
		return Status;
	}
	//2、获取该函数的序号
	if (!ZwOpenSymbolicLinkObjectIndex)
	{
		switch (Version_Flag)
		{
			case WINDOWS_VERSION_2K:
			{
				ZwOpenSymbolicLinkObjectIndex = 0x6E;
				break;
			}
			case WINDOWS_VERSION_XP:
			{
				ZwOpenSymbolicLinkObjectIndex = 0x7F;
				break;
			}
			case WINDOWS_VERSION_2K3_SP1_SP2:
			{
				ZwOpenSymbolicLinkObjectIndex = 0xC8;
				break;
			}
			case WINDOWS_VERSION_VISTA_2008:
			{
				ZwOpenSymbolicLinkObjectIndex = 0xC8;
				break; 
			}
			case WINDOWS_VERSION_7:
			{
				ZwOpenSymbolicLinkObjectIndex = 0xC5;
				break;
			}
			case WINDOWS_VERSION_8_9200‬:
			{
				ZwOpenSymbolicLinkObjectIndex = 0xD6;
				break;
			}
			case WINDOWS_VERSION_8_9600:
			{
				ZwOpenSymbolicLinkObjectIndex = 0xD9;
				break;
			}
			case ‬WINDOWS_VERSION_10:
			{
				if (*(UCHAR *)ZwOpenSymbolicLinkObject == 0xB8u
				&& *(ULONG *)((PCHAR)ZwOpenSymbolicLinkObject + 1) < (NumberOfServices))
				{
					ZwOpenSymbolicLinkObjectIndex = *(ULONG *)((PCHAR)ZwOpenSymbolicLinkObject + 1);
				}
				break;
			}
			default:
			{
				if (g_VersionFlag != ‬WINDOWS_VERSION_10)
				{
					return Status;
				}
				break;
			}
		}
	}
	ZwOpenSymbolicLinkObjectPtr = *(PVOID*)((ULONG)ServiceTableBase + 4 * ZwOpenSymbolicLinkObjectIndex);
	Status = ZwOpenSymbolicLinkObjectPtr(LinkHandle, DesiredAccess, ObjectAttributes);
	return Status;
}


PVOID Safe_AllocBuff(POOL_TYPE PoolType, ULONG Size, ULONG Tag)
{
	PVOID pBuff;
	pBuff = ExAllocatePoolWithTag(PoolType, Size, Tag);
	if (!pBuff)
		return FALSE;
	RtlZeroMemory(pBuff, Size);
	return pBuff;
}

//释放空间
PVOID Safe_ExFreePool(IN PVOID pBuff)
{
	if (MmIsAddressValid(pBuff))
	{
		ExFreePool(pBuff);
	}
}

//通过Handle获取Eprocess->UniqueProcessId
HANDLE NTAPI Safe_GetUniqueProcessId(HANDLE Handle)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	ULONG    UniqueProcessId = NULL;
	PEPROCESS pPeprocess = NULL;
	//1、获取该句柄Eprocess结构
	Status = ObReferenceObjectByHandle(Handle, NULL, PsProcessType, UserMode, &pPeprocess, 0);
	if (NT_SUCCESS(Status))
	{
		//2、获取Eprocess->UniqueProcessId
		UniqueProcessId = Safe_pPsGetProcessId(pPeprocess);
		ObfDereferenceObject((PVOID)pPeprocess);
	}
	else
	{
		UniqueProcessId = 0;
	}
	return UniqueProcessId;
}

ULONG NTAPI Safe_pPsGetProcessId(PVOID VirtualAddress)
{
	if (VirtualAddress < MmUserProbeAddress || !MmIsAddressValid(VirtualAddress))
		return 0;
	if (g_dynData->Eprocess_Offset._Eprocess_UniqueProcessIdIndex)
	{
		if (MmIsAddressValid((CHAR *)VirtualAddress + g_dynData->Eprocess_Offset._Eprocess_UniqueProcessIdIndex))
			return *(ULONG *)((CHAR *)VirtualAddress + g_dynData->Eprocess_Offset._Eprocess_UniqueProcessIdIndex);
		return 0;
	}
	return g_dynData->pPsGetProcessId(VirtualAddress);
}


//ZwCreateFile和ZwOpenFile使用的
//判断是不是打开的是3600目录路径
BOOLEAN NTAPI Safe_CheckProtectPath(IN HANDLE FileHandle, IN KPROCESSOR_MODE AccessMode)
{
	IO_STATUS_BLOCK StatusBlock = { 0 };
	FILE_STANDARD_INFORMATION FileInformation = { 0 };
	ULONG ReturnLength = NULL;
	CHAR	ObjectInformation[0x500] = { 0 };
	PPUBLIC_OBJECT_TYPE_INFORMATION	pPubObjTypeInfo;
	ULONG Tag = 0x206B6444;
	UNICODE_STRING x3600Signa;				//判断字符串末尾是不是3600
	UNICODE_STRING CmpBuffSelf;				//临时使用
	UNICODE_STRING CmpBuff3600;				//临时使用
	UNICODE_STRING CmpBuffa3600Safe;		//临时使用
	UNICODE_STRING CmpBuffaa3600SafeBox;    //临时使用
	WCHAR a3600Safe[] = { L"\\3600Safe" };	
	WCHAR a3600SafeBox[] = { L"\\3600SafeBox" };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	Status = AccessMode ? Safe_UserMode_ZwQueryInformationFile(FileHandle, &StatusBlock, (PVOID)&FileInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, g_HighgVersionFlag) : ZwQueryInformationFile(FileHandle, &StatusBlock, (PVOID)&FileInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("Cannot Query File Size! %08X\n", Status);
		return TRUE;
	}
	//判断是否为目录 
	if (FileInformation.Directory != TRUE)
	{
		//非目录退出了
		return TRUE;
	}
	if (AccessMode)
	{
		Status = Safe_UserMode_ZwQueryObject(g_HighgVersionFlag,FileHandle, ObjectNameInformation, ObjectInformation, sizeof(ObjectInformation), &ReturnLength);
	}
	else
	{
		Status = ZwQueryObject(FileHandle, ObjectNameInformation, ObjectInformation, sizeof(ObjectInformation), &ReturnLength);
	}
	pPubObjTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)ObjectInformation;
	//判断字符串末尾是否//3600
	RtlInitUnicodeString(&x3600Signa, L"\\3600");
	CmpBuff3600.Length = x3600Signa.Length;
	if (!NT_SUCCESS(Status)												//返回失败
		|| (pPubObjTypeInfo->TypeName.Length < x3600Signa.Length)		//长度 < \\3600
		|| (CmpBuff3600.Buffer = (ULONG)pPubObjTypeInfo->TypeName.Buffer + pPubObjTypeInfo->TypeName.Length - x3600Signa.Length,
		!RtlEqualUnicodeString(&CmpBuff3600, &x3600Signa, TRUE))		//末尾不是3600结尾，
		)
	{
		return TRUE;
	}
	//后面就有点矛盾了：
	//结尾是XXXXX//3600,那么3600Safe跟3600Safebox不会成立了啊？？？？？？？？
	//进一步判断//3600Safe、//3600Safebox
	RtlCopyMemory((PVOID)((ULONG)pPubObjTypeInfo->TypeName.Buffer + pPubObjTypeInfo->TypeName.Length), a3600Safe, wcslen(a3600Safe) * 2);
	RtlInitUnicodeString(&CmpBuffa3600Safe, pPubObjTypeInfo->TypeName.Buffer);
	if (Safe_QueryInformationFileList_Name(&CmpBuffa3600Safe))    //路径://3600Safe
	{
		KdPrint(("你访问的路径是://3600Safe\t\n"));
		return FALSE;
	}
	//3600Safebox
	RtlCopyMemory((PVOID)((ULONG)pPubObjTypeInfo->TypeName.Buffer + pPubObjTypeInfo->TypeName.Length), a3600SafeBox, wcslen(a3600SafeBox) * 2);
	RtlInitUnicodeString(&CmpBuffaa3600SafeBox, pPubObjTypeInfo->TypeName.Buffer);
	if (Safe_QueryInformationFileList_Name(&CmpBuffaa3600SafeBox)) //路径://3600SafeBox
	{
		KdPrint(("你访问的路径是://3600SafeBox\t\n"));
		return FALSE;
	}
	//自身
	RtlInitUnicodeString(&CmpBuffSelf, pPubObjTypeInfo->TypeName.Buffer);
	if (Safe_QueryInformationFileList_Name(&CmpBuffSelf))			//路径://3600
	{
		KdPrint(("你访问的路径是://3600\t\n"));
		return FALSE;
	}
	return TRUE;
}

//PE结构数字签名相关
BOOLEAN NTAPI Safe_18108(IN PCWSTR SourceString)
{
	UNICODE_STRING		      DestinationString;
	NTSTATUS			      Status = STATUS_UNSUCCESSFUL;
	HANDLE				      FileHandle = NULL;
	ULONG				      ulShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	ULONG				      ulCreateOpt = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE;
	FILE_STANDARD_INFORMATION FileStInformation = { 0 };
	SIZE_T					  ulLength = NULL;		// 读取多少字节
	BOOLEAN                   FreeVirtual_Flag = FALSE;	//使用ZwAllocateVirtualMemory申请内存的标识
	ULONG                     Tag = 0x206B6444u;
	PVOID                     pBuff = NULL;
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FALSE;
	}
	// 1. 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	RtlInitUnicodeString(&DestinationString, SourceString);
	InitializeObjectAttributes(&ObjectAttributes, &DestinationString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	//2、创建文件对象,比ZwCreateFile更加底层
	Status = IoCreateFile(
		&FileHandle,					// 返回文件句柄
		GENERIC_READ | SYNCHRONIZE,		// 文件操作描述
		&ObjectAttributes,				// OBJECT_ATTRIBUTES
		&IoStatusBlock,					// 接受函数的操作结果
		0,								// 初始文件大小
		FILE_ATTRIBUTE_NORMAL,			// 新建文件的属性
		ulShareAccess,				    // 文件共享方式
		FILE_OPEN,						// 打开文件
		ulCreateOpt,					// 打开操作的附加标志位
		NULL,							// 扩展属性区
		NULL,							// 扩展属性区长度
		CreateFileTypeNone,				// 必须是CreateFileTypeNone
		NULL,							// InternalParameters
		IO_NO_PARAMETER_CHECKING		// Options
		);
	//2、1 假设失败调用ZwCreateFile
	if (!NT_SUCCESS(Status))
	{
		Status = ZwCreateFile(
			&FileHandle,           // 返回文件句柄
			GENERIC_ALL,           // 文件操作描述
			&ObjectAttributes,     // OBJECT_ATTRIBUTES
			&IoStatusBlock,        // 接受函数的操作结果
			0,                     // 初始文件大小
			FILE_ATTRIBUTE_NORMAL, // 新建文件的属性
			ulShareAccess,         // 文件共享方式
			FILE_OPEN_IF,          // 文件存在则打开不存在则创建
			ulCreateOpt,           // 打开操作的附加标志位
			NULL,                  // 扩展属性区
			0);                    // 扩展属性区长度
		if (!NT_SUCCESS(Status))
		{
			if (Status != STATUS_OBJECT_PATH_SYNTAX_BAD)		//该路径非目录
			{
				DbgPrint("check by file : open file %ws failed! stat = %08X\n", SourceString, Status);
			}
			//失败返回
			return FALSE;
		}
	}
	//3、获取文件基本信息
	Status = ZwQueryInformationFile(FileHandle, &IoStatusBlock, (PVOID)&FileStInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (NT_SUCCESS(Status))
	{
		//3、1 new同等空间
		ulLength = FileStInformation.EndOfFile.LowPart;
		if (FileStInformation.EndOfFile.QuadPart <= 0x6400000ui64)
		{
			pBuff = Safe_AllocBuff(PagedPool, ulLength, Tag);
			if (!pBuff)
			{
				//3、2 换个ZwAllocateVirtualMemory函数继续申请内存
				Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pBuff, NULL, &ulLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				//win7或则Win7以上版本成立
				if (g_HighgVersionFlag || !NT_SUCCESS(Status))
				{
					//失败返回
					ZwClose(FileHandle);
					return FALSE;
				}
				//设置标志位，用来区分程序是用ZwAllocateVirtualMemory还是ExAllocatePoolWithTag来分配的空间，后续用来区分释放函数
				FreeVirtual_Flag = TRUE;
			}
			//4、 读取文件
			Status = ZwReadFile(
				FileHandle,    // 文件句柄
				NULL,          // 信号状态(一般为NULL)
				NULL, NULL,    // 保留
				&IoStatusBlock,// 接受函数的操作结果
				pBuff,		   // 保存读取数据的缓存
				ulLength,      // 想要读取的长度
				NULL,          // 读取的起始偏移
				NULL);         // 一般为NULL
			//5、读取文件成功进行后续XXX操作
			if (NT_SUCCESS(Status))
			{
				//后续PE检查操作,数字签名相关
				Safe_17C8A(pBuff, ulLength);
			}
			//区分释放空间的方式
			if (FreeVirtual_Flag)
			{
				//设置标志位置0
				FreeVirtual_Flag = FALSE;
				ZwFreeVirtualMemory(NtCurrentProcess(), &pBuff, &ulLength, MEM_RELEASE);
			}
			if (pBuff)
			{
				ExFreePool(pBuff);
			}
		}
	}
	else
	{
		DbgPrint("Cannot Query File Size! %08X\n", Status);
	}
	ZwClose(FileHandle);
	return TRUE;
}

//检查进程名称标志
BOOLEAN NTAPI Safe_CheckProcessNameSign(IN UNICODE_STRING SourceString)
{
	UNICODE_STRING NewDosPathString;			//新路径：/??/ + SourceString
	UNICODE_STRING PathSignString;
	WCHAR          PathSignBuff[] = L"\\??\\";
	ULONG          Tag = 0x206B6444u;
	ULONG          NewDosPathLen = NULL;
	if (!Safe_18108(SourceString.Buffer))
	{
		//路径前面加上:/??/
		//new的长度设置为原始的三倍防止溢出之类的
		NewDosPathLen = (SourceString.Length * 3) + wcslen(PathSignBuff) * 2;
		NewDosPathString.Length = NewDosPathLen;
		NewDosPathString.MaximumLength = NewDosPathLen + 2;			//MaximumLength字段包含NULL结束符所以多两个字节
		NewDosPathString.Buffer = Safe_AllocBuff(PagedPool, NewDosPathLen, Tag);
		if (!NewDosPathString.Buffer)
		{
			return FALSE;
		}
		//此时//??//
		RtlInitUnicodeString(&PathSignString, PathSignBuff);
		RtlCopyUnicodeString(&NewDosPathString, &PathSignString);
		//继续拼接字符串 -> //??// + SourceString
		RtlAppendUnicodeStringToString(&NewDosPathString, &SourceString);
		if (!Safe_18108(NewDosPathString.Buffer))
		{
			//失败返回
			DbgPrint("CheckProcessNameSign 2 failed\n");
			if (NewDosPathString.Buffer)
			{
				ExFreePool(NewDosPathString.Buffer);
			}
			return FALSE;
		}
		ExFreePool(NewDosPathString.Buffer);
	}
	return TRUE;
}



//************************************     
// 函数名称: Safe_PeLdrFindExportedRoutineByName     
// 函数说明：根据LDR链获取该DLL导入表信息，先获取kernel32然后再去导入表查找对应的API函数
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/04/21     
// 返 回 值: ULONG NTAPI                       成功返回对应的函数地址，失败返回0
// 参    数: IN PCHAR In_SourceAPINameBuff     要查找的API函数名
// 参    数: IN ULONG In_Flag                  区分Win7还是Win2K_XP_2003版本标识
//************************************ 
ULONG NTAPI Safe_PeLdrFindExportedRoutineByName(IN PCHAR In_SourceAPINameBuff, IN ULONG In_Flag)
{
	NTSTATUS	 Status = STATUS_SUCCESS;
	ULONG		 ReturnLength = NULL;
	PROCESS_BASIC_INFORMATION ProcessInfo;
	PLDR_DATA_TABLE_ENTRY pDataEntry;
	ULONG        DllBase = NULL;
	ANSI_STRING	FindAPIString;
	RtlInitAnsiString(&FindAPIString, In_SourceAPINameBuff);
	//1、获取进程信息
	Status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, (PVOID)&ProcessInfo, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
	if (!NT_SUCCESS(Status))
	{
		return 0;
	}
	//2、获取PEB信息
	PUCHAR Peb = (ULONG)ProcessInfo.PebBaseAddress;
	if (Peb > MmUserProbeAddress)
	{
		return 0;
	}
	//3、_PEB_LDR_DATA 地址
	PPEB_LDR_DATA LdrData = *(PUCHAR *)(Peb + PEB_LDR_DATA_OFFSET);
	PLIST_ENTRY InInitializationOrder = &LdrData->InInitializationOrderModuleList;
	PLIST_ENTRY pTemp = InInitializationOrder->Flink;
	pTemp = pTemp->Flink;
	//获取Kernel32.dll
	if (!In_Flag)
	{
		//Win2K_XP_2003版本
		pDataEntry = (PLDR_DATA_TABLE_ENTRY)pTemp;
		//第3个链表要 -0x10
		pDataEntry = (ULONG)pDataEntry - 0x10;
		DllBase = pDataEntry->DllBase;
	}
	else
	{
		//Win7
		pTemp = pTemp->Flink;
		pDataEntry = (PLDR_DATA_TABLE_ENTRY)pTemp;
		//第3个链表要 -0x10
		pDataEntry = (ULONG)pDataEntry - 0x10;
		DllBase = pDataEntry->DllBase;
	}
	if (DllBase > MmUserProbeAddress)
	{
		return 0;
	}
	return Safe_GetSymbolAddress(&FindAPIString, DllBase);
}

//获取句柄权限
NTSTATUS NTAPI Safe_GetGrantedAccess(IN HANDLE Handle, OUT PACCESS_MASK Out_GrantedAccess)
{
	NTSTATUS					result = STATUS_SUCCESS;
	NTSTATUS					Status = STATUS_SUCCESS;
	PVOID						Object = NULL;
	OBJECT_HANDLE_INFORMATION   HandleInfo = { 0 };
	if (Handle)
	{
		Status = ObReferenceObjectByHandle(Handle, NULL, NULL, UserMode, &Object, &HandleInfo);
		if (NT_SUCCESS(Status))
		{
			*Out_GrantedAccess = HandleInfo.GrantedAccess;
			ObfDereferenceObject(Object);
		}
		result = Status;
	}
	else
	{
		result = STATUS_UNSUCCESSFUL;
	}
	return result;
}


//检查进程合法性之类的函数
NTSTATUS NTAPI Safe_2555E(IN PWCHAR In_UserBuffPath, IN ULONG In_Type, IN SIZE_T In_UserBuffLen, IN ULONG In_Flag)
{
	NTSTATUS					result = STATUS_SUCCESS;
	NTSTATUS					Status = STATUS_SUCCESS;
	return result;
}