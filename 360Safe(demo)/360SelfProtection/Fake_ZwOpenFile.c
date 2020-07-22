#include "Fake_ZwOpenFile.h"

//************************************     
// 函数名称: After_ZwOpenFile_Func     
// 函数说明：原始函数执行后检查,保护进程路径则禁止用户打开（将句柄清零，看你怎么打开）   
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/03/31     
// 返 回 值: NTSTATUS NTAPI     
// 参    数: IN ULONG FilterIndex      [In]After_ZwOpenFileIndex序号
// 参    数: IN PVOID ArgArray         [In]ZwOpenFile参数的首地址
// 参    数: IN NTSTATUS Result        [In]调用原始ZwOpenFile返回值
// 参    数: IN PULONG RetFuncArgArray [In]与返回的函数指针对应的一个参数,在调用RetFuncArray中的一个函数时需要传递在本参数中对应的参数
//************************************  
NTSTATUS NTAPI After_ZwOpenFile_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS       Status, result;
	ULONG          ListIndex = 0;
	HANDLE         Handle_v5 = NULL;
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile = { 0 };			//文件信息
	result = STATUS_SUCCESS;
	//0、获取ZwOpenFile原始参数
	PHANDLE In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	ACCESS_MASK In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	PIO_STATUS_BLOCK In_IoStatusBlock = *(ULONG*)((ULONG)ArgArray + 0xC);
	ULONG In_ShareAccess = *(ULONG*)((ULONG)ArgArray + 0x10);
	ULONG In_OpenOptions = *(ULONG*)((ULONG)ArgArray + 0x14);
	//KdPrint(("After_ZwOpenFile_Func\t\n"));
	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	//检查地址合法性
	if (myProbeRead(In_FileHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(After_ZwOpenFile_Func：In_FileHandle) error \r\n"));
		return result;
	}
	//2、获取文件基本信息
	Handle_v5 = *(HANDLE*)In_FileHandle;
	Status = Safe_GetInformationFile(Handle_v5, (ULONG)&System_InformationFile, UserMode);
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	//3、查找该文件信息是否在列表中，找到返回1，失败返回0
	Status = Safe_QueryInformationFileList(System_InformationFile.IndexNumber_LowPart,
		System_InformationFile.u.IndexNumber_HighPart,
		System_InformationFile.VolumeSerialNumber);
	//不在列表中
	if (Status == 0)
	{
		//判断打开路径是不是//360、//360safe、//360SafeBox等
		if (!Safe_CheckProtectPath(Handle_v5, UserMode))
		{
			Handle_v5 = *(HANDLE*)In_FileHandle;
		}
		else
		{
			result = STATUS_SUCCESS;
			return result;
		}
	}
	//保护进程直接句柄清零，禁止访问
	Safe_ZwNtClose(Handle_v5,g_VersionFlag);
	*(HANDLE*)In_FileHandle = 0;
	result = STATUS_ACCESS_DENIED;
	return result;
}

//比较OpenFile文件对象名称 == \\Device\\LanmanServer
NTSTATUS NTAPI Safe_CmpLanmanServer(POBJECT_ATTRIBUTES ObjectAttributes)
{
	NTSTATUS       Status, result;
	PUNICODE_STRING ObjectName;
	result = STATUS_SUCCESS;

	UNICODE_STRING LanmanServerString;
	RtlInitUnicodeString(&LanmanServerString, L"\\Device\\LanmanServer");
	if (((ULONG)ObjectAttributes <= MmUserProbeAddress) &&		//是否小于系统地址
		(!ObjectAttributes->RootDirectory) &&					//可选的处理的根对象目录路径名指定的成员的ObjectName。如果RootDirectory是NULL, ObjectName必须指向一个完全限定对象名称,包括目标对象的完整路径。如果非空RootDirectory, ObjectName指定一个对象名称相对于RootDirectory目录。RootDirectory处理可以引用一个文件系统目录或目录对象管理器对象名称空间。
		(ObjectAttributes->Attributes == OBJ_CASE_INSENSITIVE)  //不区分大小写比较
		)
	{
		//判断OpenFile文件对象名称 == \\Device\\LanmanServer
		ObjectName = ObjectAttributes->ObjectName;
		if (((ULONG)ObjectName <= MmUserProbeAddress) && ObjectName->Length == LanmanServerString.Length)
		{
			if (ObjectName->Buffer <= MmUserProbeAddress)
			{
				Status = RtlEqualUnicodeString(ObjectName, &LanmanServerString, TRUE);
				if (Status)
				{
					//设置个开关防止重复操作
					Status = InterlockedCompareExchange(&g_HookSrvTransactionNotImplementedFlag, 1, 0);
					//第一次进入
					if (!Status)
					{
						//永恒之蓝的那个漏洞
						//永恒之蓝漏洞(CVE - 2017 - 0144), 替换srv!SrvTransaction2DispatchTable的0x0e
						result = Safe_HookSrvTransactionNotImplemented();
					}
				}
			}
		}
	}
	return result;
}

NTSTATUS NTAPI Fake_ZwOpenFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg)
{

	NTSTATUS    Status = STATUS_SUCCESS;
	NTSTATUS	result = STATUS_SUCCESS;
	PVOID		Object = NULL;
	HANDLE      FileHandle = NULL;
	HANDLE      TempRootDirectory = NULL;
	HANDLE		Handle_v4 = NULL;
	HANDLE		Handle_v5 = NULL;										//ZwOpenSymbolicLinkObject的句柄
	BOOLEAN     RootDirectoryFlag = FALSE;								//释放标识符
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile_XOR = { 0 };		//文件信息
	OBJECT_ATTRIBUTES TempObjectAttributes = { 0 };						//临时变量
	//0、获取ZwOpenFile原始参数
	HANDLE             In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	ACCESS_MASK        In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	PIO_STATUS_BLOCK   In_IoStatusBlock = *(ULONG*)((ULONG)ArgArray + 0xC);
	ULONG              In_ShareAccess = *(ULONG*)((ULONG)ArgArray + 0x10);
	ULONG              In_OpenOptions = *(ULONG*)((ULONG)ArgArray + 0x14);
	//1、必须是应用层调用
	if (!ExGetPreviousMode())
	{
		return result;
	}
	//2、获取自身句柄
	Handle_v4 = PsGetCurrentProcessId();
	//2、1非指定进程wininit.exe或则白名单进程
	if (Safe_QueryWhitePID(Handle_v4) || g_dynData->SystemInformation.Wininit_ProcessId && PsGetCurrentProcessId() == (HANDLE)g_dynData->SystemInformation.Wininit_ProcessId)
	{
		return result;
	}
	//3、比较OpenFile文件对象名称 == \\Device\\LanmanServer
	//成立启动永恒之蓝那个漏洞
	Safe_CmpLanmanServer(In_ObjectAttributes);
	//检查地址合法性
	if (myProbeRead(In_FileHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(Fake_ZwOpenFile：In_FileHandle) error \r\n"));
		return result;
	}
	//获取ZwOpenSymbolicLinkObject函数地址并执行
	Status = Safe_RunZwOpenSymbolicLinkObject(
		&Handle_v5,																	//[Out]句柄
		1,																			//[In]权限
		In_ObjectAttributes,														//[In]
		g_VersionFlag,																//[In]版本
		g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeServiceTableBase,			//[In]SSDT表基地址
		g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeNumberOfServices			//[In]SSDT表个数
		);
	if (NT_SUCCESS(Status))
	{
		Safe_ZwNtClose(Handle_v5,g_HighgVersionFlag);
		result = STATUS_SUCCESS;
		return result;
	}
	//判断共享属性,这是在判断撒？
	if (!(In_ShareAccess & 0x1000))
	{
		if (!(In_DesiredAccess & 0x520D0156) && (((ULONG)In_IoStatusBlock & 1) || !(In_DesiredAccess & 0xFEEDFF7F)))
		{
			result = STATUS_SUCCESS;
			return result;
		}
	}
	//没有启动userinit.exe
	if (!g_dynData->SystemInformation.Userinit_Flag)
	{
		//设置g_System_InformationFile_Data[Index]对应的SystemInformationList结构的PID和Eprocess值
		if (Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_SMSS_EXE, g_VersionFlag))
		{
			result = STATUS_SUCCESS;
			return result;
		}
	}
	//判断共享属性,这是在判断撒？
	if (!(In_ShareAccess & 0x1000))
	{
		*ret_func = After_ZwOpenFile_Func;
		result = STATUS_SUCCESS;
		return result;
	}
	TempRootDirectory = In_ObjectAttributes->RootDirectory;
	if (!In_ObjectAttributes->ObjectName->Length)
	{
		if (TempRootDirectory)
		{
			//获取文件信息
			Status = Safe_GetInformationFile(TempRootDirectory, (ULONG)&System_InformationFile_XOR, UserMode);
			//验证文件信息
			if (NT_SUCCESS(Status))
			{
				//查询XOR在不在列表中
				if (Safe_QueryInformationFileList(
					System_InformationFile_XOR.IndexNumber_LowPart,
					System_InformationFile_XOR.u.IndexNumber_HighPart,
					System_InformationFile_XOR.VolumeSerialNumber))
				{
					result = STATUS_ACCESS_DENIED;
					return result;
				}
			}
		}
		result = STATUS_SUCCESS;
		return result;
	}
	//win7或则Win7以上版本成立
	if (g_HighgVersionFlag && TempRootDirectory)
	{
		//1、得到文件对象指针
		Status = ObReferenceObjectByHandle(TempRootDirectory, NULL, NULL, UserMode, &Object, NULL);
		if (!NT_SUCCESS(Status))
		{
			TempRootDirectory = 0;
		}
		else
		{
			Status = ObOpenObjectByPointer(Object, OBJ_KERNEL_HANDLE, NULL, NULL, NULL, KernelMode, &TempRootDirectory);
			if (NT_SUCCESS(Status))
			{
				//RootDirectoryFlag为真表示使用ObOpenObjectByPointer获取的，这个需要释放的
				RootDirectoryFlag = TRUE;
			}
			else
			{
				TempRootDirectory = 0;
			}
			//引用计数记得-1
			ObfDereferenceObject(Object);
		}
	}
	InitializeObjectAttributes(
		&TempObjectAttributes,
		In_ObjectAttributes->ObjectName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		TempRootDirectory,
		NULL
		);
	Status = Safe_IoCreateFile(&TempObjectAttributes, &FileHandle);
	//RootDirectoryFlag为真表示使用ObOpenObjectByPointer获取的，这个需要释放的
	if (RootDirectoryFlag)
	{
		ZwClose(TempRootDirectory);
	}
	if (Status != STATUS_GUARD_PAGE_VIOLATION)
	{
		if (NT_SUCCESS(Status))
		{
			//获取文件信息
			Status = Safe_GetInformationFile(FileHandle, (ULONG)&System_InformationFile_XOR, KernelMode);
			//验证文件信息
			if (NT_SUCCESS(Status))
			{
				//查询XOR在不在列表中
				if (Safe_QueryInformationFileList(
					System_InformationFile_XOR.IndexNumber_LowPart,
					System_InformationFile_XOR.u.IndexNumber_HighPart,
					System_InformationFile_XOR.VolumeSerialNumber))
				{
					ZwClose(FileHandle);
					result = STATUS_ACCESS_DENIED;
					return result;
				}
				if (!Safe_CheckProtectPath(FileHandle, KernelMode))
				{
					ZwClose(FileHandle);
					result = STATUS_ACCESS_DENIED;
					return result;
				}
			}
			ZwClose(FileHandle);
		}
		result = STATUS_SUCCESS;
		return result;
	}
	result = STATUS_GUARD_PAGE_VIOLATION;
	return result;
}
