#include "Fake_ZwCreateFile.h"

//************************************     
// 函数名称: After_ZwCreateFile_Func     
// 函数说明：原始函数执行后检查，保护进程路径则禁止用户打开（将句柄清零，看你怎么打开）  
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
NTSTATUS NTAPI After_ZwCreateFile_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS       Status, result;
	ULONG          ListIndex = 0;
	HANDLE         Handle_v5 = NULL;
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile = { 0 };			//文件信息
	result = STATUS_SUCCESS;
	//0、获取ZwCreateFile原始参数
	IN HANDLE             In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	IN ACCESS_MASK        In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	IN POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	IN PIO_STATUS_BLOCK	  In_IoStatusBlock = *(ULONG*)((ULONG)ArgArray + 0xC);
	IN PLARGE_INTEGER	  In_AllocationSize = *(ULONG*)((ULONG)ArgArray + 0x10);
	IN ULONG			  In_FileAttributes = *(ULONG*)((ULONG)ArgArray + 0x14);
	IN ULONG			  In_ShareAccess = *(ULONG*)((ULONG)ArgArray + 0x18);
	IN ULONG			  In_CreateDisposition = *(ULONG*)((ULONG)ArgArray + 0x1C);
	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	//2、判断HookPort版本合法性,我分析的就是0x3F1
	//if (g_HookPort_Version >= 0x3F1)
	//{
	//	if ((In_ShareAccess == FILE_SHARE_WRITE) || (In_ShareAccess == (FILE_SHARE_WRITE || FILE_SHARE_READ)) || (!In_ShareAccess) || (In_ShareAccess == (FILE_SHARE_READ | FILE_SHARE_DELETE)))
	//	{

	//	}
	//}
	//3、获取文件基本信息
	Handle_v5 = *(HANDLE*)In_FileHandle;
	Status = Safe_GetInformationFile(Handle_v5, (ULONG)&System_InformationFile, UserMode);
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	//4、查找该文件信息是否在列表中，找到返回1，失败返回0
	Status = Safe_QueryInformationFileList(System_InformationFile.IndexNumber_LowPart,
		System_InformationFile.u.IndexNumber_HighPart,
		System_InformationFile.VolumeSerialNumber);
	//不在列表中
	if (Status == 0)
	{
		//判断打开路径是不是//3600、//3600safe、//3600SafeBox等
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
	Safe_ZwNtClose(Handle_v5, g_VersionFlag);
	*(HANDLE*)In_FileHandle = 0;
	result = STATUS_ACCESS_DENIED;
	return result;
}

NTSTATUS NTAPI Fake_ZwCreateFile(IN ULONG CallIndex,IN PVOID ArgArray,IN PULONG ret_func,IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	PVOID		Object = NULL;
	HANDLE      FileHandle = NULL;
	HANDLE      TempRootDirectory = NULL;
	HANDLE		Handle_v4 = NULL;
	HANDLE		Handle_v5 = NULL;
	BOOLEAN     RootDirectoryFlag = NULL;								//释放标识符
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile_XOR = { 0 };		//文件信息
	OBJECT_ATTRIBUTES TempObjectAttributes = { 0 };						//临时变量
	result = STATUS_SUCCESS;
	//0、获取ZwCreateFile原始参数
	IN HANDLE             In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	IN ACCESS_MASK        In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	IN POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	IN PIO_STATUS_BLOCK	  In_IoStatusBlock = *(ULONG*)((ULONG)ArgArray + 0xC);
	IN PLARGE_INTEGER	  In_AllocationSize = *(ULONG*)((ULONG)ArgArray + 0x10);
	IN ULONG			  In_FileAttributes = *(ULONG*)((ULONG)ArgArray + 0x14);
	IN ULONG			  In_ShareAccess = *(ULONG*)((ULONG)ArgArray + 0x18);
	IN ULONG			  In_CreateDisposition = *(ULONG*)((ULONG)ArgArray + 0x1C);
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
		Safe_ZwNtClose(Handle_v5, g_HighgVersionFlag);
		result = STATUS_SUCCESS;
		return result;
	}
	//根据HookPort版本判断执行流程,低于0x3F1略版本懒的逆向了,我分析的是0x3F1的，反正代码执行不到哪里
	//xxxxxxxxxxxxxxx
	//非读写文件
	if (In_ShareAccess != FILE_SHARE_WRITE && In_ShareAccess != (FILE_SHARE_WRITE | FILE_SHARE_READ))
	{
		//设备和中间层驱动一般设置ShareAccess 为0，表示调用者以独占访问方式打开文件
		if (In_ShareAccess)
		{
			//!(*(WCHAR*)((ULONG)ArgArray + 0x1D) &0x10)这一句在干嘛？
			//取In_CreateDisposition低16为的高8位，& FILE_OVERWRITE_IF | FILE_MAXIMUM_DISPOSITION ？？？？？？？？？  看不懂
			if ((In_ShareAccess != (FILE_SHARE_DELETE | FILE_SHARE_READ)) && (In_ShareAccess != FILE_SHARE_DELETE) && !(*(WCHAR*)((ULONG)ArgArray + 0x1D) & 0x10))
			{
				//这里在干嘛？？？？？
				if (!(In_DesiredAccess & 0x520D0156) && ((In_FileAttributes & FILE_ATTRIBUTE_READONLY) || !(In_DesiredAccess & 0xFEEDFF7F)))
				{			
					result = STATUS_SUCCESS;
					return result;
				}
			}
		}
	}
	//!(*(WCHAR*)((ULONG)ArgArray + 0x1D) &0x10)这一句在干嘛？
	//取In_CreateDisposition低16为的高8位，& FILE_OVERWRITE_IF | FILE_MAXIMUM_DISPOSITION ？？？？？？？？？  看不懂
	if ((In_ShareAccess != (FILE_SHARE_DELETE | FILE_SHARE_READ)) && (In_ShareAccess != FILE_SHARE_DELETE) && !(*(WCHAR*)((ULONG)ArgArray + 0x1D) & 0x10))
	{
		*ret_func = After_ZwCreateFile_Func;
		result = STATUS_SUCCESS;
		return result;
	}
	if (myProbeRead(In_ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(Fake_ZwCreateFile：In_ObjectAttributes) error \r\n"));
		return 0;
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
		if (!NT_SUCCESS(Status))
		{
			//判断HookPort版本合法性,我分析的就是0x3F1,这一句是多余的，因为我不分析其他版本。。。。
			//if ((unsigned int)g_HookPort_Version < 0x3F1)
			//	return 0;
			if (In_ShareAccess)
			{
				if (In_ShareAccess != (FILE_SHARE_DELETE | FILE_SHARE_READ))
				{
					result = STATUS_SUCCESS;
					return result;
				}
			}
			*ret_func = After_ZwCreateFile_Func;
			result = STATUS_SUCCESS;
			return result;
		}
		else
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
				//禁止用户打开保护路径
				if (Safe_CheckProtectPath(FileHandle, KernelMode))
				{
					ZwClose(FileHandle);
					result = STATUS_SUCCESS;
					return result;
				}
			}
			ZwClose(FileHandle);
			result = STATUS_ACCESS_DENIED;
			return result;
		}
	}
	result = STATUS_GUARD_PAGE_VIOLATION;
	return result;
}
