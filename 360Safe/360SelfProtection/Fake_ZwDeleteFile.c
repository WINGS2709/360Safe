#include "Fake_ZwDeleteFile.h"


//删除文件
NTSTATUS NTAPI Fake_ZwDeleteFile(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	PVOID		Object = NULL;
	HANDLE      FileHandle = NULL;
	HANDLE      TempRootDirectory = NULL;
	HANDLE		Handle_v4 = NULL;
	HANDLE		Handle_v5 = NULL;
	BOOLEAN     RootDirectoryFlag = FALSE;								//释放标识符
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile_XOR = { 0 };		//文件信息
	OBJECT_ATTRIBUTES TempObjectAttributes = { 0 };						//临时变量
	result = STATUS_SUCCESS;
	//0、获取ZwDelteFile原始参数
	IN POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	//1、必须是应用层调用
	if (!ExGetPreviousMode())
	{
		return result;
	}
	if (myProbeRead(In_ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(Fake_ZwDeleteFile：In_ObjectAttributes) error \r\n"));
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
	result = STATUS_GUARD_PAGE_VIOLATION;
	if (Status != STATUS_GUARD_PAGE_VIOLATION)
	{
		if (NT_SUCCESS(Status))
		{
			//获取文件信息
			Status = Safe_GetInformationFile(FileHandle, (ULONG)&System_InformationFile_XOR, KernelMode);
			ZwClose(FileHandle);
			//验证文件信息
			if (NT_SUCCESS(Status))
			{
				//查询XOR在不在列表中
				if (Safe_QueryInformationFileList(
					System_InformationFile_XOR.IndexNumber_LowPart,
					System_InformationFile_XOR.u.IndexNumber_HighPart,
					System_InformationFile_XOR.VolumeSerialNumber))
				{
					//非白名单直接错误返回
					if (!Safe_QueryWhitePID(PsGetCurrentProcessId()))
					{
						return STATUS_ACCESS_DENIED;
					}
				}
			}
		}
		result = STATUS_SUCCESS;
		return result;
	}
	return result;
}
