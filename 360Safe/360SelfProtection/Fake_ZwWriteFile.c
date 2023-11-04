#include "Fake_ZwWriteFile.h"


//NTSTATUS NTAPI After_ZwWriteFile(IN HANDLE  FileHandle, IN HANDLE  Event  OPTIONAL, IN PIO_APC_ROUTINE  ApcRoutine  OPTIONAL, IN PVOID  ApcContext  OPTIONAL, OUT PIO_STATUS_BLOCK  IoStatusBlock, IN PVOID  Buffer, IN ULONG  Length, IN PLARGE_INTEGER  ByteOffset  OPTIONAL, IN PULONG  Key  OPTIONAL)
NTSTATUS NTAPI Fake_ZwWriteFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg)
{
	NTSTATUS       Status,result;
	PFILE_OBJECT   FileObject = NULL;
	PDRIVER_OBJECT pDeviceObject = NULL;
	ULONG		   DeviceType = 0;
	PDEVICE_OBJECT DeviceObject1 = NULL;
	PDEVICE_OBJECT pDiskDeviceObject = NULL;
	ULONG          Tag = 0x206B6444;
	PQUERY_PASS_R0SENDR3_DATA  pQuery_Pass = NULL;
	ULONG		   Flag = NULL;
	result = STATUS_SUCCESS;
	//将ZwWriteFile参数提出来
	IN HANDLE  In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	IN PVOID   In_ApcContext = *(ULONG*)((ULONG)ArgArray+0xC);
	//1、必须是应用层调用
	if (!ExGetPreviousMode())
	{
		return result;
	}
	//特殊白名单目前只发现360Tray.exe启动+1
	if (!g_SpecialWhite_List.SpecialWhiteListNumber)
	{
		return result;
	}
	//1、得到文件对象指针
	Status = ObReferenceObjectByHandle(In_FileHandle, FILE_ANY_ACCESS, *IoFileObjectType, UserMode, (PVOID*)&FileObject, NULL);
	//1、1判断操作是否成功
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	//2 判断设备对象、驱动对象、文件设备类型等
	pDeviceObject = FileObject->DeviceObject;
	if ((!FileObject->DeviceObject) || (!FileObject->DeviceObject->DriverObject) || (FileObject->DeviceObject->DeviceType != FILE_DEVICE_DISK))
	{
		//关闭设备句柄
		ObfDereferenceObject(FileObject);
		return result;
	}
	//3、通过设备相关文件对象指针得到设备对象指针
	DeviceObject1 = IoGetBaseFileSystemDeviceObject(FileObject);
	//4、获取磁盘对象
	Status = Safe_IoGetDiskDeviceObjectPrt(DeviceObject1, &pDiskDeviceObject);
	if (DeviceObject1 && NT_SUCCESS(Status))
	{
		ObfDereferenceObject(pDiskDeviceObject);
		if (FileObject->FileName.Buffer || FileObject->FileName.Length)
		{
			ObfDereferenceObject(FileObject);
			return result;
		}
	}
	//5、获取磁盘对象失败？？？？？？
	//关闭设备句柄
	ObfDereferenceObject(FileObject);
	if (PsGetCurrentProcessId() != g_Thread_Information.CurrentProcessId_0) 
	{
		if (PsGetCurrentProcessId() != g_Thread_Information.CurrentProcessId_1)
		{
			
			pQuery_Pass = (PQUERY_PASS_R0SENDR3_DATA)Safe_AllocBuff(NonPagedPool, sizeof(QUERY_PASS_R0SENDR3_DATA), Tag);
			if (!pQuery_Pass)
			{
				return result;
			}
			pQuery_Pass->Unknown_Flag_2 = 3;
			pQuery_Pass->CheckWhitePID = PsGetCurrentProcessId();								//后面用来判断是否是白名单进程
			pQuery_Pass->Unknown_CurrentThreadId_4 = PsGetCurrentThreadId();
			pQuery_Pass->Unknown_CurrentThreadId_5 = PsGetCurrentThreadId();
			pQuery_Pass->Unknown_Flag_6 = 1;
			pQuery_Pass->Unknown_Flag_8A = 0x200;
			pQuery_Pass->Unknown_Flag_8B = 0;
			pQuery_Pass->ApcContext = In_ApcContext;
			//R3与R0通讯部分没写
			//Flag = Safe_push_request_in_and_waitfor_finish(pQuery_Pass, 1);
			//发送到R3然后将这段地址空间释放
			if (pQuery_Pass)
			{
				ExFreePool(pQuery_Pass);
				pQuery_Pass = NULL;
			}
			switch (Flag)
			{
				case 0:						    //正常进程，返回0
				{
					g_Thread_Information.CurrentProcessId_0 = (ULONG)PsGetCurrentProcessId();
					result = STATUS_SUCCESS;
					break;
				}
				case 2:							//错误返回，返回2
				{
					result = STATUS_ACCESS_DENIED;
					break;
				}
				case 3:							 //保护进程，返回3
				{
					result = STATUS_SUCCESS;
					break;
				}
				default:						//一般不会执行到这里
				{
					g_Thread_Information.CurrentProcessId_1 = (ULONG)PsGetCurrentProcessId();
					result = STATUS_ACCESS_DENIED;
					break;
				}
			}
		}
		else
		{
			result = STATUS_ACCESS_DENIED;
			return result;
		}
	}
	return result;
}

//获取IoGetDiskDeviceObject函数地址，并调用该函数
NTSTATUS NTAPI Safe_IoGetDiskDeviceObjectPrt(PDEVICE_OBJECT FileSystemDeviceObject,PDEVICE_OBJECT* DiskDeviceObject)
{
	NTSTATUS       Status;
	UNICODE_STRING IoGetDiskDeviceObjectString;
	NTSTATUS (*IoGetDiskDeviceObjectPtr)(PDEVICE_OBJECT FileSystemDeviceObject, PDEVICE_OBJECT *DiskDeviceObject);
	//1、判断是不是第一次进去，如果是用MmGetSystemRoutineAddress方式获取IoGetDiskDeviceObject函数地址并保存起来
	IoGetDiskDeviceObjectPtr = g_Thread_Information.pIoGetDiskDeviceObjectPtr;
	if (!IoGetDiskDeviceObjectPtr)
	{
		RtlInitUnicodeString(&IoGetDiskDeviceObjectString, L"IoGetDiskDeviceObject");
		g_Thread_Information.pIoGetDiskDeviceObjectPtr = (ULONG)MmGetSystemRoutineAddress(&IoGetDiskDeviceObjectString);
		IoGetDiskDeviceObjectPtr = g_Thread_Information.pIoGetDiskDeviceObjectPtr;
		//1、1 还是获取失败直接返回
		if (!IoGetDiskDeviceObjectPtr)
		{
			Status = STATUS_UNSUCCESSFUL;
			return Status;
		}
	}
	//2、调用IoGetDiskDeviceObject函数
	Status = IoGetDiskDeviceObjectPtr(FileSystemDeviceObject, DiskDeviceObject);
	return Status;
}
