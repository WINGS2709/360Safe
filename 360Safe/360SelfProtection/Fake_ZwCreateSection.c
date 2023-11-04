/*
说明：
拦截KnownDLLs劫持
参考资料：
1、老树开新花：DLL劫持漏洞新玩法 
网址：https://www.freebuf.com/articles/78807.html
*/
#include "Fake_ZwCreateSection.h"

#define WHILEDEVICENUMBER_ZWCREATESECTION 0x7
//禁止访问的白名单
PWCHAR g_WhiteDriverName_ZwCreateSection[WHILEDEVICENUMBER_ZWCREATESECTION+1] = {
	L"\\safemon\\360Tray.exe",
	L"\\safemon\\QHSafeTray.exe",
	L"\\deepscan\\zhudongfangyu.exe",
	L"\\deepscan\\QHActiveDefense.exe",
	L"\\360SD.EXE",
	L"\\360RP.EXE",
	L"\\360RPS.EXE"
};

//************************************     
// 函数名称: After_ZwCreateSection_Func     
// 函数说明：原始函数执行后检查,保护进程路径则禁止用户打开（将句柄清零，看你怎么打开）   
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/03/31     
// 返 回 值: NTSTATUS NTAPI     
// 参    数: IN ULONG FilterIndex      
// 参    数: IN PVOID ArgArray         
// 参    数: IN NTSTATUS Result        
// 参    数: IN PULONG RetFuncArgArray 
//************************************ 
NTSTATUS NTAPI After_ZwCreateSection_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS       Status, result;
	CHAR		   ObjectInformation[0x500] = { 0 };						//大数字又写固定长度缓冲区（0x210u），溢出警告
	ULONG          ReturnLength = NULL;
	SIZE_T         KnownDllsSize = 0xB;
	PPUBLIC_OBJECT_TYPE_INFORMATION	pPubObjTypeInfo = NULL;
	result = STATUS_SUCCESS;
	//0、获取ZwCreateSection原始参数
	PHANDLE            In_SectionHandle = *(ULONG*)((ULONG)ArgArray);					
	ACCESS_MASK        In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	PLARGE_INTEGER     In_MaximumSize = *(ULONG*)((ULONG)ArgArray + 0xC);
	ULONG              In_SectionPageProtection = *(ULONG*)((ULONG)ArgArray + 0x10);
	ULONG              In_AllocationAttributes = *(ULONG*)((ULONG)ArgArray + 0x14);
	HANDLE             In_FileHandle = *(ULONG*)((ULONG)ArgArray + 0x18);
	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	//检查地址合法性
	if (myProbeRead(In_SectionHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(After_ZwCreateSection_Func：In_SectionHandle) error \r\n"));
		return result;
	}
	//假设是SafeMod白名单里面的进程信息，直接添加到列表中然后就返回即可
	if (RetFuncArgArray)
	{
		Safe_InsertSafeMonDataList(*(HANDLE*)In_SectionHandle, RetFuncArgArray);
		return result;
	}
	//非正常进程进行验证，执行到这里都是一些非保护或则非系统进程，这些都要检查
	Status = Safe_UserMode_ZwQueryObject(g_HighgVersionFlag, *(HANDLE*)In_SectionHandle, ObjectNameInformation, ObjectInformation, sizeof(ObjectInformation), &ReturnLength);
	pPubObjTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)ObjectInformation;
	if (!NT_SUCCESS(Status) ||
		!pPubObjTypeInfo->TypeName.Length 
		)
	{
		return result;
	}
	//KnownDlls检测
	//相等返回0，不等返回非0
	if (_wcsnicmp(pPubObjTypeInfo->TypeName.Buffer, L"\\KnownDlls\\", KnownDllsSize))
	{
		//正常
		return result;
	}
	//不正常继续检查（KnownDlls路径）
	if (g_dynData->SystemInformation.Userinit_Flag || (!Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_SMSS_EXE, g_VersionFlag)))
	{
		//调用SeDeleteObjectAuditAlarm多此一举？？？？？？？，我真没看懂这一句作用。有知道的可以告诉我下
		Safe_Run_SeDeleteObjectAuditAlarm(*(HANDLE*)In_SectionHandle);
		//进程直接句柄清零，禁止访问
		Safe_ZwNtClose(*(HANDLE*)In_SectionHandle, g_VersionFlag);
		*(HANDLE*)In_SectionHandle = 0;
		//Safe_18A72_SendR3(PsGetCurrentProcessId(), PsGetCurrentThreadId(),0x9);
		result = STATUS_ACCESS_DENIED;
		return result;
	}
	return result;
}

//略
BOOLEAN NTAPI Safe_18FDE(PDEVICE_OBJECT DeviceObject)
{
	ULONG DeviceType = NULL;
	BOOLEAN Result = FALSE;
	UNICODE_STRING DestinationString;
	PFILE_OBJECT	 FileObject = NULL;
	struct _KSEMAPHORE *v5;
	PDEVICE_OBJECT   pUnknownDeviceObject = NULL;
	//1、过滤掉特定文件设备类型
	DeviceType = DeviceObject->DeviceType;
	if (DeviceType == FILE_DEVICE_DISK ||			//磁盘设备
		DeviceType == FILE_DEVICE_CD_ROM ||			//CD光驱设备
		DeviceType == FILE_DEVICE_TAPE_FILE_SYSTEM //磁带文件系统
		)
	{
		RtlInitUnicodeString(&DestinationString, L"\\Device\\MountPointManager");
		if (IoGetDeviceObjectPointer(&DestinationString, GENERIC_ALL, (PFILE_OBJECT *)&FileObject, &pUnknownDeviceObject) >= 0)
		{
			PVOID v3 = pUnknownDeviceObject->DeviceExtension;
			ULONG v4 = 0;
			if (!v3
				|| (v5 = (struct _KSEMAPHORE *)((CHAR *)v3 + 0x1C), KeReadStateSemaphore((PRKSEMAPHORE)((CHAR *)v3 + 0x1C))))
			{
				ObfDereferenceObject(FileObject);
				Result = 1;
			}
			else
			{
				if (KeWaitForSingleObject(v5, 0, 0, 0, NULL) != STATUS_TIMEOUT)
				{
					KeReleaseSemaphore(v5, 0, 1, 0);
					v4 = 1;
				}
				ObfDereferenceObject(FileObject);
				Result = v4;
			}
		}
		else
		{
			Result = TRUE;
		}
	}
	else
	{
		Result = FALSE;
	}
	return Result;
}
//根据句柄获取Dos路径
NTSTATUS NTAPI Safe_DbgFileName(IN HANDLE Handle, OUT PUNICODE_STRING FullPathNameString, IN ULONG FullPathNameSize)
{
	UNICODE_STRING DosName;
	NTSTATUS       Status, result;
	PFILE_OBJECT   FileObject = NULL;
	PVOID          pBuff = NULL;
	ULONG		   Tag = 0x206B6444u;
	BOOLEAN		   WillFreeTargetVolumeName = TRUE;
	UNICODE_STRING TargetFileVolumeName;
	result = STATUS_SUCCESS;
	//1、非File类型继续执行
	if (!Handle || !Safe_QueryObjectType(Handle, L"File"))
	{
		result = STATUS_UNSUCCESSFUL;
		return result;
	}
	//2、得到文件对象指针
	Status = ObReferenceObjectByHandle(Handle, GENERIC_READ, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
	//2、1判断操作是否成功
	if (!NT_SUCCESS(Status) && !FileObject)
	{
		result = Status;
		return result;
	}
	//2、2 判断字符串
	if (!FileObject->FileName.Buffer || !FileObject->FileName.Length)
	{
		//关闭设备句柄
		ObfDereferenceObject(FileObject);
		result = STATUS_UNSUCCESSFUL;
		return result;
	}
	//3、new空间用来保存DosName地址
	pBuff = Safe_AllocBuff(NonPagedPool, FullPathNameSize, Tag);
	if (!pBuff)
	{
		//关闭设备句柄
		ObfDereferenceObject(FileObject);
		result = STATUS_NO_MEMORY;
		return result;
	}
	////略
	//if(!Safe_18FDE(FileObject->DeviceObject))
	//{
	//	ExFreePool(pBuff);
	//	result = STATUS_FILE_LOCK_CONFLICT;
	//	ObfDereferenceObject(FileObject);
	//	return result;
	//}

	//后面就是转换成Dos路径操作
	TargetFileVolumeName.Buffer = 0;
	TargetFileVolumeName.Length = 0;
	TargetFileVolumeName.MaximumLength = 0;
	//因为FILE_OBJECT.FileName的路径是不带盘符的，所以需要再获取盘符然后拼接起来
	//4、1 取得盘符DOS名
	Status = RtlVolumeDeviceToDosName(FileObject->DeviceObject, &TargetFileVolumeName);
	if (!NT_SUCCESS(Status))
	{
		RtlInitUnicodeString(&TargetFileVolumeName, L"\\");
		WillFreeTargetVolumeName = FALSE;
	}
	if (TargetFileVolumeName.Length + FileObject->FileName.Length >= 518)
	{
		ObfDereferenceObject(FileObject);
		if (WillFreeTargetVolumeName)
		{
			if (MmIsAddressValid(TargetFileVolumeName.Buffer))
				ExFreePool(TargetFileVolumeName.Buffer);
		}
		ExFreePool(pBuff);
		result = STATUS_INVALID_PARAMETER;
		return result;
	}
	//5、连接文件名：盘符 + FILE_OBJECT.FileName
	RtlInitUnicodeString(FullPathNameString, (PCWSTR)pBuff);
	FullPathNameString->MaximumLength = FullPathNameSize;
	Status = RtlAppendUnicodeStringToString(FullPathNameString, &TargetFileVolumeName);
	if (!NT_SUCCESS(Status))
	{
		ObfDereferenceObject(FileObject);
		if (WillFreeTargetVolumeName)
		{
			if (MmIsAddressValid(TargetFileVolumeName.Buffer))
				ExFreePool(TargetFileVolumeName.Buffer);
		}
		ExFreePool(pBuff);
		result = STATUS_INVALID_PARAMETER;
		return result;
	}
	Status = RtlAppendUnicodeStringToString(FullPathNameString, &FileObject->FileName);
	if (!NT_SUCCESS(Status))
	{
		ObfDereferenceObject(FileObject);
		if (WillFreeTargetVolumeName)
		{
			if (MmIsAddressValid(TargetFileVolumeName.Buffer))
				ExFreePool(TargetFileVolumeName.Buffer);
		}
		ExFreePool(pBuff);
		result = STATUS_INVALID_PARAMETER;
		return result;
	}
	ObfDereferenceObject(FileObject);
	if (WillFreeTargetVolumeName && MmIsAddressValid(TargetFileVolumeName.Buffer))
	{
		ExFreePool(TargetFileVolumeName.Buffer);
	}
	result = STATUS_SUCCESS;
	return result;
}


NTSTATUS NTAPI Fake_ZwCreateSection(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       Status, result;
	UNICODE_STRING FullPathNameString;													//FullPathNameString.buff缓冲区是new出来的，需要释放
	ULONG          FullPathNameSize = 0x1024;											//名称路径最大长度
	ULONG		   SEC_IMAGE = 0x1000000;
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile = { 0 };							//文件信息
	result = STATUS_SUCCESS;
	//0、获取ZwCreateSection原始参数
	PHANDLE            In_SectionHandle = *(ULONG*)((ULONG)ArgArray);					//这个接受返回的section的句柄。这和创建文件对象是一个套路
	ACCESS_MASK        In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	PLARGE_INTEGER     In_MaximumSize = *(ULONG*)((ULONG)ArgArray + 0xC);
	ULONG              In_SectionPageProtection = *(ULONG*)((ULONG)ArgArray + 0x10);
	ULONG              In_AllocationAttributes = *(ULONG*)((ULONG)ArgArray + 0x14);
	HANDLE             In_FileHandle = *(ULONG*)((ULONG)ArgArray + 0x18);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//初始化清零
		*(ULONG*)ret_arg = 0;							//如果你打开了受保护进程，就返回该受保护进程的信息，进行调用后检查
		if (In_DesiredAccess == SECTION_ALL_ACCESS
			&& In_SectionPageProtection == PAGE_EXECUTE
			&& In_AllocationAttributes == SEC_IMAGE
			&& !g_Win2K_XP_2003_Flag
			)
		{
			//2、根据句柄获取Dos路径
			Status = Safe_DbgFileName(In_FileHandle, &FullPathNameString, FullPathNameSize);
			if (!NT_SUCCESS(Status))
			{
				if (//Status == STATUS_FILE_LOCK_CONFLICT
					NT_SUCCESS(Safe_GetInformationFile(In_FileHandle, &System_InformationFile, UserMode))
					)
				{

					//  略
					// 防止打开受保护进程
					//	Safe_CheckCreateProcessCreationFlags();
				}
			}
			else
			{
				//3、查找该dos路径在列表第几项，ret_arg = 返回数组下标， 
				if (Safe_QuerSafeMonPathList(FullPathNameString.Buffer, &ret_arg)
					//Safe_CheckProcessNameSign(FullPathNameString);				废弃检查PE数字签名之类的
					)
				{
					Safe_CheckCreateProcessCreationFlags();
				}
				ExFreePool(FullPathNameString.Buffer);
			}
			if (ret_arg)
			{
				*ret_func = After_ZwCreateSection_Func;
				return result;
			}
		}
		if (In_ObjectAttributes)
		{
			*ret_func = After_ZwCreateSection_Func;
		}
	}
	return result;
}