#include "Object.h"

////不能将UNICODE_STRING转换成_OBJECT_NAME_INFORMATION当参数传入
//根据Object查询注册表路径
NTSTATUS NTAPI Safe_ObGetObjectNamePath(IN HANDLE In_ObjectHandle, OUT POBJECT_NAME_INFORMATION Out_ObjectNameInfo, IN ULONG In_Length)
{
	NTSTATUS Status = NULL;
	PVOID    Object = NULL;
	HANDLE   ObjectHandle = NULL;
	ULONG    ReturnLength = NULL;
	ULONG (NTAPI *pObGetObjectType)(HANDLE);
	UNICODE_STRING32 ObGetObjectTypeString;
	//1、获取ObGetObjectType
	Status = ObReferenceObjectByHandle(In_ObjectHandle, 0, 0, UserMode, &ObjectHandle, 0);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	pObGetObjectType = g_Thread_Information.pObGetObjectType;
	//判断是否存在值
	if (!g_Thread_Information.pObGetObjectType)
	{
		RtlInitUnicodeString(&ObGetObjectTypeString, L"ObGetObjectType");
		pObGetObjectType = MmGetSystemRoutineAddress(&ObGetObjectTypeString);
		g_Thread_Information.pObGetObjectType = (ULONG)pObGetObjectType;
		//无法找到直接退出
		if (!pObGetObjectType)
		{
			ObfDereferenceObject(ObjectHandle);
			return Status;
		}
	}
	//2、调用ObGetObjectType
	Object = pObGetObjectType(ObjectHandle);
	//3、驱动层通过注册表_OBJECT指针查询注册表路径ObQueryNameString
	if (Object)
	{
		Status = ObQueryNameString(Object, Out_ObjectNameInfo, In_Length, &ReturnLength);
	}
	//解引用
	ObfDereferenceObject(ObjectHandle);
	return Status;
}

//查找指定的Object类型
//成功返回：1
//失败返回：0
BOOLEAN NTAPI Safe_QueryObjectType(IN HANDLE ObjectHandle, IN PWCHAR pObjectTypeName)
{
	NTSTATUS Status = NULL;
	BOOLEAN  bReturn = FALSE;
	ULONG    ReturnLength = NULL;
	ULONG    FullPathSize = 0x1024;
	UNICODE_STRING32 CmpObjectTypeNameString;
	UNICODE_STRING32 CmpObjectPath;				//临时使用		
	POBJECT_NAME_INFORMATION pFullPath;
	ULONG Tag = 0x206B6444u;
	RtlInitUnicodeString(&CmpObjectTypeNameString, pObjectTypeName);
	pFullPath = (POBJECT_NAME_INFORMATION)Safe_AllocBuff(NonPagedPool, FullPathSize, Tag);
	if (!pFullPath)
	{
		bReturn = FALSE;
		return bReturn;
	}
	//win7或则Win7以上版本成立
	if (g_HighgVersionFlag)
	{
		Status = Safe_ObGetObjectNamePath(ObjectHandle, pFullPath, 0xC8);
		//判断字符串长度
		if (!NT_SUCCESS(Status))
		{
			ExFreePool(pFullPath);
			bReturn = FALSE;
			return bReturn;
		}
		//取ObjectNameInfo最后几个字节用来比较例如：xxxx//File,只取//后面的内容：File
		CmpObjectPath.Length = CmpObjectTypeNameString.Length;
		CmpObjectPath.Buffer = (ULONG)pFullPath->Name.Buffer + pFullPath->Name.Length - CmpObjectTypeNameString.Length;
		//判断字符串
		Status = RtlEqualUnicodeString(&CmpObjectPath, &CmpObjectTypeNameString, TRUE);
	}
	else
	{
		Status = ZwQueryObject(ObjectHandle, ObjectTypeInformation, &pFullPath, 0xC8, &ReturnLength);
		//判断字符串长度
		if (!NT_SUCCESS(Status) || (pFullPath->Name.Length != CmpObjectTypeNameString.Length))
		{
			ExFreePool(pFullPath);
			bReturn = FALSE;
			return bReturn;
		}
		//判断字符串
		Status = RtlEqualUnicodeString(&pFullPath->Name, &CmpObjectTypeNameString, TRUE);
	}
	ExFreePool(pFullPath);
	bReturn = Status ? 1 : 0;
	return bReturn;
}

NTSTATUS NTAPI Safe_Run_SeDeleteObjectAuditAlarm(IN HANDLE In_Handle)
{
	NTSTATUS result = STATUS_SUCCESS;
	NTSTATUS Status = NULL;
	PVOID	 Object = NULL;
	OBJECT_HANDLE_INFORMATION HandleInformation = { 0 };
	if (g_HighgVersionFlag)
	{
		Status = ObReferenceObjectByHandle(In_Handle, 0, 0, 1, &Object,&HandleInformation);
		if (NT_SUCCESS(Status))
		{
			ObMakeTemporaryObject(Object);
			if (HandleInformation.HandleAttributes & 4)
			{
				if (!pSeDeleteObjectAuditAlarmWithTransaction)
				{
					pSeDeleteObjectAuditAlarmWithTransaction = (NTSTATUS(NTAPI *)(PVOID, HANDLE, ULONG))MmGetSystemRoutineAddress(&SeDeleteObjectAuditAlarmWithTransaction);
					if (!pSeDeleteObjectAuditAlarmWithTransaction)
						SeDeleteObjectAuditAlarm(Object,In_Handle);
				}
				pSeDeleteObjectAuditAlarmWithTransaction(Object, In_Handle, 0);
			}
			//解引用
			ObfDereferenceObject(Object);
		}
		result = Status;
	}
	else
	{
		//驱动程序删除一个持久对象的惟一方法, 是通过调用ZwMakeTemporaryObject例程, 将对象转换为临时对象。
		result = ZwMakeTemporaryObject(In_Handle);
	}
	return result;
}