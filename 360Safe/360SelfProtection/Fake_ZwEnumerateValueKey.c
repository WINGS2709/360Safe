/*
参考资料：
1、内核中访问HKCU注册表           
网址：https://blog.csdn.net/cssxn/article/details/103089140
*/
#include "Fake_ZwEnumerateValueKey.h"

#define WHILEKEYNAMENUMBER 1
//拦截的白名单子项
PWCHAR g_CmpWhiteDeviceNameString[WHILEKEYNAMENUMBER + 1] = {
	L"360Disabled"
};



//************************************     
// 函数名称: After_ZwCreateSection_Func     
// 函数说明：原始函数执行后检查  
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
NTSTATUS NTAPI After_ZwEnumerateValueKey_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS                    Status = STATUS_SUCCESS;
	NTSTATUS	                result = STATUS_SUCCESS;
	// PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
	//0、获取ZwEnumerateValueKey原始参数
	HANDLE						In_KeyHandle = *(ULONG*)((ULONG)ArgArray);
	KEY_VALUE_INFORMATION_CLASS In_KeyValueInformationClass = *(ULONG*)((ULONG)ArgArray + 8);
	ULONG						In_Length = *(ULONG*)((ULONG)ArgArray + 0x10);
	ULONG						In_ResultLength = *(ULONG*)((ULONG)ArgArray + 0x14);
	PKEY_VALUE_FULL_INFORMATION In_KeyValueInformation = *(ULONG*)((ULONG)ArgArray + 0xC);			//只有KeyValueFullInformation的情况
	//1、判断上次调用原始函数返回值,并且检查KeyValueInformationClass（有点多此一举，只有为KeyValueFullInformation才进来）
	if (!NT_SUCCESS(InResult) && (In_KeyValueInformationClass != KeyValueFullInformation))
	{
		return InResult;
	}
	//2、检查参数合法性
	if (myProbeRead(In_KeyValueInformation, sizeof(KEY_VALUE_FULL_INFORMATION), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(After_ZwEnumerateValueKey_Func：In_KeyValueInformation) error \r\n"));
		return result;
	}
	//略
	return result;
}


//枚举valuekey
NTSTATUS NTAPI Fake_ZwEnumerateValueKey(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	HANDLE         Object = NULL;
	ULONG          NumberOfBytes = 0x1024;
	ULONG          ReturnLength = NULL;
	UNICODE_STRING CurrentVersion_RunPath = { 0 };
	UNICODE_STRING Out_CurrentUserKeyPath = { 0 };		//注意后续要释放：RtlFreeUnicodeString(&Out_CurrentUserKeyPath)
	UNICODE_STRING FullPathNameString = { 0 };			//完整路径：\\REGISTRY\\USER\\S-1-5-18  +  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
	ULONG          FullPathNameSize = 0;				//完整路径的大小
	ULONG          Tag = 0x206B6444u;
	PVOID          pBuff = NULL;						//new出来的空间，需要释放
	POBJECT_NAME_INFORMATION pFileNameInfo = NULL;		//new出来的空间，需要释放

	RtlInitUnicodeString(&CurrentVersion_RunPath, L"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
	//0、获取ZwEnumerateValueKey原始参数
	HANDLE In_KeyHandle = *(ULONG*)((ULONG)ArgArray);
	KEY_VALUE_INFORMATION_CLASS In_KeyValueInformationClass = *(ULONG*)((ULONG)ArgArray + 8);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//2、过滤部分条件
		if (!Safe_QueryWhitePID(PsGetCurrentProcessId()) &&				//非保护进程要检查
			In_KeyValueInformationClass == KeyValueFullInformation &&   //该值记载了子键对应的名字和内容
			Safe_CmpImageFileName("explorer.exe"))
		{
			Status = ObReferenceObjectByHandle(*(ULONG*)In_KeyHandle, 0, 0, UserMode, &Object, 0);
			if (!NT_SUCCESS(Status))
			{
				return result;
			}
			pFileNameInfo = (POBJECT_NAME_INFORMATION)Safe_AllocBuff(NonPagedPool, NumberOfBytes, Tag);
			if (!pFileNameInfo)
			{
				ObfDereferenceObject(Object);
				return result;
			}
			//2、驱动层通过注册表_OBJECT指针查询注册表路径ObQueryNameString
			Status = ObQueryNameString(Object, pFileNameInfo, NumberOfBytes, &ReturnLength);
			//解引用
			ObfDereferenceObject(Object);
			if (!NT_SUCCESS(Status) || !pFileNameInfo->Name.Buffer || !pFileNameInfo->Name.Length)
			{
				ExFreePool(pFileNameInfo);
				return result;
			}
			//3、敏感路径：\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run  开机启动的
			if (RtlEqualUnicodeString(&pFileNameInfo->Name, &CurrentVersion_RunPath, TRUE))
			{
				//敏感路径,需要函数执行后检查
				ExFreePool(pFileNameInfo);
				pFileNameInfo = NULL;
				*ret_func = After_ZwEnumerateValueKey_Func;
				return result;
			}
			//4、获取当前用户的SID
			Status = Safe_RunRtlFormatCurrentUserKeyPath(&Out_CurrentUserKeyPath);
			if (NT_SUCCESS(Status))
			{
				//5、合成路径：\\REGISTRY\\USER\\S-1-5-18  +  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
				//防止意外：申请原来空间的两倍应该不会出问题了把
				FullPathNameSize = (Out_CurrentUserKeyPath.MaximumLength + CurrentVersion_RunPath.MaximumLength) * 2;
				pBuff = Safe_AllocBuff(NonPagedPool, FullPathNameSize, Tag);
				if (pBuff)
				{
					FullPathNameString.MaximumLength = FullPathNameSize;
					FullPathNameString.Buffer = pBuff;
					RtlAppendUnicodeStringToString(&FullPathNameString, &Out_CurrentUserKeyPath);
					RtlAppendUnicodeToString(&FullPathNameString, CurrentVersion_RunPath.Buffer);
					//6、敏感路径：\\REGISTRY\\USER\\S-1-5-18\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run  开机启动的
					if (RtlEqualUnicodeString(&pFileNameInfo->Name, &FullPathNameString, TRUE))
					{
						*ret_func = After_ZwEnumerateValueKey_Func;
					}
					ExFreePool(pBuff);
					pBuff = NULL;
				}
				RtlFreeUnicodeString(&Out_CurrentUserKeyPath);
				//释放空间
				if (pFileNameInfo)
				{
					ExFreePool(pFileNameInfo);
					pFileNameInfo = NULL;
				}
				return result;
			}
			else
			{
				//释放空间
				if (pFileNameInfo)
				{
					ExFreePool(pFileNameInfo);
					pFileNameInfo = NULL;
				}
			}

		}
	}
	return result;
}