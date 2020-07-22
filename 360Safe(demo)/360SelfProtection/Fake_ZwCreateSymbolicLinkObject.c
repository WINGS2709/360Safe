/*
函数功能：
1、过滤掉\\Device\\PhysicalMemory敏感地址访问

参考资料：
1、突破HIPS的防御思路之duplicate physical memory    
网址：https://bbs.pediy.com/thread-89068.htm
2、续PhysicalMemory攻击                            
网址：https://bbs.pediy.com/thread-94203.htm
*/

#include "Fake_ZwCreateSymbolicLinkObject.h"



//创建符号链接
NTSTATUS NTAPI Fake_ZwCreateSymbolicLinkObject(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS            result = STATUS_SUCCESS;
	NTSTATUS            Status = STATUS_SUCCESS;
	HANDLE              FileHandle = NULL;
	ULONG               ulAttributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	OBJECT_ATTRIBUTES   ObjectAttributes = { 0 };
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile_XOR = { 0 };			//文件信息
	UNICODE_STRING      PhysicalMemoryString;								//防止R3直接访问\\Device\\PhysicalMemory，保护进程访问除外
	UNICODE_STRING      DevicesLanmanRedirectorString;						//禁止非进程访问共享文件夹
	UNICODE_STRING      DosDevicesComString;								//白名单：\\DosDevices\\COM
	UNICODE_STRING      DeviceMailSlotString;								//白名单：\\Device\\MailSlot
	UNICODE_STRING      DeviceNamedPipeString;								//白名单：\\Device\\NamedPipe
	UNICODE_STRING      DeviceMupString;									//白名单：\\Device\\Mup
	UNICODE_STRING      DeviceLPTString;									//白名单：\\Device\\LPT
	UNICODE_STRING      DeviceWebDavRedirectorString;						//白名单：\\Device\\WebDavRedirector
	//0、获取ZwCreateSymbolicLinkObject原始函数
	ACCESS_MASK			In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	POBJECT_ATTRIBUTES  In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	PUNICODE_STRING		In_TargetName = *(ULONG*)((ULONG)ArgArray + 0xC);
	//1、初始化字符串部分
	RtlInitUnicodeString(&PhysicalMemoryString, L"\\Device\\PhysicalMemory");
	RtlInitUnicodeString(&DevicesLanmanRedirectorString, L"\\Device\\LanmanRedirector");
	RtlInitUnicodeString(&DosDevicesComString, L"\\DosDevices\\COM");
	RtlInitUnicodeString(&DeviceMailSlotString, L"\\Device\\MailSlot");
	RtlInitUnicodeString(&DeviceNamedPipeString, L"\\Device\\NamedPipe");
	RtlInitUnicodeString(&DeviceMupString, L"\\Device\\Mup");
	RtlInitUnicodeString(&DeviceLPTString, L"\\Device\\LPT");
	RtlInitUnicodeString(&DeviceWebDavRedirectorString, L"\\Device\\WebDavRedirector");
	//2、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//判断参数合法性
		if (myProbeRead(In_TargetName, sizeof(UNICODE_STRING), sizeof(CHAR)))
		{
			KdPrint(("ProbeRead(Fake_ZwCreateSymbolicLinkObject：In_TargetName) error \r\n"));
			return result;
		}
		//访问敏感符号路径：\\Device\\PhysicalMemory，只有白名单调用者才有资格访问
		if (RtlEqualUnicodeString(In_TargetName, &PhysicalMemoryString, TRUE) && !Safe_QueryWhitePID(PsGetCurrentProcessId()))
		{
			result = STATUS_ACCESS_DENIED;
		}
		//访问敏感符号路径：\\Device\\LanmanRedirector 共享文件夹，只有白名单调用者才有资格访问
		else if (RtlEqualUnicodeString(In_TargetName, &DosDevicesComString, TRUE))
		{
			InitializeObjectAttributes(
				&ObjectAttributes,								 // 返回初始化完毕的结构体
				In_TargetName,									 // 文件对象名称
				ulAttributes,									 // 对象属性
				NULL, NULL);									 // 一般为NULL
			Status = Safe_IoCreateFile(&ObjectAttributes, &FileHandle);
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
			}
			else
			{
				//错误返回
				result = Status;
			}
		}
		//白名单的符号路径
		else if (RtlEqualUnicodeString(In_TargetName, &DosDevicesComString, TRUE) ||
			RtlEqualUnicodeString(In_TargetName, &DeviceMailSlotString, TRUE) ||
			RtlEqualUnicodeString(In_TargetName, &DeviceNamedPipeString, TRUE) ||
			RtlEqualUnicodeString(In_TargetName, &DeviceMupString, TRUE) ||
			RtlEqualUnicodeString(In_TargetName, &DeviceLPTString, TRUE) ||
			RtlEqualUnicodeString(In_TargetName, &DeviceWebDavRedirectorString, TRUE)
			)
		{
			result = STATUS_SUCCESS;
		}
	}
	return result;
}