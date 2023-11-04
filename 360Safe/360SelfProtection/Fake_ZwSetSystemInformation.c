#include "Fake_ZwSetSystemInformation.h"


NTSTATUS NTAPI After_ZwSetSystemInformation_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS       Status = STATUS_SUCCESS;
	NTSTATUS       Result = STATUS_SUCCESS;
	//0、获取ZwSetSystemInformation原始函数
	SYSTEM_INFORMATION_CLASS In_SystemInformationClass = *(ULONG*)((ULONG)ArgArray);
	PVOID In_SystemInformation = *(ULONG*)((ULONG)ArgArray + 4);
	ULONG In_SystemInformationLength = *(ULONG*)((ULONG)ArgArray + 8);
	//略
	return Result;
}

//ZwSetSystemInformation（XP生效）
NTSTATUS NTAPI Fake_ZwSetSystemInformation(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       Status = STATUS_SUCCESS;
	NTSTATUS       Result = STATUS_SUCCESS;
	UNICODE_STRING Win32kString = { 0 };
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile_New = { 0 };			//自身文件信息
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile_Old = { 0 };			//原始文件信息
	PSYSTEM_LOAD_AND_CALL_IMAGE GregsImage = NULL;
	RtlInitUnicodeString(&Win32kString, L"\\SystemRoot\\System32\\win32k.sys");
	//0、获取ZwSetSystemInformation原始函数
	SYSTEM_INFORMATION_CLASS In_SystemInformationClass = *(ULONG*)((ULONG)ArgArray);
	PVOID In_SystemInformation = *(ULONG*)((ULONG)ArgArray + 4);
	ULONG In_SystemInformationLength = *(ULONG*)((ULONG)ArgArray + 8);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//只处理敏感加载驱动部分
		switch (In_SystemInformationClass)
		{
			case SystemLoadAndCallImage:
			{
				//加载驱动常用的
				__try
				{
					//判断参数合法性
					ProbeForRead(In_SystemInformation, sizeof(SYSTEM_LOAD_AND_CALL_IMAGE), sizeof(CHAR));
					GregsImage = (PSYSTEM_LOAD_AND_CALL_IMAGE)In_SystemInformation;
					if (GregsImage->ModuleName.Length)
					{
						ProbeForRead(GregsImage->ModuleName.Buffer, GregsImage->ModuleName.Length, sizeof(CHAR));
						//加载驱动是\\SystemRoot\\System32\\win32k.sys
						//两个一样的路径难道还能算出不同的结果?????????
						//存疑
						if (RtlEqualUnicodeString(GregsImage, &Win32kString,TRUE))
						{
							//判断Win32k是否被修改
							Status = Safe_KernelCreateFile(&GregsImage->ModuleName, (ULONG)&System_InformationFile_New);	//获取自身
 							Result = Safe_KernelCreateFile(&Win32kString, (ULONG)&System_InformationFile_Old);				//获取系统目录下原始Win32k
							if (NT_SUCCESS(Status) && NT_SUCCESS(Result)&&
								(System_InformationFile_New.IndexNumber_LowPart == System_InformationFile_Old.IndexNumber_LowPart) &&
								(System_InformationFile_New.VolumeSerialNumber == System_InformationFile_Old.VolumeSerialNumber) &&
								(System_InformationFile_New.u.IndexNumber_HighPart == System_InformationFile_Old.u.IndexNumber_HighPart))
							{
								//未被修改正常返回
								Result = STATUS_SUCCESS;
							}
							else
							{
								//失败返回
								Safe_18A72_SendR3(PsGetCurrentProcessId(), PsGetCurrentThreadId(), 0x0);
								Result = STATUS_ACCESS_DENIED;
							}
						}
						else
						{
							//正常驱动加载路径直接略
							Result = STATUS_SUCCESS;
						}
						//设置调用后检查
						*(ULONG*)ret_func = After_ZwSetSystemInformation_Func;
					}
					else
					{
						Result = STATUS_SUCCESS;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Result = STATUS_SUCCESS;
					return Result;
				}
				break;
			}
			case SystemHotpatchInformation:
			{
				//加载驱动常用的
				if (g_SystemHotpatchInformation_Switch &&	g_VersionFlag == WINDOWS_VERSION_XP)
				{
					//错误返回
					Safe_18A72_SendR3(PsGetCurrentProcessId(), PsGetCurrentThreadId(), 0x7);
					Result = STATUS_ACCESS_DENIED;
				}
				else
				{
					Result = STATUS_SUCCESS;
				}
				break;
			}
			case SystemLoadGdiDriverInSystemSpace:
			{
				//大数字没有进行拦截
				// 这个xp 默认返回 STATUS_INFO_LENGTH_MISMATCH
				break;
			}
			case SystemLoadImage:
			{
				//大数字没有进行拦截
				// 这个xp 默认返回 STATUS_INFO_LENGTH_MISMATCH
				break;
			}
			default:
			{
				//不感兴趣的无视
				Result = STATUS_SUCCESS;
				break;
			}
		}
	}
	return Result;
}
