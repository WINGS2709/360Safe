//拦截DLL注入的,防止DLL劫持
//参考资料：
//1、一种绕过全局钩子安装拦截的思路
//网址：https://bbs.pediy.com/thread-92717.htm
#include "Fake_KeUserModeCallback.h"

NTSTATUS NTAPI Fake_ClientLoadLibrary(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg)
{
	NTSTATUS	result = STATUS_SUCCESS;
	UNICODE_STRING prl_hookString = { 0 };
	UNICODE_STRING DestinationString = { 0 };
	UNICODE_STRING ptrDllString = { 0 };
	 ULONG MsctfDllSize = 5;
	 ULONG MsctfDllPathMinSize = 0x12;
	 ULONG prl_hookDllSize = 8;
	 ULONG prl_hookPathMinSize = 0x18;
	 WCHAR szDllName[MAX_PATH] = { 0 };
	 WCHAR Wildcard[] = { L"\\??\\" };
	 WCHAR SystemRootWildcard[] = { L"\\SystemRoot\\system32" };
	 PCLientLoadLibraryParam pCLientLoadLibraryParam = NULL;
	 SYSTEM_INFORMATIONFILE_XOR System_InformationFile = { 0 };		
	 RtlInitUnicodeString(&prl_hookString, L"C:\\Program Files\\Parallels\\Parallels Tools\\Services\\prl_hook.dll");
	 //将ClientLoadLibrary参数提出来
	 IN PVOID In_InputBuffer = *(ULONG*)((ULONG)ArgArray + 4);
	 IN PVOID In_InputLength = *(ULONG*)((ULONG)ArgArray + 8);
	//判断是不是保护进程，是返回：1  不是返回0
	result = Safe_QueryWhitePID(PsGetCurrentProcessId());
	if (result)
	{
		//判断长度
		if (!In_InputLength)
		{
			return STATUS_SUCCESS;
		}
		//设置要比较的DLL字符串信息
		pCLientLoadLibraryParam = (PCLientLoadLibraryParam)In_InputBuffer;
		ptrDllString.MaximumLength = pCLientLoadLibraryParam->MaximumLength;
		ptrDllString.Buffer = ((ULONG)In_InputBuffer + (ULONG)pCLientLoadLibraryParam->ptrDllString);		//基地+偏移
		ptrDllString.Length = 2 * wcslen(ptrDllString.Buffer);
		if (ptrDllString.Length >= MsctfDllPathMinSize)
		{
			//参考MJ0011
			//防止修改msctf绕过安全软件的全局钩子拦截
			if (_wcsnicmp((PWSTR)((CHAR *)ptrDllString.Buffer + (ptrDllString.Length - MsctfDllPathMinSize)), L"msctf.dll", MsctfDllSize) == 0)
			{
				if (wcschr(ptrDllString.Buffer, '\\'))
				{
					//构造 //??//通配符
					RtlCopyMemory(szDllName, Wildcard, wcslen(Wildcard) * 2);
					RtlCopyMemory((PVOID)(szDllName + 4), ptrDllString.Buffer, ptrDllString.Length);
					RtlInitUnicodeString(&DestinationString, (PCWSTR)szDllName);
				}
				else
				{
					//构造\\SystemRoot\\system32通配符
					RtlCopyMemory(szDllName, SystemRootWildcard, wcslen(SystemRootWildcard) * 2);
					RtlCopyMemory((PVOID)(szDllName + 0x14), ptrDllString.Buffer, ptrDllString.Length);
					RtlInitUnicodeString(&DestinationString, (PCWSTR)szDllName);
				}
				//计算DLL防止恶意修改做校验
				result = Safe_KernelCreateFile(&DestinationString, (ULONG)&System_InformationFile);// 防止恶意修改做校验
				if (!NT_SUCCESS(result))
				{
					return result;
				}
				//检查运行过程中DLL是否被修改(msctf.dll)
				if ((System_InformationFile.IndexNumber_LowPart == g_System_InformationFile_Data[SYSTEMROOT_SYSTEM32_MSCTF_DLL].IndexNumber_LowPart) &&
					(System_InformationFile.VolumeSerialNumber == g_System_InformationFile_Data[SYSTEMROOT_SYSTEM32_MSCTF_DLL].VolumeSerialNumber) &&
					(System_InformationFile.u.IndexNumber_HighPart == g_System_InformationFile_Data[SYSTEMROOT_SYSTEM32_MSCTF_DLL].u.IndexNumber_HighPart)
					)
				{
					//成功返回
					return STATUS_SUCCESS;
				}
				else
				{
					//失败返回，msctf.dll被恶意修改
					return STATUS_ACCESS_DENIED;
				}
			}
		}
		//prl_hook.dll？？？？？,冷门的DLL？？？？？，有明白的小伙伴可以告诉下我
		if ((ptrDllString.Length >= prl_hookPathMinSize) && (_wcsnicmp((PWSTR)((CHAR *)ptrDllString.Buffer + (ptrDllString.Length - prl_hookPathMinSize)), L"prl_hook.dll", prl_hookDllSize) == 0))
		{
			if (!RtlEqualUnicodeString(&prl_hookString, &ptrDllString, TRUE) || !g_Thread_Information.UniqueProcessId)
			{
				return STATUS_ACCESS_DENIED;
			}
			else
			{
				return STATUS_SUCCESS;
			}
			
		}
		//特殊关照的黑名单？？？？？？？？
		result = RtlEqualUnicodeString(&ptrDllString, &g_IllegalityDllPath, TRUE) != 0 ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
	}
	//非保护进程直接退出
	return result;
}