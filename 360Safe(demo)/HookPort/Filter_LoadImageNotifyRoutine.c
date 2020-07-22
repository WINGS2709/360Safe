/*
待逆向部分：win10版本的懒得逆了
这个LoadImageNotifyRoutine的Fake函数就在HookPort自身设置了，并非在360SelfProtection设置
*/

#include "Filter_LoadImageNotifyRoutine.h"


//Filter_LoadImageNotifyRoutine回调函数里面的开关，防止重复操作
ULONG Global_LoadImageNotifyRoutine_Flag = NULL;		//开关，执行就置1，未执行置0，防止重复操作

// 作用不明
VOID HookPort_SetFlag_Off()
{
	dword_1B110 = 0;
}

BOOL HookPort_CmpNtdll(PUNICODE_STRING FullImageName)
{
	UNICODE_STRING String_Ntdll = { 0 };
	UNICODE_STRING String_System32Ntdll = { 0 };
	NTSTATUS result = FALSE;
	RtlInitUnicodeString(&String_Ntdll, L"\\SystemRoot\\System32\\ntdll.dll");
	if ((RtlEqualUnicodeString(FullImageName, &String_Ntdll, TRUE) == 1) || (FullImageName->Length > 0x28))
	{
		if (_wcsnicmp((PWSTR)((CHAR *)FullImageName->Buffer + FullImageName->Length - 0x26), L"\\System32\\ntdll.dll", 0x13u) == 0)
		{
			result = TRUE;
		}
	}

	return result;

}

//这个LoadImageNotifyRoutine的Fake函数就在HookPort自身设置了，并非在360SelfProtection设置
VOID Filter_LoadImageNotifyRoutine(IN PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo)
{
	NTSTATUS result;
	PULONG FuncTable[16];
	PULONG ArgTable[16];

	ULONG		RetCount;
	PVOID		pArgArray = &FullImageName;//参数数组，指向栈中属于本函数的所有参数
	if (Global_Version_Win10_Flag)
	{
		//未完待续Win10未逆向
		if (!Global_Win32kFlag)
		{
			if (FullImageName)
			{
				if (BYTE1(ImageInfo->Properties) & 1)
				{
					if (HookPort_CmpNtdll(FullImageName))
					{
						//设置个开关防止重复操作
						if (!InterlockedCompareExchange(Global_LoadImageNotifyRoutine_Flag, 1, 0))
						{
							////后续待逆向
							//if (HookPort_12864(ImageInfo->ImageBase, 1))
							//{
							//	HookPort_InitFilterTable();
							//	if (HookPort_InitProxyAddress(0))
							//	{
							//		//设置ZwSetSystemInformation函数的hook开关
							//		g_SS_Filter_Table->SwitchTableForSSDT[g_SSDT_Func_Index_Data.ZwSetSystemInformationIndex] = 1;
							//		//sub_18500();
							//		HookPort_SetFlag_Off();
							//	}
							//}
						}
					}
				}
			}
		}
	}
	HookPort_DoFilter(LoadImageNotifyRoutine_FilterIndex, pArgArray, 0, 0, 0, 0);
}

