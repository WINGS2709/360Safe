#include "System.h"

NTSTATUS HookPort_PsGetVersion()
{
	//1、获取版本信息
	ULONG result;
	RtlZeroMemory(&Global_osverinfo, sizeof(RTL_OSVERSIONINFOEXW));
	UNICODE_STRING ustrFuncName = { 0 };
	PFN_RtlGetVersion pfnRtlGetVersion = NULL;
	RtlInitUnicodeString(&ustrFuncName, L"RtlGetVersion");
	pfnRtlGetVersion = (PFN_RtlGetVersion)MmGetSystemRoutineAddress(&ustrFuncName);
	if (pfnRtlGetVersion)
	{
		pfnRtlGetVersion((PRTL_OSVERSIONINFOW)&Global_osverinfo);
	}
	else
	{
		PsGetVersion(&Global_osverinfo.dwMajorVersion, &Global_osverinfo.dwMinorVersion, &Global_osverinfo.dwBuildNumber, NULL);
	}
	if (Global_osverinfo.dwMajorVersion != 5 || Global_osverinfo.dwMinorVersion && Global_osverinfo.dwMinorVersion != 1)
	{
		if (Global_osverinfo.dwMajorVersion != 6)
		{
			goto LABEL_Win10;
		}
		if ((Global_osverinfo.dwMinorVersion || Global_osverinfo.dwBuildNumber != 6000 && Global_osverinfo.dwBuildNumber != 6001 && Global_osverinfo.dwBuildNumber != 6002 && Global_osverinfo.dwBuildNumber != 6003)
			&& (Global_osverinfo.dwMinorVersion != 1 || Global_osverinfo.dwBuildNumber != 7600 && Global_osverinfo.dwBuildNumber != 7601)
			&& (Global_osverinfo.dwMinorVersion != 2 || Global_osverinfo.dwBuildNumber != 9200))
		{
			if (Global_osverinfo.dwMinorVersion != 3)
			{
				return STATUS_NOT_SUPPORTED;
			}
			if (Global_osverinfo.dwBuildNumber == 9600)
			{
				return STATUS_SUCCESS;
			}
		LABEL_Win10:
			if (Global_osverinfo.dwMajorVersion == 10 && !Global_osverinfo.dwMinorVersion && (Global_osverinfo.dwBuildNumber == 10240 || Global_osverinfo.dwBuildNumber == 10586 || Global_osverinfo.dwBuildNumber > 10586))
			{
				Global_Version_Win10_Flag = 1;
				return STATUS_SUCCESS;
			}
			return STATUS_NOT_SUPPORTED;
		}
	}
	return STATUS_SUCCESS;
}