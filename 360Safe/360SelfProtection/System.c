/*
文件说明：获取系统版本信息之类的
*/

#include "System.h"


//************************************     
// 函数名称: Safe_PsGetVersion     
// 函数说明：获取系统版本信息   
// IDA地址 ：Sub_23B32 
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/11/29     
// 返 回 值: ULONG     
//************************************  
ULONG Safe_PsGetVersion()
{
	ULONG result;
	RtlZeroMemory(&osverinfo, sizeof(RTL_OSVERSIONINFOEXW));
	UNICODE_STRING ustrFuncName = { 0 };
	PFN_RtlGetVersion pfnRtlGetVersion = NULL;
	RtlInitUnicodeString(&ustrFuncName, L"RtlGetVersion");
	pfnRtlGetVersion = MmGetSystemRoutineAddress(&ustrFuncName);
	if (pfnRtlGetVersion)
	{
		pfnRtlGetVersion((PRTL_OSVERSIONINFOW)&osverinfo);
	}
	else
	{
		PsGetVersion(&osverinfo.dwMajorVersion, &osverinfo.dwMinorVersion, &osverinfo.dwBuildNumber, NULL);
	}
	result = osverinfo.dwMajorVersion;
	g_Win2K_XP_2003_Flag = 1;					//Win2K版本置0，默认是1
	g_VersionFlag = 0;
	//Win2K、WinXP、Win2003
	if (osverinfo.dwMajorVersion == 5)
	{
		result = osverinfo.dwMajorVersion;
		//Win_2K
		if (!osverinfo.dwMinorVersion)
		{
			g_VersionFlag = WINDOWS_VERSION_2K;
		LABEL_4:
			g_Win2K_XP_2003_Flag = 0;
			return result;
		}
		//Win_XP
		if (osverinfo.dwMinorVersion == 1)
		{
			g_VersionFlag = WINDOWS_VERSION_XP;
			goto LABEL_4;
		}
		//Win2003
		if (osverinfo.dwMinorVersion == 2)
		{
			g_VersionFlag = WINDOWS_VERSION_2K3;
			goto LABEL_4;
		}
	}
	//Win7、Win8
	else if (osverinfo.dwMajorVersion == 6)
	{
		result = osverinfo.dwMajorVersion;
		if (osverinfo.dwMinorVersion)
		{
			//Win7
			if (osverinfo.dwMinorVersion == 1)
			{
				result = osverinfo.dwBuildNumber;
				if (
					osverinfo.dwBuildNumber == 0x1BBC ||		//Win7 ‭7100‬
					osverinfo.dwBuildNumber == 0x1DB0 ||		//Win7 ‭7600‬
					osverinfo.dwBuildNumber == 0x1DB1			//Win7 7601
					)
					g_VersionFlag = WINDOWS_VERSION_7;
			}
			//‭Win8 9200‬
			else if (osverinfo.dwMinorVersion == 2)
			{
				if (osverinfo.dwBuildNumber == 0x23F0)
					g_VersionFlag = WINDOWS_VERSION_8_9200‬;
			}
			//Win8 9600
			else if (osverinfo.dwMinorVersion == 3 && osverinfo.dwBuildNumber == 0x2580)
			{
				g_VersionFlag = WINDOWS_VERSION_8_9600;
			}
		}
		//VISTA 
		else
		{
			result = osverinfo.dwBuildNumber;
			if (osverinfo.dwBuildNumber != 0x1770 && osverinfo.dwBuildNumber != 0x1771)
			{
				//vista sp2 6002 6003
				if (osverinfo.dwBuildNumber == 0x1772 || osverinfo.dwBuildNumber == 0x1773)
					osverinfo.dwBuildNumber = WINDOWS_VERSION_VISTA_2008;
			}
			//vista 6000 sp1 6001
			else
			{
				g_VersionFlag = 	WINDOWS_VERSION_2K3_SP1_SP2;
			}
		}
	}
	//Win10
	else if (osverinfo.dwMajorVersion == 10 && !osverinfo.dwMinorVersion)
	{
		result = osverinfo.dwBuildNumber;
		if (
			osverinfo.dwBuildNumber == 0x2800 ||		//10240
			osverinfo.dwBuildNumber == 0x295A ||		//‭10586‬
			osverinfo.dwBuildNumber >= 0x295A			//>‭10586‬
			)
		{
			g_VersionFlag = ‬WINDOWS_VERSION_10;
		}
	}
	return result;
}


