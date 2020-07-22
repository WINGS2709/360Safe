#include "Context.h"

//************************************     
// 函数名称: KeGetTrapFrame     
// 函数说明：获取_KTRAP_FRAME结构    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/04/18     
// 返 回 值: PKTRAP_FRAME NTAPI     
// 参    数: IN ULONG TrapFrameIndex    Win7 +0x128 TrapFrame        : Ptr32 _KTRAP_FRAME  
//************************************ 
PKTRAP_FRAME NTAPI Safe_KeGetTrapFrame(IN ULONG TrapFrameIndex)
{
	//KeGetCurrentThread返回_KTHREAD结构
	//_KTHREAD + TrapFrameIndex  = +0x128 TrapFrame        : Ptr32 _KTRAP_FRAME 
	return *((ULONG *)KeGetCurrentThread() + TrapFrameIndex);
}

ULONG NTAPI Safe_CheckCreateProcessCreationFlags()
{
	ULONG	     Result = NULL;
	ULONG		 Flag = NULL;
	PKTRAP_FRAME TrapFrame = NULL;          //_KTRAP_FRAME结构
	//判断是不是保护进程，是返回：1  不是返回0
	Result = Safe_QueryWhitePID((ULONG)PsGetCurrentProcessId());
	if (Result)
	{
		return Result;
	}
	//根据版本分支获取_KTRAP_FRAME
	if (g_VersionFlag == WINDOWS_VERSION_XP)
	{
		//相同返回1，不同返回非0
		if (!Safe_CmpImageFileName("explorer.exe"))
		{
			Result = Safe_CmpImageFileName("services.exe");
			if (!Result)
			{
				return Result;
			}
		}
		//获取_KTRAP_FRAME结构
		TrapFrame = Safe_KeGetTrapFrame(0x4D);
	}
	else
	{
		//非win7直接退出
		if (g_VersionFlag != WINDOWS_VERSION_7)
		{
			return Result;
		}
		//相同返回1，不同返回非0
		if (!Safe_CmpImageFileName("explorer.exe") && !Safe_CmpImageFileName("services.exe"))
		{
			Result = Safe_CmpImageFileName("svchost.exe");
			if (!Result)
			{
				return Result;
			}
			Flag = 1;
		}
		//获取_KTRAP_FRAME结构
		TrapFrame = Safe_KeGetTrapFrame(0x4A);
	}
	//根据LDR链表获取对应的API函数地址
	if (Flag)
	{
		//Win7
		Result = g_dynData->pCreateProcessAsUserW;
		if (!Result)
		{
			Result = Safe_PeLdrFindExportedRoutineByName("CreateProcessAsUserW",1);
			g_dynData->pCreateProcessAsUserW = Result;
			if (!Result)
			{
				return Result;
			}
		}
	}
	else
	{
		//Win2K_XP_2003
		Result = g_dynData->pCreateProcessW;
		if (!Result)
		{
			Result = Safe_PeLdrFindExportedRoutineByName("CreateProcessW", g_Win2K_XP_2003_Flag != 0);
			g_dynData->pCreateProcessW = Result;
			if (!Result)
			{
				return Result;
			}
		}
	}
	//保存获取到的函数地址 pCreateProcessW or pCreateProcessAsUserW
	ULONG pCreateProcessAddress = Result;
	//然后获取Ebp
	if (TrapFrame)
	{
		ULONG Ebp_v5 = TrapFrame->Ebp;
		ULONG OldEbp_v5 = TrapFrame->Ebp;				//原始Ebp
		ULONG Number = 0;								//计数器
		ULONG NumberMaxSize = 0x64;						//计数器最大值
		ULONG TempEbp_v8 = 0;
		//栈回溯找返回地址，然后校验
		do
		{
			if (!Ebp_v5)
			{
				break;
			}
			if (Ebp_v5 > MmUserProbeAddress)
			{
				break;
			}
			//获取ebp+4 返回地址
			ULONG Ret_Address = *(ULONG*)(Ebp_v5 + 4);
			if (Ret_Address > MmUserProbeAddress)
			{
				break;
			}
			//CreateProcessW
			//.text : 77DE204D                 mov     edi, edi
			//.text : 77DE204F                 push    ebp
			//.text : 77DE2050                 mov     ebp, esp
			//.text : 77DE2052                 push    0
			//.text : 77DE2054                 push    [ebp + lpProcessInformation]
			//.text : 77DE2057                 push    [ebp + lpStartupInfo]
			//.text : 77DE205A                 push    [ebp + lpCurrentDirectory]
			//.text : 77DE205D                 push    [ebp + lpEnvironment]
			//.text : 77DE2060                 push    [ebp + dwCreationFlags]     ->Ebp + 0x20就是这里
			//.text : 77DE2063                 push    [ebp + bInheritHandles]
			//.text : 77DE2066                 push    [ebp + lpThreadAttributes]
			//.text : 77DE2069                 push    [ebp + lpProcessAttributes]
			//.text : 77DE206C                 push    [ebp + lpCommandLine]
			//.text : 77DE206F                 push    [ebp + lpApplicationName]
			//.text : 77DE2072                 push    0
			//.text : 77DE2074                 call    _CreateProcessInternalW@48; CreateProcessInternalW(x, x, x, x, x, x, x, x, x, x, x, x)
			//.text : 77DE2079                 pop     ebp                         ->Ebp + 4就是这里
			//.text : 77DE207A                 retn    28h
			//判断返回地址的合法性
			if (Ret_Address > pCreateProcessAddress && Ret_Address - pCreateProcessAddress < 40)
			{
				ULONG dwCreationFlags = *(ULONG*)(OldEbp_v5 + 0x20) & 0xFFFFF7FF;// 将某一位清零;		//CREATE_SEPARATE_WOW_VDM???????? 16位进程
				Result = g_Win2K_XP_2003_Flag;
				//判断标志位拦截敏感权限
				if (!g_Win2K_XP_2003_Flag && dwCreationFlags == (CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | DETACHED_PROCESS)						// Win7
					|| g_Win2K_XP_2003_Flag == 1 && dwCreationFlags == (BELOW_NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED)	//非Win7
					|| !g_Win2K_XP_2003_Flag && dwCreationFlags == (CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT | CREATE_DEFAULT_ERROR_MODE)		//Win7
					|| g_Win2K_XP_2003_Flag == 1 && dwCreationFlags == (CREATE_DEFAULT_ERROR_MODE | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | CREATE_NEW_CONSOLE)																	//非Win7
					)
				{
					//设置权限
					*(ULONG *)(OldEbp_v5 + 0x20) = dwCreationFlags | CREATE_PRESERVE_CODE_AUTHZ_LEVEL;
				}
				return Result;
			}
			TempEbp_v8 = Ebp_v5;
			Ebp_v5 = *(ULONG*)Ebp_v5;
			Number++;									//自增
		} while (TempEbp_v8 != Ebp_v5 && Number <= NumberMaxSize);
	}
	return Result;
}