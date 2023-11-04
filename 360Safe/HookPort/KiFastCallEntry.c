#include "KiFastCallEntry.h"

//Dpc计数使用
TsFlt_DPC g_TsFltDpcInfo = { 0 };
//查找Int2E KiSystemServiceHook点的代码

//
//	这是在安装KiFastCallEntry时用来定位挂钩位置的指令值
//	查找到代码中的这个值就把这两个指令替换为一个我们的JMP，见g_KiFastCallEntry_eb_jmp_address
//	2be1            sub    esp,ecx 
//	c1e902          shr    ecx,2   
//
CHAR g_KiFastCallEntry_Condition_Code[5] = { 0x2B, 0xE1, 0xC1, 0xE9, 0x02 };

//loc_1AEE8
CHAR g_FindKiSystemService_HookPoint_Code[] = {
	0x8B, 0xFC,										//mov     edi, esp
	0x3B, 0x35, 0x00, 0x00, 0x00, 0x00,				//cmp     esi, large ds:0				//需要修复的地方  修复后：- >cmp     esi,dword ptr [nt!MmUserProbeAddress (841a571c)]
	0x0F, 0x83, 0x00, 0x00, 0x8B, 0xFC,				//jnb     near ptr 0FC8CAEF6h			//
	0xF6, 0x45, 0x72, 0x02,							//test    byte ptr [ebp+72h]
	0x75, 0x06,										//jnz     short loc_1AF02
	0xF6, 0x45, 0x6C, 0x01,							//test    byte ptr [ebp+6Ch]
	0x74, 0x0C,										//jz      short loc_1AF0E
	0x3B, 0x35, 0x00, 0x00, 0x00, 0x00,				//cmp     esi, large ds:0				//需要修复的地方   修复后：- >cmp     esi, dword ptr[nt!MmUserProbeAddress(841a571c)]
	0x0F, 0x83, 0x00, 0x00, 0x32, 0x36,				//jnb     near ptr 3633AF0Eh			
	0x30, 0x30,										//xor     [eax], dh
	0x00, 0x36,										//add     [esi], dh
	0x30, 0x30,										//xor     [eax], dh
	0x30, 0x00,										//xor     [eax], al 
	0x36, 0x30, 0x30,								//xor     ss:[eax], dh
	0x31, 0x00,										//xor     [eax], eax
	0x36, 0x30, 0x30,								//xor     ss:[eax], dh
	0x32, 0x00,										//xor     al, [eax]
	0x37,											//aaa
	0x36, 0x30, 0x30,								// xor     ss:[eax], dh
	0x00, 0x37,										//add     [edi], dh  
	0x36, 0x30, 0x31,								//xor     ss:[ecx], dh 
	0x00, 0x39,										//add     [ecx], bh
	0x32, 0x30,										//xor     dh, [eax]
	0x30, 0x00,										//xor     [eax], al
	0x39, 0x36,										//cmp     [esi], esi
	0x30, 0x30										//xor     [eax], dh
};

//一堆shellcode
CHAR Hook_ShellCode_sub_15520[] = {							//sub_15520
	0XFF, 0X35, 0XFF, 0XFF, 0XFF, 0XFF,						// push    dword_1B0E4     -> 后面变成 push  A
	0x81, 0x34, 0x24, 0x00, 0x36, 0x00, 0x36,				// xor     [esp+4+var_4], 36003600h
	0xC3,													// retn 
	0X90, 0X90, 0X90, 0X90,                                 // 这四个字节是有套路的，当变量使用(称为A)
	0X90, 0X90, 0X90, 0X90, 0X90, 0X90, 0X90, 0X90, 0X90    // 这些字节都是无用的，充数的
};

CHAR Hook_ShellCode_sub_15538[] = {							//sub_15538
	0x8B, 0xFF,												// mov    edi,edi 
	0x9C,													// pushf
	0XFF, 0X35, 0XFF, 0XFF, 0XFF, 0XFF,						// push    dword_1B0E4	   -> 后面变成 push  A
	0x81, 0x34, 0x24, 0x00, 0x36, 0x00, 0x36,				// xor     [esp+8+var_8], 36003600h
	0xC3,													// retn 
	0X90, 0X90, 0X90, 0X90,                                 // 这四个字节是有套路的，当变量使用(称为A)
	0X90, 0X90, 0X90, 0X90, 0X90, 0X90, 0X90, 0X90, 0X90    // 这些字节都是无用的，充数的
};

//************************************     
// 函数名称: Hookport_Common_KiFastCallEntry_IDT     
// 函数说明：VISTA之前的系统采用IDT 4方式hook  
//           sub     esp, ecx    -> Int 4
//           shr     ecx, 2
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值:      
//************************************  
__declspec(naked) Hookport_Common_KiFastCallEntry_IDT()
{
	_asm
	{
			mov     edi, edi
			push    eax
			mov     eax, g_KiFastCallEntry_360HookPoint
			cmp     eax, [esp + 4]
			jz      loc_155A8
			pop     eax
			push[esp + 0x8]
			popfd
			jmp     Global_KiTrap04
		loc_155A8 :
			pop     eax
			add     esp, 8
			pushad
			push    edi									//edi指向KiServiceTable或W32pServiceTable 
			push    ebx									//ebx是原始的KiFastCallEntry从SSDT中取到的服务函数地址 
			push    eax									//eax是服务号
			call    HookPort_KiFastCallEntryFilterFunc  //KiFastCallEntryFilterFunc ，这个地址不清楚是怎么设置的，运行时没有看见设置的代码，难道是编译之后修改的？
			mov[esp + 0x10], eax					//（唯一区别）
			popad
			popfd
			sub     esp, ecx
			push    g_KiFastCallEntry_360HookPoint      //这里是回跳的地址（g_KiFastCallEntry_Fake_rtn_address）,push/ret方式跳回去，这个地址不清楚是怎么设置的，运行时没有看见设置的代码，难道是编译之后修改的？
			retn
	}
}

//************************************     
// 函数名称: Hookport_High_KiFastCallEntry_IDT     
// 函数说明：VISTA之后的系统采用IDT 4方式hook 
//           sub     esp, ecx    -> Int 4
//           shr     ecx, 2
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值:      
//************************************ 
__declspec(naked) Hookport_High_KiFastCallEntry_IDT()
{
	_asm
	{
		mov     edi, edi
		push    eax
		mov     eax, g_KiFastCallEntry_360HookPoint
		cmp     eax, [esp + 4]
		jz      loc_155A8
		pop     eax
		push[esp + 0x8]
		popfd
		jmp     Global_KiTrap04
		loc_155A8 :
		pop     eax
		add     esp, 8
		pushad
		push    edi									//edi指向KiServiceTable或W32pServiceTable 
		push    edx									//edx是原始的KiFastCallEntry从SSDT中取到的服务函数地址 
		push    eax									//eax是服务号
		call    HookPort_KiFastCallEntryFilterFunc  //KiFastCallEntryFilterFunc ，这个地址不清楚是怎么设置的，运行时没有看见设置的代码，难道是编译之后修改的？
		mov[esp + 0x14], eax					//（唯一区别）
		popad
		popfd
		sub     esp, ecx
		push    g_KiFastCallEntry_360HookPoint  //这里是回跳的地址（g_KiFastCallEntry_Fake_rtn_address）,push/ret方式跳回去，这个地址不清楚是怎么设置的，运行时没有看见设置的代码，难道是编译之后修改的？
		retn
	}
}


//************************************     
// 函数名称: Hookport_Common_KiFastCallEntry     
// 函数说明：VISTA之前的系统采用传统方式hook   
//           sub     esp, ecx    -> JMP  Fake_KiFastCallEntry
//           shr     ecx, 2
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值:      
//************************************ 
__declspec(naked) Hookport_Common_KiFastCallEntry()
{
	_asm{
			mov    edi, edi
			pushad
			push    edi									//edi指向KiServiceTable或W32pServiceTable 
			push    ebx									//ebx是原始的KiFastCallEntry从SSDT中取到的服务函数地址 
			push    eax									//eax是服务号
			call    HookPort_KiFastCallEntryFilterFunc  //KiFastCallEntryFilterFunc ，这个地址不清楚是怎么设置的，运行时没有看见设置的代码，难道是编译之后修改的？
			mov[esp + 0x10], eax					//（唯一区别）
			popad
			popfd
			sub     esp, ecx
			shr     ecx, 2
			push    g_KiFastCallEntry_Fake_rtn_address  //这里是回跳的地址（g_KiFastCallEntry_Fake_rtn_address）,push/ret方式跳回去，这个地址不清楚是怎么设置的，运行时没有看见设置的代码，难道是编译之后修改的？
			retn
	}
}

//************************************     
// 函数名称: Hookport_High_KiFastCallEntry     
// 函数说明：VISTA之后的系统采用传统方式hook   
//           sub     esp, ecx    -> JMP  Fake_KiFastCallEntry
//           shr     ecx, 2
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值:      
//************************************ 
__declspec(naked) Hookport_High_KiFastCallEntry()
{
	_asm{
			mov    edi, edi
			pushad
			push    edi									//edi指向KiServiceTable或W32pServiceTable 
			push    edx									//edx是原始的KiFastCallEntry从SSDT中取到的服务函数地址 
			push    eax									//eax是服务号
			call    HookPort_KiFastCallEntryFilterFunc  //KiFastCallEntryFilterFunc 
			mov[esp + 0x14], eax						//（唯一区别）
			popad
			popfd
			sub     esp, ecx
			shr     ecx, 2
			push    g_KiFastCallEntry_Fake_rtn_address  //这里是回跳的地址（g_KiFastCallEntry_Fake_rtn_address）,push/ret方式跳回去
			retn
	}
}

//不带浮点
VOID NTAPI HookPort_InlineHook5Byte_1521C(ULONG JmpAddress_a1, ULONG MdlAddress_a2, ULONG a3, ULONG a4)
{
	/*
	*(_DWORD *)MdlAddress_a2 = *(_DWORD *)JmpAddress_a1;
	*(_BYTE *)(MdlAddress_a2 + 4) = *(_BYTE *)(JmpAddress_a1 + 4);
	*/
	//修改前->
	//	2be1            sub    esp,ecx 
	//	c1e902          shr    ecx,2   
	//修改后->
	//  E9 XXXX         jmp     XXXXX
	//大数字直接memcpy，没有原子操作
	//.text:00015229 00C A5                                      movsd
	//.text:0001522A 00C A4                                      movsb
	RtlCopyMemory(MdlAddress_a2, JmpAddress_a1, 5);

}

//带浮点5字节hook
VOID NTAPI HookPort_InterlockedCompareExchange64_15236(ULONG* a1, ULONG a2, ULONG a3, ULONG a4)
{
	ULONG v4 = 0; // ebx@1
	ULONG v5 = 0; // ecx@1
	bool v6 = 0; // zf@1

	v4 = *a1;
	v5 = *(_DWORD*)(a2 + 4);
	LOBYTE(v5) = *((_BYTE*)a1 + 4);
	v6 = _InterlockedCompareExchange64((volatile signed __int64*)a2, __PAIR__(v5, *a1), *(_QWORD*)a2) == __PAIR__(v5, v4);
}

//完全没看明白这个函数在干嘛？？？？？？
ULONG sub_1567A(IN RTL_OSVERSIONINFOEXW osverinfo)
{
	PSYSTEM_PROCESS_INFORMATION pInfo = NULL;
	PSYSTEM_PROCESS_INFORMATION pNextpInfo = NULL; // eax@2
	ULONG ThreadCount; // eax@13
	BOOLEAN Result=TRUE;
	ULONG v8 = NULL; // ebx@13
	LARGE_INTEGER   UserTime = { 0 };
	UNICODE_STRING String1 = { 0 };
	ULONG BuildNumber = osverinfo.dwBuildNumber;
	ULONG MinorVersion = osverinfo.dwMinorVersion;
	ULONG MajorVersion = osverinfo.dwMajorVersion;
	RtlInitUnicodeString(&String1, L"Registry");
	pInfo = HookPort_QuerySystemInformation(SystemProcessInformation);
	if (!pInfo)
	{
		return Result;
	}
	if (pInfo->NextEntryDelta == 0)
	{
	LABEL_8:
		ExFreePool(pInfo);
		return Result;
	}
	pNextpInfo = pInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryDelta);
	if (pNextpInfo)
	{
		if (MajorVersion != 10 || MinorVersion || BuildNumber < 17134)
			goto LABEL_11;
		if (!RtlEqualUnicodeString(&String1, &pNextpInfo->ProcessName, TRUE))     //ProcessName
			goto LABEL_8;
	}
	ThreadCount = pNextpInfo->ThreadCount;	//ThreadCount
	if (ThreadCount)
	{
		UserTime = pNextpInfo->Threads[v8].UserTime;
		do
		{
			if (UserTime.LowPart == 0x20)
				break;
			if (UserTime.LowPart == 0x1F)
				break;
			if (UserTime.LowPart == 0x26)
				break;
			if (UserTime.LowPart == 0x1E)
				break;
			++v8;
		} while (v8 < ThreadCount);
	}
	if (v8 == ThreadCount)
	{
		Result = FALSE;
		goto LABEL_12;
	}
LABEL_11:
	Result = TRUE;
LABEL_12:
	ExFreePool(pInfo);
	return Result;
}


//多核模式下hook修改
VOID NTAPI DeferredRoutine1(
	IN struct _KDPC   *Dpc,
	IN PVOID   DeferredContext,
	IN PVOID   SystemArgument1,
	IN PVOID   SystemArgument2)
{
	KIRQL OldIrql; // bl@1
	PTsFlt_DPC pTsFltDpcInfo = (PTsFlt_DPC)DeferredContext;

	OldIrql = KfRaiseIrql(DISPATCH_LEVEL);
	InterlockedIncrement((LONG *)pTsFltDpcInfo->pFlag);
	KefAcquireSpinLockAtDpcLevel(pTsFltDpcInfo->pSpinLock);
	KefReleaseSpinLockFromDpcLevel(pTsFltDpcInfo->pSpinLock);
	KfLowerIrql(OldIrql);
}

//************************************     
// 函数名称: HookPort_Hook_153D0     
// 函数说明：hook    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值: NTSTATUS                               成功返回0，失败返回258
// 参    数: VOID     
// 参    数: NTAPI * Hook                       设置跳转地址的函数   
// 参    数: ULONG Jmp_Address                      Hook跳转的地址
// 参    数: ULONG KiFastCallEntry_360HookPoint     Hook点
// 参    数: ULONG a4                               无用
// 参    数: ULONG a5                               无用
//************************************  
NTSTATUS HookPort_Hook_153D0(VOID(NTAPI *Hook)(ULONG, ULONG, ULONG, ULONG), ULONG Jmp_Address, ULONG KiFastCallEntry_360HookPoint, ULONG a4, ULONG a5)
{
	ULONG CpuNumber = 32;			//CPU核心最大应该不超过32
	KAFFINITY ActiveProcessors_v5;
	ULONG NumberOfCpu_v6;
	KIRQL oldIrql_v8;
	PKDPC pDpc_v10, pDpc_v11;
	KIRQL NewIrql;
	ULONG nCurCpu_v18;
	ULONG nCount_v15;				//计算CPU个数的
	ULONG nLoopTimes_v13;			//耗时间代码，为了更安全hook完全部核心
	ULONG Numbera;
	ULONG Flag;
	nLoopTimes_v13 = 100000;
	nCurCpu_v18 = 0;
	nCount_v15 = 0;
	Numbera = 0;
	Flag = 0;
	NumberOfCpu_v6 = 0;
	if (MmIsAddressValid(Hook))
	{
		//统计CPU个数
		ActiveProcessors_v5 = KeQueryActiveProcessors();
		for (ULONG i_v7 = 0; i_v7 < CpuNumber; i_v7++)
		{
			if ((ActiveProcessors_v5 >> i_v7) & 1)
			{
				++NumberOfCpu_v6;
			}
		}
		//假设是单核
		if (NumberOfCpu_v6 == 1)
		{
			oldIrql_v8 = KfRaiseIrql(DISPATCH_LEVEL);
			_disable();
			Hook(Jmp_Address, KiFastCallEntry_360HookPoint, a4, a5);
			_enable();
			KfLowerIrql(oldIrql_v8);
			return 0;
		}
		//假设是多核 将除当前cpu以外的cpu用自旋锁锁住
		else
		{
			g_TsFltDpcInfo.pSpinLock = &g_SpinLock_WhiteList;
			g_TsFltDpcInfo.pFlag = &g_DpcFlag_dword_1B41C;
			KeInitializeSpinLock(&g_SpinLock_WhiteList);
			for (ULONG i = 0; i < CpuNumber; i++)
			{
				pDpc_v11 = &g_Dpc[i];
				//所述KeInitializeDpc例程初始化一个DPC对象，并注册CustomDpc该对象例程。
				KeInitializeDpc(pDpc_v11, DeferredRoutine1, &g_TsFltDpcInfo);
				//该KeSetTargetProcessorDpc程序指定的处理器，一个DPC例程将上运行。
				KeSetTargetProcessorDpc(pDpc_v11, i);
				//该KeSetImportanceDpc程序指定的DPC例程是如何立即运行。
				KeSetImportanceDpc(pDpc_v11, HighImportance);
			}
			g_DpcFlag_dword_1B41C = 0;	
			NewIrql = KfAcquireSpinLock(&g_SpinLock_WhiteList);
			for (ULONG i_v12 = 0; i_v12 < CpuNumber; i_v12++)
			{
				pDpc_v10 = &g_Dpc[i_v12];
				if ((1 << i_v12) & ActiveProcessors_v5)
				{
					++nCount_v15;
					nCurCpu_v18 = __readfsdword(0x51);
					if (i_v12 != nCurCpu_v18)//非当前核心，就Dpc方式处理
					{
						KeInsertQueueDpc(pDpc_v10, 0, 0);
					}
				}
			}
			//耗时间代码
			KeStallExecutionProcessor(0xAu);
			while (TRUE)
			{
				if (g_DpcFlag_dword_1B41C == nCount_v15 - 1)
				{
					Hook(Jmp_Address, KiFastCallEntry_360HookPoint, a4, a5);
					goto LABEL_21;
				}
				//超时失败返回
				if (++Numbera >= nLoopTimes_v13)
				{
					break;
				}
				KeStallExecutionProcessor(0xAu);
			}
			Flag = 1;
		LABEL_21:
			//恢复多核运行
			KfReleaseSpinLock(&g_SpinLock_WhiteList, NewIrql);
			if (Flag != 1)
			{
				return 0;
			}
			return 258;
		}
	}
	return 258;
}


//************************************     
// 函数名称: Fake_ZwSetEvent     
// 函数说明：Hook有两种方式：
//           修改：Jmpxxxx            Global_IdtHook_Or_InlineHook == 0  
//           修改：Int 4              Global_IdtHook_Or_InlineHook == 1
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值: ULONG NTAPI     
// 参    数: HANDLE EventHandle     
// 参    数: PULONG PreviousState     
//************************************  
NTSTATUS NTAPI Fake_ZwSetEvent(HANDLE EventHandle, PULONG PreviousState)
{
	ULONG           Return;
	volatile LONG   *ZwSetEventAddress;
	volatile LONG   *KiFastCallEntry_360HookPoint;			//360Hook点
	PMDL			MemoryDescriptorList;
	CHAR			SystemInformation = 0;
	PCHAR  			fake_fuc, ebp_value, address, cr0_value;
	PCHAR  			p_address;
	PCHAR           pBuffer_v4, pBuffer_v5, pBuffer_v11, pBuffer_v17, pBuffer_v21;
	ULONG   		n, m, Local_KiTrap04;
	UCHAR		    Jmp_Address[8] = { 0 };
	PMDL		    v27;
	ULONG		    BuildNumber  = Global_osverinfo.dwBuildNumber;
	ULONG		    MinorVersion = Global_osverinfo.dwMinorVersion;
	ULONG		    MajorVersion = Global_osverinfo.dwMajorVersion;
	v27 = 0;
	Jmp_Address[0] = 0xE9u;                                   // 构造指令：jmp xxxxx
	Global_IdtHook_Or_InlineHook = 1;				          //默认是1
	Return = STATUS_SUCCESS;
	//1、非正常调用获取获取KiFastCallEntry的地址
	if (EventHandle == (PHANDLE)Global_Fake_ZwSetEvent_Handle && !ExGetPreviousMode())
	{
		Global_ZwSetEventHookFlag = 1;
		//sub_1567A函数实在看不懂，有明白的老哥告诉下
		if (!Global_Win32kFlag && !sub_1567A(Global_osverinfo))
		{
			Global_IdtHook_Or_InlineHook = 0;
		}
		//获取CPU数目，CPU>32返回1
		if (HookPort_CheckCpuNumber(Global_osverinfo) == 1)
		{
			Global_IdtHook_Or_InlineHook = 0;
		}
		ZwSetEventAddress = HookPort_LockMemory((DWORD)((PCHAR)g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeServiceTableBase + 4 * g_SSDT_Func_Index_Data.ZwSetEventIndex), sizeof(ULONG), &MemoryDescriptorList, Global_Version_Win10_Flag);
		if (!ZwSetEventAddress)
		{
			if (MemoryDescriptorList)
				HookPort_RemoveLockMemory(MemoryDescriptorList);
			HookPort_RtlWriteRegistryValue(10);
			return STATUS_NO_MEMORY;
		}
		InterlockedExchange(ZwSetEventAddress, g_SSDT_Func_Index_Data.pZwSetEvent);			// 恢复SSDT钩子（ZwSetEvent）
		if (MemoryDescriptorList)
		{
			HookPort_RemoveLockMemory(MemoryDescriptorList);
			MemoryDescriptorList = 0;
		}
		//_asm
		//{
		//	MOV  ebp_value, EBP
		//}

		//// 栈回溯获取返回地址[EBP+4]（这里指的是正常调用时返回到KiFastCallEntry中的地址）
		//g_call_ring0_rtn_address = (PVOID)*(ULONG *)((char *)ebp_value + 4);
		g_call_ring0_rtn_address = _ReturnAddress();
		//判断返回值的合法性
		if (g_call_ring0_rtn_address < g_HookPort_Nt_Win32k_Data.NtData.NtImageBase || g_call_ring0_rtn_address >((ULONG)g_HookPort_Nt_Win32k_Data.NtData.NtImageBase + g_HookPort_Nt_Win32k_Data.NtData.NtImageSize))
		{
			HookPort_RtlWriteRegistryValue(11);
			return STATUS_NOT_FOUND;
		}
		address = g_call_ring0_rtn_address;
		p_address = (char *)g_call_ring0_rtn_address;
		// 查找特征指令（回溯100字节范围），以便我们安装HOOK
		for (m = 0; m <= 100; m++)
		{
			for (n = 0; n < 5; n++)
			{
				if (*p_address != g_KiFastCallEntry_Condition_Code[n])
				{
					break;
				}
				p_address++;
			}
			//找到了符合条件的
			if (n == 5)
			{
				//
				// 找到特征指令
				//

				// 保存特征指令之后的那个地址，即钩子处理之后的返回地址
				//840541a4 2be1            sub     esp, ecx     此时address                            = 840541a4
				//840541a6 c1e902          shr     ecx, 2       此时g_KiFastCallEntry_360HookPoint     = 840541a6
				//840541a9 8bfc            mov     edi, esp     此时g_KiFastCallEntry_Fake_rtn_address = 840541a9
				g_KiFastCallEntry_Fake_rtn_address = address + 5;
				g_KiFastCallEntry_360HookPoint = address + 2;
				break;
			}
			address--;
			p_address = (char *)address;
		}
		//判断是否查找失败
		if (m == 100 || !g_KiFastCallEntry_Fake_rtn_address || !g_KiFastCallEntry_360HookPoint)
		{
			HookPort_RtlWriteRegistryValue(12);
			return STATUS_NOT_FOUND;
		}
		//new空间存储构造的跳转指令
		pBuffer_v4 = ExAllocatePoolWithTag(NonPagedPool, p_jmpstub_codeLen, HOOKPORT_POOLTAG2);
		RtlZeroMemory(pBuffer_v4, p_jmpstub_codeLen);
		p_jmpstub_code = pBuffer_v4;
		if (!pBuffer_v4)
		{
			HookPort_RtlWriteRegistryValue(15);
			return STATUS_NO_MEMORY;
		}
		//默认是1  
		//如果是1  启用:IdtHook4号中断 
		//如果是0  启用:InlineHook
		if (Global_IdtHook_Or_InlineHook)
		{
			//Win7
			if (MajorVersion != 5 || MinorVersion && MinorVersion != 1)
			{
				if (ZwQuerySystemInformation(0xC4, &SystemInformation, 4u, 0) < 0)// 这里在干嘛？没有0XC4的选项啊？？？？？？？？？？
				{
					*&SystemInformation = 0;
				}
				pBuffer_v4 = p_jmpstub_code;
			}
			pBuffer_v5 = Hook_ShellCode_sub_15520;
			if (*(unsigned short*)pBuffer_v5 == 0xFF8Bu)
			{
				pBuffer_v5 = Hook_ShellCode_sub_15520 + 2;
			}
			RtlCopyMemory(pBuffer_v4, pBuffer_v5, 0x12);
			//push xxxx
			*(PVOID*)((PCHAR)p_jmpstub_code + 0X2) = (PVOID)((PCHAR)p_jmpstub_code + 0XE);
			//获取IDT表4号中断地址
			Global_KiTrap04 = HookPort_GetInterruptFuncAddress(4);
			Local_KiTrap04 = Global_KiTrap04;
			if (Global_KiTrap04 < g_HookPort_Nt_Win32k_Data.NtData.NtImageBase || Global_KiTrap04 >((DWORD)g_HookPort_Nt_Win32k_Data.NtData.NtImageBase + g_HookPort_Nt_Win32k_Data.NtData.NtImageSize))
			{
				ExFreePool(p_jmpstub_code);
				HookPort_RtlWriteRegistryValue(0xE);
				return STATUS_NOT_SUPPORTED;
			}
			if (SystemInformation & 1)
			{
				ULONG v9 = 0;
				ULONG v10 = 0;
				ULONG KiTrap04FunSize = 0x80;
				while (1)
				{
					if (*(unsigned short*)((PCHAR)Global_KiTrap04 + v9) == 0xC483u && *(unsigned char*)((PCHAR)Global_KiTrap04 + v9 + 3) == 0xE9u)
					{
						v10 = (Global_KiTrap04 + *(unsigned short*)((PCHAR)Global_KiTrap04 + v9 + 4)) + v9 + 8;
						if (v10 > g_HookPort_Nt_Win32k_Data.NtData.NtImageBase && v10 < ((PCHAR)g_HookPort_Nt_Win32k_Data.NtData.NtImageBase + g_HookPort_Nt_Win32k_Data.NtData.NtImageSize))
							break;
					}
					if (++v9 >= KiTrap04FunSize)
						goto LABEL_47;
				}
				v27 = (Global_KiTrap04 + v9 + 4);
				Local_KiTrap04 = v10;
				Global_KiTrap04 = v10;
			}
		LABEL_47:
			//填充4个nop位置
			*(PVOID*)((PCHAR)p_jmpstub_code + 0XE) = Global_KiTrap04;
			//根据高低版本区分不同的Shellcode
			pBuffer_v11 = Hookport_High_KiFastCallEntry_IDT;// VISTA之后的系统
			if (BuildNumber < 6000)
			{
				pBuffer_v11 = Hookport_Common_KiFastCallEntry_IDT;// VISTA之前的系统
			}
			//xor     [esp+4+var_4], 36003600h->(这个常量替换掉)
			*(PVOID*)((PCHAR)p_jmpstub_code + 0X9) = Global_KiTrap04 ^ (ULONG)pBuffer_v11;
			//Mdl映射HookPoint
			KiFastCallEntry_360HookPoint = HookPort_LockMemory(
				(PVOID)((PCHAR)g_KiFastCallEntry_360HookPoint - 2),
				2u,
				&MemoryDescriptorList,
				Global_Version_Win10_Flag
				);
			//判断合法性
			if (!KiFastCallEntry_360HookPoint)
			{
				goto Exit1;
			}
			//这里看不懂在干嘛
			if (SystemInformation & 1 && v27)
			{
				ULONG v14 = (PCHAR)p_jmpstub_code - v27 - 4;
				volatile LONG *v15 = HookPort_LockMemory(v27, sizeof(ULONG), &v27, Global_Version_Win10_Flag);
				if (!v15)
				{
					if (v27)
					{
						HookPort_RemoveLockMemory(v27);
					}
					goto Exit2;
				}
				InterlockedExchange(v15, v14);
				if (v27)
				{
					HookPort_RemoveLockMemory(v27);
				}
			}
			else
			{
				//IDT4号中断Hook,正确返回应该是0
				Return = HookPort_Hook_IDT_152DA(HookPort_SetKiTrapXAddress, p_jmpstub_code);
				if (Return)
				{
					if (Return == 258)
					{
						HookPort_RtlWriteRegistryValue(0x11);
					}
					ExFreePool(p_jmpstub_code);
					p_jmpstub_code = 0;
					if (MemoryDescriptorList)
						HookPort_RemoveLockMemory(MemoryDescriptorList);
					return Return;
				}
			}
			//写个int4
			InterlockedExchange(KiFastCallEntry_360HookPoint, 0xE9C104CD);
			if (MemoryDescriptorList)
				HookPort_RemoveLockMemory(MemoryDescriptorList);
		}
		//传统Jmp xxxx方式
		else
		{
			//第一层要xor解密的
			pBuffer_v17 = Hook_ShellCode_sub_15538;
			if (*(unsigned short*)pBuffer_v17 == 0xFF8Bu)
			{
				pBuffer_v17 = Hook_ShellCode_sub_15538 + 2;
			}
			RtlCopyMemory(pBuffer_v4, pBuffer_v17, 0x13);
			//push xxxx
			*(PVOID*)((PCHAR)p_jmpstub_code + 0X3) = (PVOID)((PCHAR)p_jmpstub_code + 0XF);
			//
			*(PVOID*)((PCHAR)p_jmpstub_code + 0XF) = (PVOID)((PCHAR)g_KiFastCallEntry_Fake_rtn_address - 5);
			//根据版本判断选用不同的shellcode代码
			if (BuildNumber < 6000)
			{
				pBuffer_v21 = Hookport_Common_KiFastCallEntry;
			}
			else
			{
				pBuffer_v21 = Hookport_High_KiFastCallEntry;
			}
			*(PVOID*)((PCHAR)p_jmpstub_code + 0XA) = (ULONG)pBuffer_v21 ^ (ULONG)((PCHAR)g_KiFastCallEntry_Fake_rtn_address - 5);
			//Mdl映射HookPoint
			KiFastCallEntry_360HookPoint = HookPort_LockMemory((PVOID)((PCHAR)g_KiFastCallEntry_Fake_rtn_address - 5), 5u, &MemoryDescriptorList, Global_Version_Win10_Flag);
			//判断合法性
			if (!KiFastCallEntry_360HookPoint)
			{
			Exit1:
				if (MemoryDescriptorList)
				{
					HookPort_RemoveLockMemory(MemoryDescriptorList);
				}
			Exit2:
				HookPort_RtlWriteRegistryValue(16);
				Return = STATUS_NO_MEMORY;
			Exit3:
				ExFreePool(p_jmpstub_code);
				p_jmpstub_code = 0;
				return Return;
			}
			//获取相对偏移
			ULONG Offset_v30 = (ULONG)(p_jmpstub_code)-(ULONG)(g_KiFastCallEntry_Fake_rtn_address);
			//构造成jmp XXXXX   
			*(ULONG *)&Jmp_Address[1] = Offset_v30;
			if (ExIsProcessorFeaturePresent(			//所述ExIsProcessorFeaturePresent常规查询要指定的处理器的特征的存在。
				PF_COMPARE_EXCHANGE_DOUBLE)				//处理器具有8字节的存储器锁定比较和交换（CMPXCHG8B）指令
				)
			{
				//不带浮点5个字节hook
				Return = HookPort_Hook_153D0(
					HookPort_InlineHook5Byte_1521C,		//Hook函数地址
					(ULONG)Jmp_Address,					//Jmp到自己函数的地址
					(ULONG)KiFastCallEntry_360HookPoint,//要修改的地址
					0,									//无用
					0);                                 //无用
			}
			else
			{
				//带浮点5字节hook
				Return = HookPort_Hook_153D0(
					(VOID(NTAPI *)(ULONG, ULONG, ULONG, ULONG))HookPort_InterlockedCompareExchange64_15236,	//Hook函数地址
					(ULONG)Jmp_Address,					  //Jmp到自己函数的地址
					(ULONG)KiFastCallEntry_360HookPoint,  //要修改的地址
					0,									  //无用
					0									  //无用
					);
			}
			if (MemoryDescriptorList)
			{
				HookPort_RemoveLockMemory(MemoryDescriptorList);
			}
			if (Return)
			{
				if (Return == 258)
				{
					HookPort_RtlWriteRegistryValue(0x11);
				}
				goto Exit3;
			}
		}
		return STATUS_SUCCESS;
	}
	//2、正常调用
	// 调用原函数
	return ((NTSTATUS(NTAPI*)(HANDLE, PLONG))g_SSDT_Func_Index_Data.pZwSetEvent)(EventHandle, PreviousState);
}

NTSTATUS NTAPI HookPort_InstallZwSetEventHook()
{
	char *SymbolAddr = 0; // eax@1
	volatile LONG *Mdlv2_MappedSystemVa = 0; // eax@3
	NTSTATUS Result = 0; // edi@7
	STRING DestinationString; // [sp+0h] [bp-Ch]@1
	PMDL MemoryDescriptorList = 0; // [sp+8h] [bp-4h]@1
	MemoryDescriptorList = 0;
	RtlInitAnsiString(&DestinationString, "ZwSetEvent");
	SymbolAddr = HookPort_GetSymbolAddress(&DestinationString, g_HookPort_Nt_Win32k_Data.NtData.NtImageBase);
	if (SymbolAddr)
	{
		g_SSDT_Func_Index_Data.ZwSetEventIndex = *(DWORD *)(SymbolAddr + 1);
		PVOID NtSetEventAddress = (DWORD)((PCHAR)g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeServiceTableBase + 4 * g_SSDT_Func_Index_Data.ZwSetEventIndex);
		Mdlv2_MappedSystemVa = HookPort_LockMemory(
			NtSetEventAddress,
			sizeof(ULONG),
			&MemoryDescriptorList,
			Global_Version_Win10_Flag
			);
		if (Mdlv2_MappedSystemVa)
		{
			g_SSDT_Func_Index_Data.pZwSetEvent = InterlockedExchange(Mdlv2_MappedSystemVa, Fake_ZwSetEvent);// 安装ZwSetEvent的SSDT钩子,并保存原始ZwSetEvent的，后面会进行恢复
		}
		if (MemoryDescriptorList)
		{
			HookPort_RemoveLockMemory(MemoryDescriptorList);
		}
		Global_Fake_ZwSetEvent_Handle = (HANDLE)0x711E8525;				//虚假的ZwSetEvent句柄（暗号）
		Result = ZwSetEvent(Global_Fake_ZwSetEvent_Handle, 0);          //用一个特定的伪句柄触发ZwSetEvent调用
		if (!Global_ZwSetEventHookFlag)								    //hook标志位：成功1、不成功0
		{
			HookPort_RtlWriteRegistryValue(10);
		}
	}
	else
	{
		HookPort_RtlWriteRegistryValue(8);
		Result = STATUS_UNSUCCESSFUL;
	}
	return Result;
}


//获取KiSystemService的Hook点
//返回Hook点
//1:
//nt!KiFastCallEntry+0xe9:
//840791a9 8bfc            mov     edi, esp
//840791ab 3b351c571a84    cmp     esi, dword ptr[nt!MmUserProbeAddress(841a571c)]
//2:
//807f295c 8bfc            mov     edi, esp
//807f295e f6457202        test    byte ptr[ebp + 72h], 2
//807f2962 7506            jne     807f296a
//807f2964 f6456c01        test    byte ptr[ebp + 6Ch], 1
//807f2968 740c            je      807f2976
//807f296a 3b351c571a84    cmp     esi, dword ptr[nt!MmUserProbeAddress(841a571c)]
ULONG HookPort_GetKiSystemService_HookPoint(IN ULONG MmUserProbeAddress, IN ULONG NtImageBase, IN ULONG NtImageSize, OUT ULONG *Index)
{
	ULONG KiSystemServiceAddress;
	ULONG PageSize = 1024;						//1页=1024个字节
	ULONG LoopNumber;							//计数
	UCHAR HookShellBuff[0x50] = { 0 };			//查找hook点的
	//1、通过IDT定位到KiSystemService函数
	KiSystemServiceAddress = HookPort_GetKiSystemService_IDT();
	if (KiSystemServiceAddress)
	{
		//2、判断KiSystemService地址合法性
		if ((KiSystemServiceAddress < (ULONG)NtImageBase) || ((ULONG)NtImageBase >((ULONG)NtImageBase + NtImageSize)))
		{
			goto Error;
		}
		//3、后面都是查找hook点操作
		RtlCopyMemory(HookShellBuff, g_FindKiSystemService_HookPoint_Code, 10);
		//修复前
		//mov     edi, esp
		//cmp     esi, large ds:0				//这一句		
		//修复后
		//mov     edi, esp
		//cmp     esi,dword ptr [nt!MmUserProbeAddress (841a571c)]   //注意看这一句
		*(ULONG*)(HookShellBuff + 4) = (ULONG)MmUserProbeAddress;
		////第1种方法查找
		for (LoopNumber = 0; LoopNumber < PageSize; LoopNumber++)
		{
			if (RtlCompareMemory((CONST VOID*)(KiSystemServiceAddress + LoopNumber), HookShellBuff, 0xA) == 0xA)
			{
				//找到hook点
				//nt!KiFastCallEntry+0xe9:
				//840791a9 8bfc            mov     edi, esp
				//840791ab 3b351c571a84    cmp     esi, dword ptr[nt!MmUserProbeAddress(841a571c)]
				break;
			}
		}
		//第2种方法查找
		if (LoopNumber == PageSize)
		{
			RtlZeroMemory(HookShellBuff, sizeof(HookShellBuff));
			RtlCopyMemory(HookShellBuff, (CONST VOID*)(g_FindKiSystemService_HookPoint_Code + 0xC), 0x16);
			//修复前
			//cmp     esi, large ds:0
			//jnb     near ptr 3633AF0Eh			//这一句
			//修复后
			//807f2968 740c            je      807f2976
			//807f296a 3b351c571a84    cmp     esi, dword ptr[nt!MmUserProbeAddress(841a571c)]
			*(ULONG*)(HookShellBuff + 0x10) = (ULONG)MmUserProbeAddress;
			for (LoopNumber = 0; LoopNumber < PageSize; LoopNumber++)
			{
				if (RtlCompareMemory((CONST VOID*)(KiSystemServiceAddress + LoopNumber), HookShellBuff, 0x16) == 0x16)
				{
					//2:
					//807f295c 8bfc            mov     edi, esp
					//807f295e f6457202        test    byte ptr[ebp + 72h], 2
					//807f2962 7506            jne     807f296a
					//807f2964 f6456c01        test    byte ptr[ebp + 6Ch], 1
					//807f2968 740c            je      807f2976
					//807f296a 3b351c571a84    cmp     esi, dword ptr[nt!MmUserProbeAddress(841a571c)]
					break;
				}
			}
			//还是找不到直接跳到错误地方退出
			if (LoopNumber == PageSize)
			{
				goto Error;
			}
			*Index = 0x10;
		}
		else
		{
			*Index = 4;
		}
		//返回Hook点
		//1:
		//nt!KiFastCallEntry+0xe9:
		//840791a9 8bfc            mov     edi, esp
		//840791ab 3b351c571a84    cmp     esi, dword ptr[nt!MmUserProbeAddress(841a571c)]
		//2:
		//807f295c 8bfc            mov     edi, esp
		//807f295e f6457202        test    byte ptr[ebp + 72h], 2
		//807f2962 7506            jne     807f296a
		//807f2964 f6456c01        test    byte ptr[ebp + 6Ch], 1
		//807f2968 740c            je      807f2976
		//807f296a 3b351c571a84    cmp     esi, dword ptr[nt!MmUserProbeAddress(841a571c)]
		return LoopNumber + KiSystemServiceAddress;
	}
Error:
	return 0;
}

//低版本 < 2003 KiSystemService
//InlineHook hook掉KiSystemService
//函数功能：
//1、只替换地址成自己的Fake地址，不设置FakeKiSystemService函数的内容
BOOLEAN HookPort_SetFakeKiSystemServiceAddress()
{
	UNICODE_STRING UMmUserProbeAddress;
	PMDL MemoryDescriptorList;
	ULONG MmUserProbeAddress;
	volatile LONG * Mdlv4_KiSystemServiceHookPoint = NULL;
	PVOID pKiSystemService_HookPoint;
	BOOLEAN Result = FALSE;
	ULONG Index;
	PVOID pBuff;
	MemoryDescriptorList = 0;
	RtlInitUnicodeString(&UMmUserProbeAddress, L"MmUserProbeAddress");
	MmUserProbeAddress = MmGetSystemRoutineAddress(&UMmUserProbeAddress);
	if (MmUserProbeAddress)
	{
		//1、返回得到hook点
		pKiSystemService_HookPoint = HookPort_GetKiSystemService_HookPoint(MmUserProbeAddress, (ULONG)g_HookPort_Nt_Win32k_Data.NtData.NtImageBase, g_HookPort_Nt_Win32k_Data.NtData.NtImageSize, &Index);
		//2、判断地址合法性
		if (pKiSystemService_HookPoint)
		{
			pBuff = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG), HOOKPORT_POOLTAG6);
			if (pBuff)
			{
				RtlZeroMemory(pBuff, sizeof(ULONG));
				//然后使用MDL安全hook
				Mdlv4_KiSystemServiceHookPoint = HookPort_LockMemory((PVOID)((ULONG)pKiSystemService_HookPoint + Index), sizeof(ULONG), (ULONG)&MemoryDescriptorList,Global_Version_Win10_Flag);
				if (Mdlv4_KiSystemServiceHookPoint)
				{
					//IATHook
					//假设Index=4
					//修改前
					//8404b1a9 8bfc            mov     edi, esp
					//8404b1ab 3b351c771784    cmp     esi, dword ptr[nt!MmUserProbeAddress(8417771c)] 这一句替换掉了
					//8404b1b1 0f832e020000    jae     nt!KiSystemCallExit2 + 0xa5 (8404b3e5)
					//修改后
					//8404b1a6 c1e902          shr     ecx, 2
					//8404b1a9 8bfc            mov     edi, esp
					//8404b1ab 3b35087a9886    cmp     esi, dword ptr ds : [86987A08h]   这一句替换掉了pBuff
					//假设Index=0x10(未测试)
					InterlockedExchange(Mdlv4_KiSystemServiceHookPoint, (LONG)pBuff);
					//保存
					g_Fake_KiSystemServiceFuncAddress = (ULONG)pBuff;// 保存我们构造的hook函数地址
				}
				//释放
				if (MemoryDescriptorList)
				{
					HookPort_RemoveLockMemory(MemoryDescriptorList);
				}
				Result = TRUE;
			}
		}
	}
	return Result;
}

//有空再逆把
//跟Fake_ZwSetEvent基本一致
ULONG HookPort_SetFakeKiSystemServiceData(ULONG ImageBase_a1, ULONG ImageSize_a2)
{
	return 0;
}