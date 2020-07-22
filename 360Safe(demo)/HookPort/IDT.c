#include "IDT.h"

ULONG HookPort_GetInterruptFuncAddress(ULONG InterruptIndex)
{
	IDTR		idtr;
	IDTENTRY	*pidt_entry;
	//获取到IDT
	__sidt(&idtr);
	pidt_entry = (IDTENTRY *)MAKELONG(idtr.IDT_LOWbase, idtr.IDT_HIGbase);
	return MAKELONG(pidt_entry[InterruptIndex].LowOffset, pidt_entry[InterruptIndex].HiOffset);
}

ULONG HookPort_SetKiTrapXAddress(ULONG InterruptIndex, ULONG NewInterruptFunc)
{
	IDTR		idtr;
	IDTENTRY	*pIdtEntry;
	_disable();
	//获取到IDT
	__sidt(&idtr);
	pIdtEntry = (IDTENTRY *)MAKELONG(idtr.IDT_LOWbase, idtr.IDT_HIGbase);
	//关闭内存保护
	PageProtectOff();
	//原理：
	//修改段内偏移达到HOOK IDT的作用
	//1.  替换成新的函数先替换低2字节
	pIdtEntry[InterruptIndex].LowOffset = (unsigned short)((ULONG)NewInterruptFunc & 0xFFFF);
	//2.  替换成新的函数再替换高2字节
	pIdtEntry[InterruptIndex].HiOffset = (unsigned short)((ULONG)NewInterruptFunc >> 16);
	//开启内存保护
	PageProtectOn();
	_enable();
	//返回HOOK后的IDT中断地址
	return MAKELONG(pIdtEntry[InterruptIndex].LowOffset, pIdtEntry[InterruptIndex].HiOffset);
}

VOID NTAPI DeferredRoutine(
	IN struct _KDPC   *Dpc,
	IN PVOID   DeferredContext,
	IN PVOID   SystemArgument1,
	IN PVOID   SystemArgument2)
{
	KIRQL OldIrql; // bl@1
	ULONG(*pHookPort_SetKiTrapXAddress)(ULONG InterruptIndex, ULONG NewInterruptFunc);
	OldIrql = KfRaiseIrql(DISPATCH_LEVEL);
	pHookPort_SetKiTrapXAddress = SystemArgument1;
	pHookPort_SetKiTrapXAddress(4, DeferredContext);
	KfLowerIrql(OldIrql);
	InterlockedExchangeAdd(SystemArgument2, 1);
}

//多核HOOKidt表
ULONG NTAPI HookPort_Hook_IDT_152DA(PVOID SystemArgument1, PVOID DeferredContext)
{
	ULONG Result;
	ULONG CpuNumber = 32;			//CPU核心最大应该不超过32
	KAFFINITY ActiveProcessors_v7;
	PKDPC pDpc_v3, pDpc_v4;
	KIRQL OldIrql;
	ULONG nCurCpu_v18;
	LONG v9; // [sp+14h] [bp-Ch]@1
	LONG Addend; // [sp+18h] [bp-8h]@1
	ULONG(*pHookPort_SetKiTrapXAddress)(ULONG InterruptIndex, ULONG NewInterruptFunc);
	ULONG nLoopTimes_v8;
	ULONG nLoopTimes_v13;			//耗时间代码，为了更安全hook完全部核心
	nLoopTimes_v13 = 100000;
	Result = 0;
	v9 = 0;
	nLoopTimes_v8 = 0;
	Addend = 0;
	ActiveProcessors_v7 = KeQueryActiveProcessors();
	pHookPort_SetKiTrapXAddress = SystemArgument1;
	if (MmIsAddressValid(SystemArgument1))
	{
		//SystemArgument1(DeferredContext);
		for (ULONG i = 0; i < CpuNumber; i++)
		{
			pDpc_v4 = &g_idt_Dpc[i];
			//所述KeInitializeDpc例程初始化一个DPC对象，并注册CustomDpc该对象例程。
			KeInitializeDpc(pDpc_v4, DeferredRoutine,DeferredContext);
			//该KeSetImportanceDpc程序指定的DPC例程是如何立即运行。
			KeSetImportanceDpc(pDpc_v4, HighImportance);
			//该KeSetTargetProcessorDpc程序指定的处理器，一个DPC例程将上运行。
			KeSetTargetProcessorDpc(pDpc_v4, i++);
			//++pDpc_v4;
		}
		OldIrql = KfRaiseIrql(DISPATCH_LEVEL);
		for (ULONG i_v5 = 0; i_v5 < CpuNumber; i_v5++)
		{
			pDpc_v3 = &g_idt_Dpc[i_v5];
			if ((1 << i_v5) & ActiveProcessors_v7)
			{
				//__asm mov eax, fs:[0x51]
				//__asm mov nCurCpu_v18, eax
				nCurCpu_v18 = __readfsdword(0x51);
				if (nCurCpu_v18 == i_v5)		//是当前核心直接调用HookPort_SetKiTrapXAddress函数替换
				{
					InterlockedExchangeAdd(&Addend, 1);
					InterlockedExchangeAdd(&v9, 1);
					pHookPort_SetKiTrapXAddress(4, DeferredContext);
				}
				else                            //非当前核心，就Dpc方式处理替换IDT中断
				{
					InterlockedExchangeAdd(&v9, 1);
					KeInsertQueueDpc(pDpc_v3, SystemArgument1, &Addend);
				}
			}
		}
		//纯耗时间代码,TsFltMgr驱动也是这么干的
		//ULONG nLoopTimes_v13 = 1000000;
		//while ( --nLoopTimes_v13 );
		//耗时间，为了更安全的hook完全部核心
		do
		{
			if (Addend >= v9)
			{
				break;
			}
			KeStallExecutionProcessor(0xAu);     
			++nLoopTimes_v8;
		} while (nLoopTimes_v8 != nLoopTimes_v13);
		KfLowerIrql(OldIrql);
		if (nLoopTimes_v8 == nLoopTimes_v13)
		{
			Result = 258;
		}
		else
		{
			Result = 0;
		}
	}
	else
	{
		Result = 258;
	}
	return Result;
}


//通过IDT定位到KiSystemService函数
ULONG HookPort_GetKiSystemService_IDT()
{
	IDTR		idtr;
	PVOID	    *pIdtEntry;
	ULONG       OutKiSystemServiceAddress;
	ULONG       LowAddress, MiddleAddress, HigAddress;
	USHORT      LowBuff;

	//获取到IDT
	__sidt(&idtr);
	pIdtEntry = MAKELONG(idtr.IDT_LOWbase, idtr.IDT_HIGbase);
	if (MmIsAddressValid(pIdtEntry))
	{
		LowAddress = *(ULONG*)&pIdtEntry + 0x170;
		MiddleAddress = *(ULONG*)&pIdtEntry + 0x176;
		HigAddress = *(ULONG*)&pIdtEntry + 0x178;
		if (MmIsAddressValid(LowAddress) && MmIsAddressValid(HigAddress))
		{
			OutKiSystemServiceAddress = (*(USHORT*)LowAddress) | (*(USHORT*)MiddleAddress << 16);
			if (MmIsAddressValid(OutKiSystemServiceAddress))
			{
				//返回KiSystemService函数地址
				return OutKiSystemServiceAddress;
			}

		}
	}
	return 0;
}