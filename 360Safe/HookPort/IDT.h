#pragma once
#include <ntddk.h>
#include "WinKernel.h"

#define MAKELONG(a, b) ((ULONG)(((USHORT)(a)) | ((ULONG)((USHORT)(b))) << 16));

typedef struct _IDTENTRY
{
	unsigned short LowOffset;
	unsigned short selector;
	unsigned char retention : 5;
	unsigned char zero1 : 3;
	unsigned char gate_type : 1;
	unsigned char zero2 : 1;
	unsigned char interrupt_gate_size : 1;
	unsigned char zero3 : 1;
	unsigned char zero4 : 1;
	unsigned char DPL : 2;
	unsigned char P : 1;
	unsigned short HiOffset;
} IDTENTRY, *PIDTENTRY;

//IDT相关的
typedef struct _IDTR{
	USHORT   IDT_limit;
	USHORT   IDT_LOWbase;
	USHORT   IDT_HIGbase;
}IDTR, *PIDTR;


KDPC g_idt_Dpc[0x100];
//获取X号中断的地址
ULONG HookPort_GetInterruptFuncAddress(ULONG InterruptIndex);

ULONG HookPort_SetKiTrapXAddress(ULONG InterruptIndex, ULONG NewInterruptFunc);

//多核HOOKidt表
ULONG NTAPI HookPort_Hook_IDT_152DA(PVOID SystemArgument1, PVOID DeferredContext);

//通过IDT定位到KiSystemService函数
ULONG HookPort_GetKiSystemService_IDT();