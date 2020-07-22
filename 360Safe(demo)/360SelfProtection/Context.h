#pragma once
#include <ntifs.h>
#include "WinBase.h"
#include "WinKernel.h"
#include "Data.h"

typedef struct _KTRAP_FRAME
{
	ULONG DbgEbp;
	ULONG DbgEip;
	ULONG DbgArgMark;
	ULONG DbgArgPointer;
	ULONG TempSegCs;
	ULONG TempEsp;
	ULONG Dr0;
	ULONG Dr1;
	ULONG Dr2;
	ULONG Dr3;
	ULONG Dr6;
	ULONG Dr7;
	ULONG SegGs;
	ULONG SegEs;
	ULONG SegDs;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG PreviousPreviousMode;
	struct _EXCEPTION_REGISTRATION_RECORD FAR *ExceptionList;
	ULONG SegFs;
	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Ebp;
	ULONG ErrCode;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
	ULONG V86Es;
	ULONG V86Ds;
	ULONG V86Fs;
	ULONG V86Gs;
} KTRAP_FRAME, *PKTRAP_FRAME;


//获取_KTRAP_FRAME结构
PKTRAP_FRAME NTAPI Safe_KeGetTrapFrame(IN ULONG TrapFrameIndex);

//设置线程上下文之类的
ULONG NTAPI Safe_CheckCreateProcessCreationFlags();