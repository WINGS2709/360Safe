#pragma once
#include <ntddk.h>
#include "FilterHook.h"

//这个过滤函数没有对应的Fake_XXXX
#define	ZwContinue_FilterIndex	0x87
NTSTATUS NTAPI Filter_ZwContinue(PCONTEXT Context, BOOLEAN TestAlert);