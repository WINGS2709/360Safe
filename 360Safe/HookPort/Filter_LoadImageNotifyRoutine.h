#pragma once
#include <ntddk.h>
#include "FilterHook.h"

#define	LoadImageNotifyRoutine_FilterIndex	0x81
VOID Filter_LoadImageNotifyRoutine(IN PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo);

//检查是否是ntdll
BOOL HookPort_CmpNtdll(PUNICODE_STRING FullImageName);

// 作用不明dword_1B110置0
VOID HookPort_SetFlag_Off();