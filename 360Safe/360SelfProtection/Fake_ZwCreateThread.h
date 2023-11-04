#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Data.h"
#include "SystemProcessDataList.h"
#include "VirtualMemoryDataList.h"
#include "Object.h"
#include "SafeWarning.h"
#include "WinBase.h"

typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation,
	MaxSectionInfoClass  // MaxSectionInfoClass should always be the last enum
} SECTION_INFORMATION_CLASS;

//线程创建
typedef struct _USER_STACK {
	PVOID  FixedStackBase;
	PVOID  FixedStackLimit;
	PVOID  ExpandableStackBase;
	PVOID  ExpandableStackLimit;
	PVOID  ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID TransferAddress;
	ULONG ZeroBits;
	SIZE_T MaximumStackSize;
	SIZE_T CommittedStackSize;
	ULONG SubSystemType;
	union {
		struct {
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	ULONG GpValue;
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	BOOLEAN ImageContainsCode;
	BOOLEAN Spare1;
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG Reserved[1];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySection(
	__in HANDLE SectionHandle,
	__in SECTION_INFORMATION_CLASS SectionInformationClass,
	__out_bcount(SectionInformationLength) PVOID SectionInformation,
	__in SIZE_T SectionInformationLength,
	__out_opt PSIZE_T ReturnLength
);

//看不懂的函数
BOOLEAN NTAPI Safe_19AFC(IN HANDLE In_ProcessHandle, IN ULONG In_Eip, IN ULONG In_Eax, IN ULONG In_Esp, IN ULONG In_ExpandableStackBottom, IN ULONG In_ExpandableStackSize);

//创建线程
NTSTATUS NTAPI Fake_ZwCreateThread(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);