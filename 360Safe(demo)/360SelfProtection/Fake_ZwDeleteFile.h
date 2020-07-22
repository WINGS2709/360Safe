#pragma once
#include <ntifs.h>
#include "Data.h"
#include "MemCheck.h"
#include "NoSystemProcessDataList.h"
//É¾³ýÎÄ¼þ
NTSTATUS NTAPI Fake_ZwDeleteFile(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);
