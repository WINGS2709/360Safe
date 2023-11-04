#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Data.h"
#include "Regedit.h"

//RPC通讯在各个平台上依赖的API各不相同，基本上
//win2000 : NtFsControlFile
//xp, 2003 : NtRequestWaitReplyPort
//vista, 2008.win7 : NtAlpcSendWaitReceivePort
NTSTATUS NTAPI Fake_ZwAlpcSendWaitReceivePort(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);