#pragma once
#include <ntifs.h>
#include <ntdef.h>
#include "WhiteList.h"
#include "Regedit.h"
#include "SystemProcessDataList.h"


//里面细化处理各种类型：File、Process、Section、Thread敏感操作
//File：   违规操作：访问句柄是指定的白名单驱动对象
//Process：违规操作：访问句柄是指定的白名单、自身进程是IE
//Section：违规操作：路径是\\Device\\PhysicalMemory和\\KnownDlls\\ 
//Thread： 违规操作：访问句柄是指定的白名单、自身进程是IE
NTSTATUS NTAPI Safe_26C42(IN HANDLE In_SourceHandle, IN ULONG In_Options, IN ACCESS_MASK In_DesiredAccess, IN HANDLE In_TargetProcessHandle, IN HANDLE In_SourceProcessHandle);

//判断DuplicateObject函数执行后的错误码
BOOLEAN NTAPI CheckResult_After_DuplicateObject(NTSTATUS In_Status);

//检查文件对象指针是不是分页文件
BOOLEAN NTAPI Safe_RunFsRtlIsPagingFile(IN PFILE_OBJECT In_FileObject);

//没看懂
BOOLEAN NTAPI Safe_26794(IN HANDLE In_TargetProcessHandle);

//查询注册表HIVELIST
BOOLEAN NTAPI Safe_QuerHivelist(IN ACCESS_MASK GrantedAccess, IN HANDLE In_SourceHandle, IN HANDLE In_SourceProcessHandle);

//复制句柄
NTSTATUS NTAPI Fake_ZwDuplicateObject(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);