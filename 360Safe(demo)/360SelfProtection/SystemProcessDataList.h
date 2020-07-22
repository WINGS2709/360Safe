#pragma once
#include <ntifs.h>
#include "WinKernel.h"
#include "Data.h"


/************************初始化系统进程列表*********************/
//Safe_Initialize_Data函数里面的
//初始化系统进程函数
NTSTATUS Safe_InitializeSystemInformationFile();
/************************初始化系统进程列表*********************/

/*****************************添加*****************************/
//功能：
//如果打开的是指定的系统进程，并且文件信息校验正确，就设置对应的PID和Eprocess
//g_dynData->SystemInformationList.xxxx       是指定系统进程信息
BOOLEAN NTAPI Safe_InsertSystemInformationList(IN PEPROCESS Process, IN ULONG Index, IN ULONG Version_Flag);


/*****************************添加*****************************/

/*****************************查询*****************************/
//判断是否存在
BOOLEAN NTAPI Safe_QuerySystemInformationList(IN PEPROCESS Process, IN ULONG Index);
/*****************************查询*****************************/

/*****************************检查*****************************/
//核对csrss.exe、svchost.exe、dllhost.exe合法性
BOOLEAN NTAPI Safe_CheckSysProcess();

//过滤掉csrss.exe和lsass.exe
BOOLEAN NTAPI Safe_CheckSysProcess_Csrss_Lsass(IN HANDLE In_Handle);


//coherence.exe
BOOLEAN NTAPI Safe_CheckSysProcess_Coherence();
/*****************************检查*****************************/