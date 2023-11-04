#pragma once
#include <ntifs.h>
#include "Data.h"
#include "WinKernel.h"
#include "WhiteList.h"
#include "Hash.h"
#include "DrvmkDataList.h"




NTSTATUS(NTAPI *pIoGetRequestorSessionId)(PIRP, PULONG);

PVOID NTAPI Safe_check_irp_request_in_list();

//初始化事件
BOOLEAN NTAPI Safe_setevent_called_by_iodispatcher(IN HANDLE In_User_ThreadID, IN ULONG In_User_bypass_or_not);

//设置链表

//核对IRP的SessionId == 当前进程活动SessionId
BOOLEAN NTAPI Safe_is_irp_reqeust_from_local(PIRP Irp_a1);

ULONG NTAPI Safe_push_request_in_and_waitfor_finish(IN PQUERY_PASS_R0SENDR3_DATA In_pBuff, IN ULONG In_Flag);


//这个未逆向，名字不知道取什么
//主动防御提示与应用层通讯交互
PVOID NTAPI Safe_18A72_SendR3(IN HANDLE In_PorcessID, IN HANDLE In_ThreadID, IN PROCESSINFOCLASS  ProcessInformationClass);

//这个未逆向，名字不知道取什么
//主动防御提示与应用层通讯交互
NTSTATUS NTAPI Safe_1D044_SendR3(IN HANDLE In_PorcessID, IN HANDLE In_ThreadID, IN ULONG In_Flag, IN PUNICODE_STRING In_ImagePathString);

//检查驱动合法性
NTSTATUS NTAPI Safe_CheckSys_SignatureOrHash(IN HANDLE In_PorcessID, IN HANDLE In_ThreadID, IN PUNICODE_STRING In_pImagePathString, OUT PPE_HASH_DATA Out_SendHashData, OUT ULONG Out_PassFlag, IN ULONG In_Flag_a6);