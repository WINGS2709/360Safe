#pragma once
#include <ntifs.h>
#include "Data.h"
#include "WinKernel.h"

//白名单进程个数
#define WHITELISTNUMBER						0xFE
#define WHITELISTNUMBERMAXIMUM				0x100

//特殊白名单个数,目前只发现360Tray.exe启动+1
#define SPECIALWHITELISTSIZE                0xE			
#define SPECIALWHITELISTSIZEMAXIMUM	        0x10


//R3用来交互的界面
typedef struct _SPECIALWHITELIST
{
	ULONG SpecialWhiteListNumber;								 //特殊白名单进程个数
	ULONG SpecialWhiteListPID[SPECIALWHITELISTSIZEMAXIMUM];		 //特殊白名单的PID
	ULONG SpecialWhiteListSessionId[SPECIALWHITELISTSIZEMAXIMUM];//特殊白名单的进程的终端ID(SessionId): pbi.InheritedFromUniqueProcessId 的进程名 == "services.exe"就等于3600FFFF，否则等于SessionId
	KSPIN_LOCK SpinLock;										 //操作g_SpecialWhite_List特殊白名单的SpinLock锁
}SPECIALWHITELIST, *PSPECIALWHITELIST;							 //特殊白名单目前只发现360Tray.exe启动+1,IRP通讯部分后期逆向
SPECIALWHITELIST g_SpecialWhite_List;

typedef struct _WHITELIST
{
	ULONG WhiteListNumber;										//白名单进程个数				    >= 0xFF为无效
	ULONG WhiteListPID[WHITELISTNUMBERMAXIMUM];					//白名单的PID						0x100
	ULONG SafeModIndex[WHITELISTNUMBERMAXIMUM];					//保存SafeMon,查找该dos路径在列表第几项，ret_arg = 返回数组下标
	KSPIN_LOCK SpinLock;										//自旋锁
}WHITELIST,*PWHITELIST;											//保存白名单进程PID，例如：zhudongfangyu.exe、数字xxxx.exe进程,IRP通讯部分后期逆向
WHITELIST g_White_List;


/*****************************删除*****************************/
//判断是不是白名单进程
//1：如果是：将白名单进程信息从数组中抹除
//2、如果不是：直接退出
BOOLEAN Safe_DeleteWhiteList_PID(_In_ HANDLE ProcessId);

//根据SessionId删除
BOOLEAN Safe_DeleteWhiteList_SessionId(_In_ HANDLE SessionId);

//根据PID和SessionId删除
BOOLEAN Safe_DeleteWhiteList_PID_SessionId(_In_ HANDLE ProcessId);
/*****************************删除*****************************/

/*****************************添加*****************************/
//Win2K
// 添加白名单进程信息
BOOLEAN  Safe_InsertWhiteList_PID_Win2003(_In_ HANDLE ProcessId, _In_ ULONG SessionId);

// 添加白名单进程信息
BOOLEAN  Safe_InsertWhiteList_PID(_In_ HANDLE ProcessId, _In_ ULONG SessionId);
/*****************************添加*****************************/

/*****************************查询*****************************/
//判断是不是白名单_EPROCESS
//返回值：是1，不是0
BOOLEAN Safe_QueryWhiteEProcess(_In_ PEPROCESS Process);

//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWhitePID(_In_ HANDLE ProcessId);

//函数功能：
//判断特殊白名单进程SessionId是否等于当前进程的SessionId
//返回值：
//返回值：是1，不是0
BOOLEAN Safe_QuerySpecialWhiteSessionId();

//根据ProcessHandle转换成Eprocess，然后调用Safe_QueryWhitePID_PsGetProcessId
//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWintePID_ProcessHandle(IN HANDLE ProcessHandle);

//根据线程句柄获取PID，然后判断PID是否是保护进程
//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWintePID_ThreadHandle(IN HANDLE ThreadHandle);

//Eprocess_UniqueProcessId
//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWhitePID_PsGetProcessId(IN PEPROCESS pPeprocess);

//根据ThreadHandle获取当前进程PID
BOOLEAN  Safe_QueryWhitePID_PsGetThreadProcessId(PVOID VirtualAddress);
/*****************************查询*****************************/
