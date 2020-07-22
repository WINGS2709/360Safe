#pragma once
#include <ntifs.h>
#include "Data.h"
#include "WinKernel.h"


//黑白名单个数
#define DRVMKNUMBER                         0x270E				
#define DRVMKNUMBERMAXIMUM				    0x2710

//保存PE哈希值、文件大小、放行or拦截标志位
//大小0x18个字节
typedef struct _PE_HASH_DATA
{
	ULONG  Hash[4];									//哈希值
	ULONG  PESize;									//文件大小
	ULONG  LoadDriver_Flag;							//驱动 拦截or放行标识   1拦截 0放行
}PE_HASH_DATA, *PPE_HASH_DATA;


//360的白名单或则黑名单文本							保存drvmk.dat文件内容
typedef struct _SYS_BLACK_WHITE_DATA
{
	ULONG		 ListNumber;						//保存数组使用个数
	PE_HASH_DATA Pe_Hash_Data[DRVMKNUMBERMAXIMUM];	//保存该进程的信息包含：哈希值、文件大小、拦截or放行标识
	KSPIN_LOCK   SpinLock;						    //自旋锁
}SYS_BLACK_WHITE_DATA, *PSYS_BLACK_WHITE_DATA;

PSYS_BLACK_WHITE_DATA g_Drvmk_List;

/******************************删除******************************/
//删除黑白名单
PVOID NTAPI Safe_DeleteDrvmkDataList(IN ULONG In_Hash, IN SIZE_T In_FileSize, IN ULONG Pass_Flag);
/******************************删除******************************/

/******************************添加******************************/
//添加黑白名单
PVOID NTAPI Safe_InsertDrvmkDataList(IN ULONG In_Hash, IN SIZE_T In_FileSize, IN ULONG Pass_Flag);
/******************************添加******************************/

/******************************查询******************************/
//判断是否存在
ULONG NTAPI Safe_QueryDrvmkDataList(IN ULONG In_Hash,IN SIZE_T In_FileSize);
/******************************查询******************************/

/*****************************初始化*****************************/
//读取TextOutCache键值里的内容，该内容是一个路径指向xxx\\xxx\\xxx\\drvmk.dat
NTSTATUS NTAPI Safe_InitializeTextOutCacheList(IN PCWSTR In_Data, IN ULONG Type, IN ULONG DataLength,IN ULONG Flag);

//初始化链表，保存拦截和放行进程信息的（R3和R0交互）
VOID NTAPI Safe_Initialize_List();
/*****************************初始化*****************************/