#pragma once
#include <ntifs.h>
#include "Data.h"

//进程个数
#define CREATEPROCESSNUMBER					0x4FE
#define CREATEPROCESSNUMBERMAXIMUM			0x500

typedef struct _CREATEPROCESSDATALIST
{
	ULONG      CreateProcessListNumber;							//个数>= 0x4FE为无效
	PVOID	   Eprocess[CREATEPROCESSNUMBERMAXIMUM];			//Eprocess结构
	PVOID	   ArrayIndex[CREATEPROCESSNUMBERMAXIMUM];			//SafeMon查找该dos路径在列表第几项，ret_arg = 返回数组下标	
	KSPIN_LOCK SpinLock;										//自旋锁
}CREATEPROCESSDATALIST, *PCREATEPROCESSDATALIST;				//Fake_CreateProcess函数保存数据
CREATEPROCESSDATALIST g_CreateProcessData_List;

/*****************************添加*****************************/
//新增插入  名单个数+1，
//返回值：成功返回TRUE（个数<=0x4FE），失败FALSE（个数>=0x4FE）
BOOLEAN Safe_InsertCreateProcessDataList(IN PEPROCESS Process, IN ULONG SafeModArrayIndex);
/*****************************添加*****************************/

/*****************************删除*****************************/
//判断是不是名单进程Eprocess
//1：如果是：将名单进程信息从数组中抹除
//2、如果不是：直接退出
ULONG Safe_DeleteCreateProcessDataList(_In_ PEPROCESS ProcessId);
/*****************************删除*****************************/