#pragma once
#include <ntifs.h>
#include "Data.h"

#define PIDMMNEWNUMBER        0x62					//保存分配内存信息的，每个进程可以存0x64的new的信息,实际使用0x62个
#define PIDMMNEWNUMBERMAXIMUM 0x64
#define PIDMMNUMBER           0xC6					//保存分配内存信息的，一共可以存0xC8个进程,实际使用0xC6个
#define PIDMMNUMBERMAXIMUM    0xC8

//每个进程可以分配很多次内存数据，最大限制0x62次
//大小0x4B8
typedef struct _ALLOCATEVIRTUALMEMORYDATA {
	ULONG  ListNumber;								//+0x4						目前使用了几个，计数
	PVOID  BaseAddress[PIDMMNEWNUMBERMAXIMUM];		//+0X8						分配首地址
	SIZE_T RegionSize[PIDMMNEWNUMBERMAXIMUM];		//+0X198					分配大小
	HANDLE ProcessId[PIDMMNEWNUMBERMAXIMUM];		//+0X328					PsGetCurrentProcessId
	HANDLE UniqueProcessId;							//+0X428					pPsGetProcessId
}ALLOCATEVIRTUALMEMORYDATA, *PALLOCATEVIRTUALMEMORYDATA;

//保存分配内存信息的结构体     
typedef struct _ALLOCATEVIRTUALMEMORY_DIRECTORY {
	ULONG ListNumber;														// +0   一共有多少组
	ALLOCATEVIRTUALMEMORYDATA VirtualMmBuff[PIDMMNUMBERMAXIMUM];			// +4   每一组有多少次
	KSPIN_LOCK	SpinLock;													// 末尾 自旋锁			g_SpinLock_39010
}ALLOCATEVIRTUALMEMORY_DIRECTORY, *PALLOCATEVIRTUALMEMORY_DIRECTORY;
PALLOCATEVIRTUALMEMORY_DIRECTORY g_VirtualMemoryData_List;

/*****************************添加*****************************/
//添加内存信息
//成功返回1，失败返回0
BOOLEAN Safe_InsertVirtualMemoryDataList(IN PVOID In_BaseAddress, IN SIZE_T In_RegionSize, IN HANDLE In_UniqueProcessId, IN HANDLE In_ProcessId);
/*****************************添加*****************************/

/*****************************删除*****************************/
//删除内存信息
PVOID NTAPI Safe_DeleteVirtualMemoryDataList(IN HANDLE In_ProcessId);

//删除内存信息
//WINDOWS_VERSION_XP与Win2K生效
PVOID NTAPI Safe_DeleteVirtualMemoryDataList_XP_WIN2K(IN HANDLE In_UniqueProcessId, IN HANDLE In_ProcessId, IN ULONG In_Esp, IN ULONG In_ExpandableStackBottom, IN ULONG In_ExpandableStackSize);
/*****************************删除*****************************/


/*****************************查询*****************************/
//查询内存信息
//成功返回1，失败返回0
BOOLEAN Safe_QueryVirtualMemoryDataList(IN PVOID In_BaseAddress, IN SIZE_T In_RegionSize, IN HANDLE In_UniqueProcessId, IN HANDLE In_ProcessId);
/*****************************查询*****************************/
