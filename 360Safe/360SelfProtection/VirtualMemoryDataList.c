#include "VirtualMemoryDataList.h"

//************************************     
// 函数名称: Safe_DeleteVirtualMemoryDataList     
// 函数说明：删除内存信息    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：    
// 返 回 值: PVOID
// 参    数: IN HANDLE In_ProcessId             当前进程ID   
//************************************  
PVOID NTAPI Safe_DeleteVirtualMemoryDataList(IN HANDLE In_ProcessId)
{
	KIRQL       NewIrql;
	ULONG	    result = NULL;
	ULONG       SumListNumber = 0;
	ULONG       UniqueProcessId = 0;
	ULONG       OuterIndex = 0;			//外圈循环计数器
	ULONG		InsideIndex = 0;		//内圈循环计数器
	ULONG       RunFlag = TRUE;
	//加锁
	NewIrql = KfAcquireSpinLock(&g_VirtualMemoryData_List->SpinLock);
	//获取总个数
	SumListNumber = g_VirtualMemoryData_List->ListNumber;
	//外圈
	if (SumListNumber)
	{
		for (OuterIndex = 0; OuterIndex < SumListNumber; OuterIndex++)
		{
			UniqueProcessId = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].UniqueProcessId;
			//遇到相同ID 说明存在，进行内圈查找该PID分配的所有地址空间
			if (UniqueProcessId == In_ProcessId)
			{
				//后面往前挪
				for (ULONG i = SumListNumber; i <= SumListNumber; i++)
				{
					g_VirtualMemoryData_List->VirtualMmBuff[i] = g_VirtualMemoryData_List->VirtualMmBuff[i + 1];
				}
				//外圈总数-1
				g_VirtualMemoryData_List->ListNumber--;
				break;
			}
		}
	}
	//内圈
	SumListNumber = g_VirtualMemoryData_List->ListNumber;
	if (SumListNumber)
	{
		//获取内圈个数
		ULONG InsideListNumber = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ListNumber;
		for (InsideIndex = 0; InsideIndex < InsideListNumber; InsideIndex++)
		{
			//判断ProcessId
			if (g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ProcessId[InsideIndex] == In_ProcessId)
			{
				//找到了，往前挪
				for (ULONG i = InsideIndex; i <= InsideListNumber; i++)
				{
					g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ProcessId[InsideIndex] = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ProcessId[InsideIndex + 1];
					g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].RegionSize[InsideIndex] = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].RegionSize[InsideIndex + 1];
					g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].BaseAddress[InsideIndex] = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].BaseAddress[InsideIndex + 1];
					//内圈个数-1
					g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ListNumber--;
					//跳出循环继续执行外圈大循环 ->for (InsideIndex = 0; InsideIndex < InsideListNumber; InsideIndex++)
					break;
				}
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_VirtualMemoryData_List->SpinLock, NewIrql);
}


//删除内存信息
//WINDOWS_VERSION_XP与Win2K生效
PVOID NTAPI Safe_DeleteVirtualMemoryDataList_XP_WIN2K(IN HANDLE In_UniqueProcessId, IN HANDLE In_ProcessId, IN ULONG In_Esp, IN ULONG In_ExpandableStackBottom, IN ULONG In_ExpandableStackSize)
{
	KIRQL       NewIrql;
	ULONG	    result = NULL;
	ULONG       SumListNumber = 0;
	ULONG       UniqueProcessId = 0;
	ULONG       OuterIndex = 0;			//外圈循环计数器
	ULONG		InsideIndex = 0;		//内圈循环计数器
	ULONG       RunFlag = TRUE; 
	ULONG       v5 = (In_Esp & 0xFFFFF000) - In_ExpandableStackSize + 0x1000;
	//加锁
	NewIrql = KfAcquireSpinLock(&g_VirtualMemoryData_List->SpinLock);
	//获取总个数
	SumListNumber = g_VirtualMemoryData_List->ListNumber;
	if (SumListNumber)
	{
		//外圈循环遍历找UniqueProcessId
		for (OuterIndex = 0; OuterIndex < SumListNumber; OuterIndex++)
		{
			UniqueProcessId = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].UniqueProcessId;
			//找到则退出循环
			if (In_UniqueProcessId == UniqueProcessId)
			{
				break;
			}
		}
		//判断个数是否超标
		if (OuterIndex < SumListNumber)
		{
			//获取内圈个数
			ULONG InsideListNumber = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ListNumber;
			for (InsideIndex = 0; InsideIndex < InsideListNumber; InsideIndex++)
			{
				//判断In_ExpandableStackSize 在 RegionSize范围内
				SIZE_T RegionSize = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].RegionSize[InsideIndex];
				ULONG BaseAddress = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].BaseAddress[InsideIndex];
				if ((BaseAddress <= In_Esp) && (BaseAddress + RegionSize >= In_Esp))
				{
					break;
				}
				if ((BaseAddress < In_ExpandableStackBottom + In_ExpandableStackSize) && (BaseAddress + RegionSize > In_ExpandableStackBottom))
				{
					break;
				}
				if ((BaseAddress < v5 + In_ExpandableStackSize) && (BaseAddress + RegionSize > v5))
				{
					break;
				}
			}
			//判断个数是否超标
			if (InsideIndex < InsideListNumber)
			{
				//找到了往前挪
				for (ULONG i = InsideIndex; i <= InsideListNumber; i++)
				{
					g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ProcessId[InsideIndex] = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ProcessId[InsideIndex + 1];
					g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].RegionSize[InsideIndex] = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].RegionSize[InsideIndex + 1];
					g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].BaseAddress[InsideIndex] = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].BaseAddress[InsideIndex + 1];
					//内圈个数-1
					g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ListNumber--;
					break;
				}
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_VirtualMemoryData_List->SpinLock, NewIrql);
}

//************************************     
// 函数名称: Safe_InsertVirtualMemoryDataList     
// 函数说明：添加内存信息    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：    
// 返 回 值: BOOLEAN   成功返回1，失败返回0  
// 参    数: IN PVOID In_BaseAddress			分配首地址
// 参    数: IN SIZE_T In_RegionSize			分配大小
// 参    数: IN HANDLE In_UniqueProcessId       进程ID      pPsGetProcessId
// 参    数: IN HANDLE In_ProcessId             当前进程ID  PsGetCurrentProcessId 
//************************************  
BOOLEAN Safe_InsertVirtualMemoryDataList(IN PVOID In_BaseAddress, IN SIZE_T In_RegionSize, IN HANDLE In_UniqueProcessId, IN HANDLE In_ProcessId)
{
	KIRQL       NewIrql;
	ULONG	    result = NULL;
	ULONG       SumListNumber = 0;
	ULONG       UniqueProcessId = 0;
	ULONG       RunFlag = TRUE;
	//加锁
	NewIrql = KfAcquireSpinLock(&g_VirtualMemoryData_List->SpinLock);
	//获取总个数
	SumListNumber = g_VirtualMemoryData_List->ListNumber;
	//1、判断是不是该PID是不是第一次进入
	//遇到相同PID直接使用无需重新分配
	for (ULONG OuterIndex = 0; OuterIndex < SumListNumber; OuterIndex++)
	{
		UniqueProcessId = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].UniqueProcessId;
		//相同PID直接添加即可
		//每个进程可以分配很多次内存数据，最大限制0x62次
		if (UniqueProcessId == In_UniqueProcessId)
		{
			//获取内圈个数
			ULONG InsideListNumber = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ListNumber;
			//判断个数是否超标
			if (InsideListNumber <= PIDMMNEWNUMBER)
			{
				g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].BaseAddress[InsideListNumber] = In_BaseAddress;			//分配空间首地址
				g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].RegionSize[InsideListNumber] = In_RegionSize;			//分配大小
				g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ProcessId[InsideListNumber] = In_ProcessId;				//PsGetCurrentProcessId()
				g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ListNumber++;										   //内圈使用个数+1
				//成功执行
				result = TRUE;
				RunFlag = FALSE;
				break;
			}
			else
			{
				//失败执行
				result = FALSE;
				RunFlag = FALSE;
				break;
			}
		}
	}
	//陌生PID，重新添加一份
	if (RunFlag)
	{
		//3、判断个数是否超标
		if (SumListNumber < PIDMMNUMBER)
		{
			//4、第一次进入,当然是从下标0开始啦
			g_VirtualMemoryData_List->VirtualMmBuff[SumListNumber].UniqueProcessId = In_UniqueProcessId;	//进程ID
			g_VirtualMemoryData_List->VirtualMmBuff[SumListNumber].BaseAddress[0] = In_BaseAddress;			//分配空间首地址
			g_VirtualMemoryData_List->VirtualMmBuff[SumListNumber].RegionSize[0] = In_RegionSize;			//分配大小
			g_VirtualMemoryData_List->VirtualMmBuff[SumListNumber].ProcessId[0] = In_ProcessId;				//PsGetCurrentProcessId()
			g_VirtualMemoryData_List->VirtualMmBuff[SumListNumber].ListNumber = 1;							//内圈使用个数
			//外圈个数+1
			g_VirtualMemoryData_List[SumListNumber].ListNumber++;
			result = TRUE;
		}
		else
		{
			result = FALSE;
		}
	}
	//解锁
	KfReleaseSpinLock(&g_VirtualMemoryData_List->SpinLock, NewIrql);
	return result;
}

//************************************     
// 函数名称: Safe_QueryVirtualMemoryDataList     
// 函数说明：查询内存信息    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：    
// 返 回 值: BOOLEAN   成功返回1，失败返回0  
// 参    数: IN PVOID In_BaseAddress			分配首地址
// 参    数: IN SIZE_T In_RegionSize			分配大小
// 参    数: IN HANDLE In_UniqueProcessId       进程ID      pPsGetProcessId
// 参    数: IN HANDLE In_ProcessId             当前进程ID  PsGetCurrentProcessId 
//************************************  
BOOLEAN Safe_QueryVirtualMemoryDataList(IN PVOID In_BaseAddress, IN SIZE_T In_RegionSize, IN HANDLE In_UniqueProcessId, IN HANDLE In_ProcessId)
{
	KIRQL       NewIrql;
	ULONG	    result = FALSE;
	ULONG       SumListNumber = 0;
	ULONG       UniqueProcessId = 0;
	ULONG       RunFlag = TRUE;
	ULONG       OuterIndex = 0;			//外圈循环计数器
	ULONG		InsideIndex = 0;		//内圈循环计数器

	//加锁
	NewIrql = KfAcquireSpinLock(&g_VirtualMemoryData_List->SpinLock);
	//获取总个数
	SumListNumber = g_VirtualMemoryData_List->ListNumber;
	//1、判断名单个数
	if (SumListNumber)
	{
		//遇到相同PID才进行内圈查找
		for (ULONG OuterIndex = 0; OuterIndex < SumListNumber; OuterIndex++)
		{
			UniqueProcessId = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].UniqueProcessId;
			//遇到相同ID 说明存在，进行内圈查找该PID分配的所有地址空间
			if (UniqueProcessId == In_UniqueProcessId)
			{
				//获取内圈总个数
				ULONG InsideListNumberMax = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ListNumber;
				//遍历该PID所有分配的地址空间
				for (ULONG InsideIndex = InsideListNumberMax; InsideIndex < InsideListNumberMax; InsideIndex++)
				{
					//判断ProcessId
					if (g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].ProcessId[InsideIndex] == In_ProcessId)
					{
						ULONG BaseAddress = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].BaseAddress[InsideIndex];
						ULONG RegionSize = g_VirtualMemoryData_List->VirtualMmBuff[OuterIndex].RegionSize[InsideIndex];
						//再判断内存范围 是否在xxx之间
						if (
							((ULONG)In_BaseAddress >= BaseAddress) &&
							(((ULONG)In_BaseAddress + In_RegionSize) <= (BaseAddress + RegionSize))
							)
						{
							//找到了就退出
							result = TRUE;
							goto _FunctionRet;
						}
					}
				}
			}
		}
	}
	_FunctionRet:
	//解锁
	KfReleaseSpinLock(&g_VirtualMemoryData_List->SpinLock, NewIrql);
	return result;
}