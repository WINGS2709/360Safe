#include "CreateProcessDataList.h"

//插入新数据
BOOLEAN Safe_InsertCreateProcessDataList(IN PEPROCESS Process, IN ULONG SafeModArrayIndex)
{
	KIRQL NewIrql;
	NTSTATUS	status, result;
	ULONG Index = 0;						//下标索引
	ULONG GotoFalg;							//不想同goto设置的Falg
	ULONG CreateProcessListNumber = 0;
	CreateProcessListNumber = g_CreateProcessData_List.CreateProcessListNumber;
	result = TRUE;
	NewIrql = KfAcquireSpinLock(&g_CreateProcessData_List.SpinLock);
	//1、新增插入  名单个数+1，成功返回TRUE（个数<=0x4FE），失败FALSE（个数>0x4FE）
	while (Process != (ULONG)g_CreateProcessData_List.Eprocess[Index])
	{
		//假设是新的信息就插入
		if (Index >= CreateProcessListNumber)
		{
			//进程个数<=0x4FE
			if (CreateProcessListNumber <= CREATEPROCESSNUMBER)
			{
				g_CreateProcessData_List.Eprocess[CreateProcessListNumber] = Process;
				g_CreateProcessData_List.ArrayIndex[CreateProcessListNumber] = SafeModArrayIndex;
				//个数自增1
				g_CreateProcessData_List.CreateProcessListNumber++;
				//成功返回
				result = TRUE;
				break;
			}
			else
			{
				//失败返回
				result = FALSE;
				break;
			}
		}
		else
		{
			//自增
			++Index;
		}
	}
	KfReleaseSpinLock(&g_CreateProcessData_List.SpinLock, NewIrql);
	return result;
}

//判断是不是名单进程Eprocess
//1：如果是：将名单进程信息从数组中抹除
//2、如果不是：直接退出
//返回值：删除的SafeMon查找该dos路径在列表第几项，ret_arg = 返回数组下标	
ULONG Safe_DeleteCreateProcessDataList(_In_ PEPROCESS Process)
{
	KIRQL NewIrql;
	ULONG Index = 0;						//下标索引
	ULONG SafeModArrayIndex = 0;
	ULONG CreateProcessListNumber = 0;
	CreateProcessListNumber = g_CreateProcessData_List.CreateProcessListNumber;
	//上锁
	NewIrql = KfAcquireSpinLock(&g_CreateProcessData_List.SpinLock);
	//判断名单个数
	if (CreateProcessListNumber)
	{
		for (ULONG Index = 0; Index < CreateProcessListNumber; Index++)
		{
			//在表中找到对应的EProcess（要删除的）
			if ((ULONG)Process == g_CreateProcessData_List.ArrayIndex[Index])
			{
				//获取SafeMon查找该dos路径在列表第几项，ret_arg = 返回数组下标	
				SafeModArrayIndex = g_CreateProcessData_List.ArrayIndex[Index];
				//清空退出进程的信息(后一个往前挪)
				for (ULONG i = Index; i < CreateProcessListNumber; i++)
				{
					g_CreateProcessData_List.Eprocess[i] = g_CreateProcessData_List.Eprocess[i + 1];			//进程Eprocess
					g_CreateProcessData_List.ArrayIndex[i] = g_CreateProcessData_List.ArrayIndex[i + 1];		//SafeMon查找该dos路径在列表第几项，ret_arg = 返回数组下标	
				}
				//进程信息个数-1
				--g_CreateProcessData_List.CreateProcessListNumber;
				break;
			}
			else
			{
				SafeModArrayIndex = 0;
				break;
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_CreateProcessData_List.SpinLock, NewIrql);
	return SafeModArrayIndex;
}