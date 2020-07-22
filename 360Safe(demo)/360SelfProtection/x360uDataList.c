/*
说明:
1、每个SAFEMONPATH_DIRECTORY结构(保存路径)对应一个SAFEMONDATA_DIRECTORY(该路径进程的详细信息)结构
2、一个保存路径信息、一个保存该路径进程的EPROCESS、PID、等等信息
3、该路径存储的是自身安全目录，当是该目录软件打开就给与绿色通行
*/
#include "x360uDataList.h"


//查询该DosPath是否在列表中，如果是返回Index
ULONG NTAPI Safe_QuerSafeMonPathList(IN PWCHAR DosPath, OUT ULONG ret_arg)
{
	KIRQL       NewIrql;
	ULONG	    result = NULL;
	ULONG       Index = 0;
	ULONG       ListNumber = NULL;
	PVOID       pListAddr = NULL;			//指向g_SafeMonPath_List->DosPath  二维数组首地址
	//上锁
	NewIrql = KfAcquireSpinLock(&g_SafeMonPath_List->SpinLock);
	ListNumber = g_SafeMonPath_List->ListNumber;
	pListAddr = &g_SafeMonPath_List->DosPath;
	//判断名单个数
	if (ListNumber)
	{
		for (Index = 0; Index < ListNumber; Index++)
		{
			//判断dos路径是否在列表中
			if (_wcsicmp(DosPath, pListAddr) == 0)
			{
				//找到则退出
				break;
			}
			//如果不在偏移到下一组
			pListAddr = ((ULONG)pListAddr + DOSPATHSIZE);
		}
		if (Index >= ListNumber)
		{
			//错误返回
			result = 0;
		}
		else
		{
			if (ret_arg)
			{
				*(ULONG*)ret_arg = g_SafeMonPath_List->ArrayIndex[Index];			//该DosPath路径在数组中的下标索引，其实你直接返回*(ULONG*)ret_arg = Index同理
			}
			result = 1;
		}
	}
	else
	{
		result = 0;
	}
	//解锁
	KfReleaseSpinLock(&g_SafeMonPath_List->SpinLock, NewIrql);
	return result;
}

//删除名单进程信息
//成功返回对应的下标，失败返回0
ULONG NTAPI Safe_DeleteSafeMonDataList(_In_ HANDLE SafeMonSectionHandle)
{
	ULONG	  result = NULL;
	PEPROCESS Process = NULL;
	PEPROCESS SafeMonProcess = NULL;
	NTSTATUS  Status = NULL;
	PVOID     SectionObject = NULL;
	KIRQL     NewIrql;
	ULONG     ListNumber = NULL;
	Process = IoGetCurrentProcess();
	//1、获取SectionObject
	Status = ObReferenceObjectByHandle(SafeMonSectionHandle, 0, MmSectionObjectType, UserMode, &SectionObject, 0);
	if (!NT_SUCCESS(Status))
	{
		result = FALSE;
		return result;
	}
	//减少引用计数
	ObDereferenceObject(SectionObject);
	//上锁
	NewIrql = KfAcquireSpinLock(&g_SafeMonData_List->SpinLock);
	ListNumber = g_SafeMonData_List->ListNumber;
	//判断名单个数
	if (ListNumber)
	{
		for (ULONG Index = 0; Index < ListNumber; Index++)
		{
			//找到则删除
			if (g_SafeMonData_List->SafeMonSectionHandle[Index] == SafeMonSectionHandle &&
				g_SafeMonData_List->SafeMonSectionObject[Index] == SectionObject &&
				g_SafeMonData_List->SafeMonProcess[Index] == SafeMonProcess)
			{
				//保存当前删除的数组下标
				result = g_SafeMonData_List->SafeMonIndex[Index];													//起始偏移4003*4,保存SafeMon,查找该dos路径在列表第几项，ret_arg = 返回数组下标
				//清空退出进程的信息(后一个往前挪)
				for (ULONG i = Index; i <= ListNumber; i++)
				{
					g_SafeMonData_List->SafeMonSectionHandle[i] = g_SafeMonData_List->SafeMonSectionHandle[i + 1]; //起始偏移0000*4,保存SafeMod的SectionHandle
					g_SafeMonData_List->SafeMonSectionObject[i] = g_SafeMonData_List->SafeMonSectionObject[i + 1]; //起始偏移2002*4,保存SectionObject
					g_SafeMonData_List->SafeMonIndex[i]         = g_SafeMonData_List->SafeMonIndex[i + 1];		   //起始偏移4003*4,保存SafeMon,查找该dos路径在列表第几项，ret_arg = 返回数组下标
					g_SafeMonData_List->SafeMonProcess[i]       = g_SafeMonData_List->SafeMonProcess[i + 1];	   //起始偏移6001*4,保存SafeMod的Eprocess结构
				}
				//保护进程个数-1
				--g_SafeMonData_List->ListNumber;
				break;
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_SafeMonData_List->SpinLock, NewIrql);
	return result;
}

//添加名单进程信息
// 成功返回1，失败返回0
BOOLEAN Safe_InsertSafeMonDataList(_In_ HANDLE SafeMonSectionHandle, _In_ ULONG SafeMonIndex)
{
	PEPROCESS SafeMonProcess = NULL;
	NTSTATUS  Status = NULL;
	BOOLEAN   result = TRUE;
	PVOID     SectionObject = NULL;
	KIRQL     NewIrql;
	ULONG     ListNumber = NULL;
	ULONG     Index = NULL;								//循环计数，类似于int i=0 ;i++
	SafeMonProcess = IoGetCurrentProcess();
	//1、获取SectionObject
	Status = ObReferenceObjectByHandle(SafeMonSectionHandle, 0, MmSectionObjectType, UserMode, &SectionObject, 0);
	if (!NT_SUCCESS(Status))
	{
		result = FALSE;
		return result;
	}
	//减少引用计数
	ObDereferenceObject(SectionObject);
	//上锁
	NewIrql = KfAcquireSpinLock(&g_SafeMonData_List->SpinLock);
	ListNumber = g_SafeMonData_List->ListNumber;
	//判断名单个数
	if (ListNumber)
	{
		//不存在才添加
		while (g_SafeMonData_List->SafeMonSectionHandle[Index] != SafeMonSectionHandle &&
			g_SafeMonData_List->SafeMonSectionObject[Index] != SectionObject &&
			g_SafeMonData_List->SafeMonProcess[Index] != SafeMonProcess
			)
		{
			//假设是新的信息就插入
			if (Index++ >= ListNumber)
			{
				//名单进程个数<=0x7CE
				if (ListNumber <= SAFEMODMMDATALISTNUMBER)
				{
					g_SafeMonData_List->SafeMonSectionHandle[ListNumber] = SafeMonSectionHandle;
					g_SafeMonData_List->SafeMonSectionObject[ListNumber] = SectionObject;
					g_SafeMonData_List->SafeMonProcess[ListNumber] = SafeMonProcess;
					g_SafeMonData_List->SafeMonIndex[ListNumber] = SafeMonIndex;
					g_SafeMonData_List->ListNumber++;
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

		}
	}
	//解锁
	KfReleaseSpinLock(&g_SafeMonData_List->SpinLock, NewIrql);
	return result;
}