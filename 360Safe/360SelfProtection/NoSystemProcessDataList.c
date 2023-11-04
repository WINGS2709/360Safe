/*
说明：
SystemProcessDataList跟NoSystemProcessDataList很相似这里说下区别：
1、
SystemProcessDataList保存特定系统进程文件信息一共24个
相关结构：
SystemInformationList保存PID信息
SYSTEM_INFORMATIONFILE_XOR保存文件信息

2、
NoSystemProcessDataList保存除了特定系统进程的所有文件信息，最大0x800组
相关结构：
//保存文件文件信息校验信息
//文件信息校验的SYSTEM_INFORMATIONFILE_XOR
typedef struct _ALL_INFORMATIONFILE_CRC
{
ULONG FileNumber;									// +0   保存大小的东西
SYSTEM_INFORMATIONFILE_XOR FileBuff[0x2000];		// +4   填充，后续知道再加
KSPIN_LOCK	SpinLock;								// 末尾 自旋锁
}ALL_INFORMATIONFILE_CRC, *P_ALL_INFORMATIONFILE_CRC;

P_ALL_INFORMATIONFILE_CRC g_All_InformationFile_CRC;
*/
#include "NoSystemProcessDataList.h"

//************************************     
// 函数名称: Safe_InsertInformationFileList     
// 函数说明：插入该列表中文件信息
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/04/01     
// 返 回 值: ULONG NTAPI    
// 参    数: IN ULONG IndexNumber_LowPart     [IN]该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
// 参    数: IN ULONG IndexNumber_HighPart    [IN]该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
// 参    数: IN ULONG VolumeSerialNumber      [IN]序列号体积      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
//************************************ 
ULONG NTAPI Safe_InsertInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber)
{
	KIRQL NewIrql = NULL;
	ULONG Index = NULL;						//数组下标索引
	ULONG result = FALSE;					//返回值
	//加锁
	NewIrql = KfAcquireSpinLock(&g_All_InformationFile_CRC->SpinLock);
	//1、新增插入  白名单个数+1，成功返回TRUE（个数 < 0x1FFE），失败FALSE（个数 > 0x1FFE）
	//2、已存在    无视，默认返回FALSE（失败）
	while (IndexNumber_LowPart != g_All_InformationFile_CRC->FileBuff[Index].IndexNumber_LowPart
		&& IndexNumber_HighPart != g_All_InformationFile_CRC->FileBuff[Index].u.IndexNumber_HighPart
		&& VolumeSerialNumber != g_All_InformationFile_CRC->FileBuff[Index].VolumeSerialNumber
		)
	{
		//假设是新的白名单信息就插入
		if (Index >= g_All_InformationFile_CRC->FileCRCListNumber)
		{
			//判断是否超过最大值
			if (Index <= CRCLISTNUMBER)
			{
				//插到最后面
				g_All_InformationFile_CRC->FileBuff[g_All_InformationFile_CRC->FileCRCListNumber].IndexNumber_LowPart = IndexNumber_LowPart;
				g_All_InformationFile_CRC->FileBuff[g_All_InformationFile_CRC->FileCRCListNumber].u.IndexNumber_HighPart = IndexNumber_HighPart;
				g_All_InformationFile_CRC->FileBuff[g_All_InformationFile_CRC->FileCRCListNumber].VolumeSerialNumber = VolumeSerialNumber;
				//数量自增1
				g_All_InformationFile_CRC->FileCRCListNumber++;
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
	//解锁
	KfReleaseSpinLock(&g_All_InformationFile_CRC->SpinLock, NewIrql);
	return result;
}

//************************************     
// 函数名称: Safe_DeleteInformationFileList     
// 函数说明：删除该列表中文件信息
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/04/01     
// 返 回 值: ULONG NTAPI    
// 参    数: IN ULONG IndexNumber_LowPart     [IN]该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
// 参    数: IN ULONG IndexNumber_HighPart    [IN]该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
// 参    数: IN ULONG VolumeSerialNumber      [IN]序列号体积      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
//************************************  
ULONG NTAPI Safe_DeleteInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber)
{
	KIRQL NewIrql = NULL;
	ULONG result = TRUE;					//返回值
	//加锁
	NewIrql = KfAcquireSpinLock(&g_All_InformationFile_CRC->SpinLock);
	//判断名单个数
	if (g_All_InformationFile_CRC->FileCRCListNumber)
	{
		for (ULONG Index = 0; Index < g_All_InformationFile_CRC->FileCRCListNumber; Index++)
		{
			//找到返回该数组在列表中下标
			if (
				IndexNumber_LowPart == g_All_InformationFile_CRC->FileBuff[Index].IndexNumber_LowPart
				&& IndexNumber_HighPart == g_All_InformationFile_CRC->FileBuff[Index].u.IndexNumber_HighPart
				&& VolumeSerialNumber == g_All_InformationFile_CRC->FileBuff[Index].VolumeSerialNumber
				)
			{
				//清空退出进程的信息(后一个往前挪)
				for (ULONG i = Index; i <= g_All_InformationFile_CRC->FileCRCListNumber;i++)
				{
					g_All_InformationFile_CRC->FileBuff[i].IndexNumber_LowPart = g_All_InformationFile_CRC->FileBuff[i + 1].IndexNumber_LowPart;
					g_All_InformationFile_CRC->FileBuff[i].u.IndexNumber_HighPart = g_All_InformationFile_CRC->FileBuff[i + 1].u.IndexNumber_HighPart;
					g_All_InformationFile_CRC->FileBuff[i].VolumeSerialNumber = g_All_InformationFile_CRC->FileBuff[i + 1].VolumeSerialNumber;
				}
				//数量-1
				g_All_InformationFile_CRC->FileCRCListNumber--;
				break;
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_All_InformationFile_CRC->SpinLock, NewIrql);
	return result;
}

//************************************     
// 函数名称: Safe_QueryInformationFileList     
// 函数说明：查找该文件信息是否在列表中，找到返回1，失败返回0
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/04/01     
// 返 回 值: ULONG NTAPI    找到返回1，找不到返回0  
// 参    数: IN ULONG IndexNumber_LowPart     [IN]该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
// 参    数: IN ULONG IndexNumber_HighPart    [IN]该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
// 参    数: IN ULONG VolumeSerialNumber      [IN]序列号体积      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
//************************************  
ULONG NTAPI Safe_QueryInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber)
{
	KIRQL NewIrql;
	ULONG result;
	ULONG GotoFalg;							//不想同goto设置的Falg
	result = 0;
	//加锁
	NewIrql = KfAcquireSpinLock(&g_All_InformationFile_CRC->SpinLock);
	//判断名单个数
	if (g_All_InformationFile_CRC->FileCRCListNumber)
	{
		for (ULONG Index = 0; Index < g_All_InformationFile_CRC->FileCRCListNumber; Index++)
		{
			//找到返回该数组在列表中下标
			if (
				IndexNumber_LowPart == g_All_InformationFile_CRC->FileBuff[Index].IndexNumber_LowPart
				&& IndexNumber_HighPart == g_All_InformationFile_CRC->FileBuff[Index].u.IndexNumber_HighPart
				&& VolumeSerialNumber == g_All_InformationFile_CRC->FileBuff[Index].VolumeSerialNumber
				)
			{
				result = 1;
				break;
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_All_InformationFile_CRC->SpinLock, NewIrql);
	return result;
}

//************************************     
// 函数名称: Safe_QueryInformationFileList_Name     
// 函数说明：根据文件对象名称查找是否在列表中
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/04/01     
// 返 回 值: ULONG NTAPI    找到返回1，找不到返回0  
// 参    数: IN PUNICODE_STRING ObjectName  文件对象名称
//************************************  
ULONG NTAPI Safe_QueryInformationFileList_Name(IN PUNICODE_STRING ObjectName)
{
	HANDLE FileHandle = NULL;
	ULONG Result = NULL;
	HANDLE Pid = NULL;
	NTSTATUS Status = NULL;
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile_XOR = { 0 };			//文件信息
	// 1. 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	ULONG             ulAttributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	InitializeObjectAttributes(
		&ObjectAttributes,								 // 返回初始化完毕的结构体
		ObjectName,										 // 文件对象名称
		ulAttributes,									 // 对象属性
		NULL, NULL);									 // 一般为NULL
	Pid = PsGetCurrentProcessId();
	//非白名单进程继续
	if (!Safe_QueryWhitePID(Pid))
	{
		Status = Safe_IoCreateFile(&ObjectAttributes, &FileHandle);
		if (Status == STATUS_GUARD_PAGE_VIOLATION)
		{
			Result = 1;
			return Result;
		}
		if (NT_SUCCESS(Status))
		{
			//获取文件信息
			Status = Safe_GetInformationFile(FileHandle, (ULONG)&System_InformationFile_XOR, KernelMode);
			if (NT_SUCCESS(Status))
			{
				//查询XOR在不在列表中
				if (Safe_QueryInformationFileList(
					System_InformationFile_XOR.IndexNumber_LowPart,
					System_InformationFile_XOR.u.IndexNumber_HighPart,
					System_InformationFile_XOR.VolumeSerialNumber))
				{
					Result = 1;
				}
			}
			ZwClose(FileHandle);
		}
	}
	return Result;
}