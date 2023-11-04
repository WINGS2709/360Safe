/*
1、Drvmk该文本保存360驱动加载白名单，只要往里添加该驱动信息，主动防御就不拦截
2、R0保存敏感操作的信息 Send  R3，R3发送个对话框让用户自行判断，放行or拦截然后把对应的信息写到列表中
*/
#include "DrvmkDataList.h"

//读取TextOutCache键值里的内容，该内容是一个路径指向xxx\\xxx\\xxx\\drvmk.dat
NTSTATUS NTAPI Safe_InitializeTextOutCacheList(IN PCWSTR In_Data, IN ULONG Type, IN ULONG DataLength, IN ULONG Flag)
{
	NTSTATUS       result,Status;
	HANDLE	       FileHandle = NULL;
	PVOID		   pBuffer = NULL;		// 指向g_Drvmk_List结构首地址
	ULONG          ulLength = NULL;		// 读取多少字节
	LARGE_INTEGER  ByteOffset = { 0 };	// 从哪里开始读取
	UNICODE_STRING ObjectNameString;
	FILE_STANDARD_INFORMATION FileStInformation = { 0 };
	result = STATUS_SUCCESS;
	//判断合法性
	if (Type == REG_SZ && DataLength && g_Drvmk_List)
	{
		pBuffer = g_Drvmk_List;
		//1. 初始化OBJECT_ATTRIBUTES的内容
		OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
		IO_STATUS_BLOCK IoStatusBlock = { 0 };
		RtlInitUnicodeString(&ObjectNameString, In_Data);
		InitializeObjectAttributes(&ObjectAttributes, &ObjectNameString, OBJ_CASE_INSENSITIVE, NULL, NULL);
		//2、打开Drvmk.dat文件
		Status = IoCreateFile(
			&FileHandle,
			GENERIC_READ | SYNCHRONIZE,
			&ObjectAttributes,
			&IoStatusBlock,
			0,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			0,
			0,
			CreateFileTypeNone,
			0,
			IO_NO_PARAMETER_CHECKING
			);
		if (!NT_SUCCESS(Status))
		{
			result = Status;
			return result;
		}
		//3、获取文件基本信息
		Status = ZwQueryInformationFile(FileHandle, &IoStatusBlock, (PVOID)&FileStInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (!NT_SUCCESS(Status) ||
			FileStInformation.EndOfFile.HighPart ||
			(ulLength = FileStInformation.EndOfFile.LowPart,			//后面ReadFile实际读取长度
			FileStInformation.EndOfFile.LowPart < 4)
			)
		{
			DbgPrint("Cannot Query File Size! %08X\n", Status);
			ZwClose(FileHandle);
			result = Status;
			return result;
		}
		//3、1 文件大于结构体总大小
		if (FileStInformation.EndOfFile.LowPart > (sizeof(SYS_BLACK_WHITE_DATA) - 4)	//这里-4是因为去掉KSPIN_LOCK  SpinLock的地址空间，图省事将它加进结构体
			)
		{
			//这里不可能成立的
			//超标按最大值算
			ByteOffset.LowPart = FileStInformation.EndOfFile.LowPart - (sizeof(SYS_BLACK_WHITE_DATA) - 4);
			ulLength = sizeof(SYS_BLACK_WHITE_DATA) - 4;
			FileStInformation.EndOfFile.LowPart = sizeof(SYS_BLACK_WHITE_DATA) - 4;
		}
		//4、 读取文件
		Status = ZwReadFile(
			FileHandle,    // 文件句柄
			NULL,          // 信号状态(一般为NULL)
			NULL, NULL,    // 保留
			&IoStatusBlock,// 接受函数的操作结果
			pBuffer,       // 保存读取数据的缓存
			ulLength,      // 想要读取的长度
			&ByteOffset,   // 读取的起始偏移
			NULL);         // 一般为NULL
		//5、 释放句柄
		ZwClose(FileHandle);
		if (!NT_SUCCESS(Status))
		{
			//将g_Drvmk_List结构清零释放
			g_Drvmk_List->ListNumber = 0;
			ExFreePool(g_Drvmk_List);
			result = Status;
			return result;
		}
		//6、正常结束，设置g_Drvmk_List->ListNumber的值
		g_Drvmk_List->ListNumber = (FileStInformation.EndOfFile.LowPart - 4) / sizeof(PE_HASH_DATA);
		result = STATUS_SUCCESS;
	}
	else
	{
		//错误返回
		result = STATUS_UNSUCCESSFUL;
	}
	return result;
}


//初始化链表，保存拦截和放行进程信息的（R3和R0交互）
VOID NTAPI Safe_Initialize_List()
{
	ULONG Tag = 0x206B6444;

	KeInitializeSpinLock(&g_request_list_lock);			//操作g_can_check_hook_request_list_added_by_r3和g_request_list
	InitializeListHead(&g_can_check_hook_request_list_added_by_r3);
	InitializeListHead(&g_request_list);

	KeInitializeSpinLock(&g_SpinLock_wait_info_list);
	InitializeListHead(&g_wait_info_list.list);
	
	//保存TextOutCache键值里的内容，该内容是一个路径指向xxx\\xxx\\xxx\\drvmk.dat
	//保存驱动的黑白名单
	g_Drvmk_List = Safe_AllocBuff(NonPagedPool, sizeof(SYS_BLACK_WHITE_DATA), Tag);
	if (!g_Drvmk_List)
	{
		return NULL;
	}
	KeInitializeSpinLock(&g_Drvmk_List->SpinLock);	//操作g_Drvmk_List使用
}

//************************************     
// 函数名称: Safe_QueryDrvmkDataList     
// 函数说明：查询黑白名单    
// IDA地址 ：
// 作    者：Mr.M      
// 返 回 值: ULONG NTAPI         
// 参    数: IN PPE_HASH_DATA In_QueryDrvmkData          [In]哈希值
//************************************ 
ULONG NTAPI Safe_QueryDrvmkDataList(IN PPE_HASH_DATA In_QueryDrvmkData)
{
	KIRQL NewIrql;
	ULONG Index = 0;						//下标索引
	ULONG DrvmkListNumber = 0;				//列表总个数
	ULONG Pass_Flag = 2;					//返回值：0拦截 1放行 2检查     默认是2
	DrvmkListNumber = g_Drvmk_List->ListNumber;

	//上锁
	NewIrql = KfAcquireSpinLock(&g_Drvmk_List->SpinLock);
	//判断名单个数
	if (DrvmkListNumber)
	{
		//循环查找是否存在
		for (Index = 0; Index < DrvmkListNumber; Index++)
		{
			if (RtlEqualMemory(In_QueryDrvmkData, &g_Drvmk_List->Pe_Hash_Data[Index], sizeof(PE_HASH_DATA) - sizeof(ULONG)))
			{
				//找到跳出循环
				break;
			}
		}
		if (Index >= DrvmkListNumber)
		{
			//找不到 失败返回
			Pass_Flag = 2;
		}
		else
		{
			//根据LoadDriver_Flag标识返回对应的值
			if (g_Drvmk_List->Pe_Hash_Data[Index].LoadDriver_Flag)
			{
				//1表示 拦截，所以返回0
				Pass_Flag = 0;
			}
			else
			{
				//0表示 放行，所以返回1
				Pass_Flag = 1;
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_Drvmk_List->SpinLock, NewIrql);
	return Pass_Flag;
}

//************************************     
// 函数名称: Safe_InsertDrvmkDataList     
// 函数说明：添加黑白名单    
// IDA地址 ：
// 作    者：Mr.M      
// 返 回 值: PVOID NTAPI         
// 参    数: IN PPE_HASH_DATA In_InsertDrvmkData          [In]哈希值
//************************************ 
PVOID NTAPI Safe_InsertDrvmkDataList(IN PPE_HASH_DATA In_InsertDrvmkData)
{
	KIRQL NewIrql;
	ULONG Index = 0;						//下标索引
	ULONG DrvmkListNumber = 0;				//列表总个数
	DrvmkListNumber = g_Drvmk_List->ListNumber;
	//上锁
	NewIrql = KfAcquireSpinLock(&g_Drvmk_List->SpinLock);
	//判断名单个数,并且个数 <= 0x270E
	if (DrvmkListNumber <= DRVMKNUMBER)
	{
		//1、新增插入  名单个数+1 
		//2、已存在    无视
		while (!RtlEqualMemory(In_InsertDrvmkData,&g_Drvmk_List->Pe_Hash_Data[Index], sizeof(PE_HASH_DATA)))
		{
			//假设是新的名单信息就插入
			if (Index >= DrvmkListNumber)
			{
				RtlCopyMemory(&g_Drvmk_List->Pe_Hash_Data[Index], In_InsertDrvmkData, sizeof(PE_HASH_DATA));
				//个数++
				g_Drvmk_List->ListNumber++;
				break;
			}
			else
			{
				//自增
				++Index;
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_Drvmk_List->SpinLock, NewIrql);
}

//************************************     
// 函数名称: Safe_DeleteDrvmkDataList     
// 函数说明：删除黑白名单    
// IDA地址 ：
// 作    者：Mr.M      
// 返 回 值: PVOID NTAPI         
//************************************ 
PVOID NTAPI Safe_DeleteDrvmkDataList(PPE_HASH_DATA In_DeleteDrvmkData)
{
	KIRQL NewIrql;
	ULONG Index = 0;						//下标索引
	ULONG DrvmkListNumber = 0;				//列表总个数
	DrvmkListNumber = g_Drvmk_List->ListNumber;
	//上锁
	NewIrql = KfAcquireSpinLock(&g_Drvmk_List->SpinLock);
	//判断名单个数
	if (DrvmkListNumber)
	{
		for (Index = 0; Index < DrvmkListNumber; Index++)
		{
			if (RtlEqualMemory(In_DeleteDrvmkData, &g_Drvmk_List->Pe_Hash_Data[Index], sizeof(PE_HASH_DATA)))
			{
				//清空退出进程的信息(后一个往前挪)
				for (ULONG i = Index; i <= DrvmkListNumber; i++)
				{
					RtlCopyMemory(&g_Drvmk_List->Pe_Hash_Data[Index], &g_Drvmk_List->Pe_Hash_Data[Index + 1], sizeof(PE_HASH_DATA));
				}
				//保护进程个数-1
				--g_Drvmk_List->ListNumber;
				break;
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_Drvmk_List->SpinLock, NewIrql);
}