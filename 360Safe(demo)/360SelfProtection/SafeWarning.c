/*
说明：
主动拦截提示时与应用层的通信交互，这部分代码我没看懂，直接抄大佬现成的
参考资料：
1、主动拦截提示时与应用层的通信交互 
网址：https://bbs.pediy.com/thread-144884.htm
*/
#include "SafeWarning.h"

//核对IRP的SessionId == 当前进程活动SessionId
//返回值：正常1，不正常0
BOOLEAN NTAPI Safe_is_irp_reqeust_from_local(PIRP Irp_a1)
{
	BOOLEAN Result = TRUE;
	ULONG PID = NULL;
	KIRQL NewIrql = NULL;
	ULONG Index = 0;
	ULONG SelfSessionId = NULL;
	NTSTATUS Status;
	ULONG uSessionId = NULL;
	UNICODE_STRING DestinationString;
	ULONG SpecialWhiteListNumber = 0;
	PVOID pSessionIDAddress = 0xFFDF02D8;	//Win10_14393以下版本一个固定地址可以获取到SessionId
	SpecialWhiteListNumber = g_SpecialWhite_List.SpecialWhiteListNumber;
	if (WINDOWS_VERSION_2K != g_VersionFlag)
	{
		PID = IoGetRequestorProcessId(Irp_a1);
		NewIrql = KfAcquireSpinLock(&g_SpecialWhite_List.SpinLock);
		if (SpecialWhiteListNumber)
		{
			while (g_SpecialWhite_List.SpecialWhiteListPID[Index] != PID || g_SpecialWhite_List.SpecialWhiteListSessionId[Index] != SPECIALSIGN)
			{
				if (++Index >= SpecialWhiteListNumber)
					goto LABEL_6;
			}
			//假设是特殊进程直接返回
			KfReleaseSpinLock(&g_SpecialWhite_List.SpinLock, NewIrql);
			Result = 1;
			return Result;
		}
	LABEL_6:
		//普通进程
		KfReleaseSpinLock(&g_SpecialWhite_List.SpinLock, NewIrql);
		if (pIoGetRequestorSessionId
			|| (RtlInitUnicodeString(&DestinationString, L"IoGetRequestorSessionId"),
			(pIoGetRequestorSessionId = MmGetSystemRoutineAddress(&DestinationString)) != 0))
		{
			//返回IRP发起者所在进程所属的SessionId
			Status = pIoGetRequestorSessionId(Irp_a1, &uSessionId);
			if (NT_SUCCESS(Status))
			{
				//获取自身SessionId
				if (g_dynData->pRtlGetActiveConsoleId_Win10_14393)
				{
					SelfSessionId = g_dynData->pRtlGetActiveConsoleId_Win10_14393();
					return SelfSessionId == uSessionId;
				}
				if (MmIsAddressValid(pSessionIDAddress))
				{
					SelfSessionId = *(ULONG*)pSessionIDAddress;
					return SelfSessionId == uSessionId;
				}
			}
		}
		Result = 1;
	}
	return Result;
}

PVOID NTAPI Safe_check_irp_request_in_list()
{
	//struct _LIST_ENTRY *v0; // esi@1

	//PIRP pIrp; // edi@4

	//struct _LIST_ENTRY *v2; // eax@7

	//struct _LIST_ENTRY *v3; // esi@7

	//PMDL pmdl; // eax@10

	//PVOID request_buffer1; // eax@11

	//unsigned int size; // esi@13

	//PMDL pMdl; // eax@13

	//KIRQL v8; // al@17

	//struct _LIST_ENTRY *v9; // esi@19

	//ULONG v10; // edi@19

	//struct _LIST_ENTRY *v11; // ecx@19

	//int result; // eax@22

	//IRP *v13; // [sp+Ch] [bp-14h]@8

	//unsigned int v14; // [sp+10h] [bp-10h]@13

	//void *request_buffer2; // [sp+14h] [bp-Ch]@13

	//ULONG copied_size; // [sp+18h] [bp-8h]@13

	//char v17; // [sp+1Eh] [bp-2h]@1

	//ULONG MaxSize = sizeof(QUERY_PASS_R0SENDR3_DATA) - sizeof(LIST_ENTRY);		//去掉前面LIST_ENTRY链表，后面的才是实际内容 长度是0x840 = 0x848(QUERY_PASS_R0SENDR3_DATA) - 0x8(LIST_ENTRY)

	//KIRQL i;
	//v0 = g_can_check_hook_request_list_added_by_r3.Flink;
	//for (i = KfAcquireSpinLock(&g_request_list_lock);
	//	!IsListEmpty(&g_can_check_hook_request_list_added_by_r3);
	//	i = KfAcquireSpinLock(&g_request_list_lock))
	//{
	//	if (IsListEmpty(&g_request_list))
	//	{
	//		break;
	//	}
	//	if (v0 == &g_can_check_hook_request_list_added_by_r3)
	//	{
	//		pIrp = v13;
	//	}
	//	else
	//	{
	//		while (1)

	//		{

	//			pIrp = (IRP *)&v0[-11];

	//			v13 = (IRP *)&v0[-11];

	//			if (InterlockedExchange((volatile LONG *)&v0[-4], 0))
	//			{
	//				break;
	//			}

	//			v0 = v0->Flink;

	//			if (v0 == &g_can_check_hook_request_list_added_by_r3)
	//			{
	//				goto LABEL_9;
	//			}

	//		}

	//		v2 = v0->Flink;

	//		v3 = v0->Blink;

	//		v3->Flink = v2;

	//		v2->Blink = v3;

	//		v17 = 1;

	//	}
	//LABEL_9:
	//	if (!v17)
	//	{
	//		break;
	//	}
	//	KfReleaseSpinLock(&g_request_list_lock, i);

	//	pmdl = pIrp->MdlAddress;

	//	request_buffer1 = pmdl->MdlFlags & 5 ? pmdl->MappedSystemVa : MmMapLockedPagesSpecifyCache(
	//		pmdl,
	//		0,
	//		MmCached,
	//		0,
	//		0,
	//		NormalPagePriority);

	//	copied_size = 0;

	//	request_buffer2 = request_buffer1;

	//	pMdl = pIrp->MdlAddress;

	//	size = pMdl->ByteCount;                     // 把所有的请求数据都复制到request_buffer2中  

	//	v14 = pMdl->ByteCount;

	//	if (size > 4)
	//	{
	//		*(ULONG *)request_buffer2 = 0;
	//	}
	//	//核对IRP的SessionId == 当前进程活动SessionId，返回值：正常1，不正常0
	//	if (Safe_is_irp_reqeust_from_local(pIrp))
	//	{
	//		v8 = KfAcquireSpinLock(&g_request_list_lock);
	//		if (IsListEmpty(&g_request_list))
	//		{
	//			break;
	//		}
	//		do
	//		{
	//			v9 = g_request_list.Flink->Flink;

	//			v10 = (ULONG)g_request_list.Flink;

	//			v11 = g_request_list.Flink->Blink;

	//			v11->Flink = g_request_list.Flink->Flink;

	//			v9->Blink = v11;

	//			--g_request_counter;

	//			KfReleaseSpinLock(&g_request_list_lock, v8);

	//			//去掉前面一个_LIST_ENTRY结构
	//			memcpy(request_buffer2, (VOID *)(v10 + 8), MaxSize);

	//			copied_size += MaxSize;

	//			request_buffer2 = (CHAR *)request_buffer2 + MaxSize;

	//			v14 -= MaxSize;

	//			ExFreePool((PVOID)v10);

	//			v8 = KfAcquireSpinLock(&g_request_list_lock);

	//			pIrp = v13;

	//		} while (v14 >= MaxSize);
	//		KfReleaseSpinLock(&g_request_list_lock, v8);
	//	}
	//	else
	//	{
	//		copied_size = size;
	//	}
	//	pIrp->IoStatus.Status = 0;

	//	pIrp->IoStatus.Information = copied_size;

	//	IofCompleteRequest(pIrp, 0);

	//	v0 = g_can_check_hook_request_list_added_by_r3.Flink;
	//}
	//KfReleaseSpinLock(&g_request_list_lock, i);
}

//************************************     
// 函数名称: Safe_push_request_in_and_waitfor_finish     
// 函数说明：    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：   
// 返 回 值: ULONG NTAPI             
// 0 正常返回（合法）
// 2 错误返回（不合法）
// 3 白名单保护进程（合法）
// 参    数: IN PQUERY_PASS_R0SENDR3_DATA In_pBuff     
// 参    数: IN ULONG In_Flag     
//************************************ 
ULONG NTAPI Safe_push_request_in_and_waitfor_finish(IN PQUERY_PASS_R0SENDR3_DATA In_pBuff, IN ULONG In_Flag)
{
	ULONG Result = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	KIRQL NewIrql = NULL;
	PLIST_ENTRY v5 = NULL;
	PLIST_ENTRY v7 = NULL;
	PLIST_ENTRY v8 = NULL;
	WAITFOR_INFO wait_info = { 0 };
	LARGE_INTEGER Timeout = { 0 };
	ULONG AddendMax = 0xA;
	//1、判断合法性
	if (g_Addend > AddendMax)
	{
		//错误返回
		Safe_ExFreePool(In_pBuff);
		Result = 2;
		return Result;
	}
	//2、假设是白名单进程直接返回
	if (Safe_QueryWhitePID(In_pBuff->CheckWhitePID) || !Safe_QuerySpecialWhiteSessionId())// 1、判断是不是白名单进程    2、判断特殊白名单进程SessionId是否等于当前进程的SessionId
	{
		//白名单进程
		Safe_ExFreePool(In_pBuff);
		Result = 3;
		return Result;
	}
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		return FALSE;
	}
	//3、非白名单进程
	NewIrql = KfAcquireSpinLock(&g_request_list_lock);
	v5 = g_request_list.Blink;
	In_pBuff->Entry.Blink = g_request_list.Blink;
	In_pBuff->Entry.Flink = &g_request_list;			// 插入链表操作  
	v5->Flink = (LIST_ENTRY *)In_pBuff;
	++g_request_counter;
	g_request_list.Blink = (LIST_ENTRY *)In_pBuff;
	KfReleaseSpinLock(&g_request_list_lock, NewIrql);
	//4、区分执行
	if (In_Flag)
	{
		wait_info.tid = PsGetCurrentThreadId();
		wait_info.bypass_or_not = 0;					//2是拦截，0和3通过
		KeInitializeEvent(&wait_info.Event, 0, 0);
		ExfInterlockedInsertTailList(&g_wait_info_list, &wait_info.list, &g_SpinLock_wait_info_list);
		Exfi386InterlockedIncrementLong(&g_Addend);
		Safe_check_irp_request_in_list();
		*(ULONGLONG *)&Timeout.QuadPart = -600000000i64 * g_Addend;
		Status = KeWaitForSingleObject(&wait_info.Event, 0, 0, 0, &Timeout);
		NewIrql = KfAcquireSpinLock(&g_SpinLock_wait_info_list);
		v7 = wait_info.list.Flink;
		v8 = wait_info.list.Blink;            // 把waitfor_info拆出来     
		wait_info.list.Blink->Flink = wait_info.list.Flink;
		v7->Blink = v8;
		--g_Addend;
		KfReleaseSpinLock(&g_SpinLock_wait_info_list, NewIrql);
		if (STATUS_TIMEOUT == Status)
		{
			Result = 2;
		}
		else
		{
			Result = wait_info.bypass_or_not;
		}

	}
	else
	{
		Safe_check_irp_request_in_list();
		Result = 0;
	}
	return Result;
}

//************************************     
// 函数名称: Safe_18A72_SendR3     
// 函数说明：主动防御提示与应用层通讯交互    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：   
// 返 回 值: PVOID NTAPI     
// 参    数: IN HANDLE In_PorcessID     
// 参    数: IN HANDLE In_ThreadID     
// 参    数: IN ULONG ProcessinfoclassIndex    
//           0x10：提示拦截蠕虫攻击（永恒之蓝）
//************************************ 
PVOID NTAPI Safe_18A72_SendR3(IN HANDLE In_PorcessID, IN HANDLE In_ThreadID, IN PROCESSINFOCLASS  ProcessInformationClass)
{
	//略，后续写交互代码再补充
}

//************************************     
// 函数名称: Safe_CheckSys_SignatureOrHash     
// 函数说明：检查驱动合法性   
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：   
// 返 回 值: NTSTATUS NTAPI     
// 参    数: IN HANDLE In_PorcessID                     [In]PsGetCurrentProcessId()
// 参    数: IN HANDLE In_ThreadID                      [In]PsGetCurrentThreadId()
// 参    数: IN PUNICODE_STRING In_pImagePathString     [In]该驱动路径
// 参    数: OUT PVOID Out_Hash                         [Out]计算后的哈希值
// 参    数: OUT ULONG Out_FileSize                     [Out]文件大小
// 参    数: OUT ULONG Out_PassFlag                     [Out]放行or拦截标识
// 参    数: IN ULONG In_Flag_a6                        [In]未知
//************************************  
NTSTATUS NTAPI Safe_CheckSys_SignatureOrHash(IN HANDLE In_PorcessID, IN HANDLE In_ThreadID, IN PUNICODE_STRING In_pImagePathString, OUT PVOID Out_Hash, OUT ULONG Out_FileSize, OUT ULONG Out_PassFlag, IN ULONG In_Flag_a6)
{
	NTSTATUS                  result = STATUS_SUCCESS;
	NTSTATUS	              Status = STATUS_SUCCESS;
	HANDLE                    FileHandle = NULL;
	IO_STATUS_BLOCK	          StatusBlock = { 0 };
	ULONG                     KeyBuff[0x50] = { 0 };
	SIZE_T					  ulLength = NULL;		   // new多少字节
	PVOID                     pBuff = NULL;			   // new空间
	ULONG                     Tag = 0x206B6444u;
	FILE_STANDARD_INFORMATION FileStInformation = { 0 };
	//1. 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	InitializeObjectAttributes(&ObjectAttributes, In_pImagePathString, OBJ_CASE_INSENSITIVE, NULL, NULL);
	//2、打开文件
	Status = ZwOpenFile(&FileHandle, FILE_READ_ATTRIBUTES, &ObjectAttributes, &StatusBlock, FILE_DOES_NOT_EXIST, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(Status))
	{
		goto _FunctionRet;
	}
	//3、获取文件基本信息
	Status = ZwQueryInformationFile(FileHandle, &IoStatusBlock, (PVOID)&FileStInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	//3、1 判断合法性
	if (!NT_SUCCESS(Status) || (FileStInformation.EndOfFile.QuadPart > 0x6400000ui64) || !(FileStInformation.EndOfFile.QuadPart))
	{
		DbgPrint("Cannot Query File Size! %08X\n", Status);
		goto _FunctionRet;
	}
	//3、2 new同等空间
	ulLength = FileStInformation.EndOfFile.LowPart;
	pBuff = Safe_AllocBuff(PagedPool, ulLength, Tag);
	if (!pBuff)
	{
		Status = STATUS_UNSUCCESSFUL;
		goto _FunctionRet;
	}
	//4、 读取文件
	Status = ZwReadFile(
		FileHandle,    // 文件句柄
		NULL,          // 信号状态(一般为NULL)
		NULL, NULL,    // 保留
		&IoStatusBlock,// 接受函数的操作结果
		pBuff,         // 保存读取数据的缓存
		ulLength,      // 想要读取的长度
		NULL,		   // 读取的起始偏移
		NULL);         // 一般为NULL
	if (!NT_SUCCESS(Status))
	{
		goto _FunctionRet;
	}
	//检查签名的代码我没分析略
	//略
	//合法签名直接退出，返回值Out_PassFlag = 1
	//不合法签名二次校验，查询是否在列表中
	//5、后面几步就是计算该PE文件的哈希值操作
	//Safe_14F7C_Hash(KeyBuff);
	//Safe_15846_Hash(KeyBuff, pBuff, ulLength);
	//Safe_158F8_Hash(Out_Hash, KeyBuff);
	//6、查询列表中是否存在
	*(ULONG*)Out_PassFlag = Safe_QueryDrvmkDataList(Out_Hash, ulLength);
	*(ULONG*)Out_FileSize = ulLength;
_FunctionRet:
	result = Status;
	if (pBuff)
	{
		ExFreePool(pBuff);
		pBuff = NULL;
	}
	if (FileHandle)
	{
		ZwClose(FileHandle);
		FileHandle = NULL;
	}
	return result;
}
//************************************     
// 函数名称: Safe_1D044_SendR3     
// 函数说明：主动防御提示与应用层通讯交互    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：   
// 返 回 值: NTSTATUS NTAPI     
// 参    数: IN HANDLE In_PorcessID     
// 参    数: IN HANDLE In_ThreadID     
// 参    数: IN ULONG  In_Flag     
// 参    数: IN PUNICODE_STRING In_ImagePathString     
//************************************  
NTSTATUS NTAPI Safe_1D044_SendR3(IN HANDLE In_PorcessID, IN HANDLE In_ThreadID, IN ULONG In_Flag, IN PUNICODE_STRING In_ImagePathString)
{
	PQUERY_PASS_R0SENDR3_DATA  pQuery_Pass = NULL;
	NTSTATUS                   result = STATUS_SUCCESS;
	NTSTATUS                   Status = STATUS_SUCCESS;
	ULONG                      Flag_v4 = NULL;
	ULONG                      Pass_Flag = NULL;				//判断是否放行  0错误   1放行    2第一次进入检查
	ULONG                      SpecialWhiteNumber = NULL;		//必须有R3交互界面才继续执行，否则后面发拦截信息给R3就没必要了
	ULONG                      uHash[0x10] = { 0 };				//保存哈希值
	ULONG                      FileSize = 0;					//文件大小
	ULONG                      Flag_v16 = NULL;					//保存R3用户返回的结果
	ULONG                      Tag = 0x206B6444;
	SpecialWhiteNumber = g_SpecialWhite_List.SpecialWhiteListNumber;
	//1、判断合法性
	if (Flag_v4 == 6 || !SpecialWhiteNumber)
	{
		Flag_v4 = 0;
	}
	//默认置1
	if (!g_Regedit_Data.g_SpShadow0_Data_DWORD)
	{
		return result;
	}
	//2、判断该驱动的合法性例如：签名、白名单等等
	Status = Safe_CheckSys_SignatureOrHash(In_PorcessID, In_ThreadID, In_ImagePathString, &uHash, &FileSize, &Pass_Flag, Flag_v4);
	if (NT_SUCCESS(Status))
	{
		//3、必须有R3交互界面才继续执行，否则后面发拦截信息给R3就没必要了
		if (SpecialWhiteNumber)
		{
			//0错误   1放行    2正常执行流程（要检查的）
			switch (Pass_Flag)
			{
				case 0:		//拦截进程 返回错误值即可
				{			
					result = STATUS_ACCESS_DENIED;
					break;
				}
				case 1:		//白名单进程 正常返回 STATUS_SUCCESS
				{		
					result = STATUS_SUCCESS;
					break;
				}
				case 2:		//检查的流程
				{
					//3、1 new空间，保存传递给R3的进程数据
					pQuery_Pass = (PQUERY_PASS_R0SENDR3_DATA)Safe_AllocBuff(NonPagedPool, sizeof(QUERY_PASS_R0SENDR3_DATA), Tag);
					if (pQuery_Pass)
					{

						//填充内容，后续发送R3弹对话框，让用户决定 放行or拦截
						pQuery_Pass->CheckWhitePID = In_PorcessID;
						pQuery_Pass->Unknown_CurrentThreadId_4 = In_ThreadID;
						pQuery_Pass->Unknown_CurrentThreadId_5 = PsGetCurrentThreadId();
						pQuery_Pass->Hash[0] = uHash[0];
						pQuery_Pass->Hash[1] = uHash[1];
						pQuery_Pass->Hash[2] = uHash[2];
						pQuery_Pass->Hash[3] = uHash[3];
						pQuery_Pass->Unknown_Flag_6 = 1;
						pQuery_Pass->Unknown_Flag_830 = In_Flag;
						pQuery_Pass->FileSize = FileSize;
						pQuery_Pass->Unknown_Flag_2 = 2;
						//字符串最大长度应该不超过520吧，一般大于520个长度的路径直接无视算了
						if (In_ImagePathString->Length < 520)
						{
							RtlCopyMemory(pQuery_Pass->ImagePathBuff, In_ImagePathString->Buffer, In_ImagePathString->Length);
						}
						//发送消息给R3
						//Flag_v16 = Safe_push_request_in_and_waitfor_finish(pQuery_Pass, 1);
						//根据R3的返回值做出对应操作
						if (Flag_v16 == 0)				//添加白名单进程列表，并正常返回
						{
							Safe_InsertDrvmkDataList(uHash, FileSize, 0);
							result = STATUS_SUCCESS;
						}
						else if (Flag_v16 == 1)			//添加黑名单进程列表，并返回错误值
						{
							Safe_InsertDrvmkDataList(uHash, FileSize, 1);
							result = STATUS_ACCESS_DENIED;
						}
						else if (Flag_v16 == 2)			//直接返回错误值
						{
							result = STATUS_ACCESS_DENIED;
						}
						else                            //直接正常返回
						{
							result = STATUS_SUCCESS;
						}
						//处理完毕释放
						if (pQuery_Pass)
						{
							ExFreePool(pQuery_Pass);
							pQuery_Pass = NULL;
						}
					}
					break;
				}
				default:
				{
					break;
				}
			}
		}
	}
	return result;
}
