/*
功能：
永恒之蓝的那个漏洞
替换SrvTransactionNotImplemented（0xE）
*/
#include "SrvTransactionNotImplemented.h"

//************************************     
// 函数名称: Safe_GetSrvTransaction2DispatchTable     
// 函数说明：动态定位到Srv.sys的SrvTransaction2DispatchTable地址    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/07/13     
// 返 回 值: ULONG NTAPI               [Out]SrvTransaction2DispatchTable的地址
// 参    数: IN PVOID pModuleBase      [In]srv.sys基地址
// 参    数: IN ULONG ModuleSize       [In]srv.sys大小
// 参    数: OUT ULONG * TimeDateStamp [Out]pNtH->FileHeader.TimeDateStamp
// 参    数: OUT ULONG * CheckSum      [Out]pNtH->OptionalHeader.CheckSum
//************************************
ULONG NTAPI Safe_GetSrvTransaction2DispatchTable(IN PVOID pModuleBase, IN ULONG ModuleSize, OUT ULONG* TimeDateStamp, OUT ULONG* CheckSum)
{
	PIMAGE_DOS_HEADER  			pDH = NULL;
	PIMAGE_NT_HEADERS			pNtH = NULL;
	PIMAGE_SECTION_HEADER		pSecHeader = NULL;
	ULONG					    OutSrvTransaction2DispatchTable = 0;   //输出：SrvTransaction2DispatchTable地址
	ULONG					    v17 = 0;
	ULONG						v21 = 0;							   //递增变量
	PULONG						pSrvTransaction2DispatchTable = NULL;
	//1、得到DOS头
	pDH = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}
	//2、得到NT头
	pNtH = (PIMAGE_NT_HEADERS)((PCHAR)pModuleBase + pDH->e_lfanew);
	if (pNtH->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}
	//3、得到节区首地址
	//得到第一个区段 =基地址 + pNtHeader->FileHeader.SizeOfOptionalHeader(E0) + 18（PE标志 + FileHeader）
	pSecHeader = (ULONG)pNtH + pNtH->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + sizeof(ULONG);
	//3、1 找到.data区段
	for (ULONG u_index = 0; u_index < pNtH->FileHeader.NumberOfSections; u_index++)
	{
		if (u_index <= pNtH->FileHeader.NumberOfSections)
		{
			if (_stricmp(pSecHeader->Name, ".data") == 0)
			{
				break;
			}
		}
		else
		{
			return FALSE;
		}
		//指向下一个区段
		pSecHeader++;
	}
	//4、保存.data区段的基本信息
	ULONG Rva_dataVirtualAddress = pSecHeader->VirtualAddress;
	ULONG dataVirtualSize = pSecHeader->Misc.VirtualSize;
	ULONG Va_dataVirtualAddress = Rva_dataVirtualAddress + (ULONG)pModuleBase;
	//5、判断地址合法性
	if (!MmIsAddressValid((PVOID)Va_dataVirtualAddress))
	{
		return FALSE;
	}
	//6、后面就是特征码定位到SrvTransaction2DispatchTable结构
	ULONG v16 = ((dataVirtualSize & 0xFFFFFFF8) - 0x4C) >> 3;
	if (!v16)
	{
		goto LABEL_27;
	}
	ULONG v18 = Va_dataVirtualAddress + 8;
	ULONG* v19 = (ULONG *)(Va_dataVirtualAddress + 0x50);
	ULONG VirtualAddressa = Va_dataVirtualAddress;
	while (!(VirtualAddressa & 0xFFF) && !MmIsAddressValid((PVOID)VirtualAddressa))
	{
		v21 += 0x1000;
		v19 += 0x2000;
		VirtualAddressa += 0x8000;
		v18 += 0x8000;
	LABEL_24:
		++v21;
		v19 += 2;
		VirtualAddressa += 8;
		v18 += 8;
		if (v21 >= v16)
		{
			goto LABEL_27;
		}
	}
	if (*(ULONG *)VirtualAddressa != 0xFEFEFEFE || *(ULONG *)(VirtualAddressa + 4) != 0xFEFEFEFE || *v19)		//0xFEFEFEFE,0xFEFEFEFE 后面就是pSrvTransaction2DispatchTable
	{
		goto LABEL_24;
	}
	//获取到了pSrvTransaction2DispatchTable地址，判断该地址数组的合法性
	pSrvTransaction2DispatchTable = v18;
	do
	{
		if (*pSrvTransaction2DispatchTable <= (ULONG)pModuleBase)
			break;
		if (*pSrvTransaction2DispatchTable > (ULONG)((ULONG)pModuleBase + ModuleSize))
			break;
		++v17;
		++pSrvTransaction2DispatchTable;
	} while (v17 < 5);
	if (v17 != 5)
		goto LABEL_24;
	OutSrvTransaction2DispatchTable = Va_dataVirtualAddress + 8 * v21 + 8;
LABEL_27:
	*TimeDateStamp = pNtH->FileHeader.TimeDateStamp;
	*CheckSum = pNtH->OptionalHeader.CheckSum;
	return OutSrvTransaction2DispatchTable;
}

//************************************     
// 函数名称: Safe_ReplaceSrvTransaction2DispatchTable     
// 函数说明：替换掉原始地址    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/03/21     
// 返 回 值: NTSTATUS NTAPI     
// 参    数: PVOID pModuleBase			                  [In]srv.sys基地址
// 参    数: ULONG ModuleSize			                  [In]srv.sys大小
// 参    数: ULONG TimeDateStamp                          [In]srv.sys文件创建信息
// 参    数: ULONG CheckSum                               [In]srv.sys文件校验和
// 参    数: PVOID OriginalSrvTransaction2DispatchTable   [In]srv.sys的SrvTransaction2DispatchTable原始地址
// 参    数: PVOID NewOriginalSrvTransaction2DispatchTable[In]srv.sys替换srv!SrvTransaction2DispatchTable的0x0e的fake地址
// 参    数：PUNICODE_STRING SrvSysPathString             [In]srv.sys路径:L"\\SystemRoot\\system32\\drivers\\srv.sys"
//************************************  
NTSTATUS NTAPI Safe_ReplaceSrvTransaction2DispatchTable(IN PVOID pModuleBase, IN ULONG ModuleSize, IN ULONG TimeDateStamp, IN ULONG CheckSum, IN PVOID OriginalSrvTransaction2DispatchTable, IN PVOID NewOriginalSrvTransaction2DispatchTable, IN PUNICODE_STRING SrvSysPathString)
{
	PIMAGE_DOS_HEADER  			pDH = NULL;
	PIMAGE_NT_HEADERS			pNtH = NULL;
	IO_STATUS_BLOCK				StatusBlock = { 0 };
	ULONG_PTR					ViewSize = NULL;
	HANDLE						FileHandle = NULL;
	HANDLE						SectionHandle = NULL;
	NTSTATUS					Status = STATUS_UNSUCCESSFUL;
	ULONG						BaseAddress = 0;
	ULONG						SEC_IMAGE = 0x1000000;
	ULONG						Mdl_VirtualAddress = 0;	//要MDL映射的地址
	volatile LONG *				Mdlv4_SrvTransaction2DispatchTableHookPoint = NULL;
	PMDL						MemoryDescriptorList = NULL;
	// 1. 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

	ULONG             ulAttributes =
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	InitializeObjectAttributes(
		&ObjectAttributes,								 // 返回初始化完毕的结构体
		SrvSysPathString,								 // 文件对象名称
		ulAttributes,									 // 对象属性
		NULL, NULL);									 // 一般为NULL
	//2、打开内核文件
	Status = ZwOpenFile(&FileHandle, FILE_READ_ATTRIBUTES, &ObjectAttributes, &StatusBlock, FILE_OPENED, FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	ObjectAttributes.ObjectName = NULL;
	//3、创建共享内存
	Status = ZwCreateSection(&SectionHandle, SECTION_MAP_EXECUTE_EXPLICIT, &ObjectAttributes, NULL, PAGE_READWRITE, SEC_IMAGE, FileHandle);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(FileHandle);
		return Status;
	}
	//4、创建内存映射文件
	Status = ZwMapViewOfSection(SectionHandle, NtCurrentProcess(), &BaseAddress, NULL, 0x1000, NULL, &ViewSize, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(SectionHandle);
		ZwClose(FileHandle);
		return Status;
	}
	//5、后面就是修复重定位操作
	//5、1：得到DOS头
	pDH = (PIMAGE_DOS_HEADER)BaseAddress;
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return STATUS_INVALID_SID;
	}
	//5、2：得到NT头
	pNtH = (PIMAGE_NT_HEADERS)((PCHAR)BaseAddress + pDH->e_lfanew);
	if (pNtH->Signature != IMAGE_NT_SIGNATURE)
	{
		return STATUS_INVALID_SID;
	}
	Status = STATUS_SUCCESS;
	//5、3：判断文件合法性，是否给修改过
	if (pNtH->FileHeader.TimeDateStamp == TimeDateStamp && pNtH->OptionalHeader.CheckSum == CheckSum)
	{
		//6、获取到数据目录表
		IMAGE_DATA_DIRECTORY* pDataDirectory = (IMAGE_DATA_DIRECTORY*)&pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		//6、1 重定位表判断合法性
		if (pDataDirectory->VirtualAddress && pDataDirectory->Size)
		{
			// 获取重定位表
			/*
			+-----------+
			|  重定位块  |
			+-----------+
			+-----------+
			|  重定位块  |
			+-----------+
			+-----------+
			|  重定位块  |
			+-----------+
			+-----------+
			|00000000000|
			+-----------+
			*/
			// 得到第一个重定位块的地址
			PIMAGE_BASE_RELOCATION pRelcationBlock =
				(PIMAGE_BASE_RELOCATION)(BaseAddress + pDataDirectory->VirtualAddress);
			// 最后一组重定位块信息必然是全零结尾
			while (pRelcationBlock->SizeOfBlock != 0)
			{
				ULONG uCount = (pRelcationBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(PTYPE);//本0x1000内，有多少需要重定位的地方
				ULONG uBaseRva = pRelcationBlock->VirtualAddress;     //本0x1000的起始位置
				PTYPE pType = (PTYPE)(pRelcationBlock + 1);
				for (int i = 0; i < uCount; i++)
				{
					/*
					Type的值对应以下宏:
					IMAGE_REL_BASED_ABSOLUTE (0) 使块按照32位对齐，位置为0。
					IMAGE_REL_BASED_HIGH (1) 高16位必须应用于偏移量所指高字16位。
					IMAGE_REL_BASED_LOW (2) 低16位必须应用于偏移量所指低字16位。
					IMAGE_REL_BASED_HIGHLOW (3) 全部32位应用于所有32位。
					IMAGE_REL_BASED_HIGHADJ (4) 需要32位，高16位位于偏移量，低16位位于下一个偏移量数组元素，组合为一个带符号数，加上32位的一个数，然后加上8000然后把高16位保存在偏移量的16位域内。
					IMAGE_REL_BASED_MIPS_JMPADDR (5) Unknown
					IMAGE_REL_BASED_SECTION (6) Unknown
					IMAGE_REL_BASED_REL32 (7) Unknown
					*/
					if (pType->Type == IMAGE_REL_BASED_HIGHLOW)
					{
						//uRvaData = 偏移 + 偏移所在的段地址
						ULONG  uRvaData = uBaseRva + pType->Offset;
						//最后再加上基地址
						PUCHAR pRelocPoint = (uRvaData + BaseAddress);
						if (*(USHORT *)(pRelocPoint - 3) == 0x14FF &&  *(pRelocPoint - 1) == 0x85u)
						{
							ULONG NewRelocPoint = (ULONG)pModuleBase + *(ULONG*)pRelocPoint - pNtH->OptionalHeader.ImageBase;
							if (NewRelocPoint == OriginalSrvTransaction2DispatchTable)
							{
								Mdl_VirtualAddress = (ULONG)pModuleBase + uRvaData;
								if (*(ULONG*)Mdl_VirtualAddress == OriginalSrvTransaction2DispatchTable)
								{
									break;
								}
								Mdl_VirtualAddress = 0;
							}
						}
						
					}
					pType++;
				}
				if (Mdl_VirtualAddress)
				{
					//找到了退出
					break;
				}
				pRelcationBlock = (PIMAGE_BASE_RELOCATION)((ULONG)pRelcationBlock + pRelcationBlock->SizeOfBlock);
			}
		}
		else
		{
			//失败返回
			Status = STATUS_INVALID_SID;
		}
	}
	else
	{
		Status = STATUS_IMAGE_CHECKSUM_MISMATCH;
	}
	//释放句柄
	if (BaseAddress)
	{
		ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
	}
	if (SectionHandle)
		ZwClose(SectionHandle);
	if (FileHandle)
		ZwClose(FileHandle);
	if (!Mdl_VirtualAddress)
	{
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}
	//获取地址正常，后面进行MDL映射然后hook操作
	Mdlv4_SrvTransaction2DispatchTableHookPoint = Safe_LockMemory(Mdl_VirtualAddress, sizeof(ULONG), (ULONG)&MemoryDescriptorList);
	if (Mdlv4_SrvTransaction2DispatchTableHookPoint)
	{
		//IATHook
		InterlockedExchange(Mdlv4_SrvTransaction2DispatchTableHookPoint, (LONG)NewOriginalSrvTransaction2DispatchTable);
	}
	if (MemoryDescriptorList)
	{
		Safe_RemoveLockMemory(MemoryDescriptorList);
	}
	return Status;
}

NTSTATUS NTAPI Fake_SrvTransactionNotImplemented_0xE(PVOID a1)
{
	LARGE_INTEGER CurrentTime;
	NTSTATUS(NTAPI *Original_SrvTransactionNotImplementedPtr)(PVOID);

	//1、判断是否被hook
	if ((ULONG)g_OriginalSrvTransaction2DispatchTable->srv_SrvTransactionNotImplemented != (ULONG)g_OriginalSrvTransactionNotImplementedPtr)
	{
		//触发拦截还是放行
		Safe_18A72_SendR3(PsGetCurrentProcessId(), PsGetCurrentThreadId(), 0x10);
		//执行完毕后，还原被hook的SrvSrvTransactionNotImplementedPtr函数
		g_OriginalSrvTransaction2DispatchTable->srv_SrvTransactionNotImplemented = g_OriginalSrvTransactionNotImplementedPtr;
		Original_SrvTransactionNotImplementedPtr = g_OriginalSrvTransaction2DispatchTable->srv_SrvTransactionNotImplemented;		//原始的
		//调用原始的
		return Original_SrvTransactionNotImplementedPtr(a1);
	}
	//调用原始的
	return g_OriginalSrvTransactionNotImplementedPtr(a1);
}

//永恒之蓝漏洞(CVE-2017-0144),替换srv!SrvTransaction2DispatchTable的0x0e
//dps srv!SrvTransaction2DispatchTable
BOOLEAN NTAPI Safe_HookSrvTransactionNotImplemented()
{
	PVOID 			pSrvSysModuleBase = NULL;
	ULONG 			SrvSysModuleSize = NULL;
	ULONG			TimeDateStamp = NULL;			//v14->FileHeader.TimeDateStamp;
	ULONG			CheckSum = NULL;				//v14->OptionalHeader.CheckSum;
	UNICODE_STRING  SrvSysPathString;
	UNICODE_STRING  SrvSysString;
	NTSTATUS		Status = STATUS_UNSUCCESSFUL;

	//0、如何定位到SrvTransaction2DispatchTable函数地址
	//1、判断版本合法性
	if (g_VersionFlag != WINDOWS_VERSION_XP
		&& g_VersionFlag != WINDOWS_VERSION_2K3
		&& g_VersionFlag != WINDOWS_VERSION_2K3_SP1_SP2
		&& g_VersionFlag != WINDOWS_VERSION_VISTA_2008
		&& g_VersionFlag != WINDOWS_VERSION_7
		&& g_VersionFlag != WINDOWS_VERSION_8_9200‬)
	{
		return FALSE;
	}
	
	//2、获取Srv.sys驱动基地址和大小
	RtlInitUnicodeString(&SrvSysString, L"srv.sys");
	if (!Safe_GetModuleBaseAddress(&SrvSysString, &pSrvSysModuleBase, &SrvSysModuleSize, 0))
	{
		return FALSE;
	}

	//3、获取SrvTransaction2DispatchTable函数地址
	//通过遍历PE结构；定位到.data区段，找到.data节后，最后进行内存搜索，根据SrvTransaction2DispatchTable的结构特征   0xFEFEFEFE，0xFEFEFEFE，SrvTransaction2DispatchTable
	g_OriginalSrvTransaction2DispatchTable = Safe_GetSrvTransaction2DispatchTable(pSrvSysModuleBase, SrvSysModuleSize, &TimeDateStamp, &CheckSum);
	//4、后面就是替换掉SrvTransaction2DispatchTable[0xE]原始函数
	RtlCopyMemory((VOID*)&g_MdlSrvTransaction2DispatchTable, (CONST VOID*)g_OriginalSrvTransaction2DispatchTable, sizeof(SRVTRANSACTION2DISPATCHTABLE));
	//保存原始的第0x0E项的函数地址
	g_OriginalSrvTransactionNotImplementedPtr = g_MdlSrvTransaction2DispatchTable.srv_SrvTransactionNotImplemented;
	//替换第0x0E项的函数地址为fake函数
	g_MdlSrvTransaction2DispatchTable.srv_SrvTransactionNotImplemented = Fake_SrvTransactionNotImplemented_0xE;
	//4、Mdlhook
	RtlInitUnicodeString(&SrvSysPathString, L"\\SystemRoot\\system32\\drivers\\srv.sys");
	Status = Safe_ReplaceSrvTransaction2DispatchTable(pSrvSysModuleBase, SrvSysModuleSize, TimeDateStamp, CheckSum, g_OriginalSrvTransaction2DispatchTable, (PVOID)&g_MdlSrvTransaction2DispatchTable, &SrvSysPathString);
	//5、判断是否hook失败
	if (!NT_SUCCESS(Status))
	{
		RtlZeroMemory((VOID*)&g_MdlSrvTransaction2DispatchTable, sizeof(SRVTRANSACTION2DISPATCHTABLE));
		return FALSE;
	}
	qword_38480.QuadPart = 0i64;
	return TRUE;
}
