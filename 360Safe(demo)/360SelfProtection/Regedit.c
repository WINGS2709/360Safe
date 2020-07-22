/*
参考资料：
1、Windows服务: ControlSet001 , ControlSet002 , CurrentControlSet区别 
网址：https://blog.csdn.net/qq_27445903/article/details/89878768
*/
#include "Regedit.h"

//这个->Data读取的是REG_SZ类型的
NTSTATUS NTAPI Safe_SetRegedit_RULE_360Safe(IN PCWSTR Data, IN ULONG Type, IN ULONG DataLength, IN ULONG Flag)
{
	ULONG DataMaxSize = DOSPATHSIZE;
	//判断字节长度
	if (DataLength < DataMaxSize)
	{
		//保存data
		//保存drvmk.dat路径
		RtlCopyMemory(g_Regedit_Data.g_360Safe_REG_SZ, Data, DataLength);
		//设置标志位置1
		g_Regedit_Data.Flag.RULE_360u_Flag = 1;
	}
	return 0;
}

//这个->Data读取的是REG_SZ类型的
NTSTATUS NTAPI Safe_SetRegedit_TextOutCache(IN PCWSTR Data, IN ULONG Type, IN ULONG DataLength, IN ULONG Flag)
{
	ULONG DataMaxSize = DOSPATHSIZE;
	//判断字节长度
	if (DataLength < DataMaxSize)
	{
		//保存data
		//保存drvmk.dat路径
		RtlCopyMemory(g_Regedit_Data.g_TextOutCache_REG_SZ, Data, DataLength);
		//设置标志位置1
		g_Regedit_Data.Flag.RULE_TextOutCache_Flag = 1;
	}
	return Safe_InitializeTextOutCacheList(Data, Type, DataLength, Flag);
}
//这个->Data读取的是REG_DWORD类型的
NTSTATUS NTAPI Safe_SetRegedit_i18h(IN ULONG *Data, IN ULONG Type, IN ULONG DataLength, IN ULONG Flag)
{
	NTSTATUS result; // eax@3

	if (Type != REG_DWORD || DataLength != sizeof(ULONG))
	{
		result = STATUS_UNSUCCESSFUL;
	}
	else
	{
		g_Regedit_Data.g_i18n_Data_DWORD = *Data;
		result = 0;
	}
	return result;
}

//这个->Data读取的是REG_DWORD类型的
NTSTATUS NTAPI Safe_SetRegedit_DisableDPHotPatch(IN ULONG *Data, IN ULONG Type, IN ULONG DataLength, IN ULONG Flag)
{
	NTSTATUS result; // eax@3

	if (Type != REG_DWORD || DataLength != sizeof(ULONG))
	{
		result = STATUS_UNSUCCESSFUL;
	}
	else
	{
		if (*Data)
		{
			g_HookSrvTransactionNotImplementedFlag = 1;
		}
		result = 0;
	}
	return result;
}

//这个->Data读取的是REG_DWORD类型的
NTSTATUS NTAPI Safe_SetRegedit_SpShadow0(IN ULONG *Data, IN ULONG Type, IN ULONG DataLength, IN ULONG Flag)
{
	NTSTATUS result; // eax@3

	if (Type != REG_DWORD || DataLength != sizeof(ULONG))
	{
		result = STATUS_UNSUCCESSFUL;
	}
	else
	{
		g_Regedit_Data.g_SpShadow0_Data_DWORD = *Data;
		result = 0;
	}
	return result;
}

//************************************     
// 函数名称: Safe_RPCDispatcher     
// 函数说明：根据服务类型做不同的处理   
// 根据大数字源码得到一组公式：
// 服务类型：InSendMessage（参数3） + MessageType_Offset
// 驱动长度：InSendMessage（参数3） + ServiceName_Offset + 0x4C（固定值）
// 驱动名字：InSendMessage（参数3） + ServiceName_Offset + 0x58（固定值）
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：    
// 返 回 值: NTSTATUS NTAPI     
// 参    数: IN PVOID In_SendMessage     
// 参    数: IN HANDLE In_PortHandle     
//************************************  
NTSTATUS NTAPI Safe_RPCDispatcher(IN PVOID In_SendMessage, IN HANDLE In_PortHandle)
{
	NTSTATUS         Status = STATUS_SUCCESS;
	NTSTATUS	     Result = STATUS_SUCCESS;
	SIZE_T           AppendData_Offset = 0;						//通信附加数据起始地址(根据版本变化)
	SIZE_T           Type_Offset = 0;							//服务类型偏移(根据版本变化)
	SIZE_T           ServiceName_Offset = 0;					//驱动名称偏移(根据版本变化)
	UNICODE_STRING   NtsvcsString = { 0 };						//\\RPC Control\\ntsvcs
	UNICODE_STRING   DhcpcsvcString = { 0 };					//\\RPC Control\\dhcpcsvc
	USHORT           MessageType = NULL;						//服务类型
	USHORT           MessageFlag = NULL;						//服务类型特征（低版本生效）
	RtlInitUnicodeString(&NtsvcsString, L"\\RPC Control\\ntsvcs");
	RtlInitUnicodeString(&DhcpcsvcString, L"\\RPC Control\\dhcpcsvc");
	//1、根据版本获取对应偏移
	if (g_VersionFlag == WINDOWS_VERSION_XP)
	{
		//WinXp
		AppendData_Offset = 0x20;
		Type_Offset = 0x1E;
	}
	else
	{
		//其他版本无视
		if (!g_Win2K_XP_2003_Flag)
		{
			return Result;
		}
		//到这里都是Win7 or Win7+
		AppendData_Offset = 0x2E;
		Type_Offset = 0x2C;
		ServiceName_Offset = 0x20;
	}
	__try
	{
		//判断参数合法性
		ProbeForRead(In_SendMessage, AppendData_Offset, sizeof(CHAR));
		MessageType = *(USHORT*)((UCHAR*)In_SendMessage + Type_Offset);							//服务类型（API函数）
		MessageFlag = *(USHORT*)((UCHAR*)In_SendMessage + Type_Offset - sizeof(USHORT));		//低版本生效，win7以上（这个判断作废）
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return Result;
	}
	//2、处理感兴趣的部分（其他部分不处理）：
	//1、services建立的服务端口名是 \\RPC Control\\ntsvcs
	//2、\\RPC Control\\dhcpcsvc
	if (Safe_CmpPortName(In_PortHandle, &NtsvcsString))
	{
		//Xp都是基本都是0x241,Win7没有
		//不知道这个具体含义是什么
		if (!g_Win2K_XP_2003_Flag && (MessageFlag & 0x240) != 0x240)
		{
			return Result;
		}
		//3、StartService 获取真实加载驱动意图者进程ID
		if (MessageType == STARTSERVICEA_TYPE || MessageType == STARTSERVICEW_TYPE)
		{
			g_SourceDrivenLoad_CurrentProcessId = PsGetCurrentProcessId();
			g_SourceDrivenLoad_CurrentThreadId = PsGetCurrentThreadId();
		}
		//4、
		if (MessageType == OPENSERVICEW_TYPE)
		{
			//禁止打开敏感驱动服务(降权)
		}
		if (MessageType == OPENSERVICEA_TYPE)
		{
			//禁止打开敏感驱动服务(降权)
		}
	}
	else if (Safe_CmpPortName(In_PortHandle, &DhcpcsvcString))
	{
		//略，不感兴趣直接无视
	}
	else
	{
		//找不到则退出了
	}
	return Result;
}

//比较指定Port名字的object，相同1，不同0
BOOLEAN NTAPI Safe_CmpObReferenceObjectByName(PUNICODE_STRING In_CmpPortName,PVOID In_Object)
{
	PVOID       Object = NULL;
	NTSTATUS    Status = STATUS_SUCCESS;
	BOOLEAN		Result = FALSE;							//匹配返回：真
	Status = ObReferenceObjectByName(In_CmpPortName, NULL, NULL, GENERIC_READ, g_ObjectType, NULL, NULL, &Object);
	if (NT_SUCCESS(Status))
	{
		Result = Object == In_Object;
		//解引用
		ObfDereferenceObject(Object);
		Object = NULL;
	}
	else
	{
		Result = FALSE;
	}
	return Result;
}
//************************************     
// 函数名称: Safe_CmpPortName     
// 函数说明：比较Port名字，相同1，不同0    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/07/06     
// 返 回 值: BOOLEAN NTAPI     
// 参    数: IN HANDLE In_PortHandle              打开端口的句柄
// 参    数: IN PUNICODE_STRING In_CmpPortName    要比较的名字  
//************************************  
BOOLEAN NTAPI Safe_CmpPortName(IN HANDLE In_PortHandle, IN PUNICODE_STRING In_CmpPortName)
{
	NTSTATUS    Status = STATUS_SUCCESS;
	BOOLEAN		Result = FALSE;							//匹配返回：真
	ULONG       Tag = 0x206B6444u;
	PVOID       pLPCProt = NULL;
	PVOID       LPCProt_v2 = NULL;
	PVOID       Object_v5 = NULL;
	UNICODE_STRING  ObGetObjectTypeString;
	//1、过滤掉无用信息
	if ((g_Win2K_XP_2003_Flag || !Safe_QueryObjectType(In_PortHandle, L"Port"))//Win7
		&& (g_Win2K_XP_2003_Flag != TRUE || !Safe_QueryObjectType(In_PortHandle, L"ALPC Port"))//低版本
		)
	{
		return Result;
	}
	Status = ObReferenceObjectByHandle(In_PortHandle, NULL, NULL, UserMode,&pLPCProt, NULL);//获取对象
	if (!NT_SUCCESS(Status))
	{
		return Result;
	}
	//2、根据版本获取object_Type
	if (g_VersionFlag == WINDOWS_VERSION_XP)
	{
		//Xp
		LPCProt_v2 = pLPCProt;
		if (!g_ObjectType)
		{
			g_ObjectType = *(ULONG*)((PVOID*)pLPCProt - 4);            // _OBJECT_TYPE
			if (!g_ObjectType)
			{
				//失败退出
				Result = FALSE;
				goto _FunctionRet;
			}
		}
	}
	else
	{
		//非2k版本继续执行
		if (g_VersionFlag != WINDOWS_VERSION_2K)
		{
			if (!g_Win2K_XP_2003_Flag)
			{
				//失败退出
				Result = FALSE;
				goto _FunctionRet;
			}
			//Object_v5 = 
			//调用ObGetObjectType（Win7）或则低版本 偏移获取
			if (!g_ObjectType)
			{
				if (g_VersionFlag == WINDOWS_VERSION_VISTA_2008 || g_VersionFlag == WINDOWS_VERSION_2K3_SP1_SP2)
				{
					g_ObjectType = *(ULONG*)((PVOID*)pLPCProt - 4);            // _OBJECT_TYPE
				}
				else
				{
					//无效版本
					if (g_VersionFlag != WINDOWS_VERSION_7 &&
						g_VersionFlag != WINDOWS_VERSION_8_9200‬ &&
						g_VersionFlag != WINDOWS_VERSION_8_9600 &&
						g_VersionFlag != ‬WINDOWS_VERSION_10)
					{
						//失败退出
						Result = FALSE;
						goto _FunctionRet;
					}
					if (g_dynData->pObGetObjectType)
					{
						g_ObjectType = g_dynData->pObGetObjectType(pLPCProt);// _OBJECT_TYPE
					}
				}
				if (!g_ObjectType)
				{
					//失败退出
					Result = FALSE;
					goto _FunctionRet;
				}
			}
			Object_v5 = *(ULONG*)((PVOID*)pLPCProt + 2);
			if (*(ULONG*)Object_v5)
			{
				//相同返回1，不同0
				Result = Safe_CmpObReferenceObjectByName(In_CmpPortName, *(ULONG*)Object_v5);
				goto _FunctionRet;
			}
			else
			{
				//失败退出
				Result = FALSE;
				goto _FunctionRet;
			}
		}
		if (!g_ObjectType)
		{
			g_ObjectType = *(ULONG*)((PVOID*)pLPCProt - 4);            // _OBJECT_TYPE
			if (!g_ObjectType)
			{
				//失败退出
				Result = FALSE;
				goto _FunctionRet;
			}
		}
		LPCProt_v2 = *(ULONG*)((PVOID*)pLPCProt + 2);
	}
	if (*(ULONG*)LPCProt_v2)
	{
		Result = Safe_CmpObReferenceObjectByName(In_CmpPortName, *(ULONG*)LPCProt_v2);
	}
	_FunctionRet:
	//解引用
	if (pLPCProt)
	{
		ObfDereferenceObject(pLPCProt);
		pLPCProt = NULL;
	}
	return Result;
}

//************************************     
// 函数名称: Safe_QuerRegedit     
// 函数说明：    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：    
// 返 回 值: BOOLEAN NTAPI     
// 参    数: IN PUNICODE_STRING ObjectName        
// 参    数: IN PCWSTR ValueName     
// 参    数: IN ULONG Func     
// 参    数: IN ULONG Flag     
//************************************ 
BOOLEAN NTAPI Safe_QuerRegedit(IN PUNICODE_STRING ObjectName, IN PCWSTR ValueName, IN ULONG Func, IN ULONG Flag)
{
	NTSTATUS Status;
	HANDLE KeyHandle;
	ULONG ResultLength;
	UNICODE_STRING ValueNameString;
	PKEY_VALUE_PARTIAL_INFORMATION pBuff_v5=NULL;
	ULONG Tag = 0x206B6444;
	ULONG (NTAPI *GeneralFunc)(CHAR*, ULONG, ULONG, ULONG);
	GeneralFunc = Func;
	// 1. 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	ULONG             ulAttributes =
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	InitializeObjectAttributes(
		&ObjectAttributes,								 // 返回初始化完毕的结构体
		ObjectName,										 // 文件对象名称
		ulAttributes,									 // 对象属性
		NULL, NULL);									 // 一般为NULL
	Status = ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &ObjectAttributes);
	if (NT_SUCCESS(Status))
	{
		RtlInitUnicodeString(&ValueNameString, ValueName);
		//读取注册表键的值(获取实际大小，后续方便new)
		Status = ZwQueryValueKey(KeyHandle, &ValueNameString, KeyValuePartialInformation, 0, 0, &ResultLength);
		//分配需要的空间, ZwQueryValueKey 的第4个参数可以获得需要的长度
		pBuff_v5 = (PKEY_VALUE_PARTIAL_INFORMATION)Safe_AllocBuff(NonPagedPool, ResultLength, Tag);
		if ((Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW)
			&& ResultLength
			&& pBuff_v5
			)
		{
			//查询键值
			Status = ZwQueryValueKey(KeyHandle, &ValueNameString, KeyValuePartialInformation, pBuff_v5, ResultLength, &ResultLength);
			ZwClose(KeyHandle);
			if (NT_SUCCESS(Status))
			{
				Status = GeneralFunc(pBuff_v5->Data, pBuff_v5->Type, pBuff_v5->DataLength, Flag);
				ExFreePool(pBuff_v5);
				return Status;
			}
			ExFreePool(pBuff_v5);
		}
		else
		{
			ZwClose(KeyHandle);
		}
	}
	return FALSE;
}


//初始化注册表信息的
BOOLEAN NTAPI Safe_Initialize_RegeditData(IN PUNICODE_STRING ObjectName, IN ULONG Flag)
{
	NTSTATUS result;
	result = STATUS_UNSUCCESSFUL;
	return result;
}

//获取注册表Control路径
//这个路径可以遍历驱动进程
NTSTATUS NTAPI Safe_GetControlSet00XPath()
{
	NTSTATUS Result;
	HANDLE KeyHandle = NULL;
	UNICODE_STRING ObjectNameString;
	UNICODE_STRING  Valuename;
	ULONG ResultLength;
	KEY_VALUE_PARTIAL_INFORMATION KeyValueInformation = { 0 };
	RtlZeroMemory(g_RegServicePath, sizeof(g_RegServicePath));
	Result = STATUS_UNSUCCESSFUL;
	// 1. 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	RtlInitUnicodeString(&ObjectNameString, L"\\Registry\\Machine\\System\\Select");
	InitializeObjectAttributes(&ObjectAttributes, &ObjectNameString, OBJ_CASE_INSENSITIVE, NULL, NULL);
	Result = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
	if (NT_SUCCESS(Result));
	{
		//CurrentControlSet：运行时配置
		//ControlSet001：系统真实的配置信息
		//ControlSet002：最近一次成功启动的配置信息
		//2、获取current的值
		RtlInitUnicodeString(&Valuename, L"Current");
		Result = ZwQueryValueKey(KeyHandle, &Valuename, KeyValuePartialInformation, &KeyValueInformation, sizeof(KeyValueInformation), &ResultLength);
		if (NT_SUCCESS(Result)
			&& KeyValueInformation.Type == REG_DWORD
			&& KeyValueInformation.DataLength == sizeof(ULONG)
			)
		{
			//3、拼接字符串
			Result = RtlStringCbPrintfW(&g_RegServicePath, sizeof(g_RegServicePath), L"\\Registry\\Machine\\SYSTEM\\ControlSet00%d\\services", KeyValueInformation.Data[0]);
			if (NT_SUCCESS(Result))
			{
				RtlInitUnicodeString(&g_ControlSet00XPath, g_RegServicePath);
			}
		}
		ZwClose(KeyHandle);
	}
	return Result;
}

//获取注册表KeyValueFullInformation信息
//返回值：KeyValueFullInformation地址
PVOID NTAPI Safe_GetKeyValueFullInformation(IN HANDLE In_KeyHandle, IN PUNICODE_STRING ValueName)
{
	NTSTATUS Status;
	PKEY_VALUE_FULL_INFORMATION pBuff_v3 = NULL;
	HANDLE KeyHandle = NULL;
	ULONG ResultLength = NULL;
	ULONG Tag = 0x206B6444;
	ULONG Flag = TRUE;							//In_KeyHandle有值，Flag = False,该函数内不释放句柄，留着后续自行释放
												//In_KeyHandle无值，Flag = TRUE,该函数内释放句柄
	// 1. 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	UNICODE_STRING ObjectNameString;
	RtlInitUnicodeString(&ObjectNameString, L"\\Registry\\Machine\\System\\CurrentControlSet\\Control");
	InitializeObjectAttributes(&ObjectAttributes, &ObjectNameString, OBJ_CASE_INSENSITIVE, NULL, NULL);
	//2、判断句柄类型
	if (In_KeyHandle)
	{
		KeyHandle = In_KeyHandle;
		Flag = FALSE;
	}
	else
	{
		Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
		if (!NT_SUCCESS(Status))
		{
			return 0;
		}
		Flag = TRUE;
	}
	//3、读取注册表键的值
	Status = ZwQueryValueKey(KeyHandle, ValueName, KeyValueFullInformation, 0, 0, &ResultLength);
	if (Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW)
	{
		if (Flag && KeyHandle)
		{
			ZwClose(KeyHandle);
		}
		return 0;
	}
	//分配需要的空间, ZwQueryValueKey 的第4个参数可以获得需要的长度,分配大一点防止溢出
	pBuff_v3 = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength * 0x4, Tag);
	if (!pBuff_v3)
	{
		if (Flag && KeyHandle)
		{
			ZwClose(KeyHandle);
		}
		return 0;
	}
	//查询键值
	Status = ZwQueryValueKey(KeyHandle, ValueName, KeyValueFullInformation, pBuff_v3, ResultLength, &ResultLength);
	if (Flag && KeyHandle)
	{
		ZwClose(KeyHandle);
		KeyHandle = NULL;
	}
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(pBuff_v3);
		return 0;
	}
	return pBuff_v3;
}

//查询各种白名单注册表键值是否存在例如各种：RULE_360xxxx之类的
NTSTATUS NTAPI Safe_EnumerateValueKey(IN PUNICODE_STRING ObjectName, IN ULONG Flag)
{
	NTSTATUS       result, Status;
	KIRQL		   NewIrql = NULL;
	ULONG          SubkeyIndex = NULL;			//每次++偏移下一个注册表子项
	HANDLE         KeyHandle = NULL;
	ULONG          ResultLength = NULL;			//ZwEnumerateValueKey函数的返回值，用来判断后续需要new几个字节
	ULONG          Flagb = 0;
	ULONG		   Tag = 0x206B6444u;
	PKEY_VALUE_BASIC_INFORMATION pKeyValueBasicInformation = NULL;
	result = STATUS_SUCCESS;
	//1、初始化先清零
	if (Flag)
	{
		//加锁
		NewIrql = KfAcquireSpinLock(&g_White_List.SpinLock);
		//白名单进程清零
		g_White_List.WhiteListNumber = 0;
		//解锁
		KfReleaseSpinLock(&g_White_List.SpinLock, NewIrql);
	}
	//2、各种结构体初始化清零
	//加锁
	NewIrql = KfAcquireSpinLock(&g_All_InformationFile_CRC->SpinLock);
	g_All_InformationFile_CRC->FileCRCListNumber = 0;
	//解锁
	KfReleaseSpinLock(&g_All_InformationFile_CRC->SpinLock, NewIrql);
	//加锁
	NewIrql = KfAcquireSpinLock(&g_SafeMonPath_List->SpinLock);
	g_SafeMonPath_List->ListNumber = 0;
	//解锁
	KfReleaseSpinLock(&g_SafeMonPath_List->SpinLock, NewIrql);
	g_Regedit_Data.Flag.RULE_360sd_Flag = 0;
	g_Regedit_Data.Flag.RULE_360Safe_Flag = 0;
	g_Regedit_Data.Flag.RULE_360SafeBox_Flag = 0;
	//3、初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	InitializeObjectAttributes(&ObjectAttributes, ObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
	if (NT_SUCCESS(Status))
	{
		//4、第一次调用ZwEnumerateValueKey是为了获取实际长度ResultLength
		while ((Status = ZwEnumerateValueKey(KeyHandle, SubkeyIndex, KeyValueBasicInformation, NULL, 0, &ResultLength)) != STATUS_NO_MORE_ENTRIES)
		{
			//4、1 根据ResultLength分配对应的空间
			pKeyValueBasicInformation = (PKEY_VALUE_BASIC_INFORMATION)Safe_AllocBuff(NonPagedPool, ResultLength, Tag);
			if (!pKeyValueBasicInformation)
			{
				result = STATUS_INSUFFICIENT_RESOURCES;
				ZwClose(KeyHandle);
				return result;
			}
			//4、2 读取注册表项的内容
			Status = ZwEnumerateValueKey(KeyHandle,SubkeyIndex,KeyValueBasicInformation,pKeyValueBasicInformation,ResultLength,&ResultLength);
			if (NT_SUCCESS(Status))
			{
				if (pKeyValueBasicInformation->Type == REG_SZ &&		//必须是字符串类型，就是path路径了
					pKeyValueBasicInformation->NameLength >= 0xA &&
					!_wcsnicmp(pKeyValueBasicInformation->Name, L"RULE_", 5u))	//前缀必须是RULE_ 开头的
				{
					Flagb = 0;
					if (!_wcsnicmp(pKeyValueBasicInformation->Name, L"RULE_360Safe", 0xDu))
					{
						Flagb = 4;
					}
					Status = Safe_QuerRegedit(ObjectName, pKeyValueBasicInformation->Name, Safe_SetRegedit_RULE_360Safe, Flagb);
					if (NT_SUCCESS(Status))
					{
						if (!_wcsnicmp(pKeyValueBasicInformation->Name, L"RULE_360SafeBox", 0x10u))
							g_Regedit_Data.Flag.RULE_360SafeBox_Flag = 1;
						if (!_wcsnicmp(pKeyValueBasicInformation->Name, L"RULE_360Safe", 0xDu))
							g_Regedit_Data.Flag.RULE_360Safe_Flag = 1;
						if (!_wcsnicmp(pKeyValueBasicInformation->Name, L"RULE_360sd", 0xBu))
							g_Regedit_Data.Flag.RULE_360sd_Flag = 1;
					}
				}
			}
			//记得释放
			ExFreePool(pKeyValueBasicInformation);
			pKeyValueBasicInformation = NULL;
			//每次++偏移下一个注册表子项
			++SubkeyIndex;
		}
		//释放句柄、空间
		if (KeyHandle)
		{
			ZwClose(KeyHandle);
		}
	}
	return result;
}


//判断当前驱动加载路径是否在xxxx\ControlSet001内
BOOLEAN NTAPI Safe_CheckControlSetPath(IN HANDLE KeyHandle, IN ULONG NameLength)
{
	NTSTATUS      Status = STATUS_SUCCESS;
	BOOLEAN		  Result = FALSE;
	ULONG         ResultLength = NULL;
	ULONG         Tag = 0x206B6444u;
	PKEY_NAME_INFORMATION pKeyNameInfo = NULL;
	UNICODE_STRING DestinationString = { 0 };
	//保存\\Registry\\Machine\\SYSTEM\\ControlSet00%d\\services路径
	if (g_ControlSet00XPath.Length)
	{
		//1、第一次调用是为了获取实际大小，方便后续new空间
		Status = ZwQueryKey(KeyHandle, KeyNameInformation, 0, 0, &ResultLength);
		if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
		{
			pKeyNameInfo = Safe_AllocBuff(PagedPool, ResultLength + 2, Tag);
			if (pKeyNameInfo)
			{
				//2、再次调用ZwQueryKey获取实际内容
				Status = ZwQueryKey(KeyHandle, KeyNameInformation, pKeyNameInfo, ResultLength, &ResultLength);
				if (NT_SUCCESS(Status))
				{
					//+2 是\\占两个字节
					RtlInitUnicodeString(&DestinationString, pKeyNameInfo->Name);
					if (!RtlPrefixUnicodeString(&g_ControlSet00XPath, &DestinationString, TRUE)||
						(DestinationString.Length != g_ControlSet00XPath.Length + NameLength + 2)	//g_ControlSet00XPath.Length + NameLength + 2合成路径：\\Registry\\Machine\\SYSTEM\\ControlSet00%d\\services\\xxx.sys比较
						)
					{
						Result = TRUE;
					}
				}
				//释放空间
				ExFreePool(pKeyNameInfo);
			}
			else
			{
				Result = FALSE;
			}
		}
		else
		{
			Result = FALSE;
		}
	}
	else
	{
		Result = FALSE;
	}
	return Result;
}

//字符串后面添加上.sys
BOOLEAN NTAPI Safe_AppendString_Sys(IN PUNICODE_STRING SysNameString)
{
	BOOLEAN		   Result = FALSE;
	ULONG		   Tag = 0x206B6444u;
	PVOID 		   pModuleBase = NULL;
	ULONG 		   ModuleSize = NULL;
	UNICODE_STRING Destination;
	STRING         TestDestination;
	WCHAR SysSuufix[] = L".SYS";
	if (SysNameString->Length)
	{
		//添加上.sys 驱动后缀
		Destination.Buffer = Safe_AllocBuff(NonPagedPool, SysNameString->Length * 4, Tag);
		if (Destination.Buffer)
		{
			RtlCopyMemory(Destination.Buffer, SysNameString->Buffer, SysNameString->Length);
			Destination.Length = SysNameString->Length;
			RtlAppendUnicodeToString(&Destination, &SysSuufix);
			
			//判断该驱动是否加载
			Result = Safe_GetModuleBaseAddress(&Destination, pModuleBase, ModuleSize, NULL);
			ExFreePool(Destination.Buffer);
		}
	}
	return Result;
}


//************************************     
// 函数名称: Safe_RunRtlFormatCurrentUserKeyPath     
// 函数说明：获取当前用户的SID    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：内核中访问HKCU注册表 https://blog.csdn.net/cssxn/article/details/103089140  
// 返 回 值: NTSTATUS NTAPI     
// 参    数: OUT PUNICODE_STRING CurrentUserKeyPath    	注意后续要使用RtlFreeUnicodeString(&CurrentUserKeyPath)释放;
//************************************  
NTSTATUS NTAPI Safe_RunRtlFormatCurrentUserKeyPath(OUT PUNICODE_STRING CurrentUserKeyPath)
{
	NTSTATUS	   ntStatus = STATUS_SUCCESS;
	UNICODE_STRING RtlFormatCurrentUserKeyPath_String = { 0 };
	RtlInitUnicodeString(&RtlFormatCurrentUserKeyPath_String, L"RtlFormatCurrentUserKeyPath");
	if (g_dynData->pRtlFormatCurrentUserKeyPath
		|| (g_dynData->pRtlFormatCurrentUserKeyPath = MmGetSystemRoutineAddress(&RtlFormatCurrentUserKeyPath_String)) != 0)
	{
		//CurrentUserKeyPath = "\REGISTRY\USER\S-1-5-18"
		ntStatus = g_dynData->pRtlFormatCurrentUserKeyPath(CurrentUserKeyPath);
	}
	else
	{
		ntStatus = STATUS_UNSUCCESSFUL;
	}
	return ntStatus;
}
//************************************     
// 函数名称: Safe_SetImagePathString     
// 函数说明：获取驱动路径    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2020/05/06     
// 返 回 值: NTSTATUS NTAPI     
// 参    数: IN PUNICODE_STRING In_SysString           驱动名称：xxx.sys   不带路径
// 参    数: IN HANDLE KeyHandle                       句柄
// 参    数: OUT PUNICODE_STRING Ou_ImagePathString    带路径的驱动名称：注册表ImagePath里面的
//************************************ 
NTSTATUS NTAPI Safe_SetImagePathString(IN PUNICODE_STRING In_SysString, IN HANDLE KeyHandle, OUT PUNICODE_STRING Ou_ImagePathString)
{
	NTSTATUS       result, Status;
	UNICODE_STRING ImagePathString;
	UNICODE_STRING DestinationString;
	UNICODE_STRING SystemRootString;
	UNICODE_STRING SystemRoot_System_Drivers_String;
	UNICODE_STRING SysString;
	ULONG          SizeOffset = 0;
	ULONG          SysSize = 0;
	ULONG          MaxLen = 0;
	ULONG          Switch_Flag = 0;
	ULONG          Tag = 0x206B6444u;
	PKEY_VALUE_FULL_INFORMATION pKeyValueFullInformation = NULL;
	WCHAR          SystemPath[0x100] = { 0 };
	result = STATUS_SUCCESS;
	RtlInitUnicodeString(&ImagePathString, L"ImagePath");
	RtlInitUnicodeString(&SystemRootString, L"\\SystemRoot\\");
	RtlInitUnicodeString(&SystemRoot_System_Drivers_String, L"\\SystemRoot\\System32\\Drivers\\");
	RtlInitUnicodeString(&SysString, L".SYS");
	//1、获取当前驱动路径 ImagePath ,函数里面释放了句柄
	pKeyValueFullInformation = Safe_GetKeyValueFullInformation(KeyHandle, &ImagePathString);
	if (pKeyValueFullInformation)
	{
		RtlInitUnicodeString(&DestinationString, (ULONG)pKeyValueFullInformation + pKeyValueFullInformation->DataOffset);
		//判断首字节
		if (*(UCHAR*)DestinationString.Buffer != 0x5C)
		{
			//\SystemRoot\  0x18个字节
			Switch_Flag = 1;
			SizeOffset = SystemRootString.Length;
		}
		MaxLen = DestinationString.Length;
	}
	else
	{
		//ImagePath找不到，直接\SystemRoot\System32\Drivers\xxxx     最后再加上.sys
		Switch_Flag = 2;
		MaxLen = In_SysString->Length;
		SizeOffset = SystemRoot_System_Drivers_String.Length;
		SysSize = SysString.Length;
	}

	//2、分配内存
	Ou_ImagePathString->Buffer = Safe_AllocBuff(NonPagedPool, (SizeOffset + MaxLen + SysSize) * 2, Tag);
	Ou_ImagePathString->Length =  SizeOffset + MaxLen + SysSize;
	Ou_ImagePathString->MaximumLength = Ou_ImagePathString->Length + 2;
	//3、填充字符串 输出
	if (Ou_ImagePathString->Buffer)
	{
		switch (Switch_Flag)
		{
			case 0:		
			{
				//正常返回
				RtlCopyMemory((PVOID)(Ou_ImagePathString->Buffer + SizeOffset), DestinationString.Buffer, DestinationString.Length);
				/******** 最终路径:\??\C:\XXXXSafe\WinXDebug\XXXX.sys ********/
				break;
			}
			case 1:		
			{
				// 首先添加SystemRoot
				RtlCopyMemory((PVOID)(Ou_ImagePathString->Buffer), SystemRootString.Buffer, SystemRootString.Length);
				//再加上原始的ImagePath路径
				RtlCopyMemory((PVOID)(Ou_ImagePathString->Buffer + (SizeOffset / 2)), DestinationString.Buffer, DestinationString.Length);
				/******** 最终路径:\\SystemRoot\\X:\\xxxx.sys ********/
				break;
			}
			case 2:
			{
				// 首先添加\\SystemRoot\System32\Drivers
				RtlCopyMemory((PVOID)(Ou_ImagePathString->Buffer), SystemRoot_System_Drivers_String.Buffer, SystemRoot_System_Drivers_String.Length);
				//再加上输入的In_SysString（不带路径）
				RtlCopyMemory((PVOID)(Ou_ImagePathString->Buffer + (SizeOffset / 2)), In_SysString->Buffer, In_SysString->Length);
				//最后添加上.sys后缀
				RtlCopyMemory((PVOID)(Ou_ImagePathString->Buffer + ((SizeOffset + In_SysString->Length) / 2)), SysString.Buffer, SysString.Length);
				break;
			}
			default:
			{
				break;
			}
		}
	}
	else
	{
		//分配内存失败
		result = STATUS_INSUFFICIENT_RESOURCES;
	}
	if (pKeyValueFullInformation)
	{
		//释放空间
		ExFreePool(pKeyValueFullInformation);
		pKeyValueFullInformation = NULL;
	}
	return result;
}

//判断拦截还是放行加载驱动
NTSTATUS NTAPI Safe_CheckSys(IN HANDLE KeyHandle, IN HANDLE CurrentProcessId, IN HANDLE CurrentThreadId, IN ULONG Flag)
{
	NTSTATUS       result, Status;
	ULONG		   Tag = 0x206B6444u;
	ULONG          ResultLength = NULL;
	PKEY_BASIC_INFORMATION KeyInformation = NULL;
	UNICODE_STRING DestinationString;
	UNICODE_STRING OutImagePathString = { 0 };		//带全路径的驱动地址
	result = STATUS_SUCCESS;
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL)
	{
		goto _FunctionRet;
	}
	//1、第一次调用是为了获取实际大小，方便后续new空间，虚晃一枪
	Status = ZwQueryKey(KeyHandle, KeyBasicInformation, NULL, NULL, &ResultLength);
	if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
	{
		goto _FunctionRet;
	}
	//2、new空间,后面需要添加驱动路径字符串：.sys，所以+8
	KeyInformation = Safe_AllocBuff(NonPagedPool, ResultLength * 2, Tag);
	if (!KeyInformation)
	{
		goto _FunctionRet;
	}
	//3、再次调用ZwQueryKey获取实际内容
	Status = ZwQueryKey(KeyHandle, KeyBasicInformation, KeyInformation, ResultLength, &ResultLength);
	if (!NT_SUCCESS(Status))
	{
		goto _FunctionRet;
	}
	//4、判断当前驱动加载路径是否在xxxx\ControlSet001内
	if (Safe_CheckControlSetPath(KeyHandle, KeyInformation->NameLength))
	{
		Flag = 9;										//Flag=9情况下R3提示也没有发生任何变化
	}
	RtlInitUnicodeString(&DestinationString, KeyInformation->Name);
	//5、判断该驱动是否已经加载
	if (Safe_AppendString_Sys(&DestinationString))
	{
		goto _FunctionRet;
	}
	//6、合成了路径,获取当前驱动路径注册表：ImagePath
	Status = Safe_SetImagePathString(&DestinationString, KeyHandle, &OutImagePathString);
	if (!NT_SUCCESS(Status))
	{
		goto _FunctionRet;
	}
	//7、全路径再次判断是否加载,以及校验驱动签名等等
	if (Safe_GetModuleBaseAddress(&OutImagePathString, NULL, NULL, NULL)
		|| (Status = Safe_1D044_SendR3(CurrentProcessId, CurrentThreadId, Flag, &OutImagePathString), NT_SUCCESS(Status))
		)
	{
		//成功返回
		result = STATUS_SUCCESS;
	}
	else
	{
		//失败返回
		result = STATUS_ACCESS_DENIED;
	}
_FunctionRet:
	//释放空间
	if (OutImagePathString.Buffer)
	{
		ExFreePool(OutImagePathString.Buffer);
		OutImagePathString.Buffer = NULL;
	}
	//释放空间
	if (KeyInformation)
	{
		ExFreePool(KeyInformation);
		KeyInformation = NULL;
	}
	return result;
}


//检查文件对象指针是不是分页文件
BOOLEAN NTAPI Safe_RunFsRtlIsPagingFile(IN PFILE_OBJECT In_FileObject)
{
	BOOLEAN		   result = FALSE;				//FsRtlIsPagingFile returns TRUE if the file represented by FileObject is a paging file, otherwise FALSE.
	UNICODE_STRING FsRtlIsPagingFileString;
	LOGICAL(NTAPI *pFsRtlIsPagingFile)(IN PFILE_OBJECT);
	RtlInitUnicodeString(&FsRtlIsPagingFileString, L"FsRtlIsPagingFile");
	pFsRtlIsPagingFile = (ULONG)MmGetSystemRoutineAddress(&FsRtlIsPagingFileString);
	if (pFsRtlIsPagingFile)
	{
		result = pFsRtlIsPagingFile(In_FileObject);
	}
	return result;
}

//查询注册表HIVELIST
BOOLEAN NTAPI Safe_QuerHivelist(IN ACCESS_MASK GrantedAccess, IN HANDLE In_SourceHandle, IN HANDLE In_SourceProcessHandle)
{
	BOOLEAN					       result = FALSE;
	PEPROCESS				       SourceProcess = NULL;
	PFILE_OBJECT			       FileObject = NULL;
	HANDLE					       KeyHandle = NULL;
	NTSTATUS				       Status = STATUS_SUCCESS;
	ULONG                          ulAttributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	UNICODE_STRING                 HiveListPathString = { 0 };								//\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\hivelist
	UNICODE_STRING                 SYSTEMString = { 0 };									//\\REGISTRY\\MACHINE\\SYSTEM
	UNICODE_STRING                 SOFTWAREString = { 0 };									//\\REGISTRY\\MACHINE\\SOFTWARE
	OBJECT_ATTRIBUTES              ObjectAttributes = { 0 };
	SYSTEM_INFORMATIONFILE_XOR     System_InformationFile_Self = { 0 };						//自身
	RtlInitUnicodeString(&SYSTEMString, L"\\REGISTRY\\MACHINE\\SYSTEM");
	RtlInitUnicodeString(&SOFTWAREString, L"\\REGISTRY\\MACHINE\\SOFTWARE");
	RtlInitUnicodeString(&HiveListPathString, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\hivelist");
	//1、过滤部分权限
	if ((GrantedAccess != (PROCESS_CREATE_THREAD | PROCESS_TERMINATE))
		&& (GrantedAccess != (SYNCHRONIZE | WRITE_DAC | PROCESS_CREATE_THREAD | PROCESS_TERMINATE)) ||
		In_SourceProcessHandle == NtCurrentProcess())
	{
		return result;
	}
	//2、获取源进程的Eprocess结构
	Status = ObReferenceObjectByHandle(In_SourceProcessHandle,
		NULL,
		PsProcessType,
		UserMode,
		&SourceProcess,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	//2、1 判断源进程是不是当前驱动（360SelfProtection）
	if (SourceProcess != g_CurrentProcess)
	{
		ObfDereferenceObject(SourceProcess);
		return result;
	}
	ObfDereferenceObject(SourceProcess);
	//3、得到文件对象指针
	Status = ObReferenceObjectByHandle(In_SourceHandle, NULL, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
	if (NT_SUCCESS(Status))
	{
		//3、1 判断该文件对象是不是一个分页文件,调用FsRtlIsPagingFile
		if (Safe_RunFsRtlIsPagingFile(FileObject))
		{
			ObfDereferenceObject(FileObject);
			result = TRUE;
			return result;
		}
		ObfDereferenceObject(FileObject);
	}
	//4、判断句柄类型，必须是File类型
	if (!Safe_QueryObjectType(In_SourceHandle, L"File"))
	{
		return result;
	}
	//5、获取该句柄信息
	Status = Safe_GetInformationFile(In_SourceHandle, (ULONG)&System_InformationFile_Self, UserMode);
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	//6、打开hivelist
	InitializeObjectAttributes(
		&ObjectAttributes,								 // 返回初始化完毕的结构体
		&HiveListPathString,						     // 文件对象名称
		ulAttributes,									 // 对象属性
		NULL, NULL);									 // 一般为NULL
	Status = ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &ObjectAttributes);
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	//7、分别在\\REGISTRY\\MACHINE\\SYSTEM或则\\REGISTRY\\MACHINE\\SOFTWARE路径找符合条件的
	if (Safe_QueryValueKeyInformation(KeyHandle, &SYSTEMString, &System_InformationFile_Self) || Safe_QueryValueKeyInformation(KeyHandle, &SOFTWAREString, &System_InformationFile_Self))
	{
		result = TRUE;
	}
	//扫尾操作释放句柄
	if (KeyHandle)
	{
		ZwClose(KeyHandle);
	}
	return result;
}

//************************************     
// 函数名称: Safe_QueryValueKeyInformation     
// 函数说明：获取指定路径的文件信息与传入文件信息比较  
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：     
// 返 回 值: BOOLEAN                                               [Out]相同返回1，不同返回0    
// 参    数: IN HANDLE In_KeyHandle                                [In]句柄
// 参    数: IN PUNICODE_STRING In_TargetString                    [In]要打开的路径
// 参    数: IN PSYSTEM_INFORMATIONFILE_XOR In_System_Information  [In]传入的文件信息，用来比较的  
//************************************  
BOOLEAN Safe_QueryValueKeyInformation(IN HANDLE In_KeyHandle, IN PUNICODE_STRING In_TargetString, IN PSYSTEM_INFORMATIONFILE_XOR In_System_Information)
{
	BOOLEAN                    Result = FALSE;
	NTSTATUS				   Status = STATUS_SUCCESS;
	SIZE_T                     ResultLength = 0;
	ULONG					   Tag = 0x206B6444;
	UNICODE_STRING             SymbolNameString = { 0 };
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile_Local = { 0 };
	PKEY_VALUE_PARTIAL_INFORMATION pBuff = NULL;
	//读取注册表键的值(获取实际大小，后续方便new)
	Status = ZwQueryValueKey(In_KeyHandle, In_TargetString, KeyValuePartialInformation, 0, 0, &ResultLength);
	//分配需要的空间, ZwQueryValueKey 的第4个参数可以获得需要的长度
	pBuff = (PKEY_VALUE_PARTIAL_INFORMATION)Safe_AllocBuff(NonPagedPool, ResultLength * 2, Tag);
	if ((Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW)
		&& ResultLength
		&& pBuff
		)
	{
		//查询键值
		Status = ZwQueryValueKey(In_KeyHandle, In_TargetString, KeyValuePartialInformation, pBuff, ResultLength, &ResultLength);
		if (NT_SUCCESS(Status) && pBuff->Type == REG_SZ && pBuff->DataLength)		//必须是字符串类型，就是path路径了
		{
			RtlInitUnicodeString(&SymbolNameString, pBuff->Data);
			//获取该路径的进程信息（防止给恶意修改）
			Status = Safe_KernelCreateFile(&SymbolNameString, &System_InformationFile_Local);
			//释放内存
			ExFreePool(pBuff);
			pBuff = NULL;
			if (NT_SUCCESS(Status))
			{
				//比较进程信息
				if (System_InformationFile_Local.u.IndexNumber_HighPart == In_System_Information->u.IndexNumber_HighPart
					&& System_InformationFile_Local.IndexNumber_LowPart == In_System_Information->IndexNumber_LowPart
					&& System_InformationFile_Local.VolumeSerialNumber == In_System_Information->VolumeSerialNumber)
				{
					Result = TRUE;
				}
			}
		}
	}
	return Result;
}