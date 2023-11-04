/*
功能：学习数字SelfProtection内核
参考资料：
1、DO_BUFFERED_IO和DO_DIRECT_IO与其他方式的区别    
网址：https://blog.csdn.net/qq125096885/article/details/50678744
2、十种进程注入技术介绍：常见注入技术及趋势调查     
网址：https://www.freebuf.com/articles/system/187239.html
*/
#include "Driver.h"


//初始化360Safe特殊进程
VOID NTAPI Safe_InitializeSafeWhiteProcessList()
{
	UNICODE_STRING  DestinationString;
	//包含文件信息、文件名、等等
	//该结构大小0x20，一共7组，0xE0
	//SafeName分别是:
	//0、\\safemon\\360Tray.exe
	//1、\\safemon\\QHSafeTray.exe
	//2、\\deepscan\\zhudongfangyu.exe
	//3、\\deepscan\\QHActiveDefense.exe
	//4、\\360SD.EXE
	//5、\\360RP.EXE
	//6、\\360RPS.EXE
	RtlInitUnicodeString(&g_SafeWhiteProcess[0].SafeName, L"\\safemon\\360Tray.exe");
	RtlInitUnicodeString(&g_SafeWhiteProcess[1].SafeName, L"\\safemon\\QHSafeTray.exe");
	RtlInitUnicodeString(&g_SafeWhiteProcess[2].SafeName, L"\\deepscan\\zhudongfangyu.exe");
	RtlInitUnicodeString(&g_SafeWhiteProcess[3].SafeName, L"\\deepscan\\QHActiveDefense.exe");
	RtlInitUnicodeString(&g_SafeWhiteProcess[4].SafeName, L"\\360SD.EXE");
	RtlInitUnicodeString(&g_SafeWhiteProcess[5].SafeName, L"\\360RP.EXE");
	RtlInitUnicodeString(&g_SafeWhiteProcess[6].SafeName, L"\\360RPS.EXE");
}

//得到SSDT与SSSDT的基地址
NTSTATUS NTAPI Safe_GetSSDTorSSSDTData()
{
	NTSTATUS		Status;
	Status = STATUS_UNSUCCESSFUL;
	//1、获取原始NT内核基地址
	if (!Safe_GetModuleBaseAddress(0, &g_HookPort_Nt_Win32k_Data.NtData.NtImageBase, &g_HookPort_Nt_Win32k_Data.NtData.NtImageSize, 0))
	{
		KdPrint(("获取NT内核基址失败\t\n"));
		HookPort_RtlWriteRegistryValue(2);
		return Status;
	}
	KdPrint(("NT内核基地址是：%X\t\n", g_HookPort_Nt_Win32k_Data.NtData.NtImageBase));
	//2、获取SSSDT基址没有使用懒得获取了
	//if (HookPort_GetModuleBaseAddress(WIN32KSYS, &pModuleBase, &ModuleSize, 0))
	//{
	//	KdPrint(("win32k内核基地址是：%X\t\n", pModuleBase));
	//	Global_Win32kFlag = 1;
	//	if (!HookPort_GetShadowTableAddress(
	//		&g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiServiceTableBase, //[Out]ShadowSSDT_GuiServiceTableBase
	//		&g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiNumberOfServices, //[Out]ShadowSSDT_GuiNumberOfServices
	//		&g_HookPort_Nt_Win32k_Data.ShadowSSDTTable_Data.ShadowSSDT_GuiParamTableBase,   //[Out]ShadowSSDT_GuiParamTableBase
	//		g_HookPort_Nt_Win32k_Data.NtData.NtImageBase,									//[In]Nt内核的基地址
	//		Global_Version_Win10_Flag,														//[In]Win10标志
	//		Global_osverinfo																//[In]版本信息
	//		))
	//	{
	//		HookPort_RtlWriteRegistryValue(1);
	//		return STATUS_UNSUCCESSFUL;
	//	}
	//}
	//3、获取SSDT基址
	Status = Safe_GetSSDTTableAddress(
		&g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeServiceTableBase,			//[Out]SSDT_KeServiceTableBase
		&g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeNumberOfServices,			//[Out]SSDT_KeNumberOfServices
		&g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeParamTableBase,			//[Out]SSDT_KeParamTableBase
		g_HookPort_Nt_Win32k_Data.NtData.NtImageBase								//[In]Nt内核的基地址
		);
	if (!NT_SUCCESS(Status))
	{

		KdPrint(("HookPort: Safe_GetSSDTTableAddress failed,err=%08x\n", Status));
		return Status;
	}
	KdPrint(("SSDT_KeServiceTableBase：%X\t\n", g_HookPort_Nt_Win32k_Data.SSDTTable_Data.SSDT_KeServiceTableBase));
	KdPrint(("获取SSDT表成功\t\n"));
	return Status;
}

//获取ArcName信息，不知道取什么名字好
BOOLEAN Safe_GetSymbolicLinkObjectData()
{
	PCONFIGURATION_INFORMATION ConfigInfo = NULL;
	HANDLE DirectoryHandle = NULL;
	NTSTATUS Status = NULL;
	UNICODE_STRING DestinationString;					//通用
	PKEY_VALUE_FULL_INFORMATION pSystemBootDevice_KeyValueFullInformation = NULL;
	UNICODE_STRING SystemBootString;
	PKEY_VALUE_FULL_INFORMATION pFirmwareBootDevice_KeyValueFullInformation = NULL;
	UNICODE_STRING FirmwareBootString;
	UNICODE_STRING OutDestinationString;		//得到对应的符号链接
	WCHAR          SourceBuff[0x256] = { 0 };
	//0、初始化OBJECT_ATTRIBUTES的内容
	//ZwOpenDirectoryObjectAttributes使用的
	OBJECT_ATTRIBUTES ZwOpenDirectoryObjectAttributes = { 0 };
	UNICODE_STRING    ZwOpenDirectoryString;
	RtlInitUnicodeString(&ZwOpenDirectoryString,L"\\ArcName"); 
	InitializeObjectAttributes(
		&ZwOpenDirectoryObjectAttributes,				 // 返回初始化完毕的结构体
		&ZwOpenDirectoryString,							 // 文件对象名称
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,		// 对象属性
		NULL, NULL);									 // 一般为NULL
	//aDeviceHarddisk
	//假设Safe_ZwQuerySymbolicLinkObject_Open获取失败，默认还是\\Device\\Harddisk0\\DR0？？？？？？？
	RtlInitUnicodeString(&g_FirmwareBootDeviceMax_SymLink, L"\\Device\\Harddisk0\\DR0");

	//1、获取系统中的硬件配置信息（磁盘、光盘、软盘个数）
	ConfigInfo = IoGetConfigurationInformation();
	if (!ConfigInfo)
	{
		KdPrint(("IoGetConfigurationInformation调用失败\t\n"));
		return FALSE;
	}
	Status = ZwOpenDirectoryObject(&DirectoryHandle, DIRECTORY_ALL_ACCESS, &ZwOpenDirectoryObjectAttributes);
	if (g_VersionFlag != WINDOWS_VERSION_2K && NT_SUCCESS(Status))
	{
		//2、1 得到注册表SystemBootDevice的KeyValueFullInformation信息
		RtlInitUnicodeString(&DestinationString, L"SystemBootDevice");
		pSystemBootDevice_KeyValueFullInformation = Safe_GetKeyValueFullInformation(NULL,&DestinationString);
		if (pSystemBootDevice_KeyValueFullInformation)
		{
			RtlInitUnicodeString(&SystemBootString, (ULONG)pSystemBootDevice_KeyValueFullInformation + pSystemBootDevice_KeyValueFullInformation->DataOffset);
			//查找符号链接
			//用Winobj可以查看
			if (Safe_ZwQuerySymbolicLinkObject_Open(
				&SystemBootString,                          //输入     
				DirectoryHandle,							//输入	   ZwOpenDirectoryObject的参数1句柄
				&OutDestinationString						//输出     符号链接
				))
			{
				//g_SystemBootDevice_SymLink后期用来cmp比较的
				Safe_ZwQuerySymbolicLinkObject_Open(&OutDestinationString,0,&g_SystemBootDevice_SymLink);
				//释放空间
				ExFreePool(OutDestinationString.Buffer);
			}
		}
		//2、2 得到注册表FirmwareBootDevice的KeyValueFullInformation信息
		RtlInitUnicodeString(&DestinationString, L"FirmwareBootDevice");
		pFirmwareBootDevice_KeyValueFullInformation = Safe_GetKeyValueFullInformation(NULL,&DestinationString);
		if (pFirmwareBootDevice_KeyValueFullInformation)
		{
			RtlInitUnicodeString(&FirmwareBootString, (ULONG)pFirmwareBootDevice_KeyValueFullInformation + pFirmwareBootDevice_KeyValueFullInformation->DataOffset);
			//查找符号链接
			//用Winobj可以查看
			if (Safe_ZwQuerySymbolicLinkObject_Open(
				&FirmwareBootString,                        //输入     
				DirectoryHandle,							//输入	   ZwOpenDirectoryObject的参数1句柄
				&OutDestinationString						//输出     符号链接
				))
			{
				//g_SystemBootDevice_SymLink后期用来cmp比较的
				Safe_ZwQuerySymbolicLinkObject_Open(&OutDestinationString, 0, &g_FirmwareBootDevice_SymLink);
				//释放空间
				ExFreePool(OutDestinationString.Buffer);
			}
		}
		//3、根据磁盘个数遍历
		if (ConfigInfo->DiskCount != 1)		//磁盘个数>1
		{
			for (ULONG DiskCountNumber = 0; DiskCountNumber < ConfigInfo->DiskCount; DiskCountNumber++)
			{
				//3、1 先清零再赋值
				RtlZeroMemory(SourceBuff, sizeof(SourceBuff));
				Status = RtlStringCbPrintfW(&SourceBuff, sizeof(SourceBuff), L"Device\\Harddisk%d\\Partition0", DiskCountNumber);
				if (NT_SUCCESS(Status))
				{
					//获取到最后一组？？？？？？
					RtlInitUnicodeString(&DestinationString, &SourceBuff);
					if (Safe_ZwQueryDirectoryObject(&DestinationString, DirectoryHandle, &SystemBootString) && pSystemBootDevice_KeyValueFullInformation)
					{
						Safe_ZwQuerySymbolicLinkObject_Open(&DestinationString, 0,&g_SystemBootDeviceMax_SymLink);
					}
					if (Safe_ZwQueryDirectoryObject(&DestinationString, DirectoryHandle, &FirmwareBootString) && pFirmwareBootDevice_KeyValueFullInformation)
					{
						Safe_ZwQuerySymbolicLinkObject_Open(&DestinationString, 0, &g_FirmwareBootDeviceMax_SymLink);
					}
				}
			}
		}
		//扫尾工作各种释放
		if (pFirmwareBootDevice_KeyValueFullInformation)
		{
			//释放空间
			ExFreePool(pFirmwareBootDevice_KeyValueFullInformation);
		}
		if (pSystemBootDevice_KeyValueFullInformation)
		{
			//释放空间
			ExFreePool(pSystemBootDevice_KeyValueFullInformation);
		}
		if (DirectoryHandle)
		{
			ZwClose(DirectoryHandle);
		}
	}
	return TRUE;
}

//根据版本获取偏移值
BOOLEAN NTAPI Safe_Initialize_Data()
{
	UNICODE_STRING  DestinationString;
	UNICODE_STRING  Win32kSysString;
	PVOID 			pModuleBase = NULL;
	ULONG 			ModuleSize = NULL;
	ULONG           Tag = 0x206B6444;
	//防止二次初始化，置1（函数已执行） 置0（函数未执行）
	if (Global_InitializeDataFlag)            
	{
		return TRUE;
	}
	//初始化默认值
	//设置几个全局变量默认值
	g_Regedit_Data.g_SpShadow0_Data_DWORD = 1;					//默认是1
	g_dynData->dword_3323C = 0xFF8000;
	g_ObjectType = NULL;
	g_SystemHotpatchInformation_Switch = 1;
	g_x360SelfProtection_Switch = 1;
	g_dword_34678 = 1;											//默认是1

	//g_IllegalityDllPath.Buffer = 0;								//全局变量默认都是清零的，感觉这三句有点多余
	//g_IllegalityDllPath.MaximumLength = 0;
	//g_IllegalityDllPath.Length = 0;

	RtlInitUnicodeString(&DestinationString, L"ObGetObjectType");
	g_dynData->pObGetObjectType = MmGetSystemRoutineAddress(&DestinationString);
	RtlInitUnicodeString(&DestinationString, L"ObDuplicateObject");
	g_dynData->pObDuplicateObject = (ULONG)MmGetSystemRoutineAddress(&DestinationString);
	RtlInitUnicodeString(&DestinationString,L"PsGetThreadProcessId");
	g_dynData->pPsGetThreadProcessId = (ULONG)MmGetSystemRoutineAddress(&DestinationString);
	RtlInitUnicodeString(&DestinationString, L"PsGetProcessId");
	g_dynData->pPsGetProcessId = (ULONG)MmGetSystemRoutineAddress(&DestinationString);
	RtlInitUnicodeString(&DestinationString, L"PsGetProcessImageFileName");
	g_dynData->pPsGetProcessImageFileName = (ULONG)MmGetSystemRoutineAddress(&DestinationString);
	if (!g_dynData->pPsGetProcessImageFileName || !g_dynData->pPsGetProcessId || !g_dynData->pPsGetThreadProcessId)
	{
		return FALSE;
	}
	switch (g_VersionFlag)
	{
		//WINDOWS_VERSION_2K
		case WINDOWS_VERSION_2K:
		{
			g_dynData->Eprocess_Offset.dword_34DF4 = 0x22C;		//+0x22c SecurityPort : (null) 
			g_dynData->Eprocess_Offset._Eprocess_UniqueProcessIdIndex = 0x9C;
			g_dynData->Eprocess_Offset._Eprocess_ImageFileNameIndex = 0x1FC;		//低版本代替PsGetProcessImageFileName
			g_dynData->Int2E_Index.dword_34E0C = 0x11D2;
			g_dynData->Int2E_Index.dword_34E10 = 0x1189;
			g_dynData->Int2E_Index.dword_34E14 = 0x11B1;
			g_dynData->Int2E_Index.dword_34E28 = 0x1179;
			g_dynData->Int2E_Index.dword_34E2C = 0x1173;
			g_dynData->Int2E_Index.dword_34E30 = 0x1129;
			g_dynData->Int2E_Index.dword_34E34 = 0x11A3;
			break;
		}
		//WINDOWS_VERSION_XP
		case WINDOWS_VERSION_XP:
		{
			g_dynData->Int2E_Index.dword_34E0C = 0x11E3;
			g_dynData->Int2E_Index.dword_34E10 = 0x1194;
			g_dynData->Int2E_Index.dword_34E14 = 0x11C1;
			g_dynData->Int2E_Index.dword_34E18 = 0x117A;
			g_dynData->Int2E_Index.dword_34E1C = 0x1143;
			g_dynData->Int2E_Index.dword_34E20 = 0x117F;
			g_dynData->Int2E_Index.dword_34E24 = 0x30;
			g_dynData->Int2E_Index.dword_34E28 = 0x1184;
			g_dynData->Int2E_Index.dword_34E2C = 0x117D;
			g_dynData->Int2E_Index.dword_34E30 = 0x1133;
			g_dynData->Int2E_Index.dword_34E34 = 0x11B3;
			break;
		}
		//WINDOWS_VERSION_2K3
		case WINDOWS_VERSION_2K3:
		{
			KdPrint(("g_VersionFlag:%X Error\t\n", g_VersionFlag));
			break;
		}
		//WINDOWS_VERSION_2K3_SP1_SP2
		case WINDOWS_VERSION_2K3_SP1_SP2:
		{
			g_dynData->Int2E_Index.dword_34E0C = 0x11F8;
			g_dynData->Int2E_Index.dword_34E10 = 0x11A2;
			g_dynData->Int2E_Index.dword_34E14 = 0x11D2;
			g_dynData->Int2E_Index.dword_34E18 = 0x1187;
			g_dynData->Int2E_Index.dword_34E1C = 0x114D;
			g_dynData->Int2E_Index.dword_34E20 = 0x118D;
			g_dynData->Int2E_Index.dword_34E28 = 0x1192;
			g_dynData->Int2E_Index.dword_34E2C = 0x118B;
			g_dynData->Int2E_Index.dword_34E30 = 0x113D;
			g_dynData->Int2E_Index.dword_34E34 = 0x11C1;
			g_dynData->Int2E_Index.dword_34E24 = (g_VersionFlag != WINDOWS_VERSION_2K3_SP1_SP2) + 0x31;
			break;
		}
		//WINDOWS_VERSION_VISTA_2008
		case WINDOWS_VERSION_VISTA_2008:
		{
			g_dynData->Int2E_Index.dword_34E0C = 0x11F8;
			g_dynData->Int2E_Index.dword_34E10 = 0x11A2;
			g_dynData->Int2E_Index.dword_34E14 = 0x11D2;
			g_dynData->Int2E_Index.dword_34E18 = 0x1187;
			g_dynData->Int2E_Index.dword_34E1C = 0x114D;
			g_dynData->Int2E_Index.dword_34E20 = 0x118D;
			g_dynData->Int2E_Index.dword_34E28 = 0x1192;
			g_dynData->Int2E_Index.dword_34E2C = 0x118B;
			g_dynData->Int2E_Index.dword_34E30 = 0x113D;
			g_dynData->Int2E_Index.dword_34E34 = 0x11C1;
			g_dynData->Int2E_Index.dword_34E24 = (g_VersionFlag != WINDOWS_VERSION_2K3_SP1_SP2) + 0x31;
			break;
		}
		//WINDOWS_VERSION_7     Win7  7100、7600、7601
		case WINDOWS_VERSION_7:
		{
			g_dynData->Int2E_Index.dword_34E0C = 0x1203;
			g_dynData->Int2E_Index.dword_34E10 = 0x11A7;
			g_dynData->Int2E_Index.dword_34E14 = 0x11DC;
			g_dynData->Int2E_Index.dword_34E18 = 0x118C;
			g_dynData->Int2E_Index.dword_34E1C = 0x114E;
			g_dynData->Int2E_Index.dword_34E24 = 0x32;
			g_dynData->Int2E_Index.dword_34E20 = 0x1192;
			g_dynData->Int2E_Index.dword_34E28 = 0x1197;
			g_dynData->Int2E_Index.dword_34E2C = 0x1190;
			g_dynData->Int2E_Index.dword_34E30 = 0x113E;
			g_dynData->Int2E_Index.dword_34E34 = 0x11C7;
			break;
		}
		//WINDOWS_VERSION_8_9200‬
		case WINDOWS_VERSION_8_9200‬:
		{
			g_dynData->dword_3323C = 0x7F8000;
			g_dynData->Int2E_Index.dword_34E0C = 0x11E2;
			g_dynData->Int2E_Index.dword_34E10 = 0x11AD;
			g_dynData->Int2E_Index.dword_34E14 = 0x120B;
			g_dynData->Int2E_Index.dword_34E18 = 0x11CB;
			g_dynData->Int2E_Index.dword_34E1C = 0x115D;
			g_dynData->Int2E_Index.dword_34E24 = 0x34;
			g_dynData->Int2E_Index.dword_34E20 = 0x11C5;
			g_dynData->Int2E_Index.dword_34E28 = 0x11C0;
			g_dynData->Int2E_Index.dword_34E2C = 0x11C7;
			g_dynData->Int2E_Index.dword_34E30 = 0x116D;
			g_dynData->Int2E_Index.dword_34E34 = 0x118C;
			break;
		}
		//WINDOWS_VERSION_8_9600
		case WINDOWS_VERSION_8_9600:
		{
			g_dynData->dword_3323C = 0x7F8000;
			g_dynData->Int2E_Index.dword_34E0C = 0x11E3;
			g_dynData->Int2E_Index.dword_34E10 = 0x11AE;
			g_dynData->Int2E_Index.dword_34E14 = 0x120E;
			g_dynData->Int2E_Index.dword_34E18 = 0x11CC;
			g_dynData->Int2E_Index.dword_34E1C = 0x115F;
			g_dynData->Int2E_Index.dword_34E24 = 0x36;
			g_dynData->Int2E_Index.dword_34E20 = 0x11C6;
			g_dynData->Int2E_Index.dword_34E28 = 0x11C1;
			g_dynData->Int2E_Index.dword_34E2C = 0x11C8;
			g_dynData->Int2E_Index.dword_34E30 = 0x116F;
			g_dynData->Int2E_Index.dword_34E34 = 0x118E;
			break;
		}
		//‬WINDOWS_VERSION_10			//Win10 10240、10586、>10586
		case ‬WINDOWS_VERSION_10:
		{
			g_dynData->dword_3323C = 0x7F8000;
			//2、获取Win32k基址
			RtlInitUnicodeString(&Win32kSysString, WIN32KSYS);
			if (Safe_GetModuleBaseAddress(&Win32kSysString, &pModuleBase, &ModuleSize, 0))
			{
				//Win10后续再逆向
			}
			break;
		}
		default:
		{
			//版本错误直接退出
			KdPrint(("g_VersionFlag:%X Error\t\n", g_VersionFlag));
			return FALSE;
		}
	}
	//各种new空间
	//软件自身安全目录：C:\Program Files\360\360safe\SAFEMON
	g_SafeMonPath_List = Safe_AllocBuff(NonPagedPool, sizeof(SAFEMONPATH_DIRECTORY), Tag);
	if (!g_SafeMonPath_List)
	{
		return FALSE;
	}
	//这个结构专门保存文件文件信息的
	g_All_InformationFile_CRC = Safe_AllocBuff(NonPagedPool, sizeof(ALL_INFORMATIONFILE_CRC), Tag);
	if (!g_SafeMonPath_List)
	{
		ExFreePool(g_SafeMonPath_List);
		return FALSE;
	}
	//与g_SafeMonPath_List对应
	//g_SafeMonPath_List保存路径
	//g_SafeMonData_List保存该路径进程的Eprocess、PID、等等信息
	g_SafeMonData_List = Safe_AllocBuff(NonPagedPool, sizeof(SAFEMONDATA_DIRECTORY), Tag);// 与HookPort那个结构体一样，只是出来两个参数
	if (!g_SafeMonData_List)
	{
		ExFreePool(g_SafeMonPath_List);
		ExFreePool(g_All_InformationFile_CRC);
		return FALSE;
	}
	//虚拟内存信息
	g_VirtualMemoryData_List = Safe_AllocBuff(NonPagedPool, sizeof(ALLOCATEVIRTUALMEMORY_DIRECTORY), Tag);
	if (!g_VirtualMemoryData_List)
	{
		ExFreePool(g_SafeMonPath_List);
		ExFreePool(g_All_InformationFile_CRC);
		ExFreePool(g_SafeMonData_List);
		return FALSE;
	}
	//初始化自旋锁
	KeInitializeSpinLock(&g_White_List.SpinLock);
	KeInitializeSpinLock(&g_SpecialWhite_List.SpinLock);
	KeInitializeSpinLock(&g_CreateProcessData_List.SpinLock);
	KeInitializeSpinLock(&g_All_InformationFile_CRC->SpinLock);
	KeInitializeSpinLock(&g_SafeMonData_List->SpinLock);
	KeInitializeSpinLock(&g_SafeMonPath_List->SpinLock);						
	KeInitializeSpinLock(&g_VirtualMemoryData_List->SpinLock);
	//初始化系统进程函数
	Safe_InitializeSystemInformationFile();
	//得到设备对象信息
	Safe_GetSymbolicLinkObjectData();
	//获取到\\Registry\\Machine\\SYSTEM\\ControlSet00%d\\services路径
	Safe_GetControlSet00XPath();
	//顺便获取SSDT基地址
	Safe_GetSSDTorSSSDTData();
	//初始化360Safe特殊进程
	Safe_InitializeSafeWhiteProcessList();
	//win7或则Win7以上版本成立
	if ((g_VersionFlag == WINDOWS_VERSION_7 || g_VersionFlag == WINDOWS_VERSION_8_9200‬ || g_VersionFlag == WINDOWS_VERSION_8_9600 || g_VersionFlag == ‬WINDOWS_VERSION_10))
	{
		g_HighgVersionFlag = 1;
	}
	//标志位置1
	Global_InitializeDataFlag = 1;
	return TRUE;
}



//Win10未检查的函数
PVOID Safe_1391C_Win10()
{
	UNICODE_STRING DestinationString;
	ULONG (NTAPI *pZwGetNextProcess)(HANDLE, ULONG, ULONG, ULONG, HANDLE*);
	ULONG (NTAPI *pPsIsProtectedProcess)(IN PEPROCESS);
	ULONG (NTAPI *pPsGetProcessWin32Process)(IN PEPROCESS);		//_EPROCESS->Win32Process
	HANDLE Handle_v3, Handle;
	PEPROCESS pPeprocess = NULL;
	Handle_v3 = NULL;
	Handle = 0;
	RtlInitUnicodeString(&DestinationString, L"PsGetProcessWin32Process");
	pPsGetProcessWin32Process = MmGetSystemRoutineAddress(&DestinationString);

	RtlInitUnicodeString(&DestinationString, L"PsIsProtectedProcess");
	pPsIsProtectedProcess = MmGetSystemRoutineAddress(&DestinationString);

	RtlInitUnicodeString(&DestinationString, L"ZwGetNextProcess");
	pZwGetNextProcess = MmGetSystemRoutineAddress(&DestinationString);

	if (pPsGetProcessWin32Process && 
		pZwGetNextProcess && 
		pPsIsProtectedProcess )
	{
		pZwGetNextProcess(0, 0x400, 0x200, 0, &Handle_v3);
		do
		{
			//每次释放上一次打开的句柄
			if (Handle)
			{
				ZwClose(Handle);
			}
			Handle = Handle_v3;
			if (ObReferenceObjectByHandle(Handle_v3, 0x400, PsProcessType, KernelMode, &pPeprocess, 0) >= 0)
			{
				if (pPsIsProtectedProcess(pPeprocess) && pPsGetProcessWin32Process(pPeprocess))
				{
					ZwClose(Handle);
					return pPeprocess;
				}
				ObfDereferenceObject(pPeprocess);
			}
		} while (pZwGetNextProcess(Handle, 0x400, 0x200, 0, &Handle_v3));
		if (Handle_v3)
			ZwClose(Handle_v3);
	}
	return FALSE;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING	SymbolicLinkName;		// 360SpShadow0
	UNICODE_STRING	SymbolicLinkName1;		// 360SelfProtection
	UNREFERENCED_PARAMETER(DriverObject);
	RtlInitUnicodeString(&SymbolicLinkName, SpShadow_LinkName);
	RtlInitUnicodeString(&SymbolicLinkName1, SelfProtection_LinkName);
	//删除符号链接
	if (Global_SpShadowDeviceObject != NULL)
	{
		IoDeleteDevice(Global_SpShadowDeviceObject);
		IoDeleteSymbolicLink(&SymbolicLinkName);
	}
	if (Global_SelfProtectionDeviceObject != NULL)
	{
		IoDeleteDevice(Global_SelfProtectionDeviceObject);
		IoDeleteSymbolicLink(&SymbolicLinkName1);
	}
	//释放new空间
	if (g_dynData)
	{
		ExFreePool(g_dynData);
	}
	if (g_ThreadID_Table)
	{
		ExFreePool(g_ThreadID_Table);
	}
	if (g_SafeMonPath_List)
	{
		ExFreePool(g_SafeMonPath_List);
	}
	if (g_All_InformationFile_CRC)
	{
		ExFreePool(g_All_InformationFile_CRC);
	}
	if (g_SafeMonData_List)
	{
		ExFreePool(g_SafeMonData_List);
	}
	KdPrint(("卸载成功\t\n"));
	return;
}



//************************************     
// 函数名称: Safe__CreateCloseCleanup     
// 函数说明：    
// IDA地址 ：Sub_2323A
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/11/29     
// 返 回 值: NTSTATUS     
// 参    数: IN PDEVICE_OBJECT pDevObj     
// 参    数: IN PIRP pIrp     
//************************************  
NTSTATUS Safe__CreateCloseCleanup(
	IN PDEVICE_OBJECT pDevObj,
	IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
//************************************     
// 函数名称: DriverEntry     
// 函数说明：驱动程序入口     
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/11/29     
// 返 回 值: NTSTATUS     
// 参    数: IN PDRIVER_OBJECT DriverObj     
// 参    数: IN PUNICODE_STRING RegPath     
//************************************  
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT  DriverObject,		//代表本驱动的驱动对象
	IN PUNICODE_STRING RegPath				//驱动的路径，在注册表中
	)
{
	NTSTATUS		 Status = STATUS_INVALID_DEVICE_REQUEST;
	PFILE_OBJECT	 FileObject;
	PDEVICE_OBJECT   pHookPortDeviceObject;
	UNICODE_STRING   DestinationString;
	UNICODE_STRING   SymbolicLinkName;		// 360SpShadow0
	UNICODE_STRING   DestinationString1;
	UNICODE_STRING   SymbolicLinkName1;		// 360SelfProtection
	UNICODE_STRING   RtlGetActiveConsoleIdString;
	PHOOKPORT_EXTENSION pHookPortExt;
	UNREFERENCED_PARAMETER(RegPath);
	//1、获取版本信息
	Safe_PsGetVersion();
	//1、1 版本获取错误
	if (!g_VersionFlag)
	{
		return STATUS_NOT_SUPPORTED;
	}
	KdPrint(("Safe_PsGetVersion获取版本信息成功\t\n"));
	g_CurrentProcess = (ULONG)IoGetCurrentProcess();
	//2、创建设备
	Global_DriverObject = DriverObject;
	RtlInitUnicodeString(&DestinationString, SpShadow_DeviceName);
	RtlInitUnicodeString(&SymbolicLinkName, SpShadow_LinkName);
	RtlInitUnicodeString(&DestinationString1, SelfProtection_DeviceName);
	RtlInitUnicodeString(&SymbolicLinkName1, SelfProtection_LinkName);
	Status = IoCreateDevice(	 //SpShadow_DeviceName
		DriverObject,			         //[_In_]驱动对象
		NULL,					         //[_In_]扩展大小是0
		&DestinationString,		         //[_In_opt_]设备名称
		FILE_DEVICE_UNKNOWN,	         //[_In_]设备类型，填写未知类型
		FILE_DEVICE_SECURE_OPEN,         //[_In_]驱动特征
		FALSE,							 //[_In_]Exclusive
		&Global_SpShadowDeviceObject	 //[_Out_]得到设备对象
		);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("SpShadow_DeviceName: DriverEntry IoCreateDevice failed,err=%08x\t\n", Status));
		return Status;
	}
	//我们的设备对象，有三种通讯方式：
	//1 缓冲区方式读写：(DO_BUFFERED_IO)
	//2 直接方式读写：(DO_DIRECT_IO)
	//3 其他方式读写:(在调用IoCreateDevice创建设备后对pDevObj->Flags即不设置DO_BUFFERED_IO也不设置DO_DIRECT_IO此时就是其他方式)
	Global_SpShadowDeviceObject->Flags |= DO_DIRECT_IO;

	//说明：设备名称，三环是看不到，用户层要和这个设备通讯，需要创建一个符号连接
	//给设备创建一个符号链接(SpShadow_LinkName)
	Status = IoCreateSymbolicLink(
		&SymbolicLinkName,		//[_In_]符号链接名称
		&DestinationString		//[_In_]设备名称
		);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("SpShadow_LinkName: DriverEntry IoCreateSymbolicLink failed,err=%08x\n", Status));
		IoDeleteDevice(Global_SpShadowDeviceObject);
		Global_SpShadowDeviceObject = NULL;
		return Status;
	}
	//2、1 创建设备
	Status = IoCreateDevice(				//SelfProtection_DeviceName
		DriverObject,						//[_In_]驱动对象
		NULL,								//[_In_]扩展大小是0
		&DestinationString1,				//[_In_opt_]设备名称
		FILE_DEVICE_UNKNOWN,				//[_In_]设备类型，填写未知类型
		FILE_DEVICE_SECURE_OPEN,			//[_In_]驱动特征
		FALSE,								//[_In_]Exclusive
		&Global_SelfProtectionDeviceObject	//[_Out_]得到设备对象
		);
	if (!NT_SUCCESS(Status))
	{
		IoDeleteSymbolicLink(&SymbolicLinkName);
		IoDeleteDevice(Global_SpShadowDeviceObject);
		KdPrint(("SelfProtection_DeviceName: DriverEntry IoCreateDevice failed,err=%08x\t\n", Status));
		return Status;
	}

	Status = IoCreateSymbolicLink(
		&SymbolicLinkName1,		//[_In_]符号链接名称
		&DestinationString1		//[_In_]设备名称
		);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("SelfProtection_LinkName: DriverEntry IoCreateSymbolicLink failed,err=%08x\n", Status));
		IoDeleteDevice(Global_SpShadowDeviceObject);
		IoDeleteDevice(Global_SelfProtectionDeviceObject);
		IoDeleteSymbolicLink(&SymbolicLinkName);
		Global_SpShadowDeviceObject = NULL;
		Global_SelfProtectionDeviceObject = NULL;
		return Status;
	}
	//3、 不感兴趣的通用处理
	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = Safe_CommonProc;
	}
	//3、1 设置驱动通信例程
	DriverObject->MajorFunction[IRP_MJ_CREATE] = Safe__CreateCloseCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Safe__CreateCloseCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = Safe__CreateCloseCleanup;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Safe_DeviceControl;
	DriverObject->MajorFunction[IRP_MJ_READ] = Safe_Read;
	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = Safe_Shutdown;

	//4、打开xxxHookPort.sys驱动,为了使用hookPort.sys导出的DeviceExtension接口
	RtlInitUnicodeString(&DestinationString, HookPort_DeviceName);
	//使用函数IoGetDeviceObjectPointer可以获得这个设备对象的指针
	Status = IoGetDeviceObjectPointer(&DestinationString, GENERIC_READ, &FileObject, &pHookPortDeviceObject);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("DriverEntry IoGetDeviceObjectPointer failed,err=%08x\n", Status));
		IoDeleteDevice(Global_SpShadowDeviceObject);
		IoDeleteDevice(Global_SelfProtectionDeviceObject);
		IoDeleteSymbolicLink(&SymbolicLinkName);
		IoDeleteSymbolicLink(&SymbolicLinkName1);
		Global_SpShadowDeviceObject = NULL;
		Global_SelfProtectionDeviceObject = NULL;
		return Status;
	}
	//4、1new各种全局变量空间
	g_dynData = Safe_AllocBuff(NonPagedPool, sizeof(DYNAMIC_DATA), SELFPROTECTION_POOLTAG);
	g_ThreadID_Table = Safe_AllocBuff(NonPagedPool, sizeof(UNKNOWN_THREADID_TABLE) * THREADID_TABLE_MAXSIZE, SELFPROTECTION_POOLTAG);
	if (g_ThreadID_Table && g_dynData)
	{
		//4、2 获取HookPort->DeviceExtension接口
		if (pHookPortDeviceObject->DeviceExtension &&
			(Global_HookPort_DriverObject = pHookPortDeviceObject->DriverObject,
			pHookPortExt = pHookPortDeviceObject->DeviceExtension,
			HookPort_AllocFilterRuleTable = pHookPortExt->HookPort_FilterRule_Init,					//初始化规则
			HookPort_SetFilterSwitchFunction = pHookPortExt->HookPort_SetFilterSwitchFunction,		//设置规则过滤函数
			HookPort_SetFilterRule = pHookPortExt->HookPort_SetFilterRule,							//设置规则开关
			HookPort_SetFilterRuleName = pHookPortExt->HookPort_SetFilterRuleName,			     	//设置规则名字
			g_HookPort_Version = pHookPortExt->Value3F1,											//得到HookPort版本
			(g_FilterFun_Rule_table_head_Temp = HookPort_AllocFilterRuleTable(3)) != 0) &&			//获取HookPort.sys生成的旧规则地址
			(Safe_Initialize_SetFilterSwitchFunction(),												//设置规则过滤函数
			Safe_Initialize_SetFilterRule(pHookPortDeviceObject),									//设置规则开关
			Safe_Initialize_Data())																	//初始化一些偏移给其他函数使用
			)
		{
			//设置开关启用
			g_FilterFun_Rule_table_head_Temp->IsFilterFunFilledReady = 1;
			//清理垃圾
			ObfDereferenceObject(FileObject);
			//查询注册表相关的
			Safe_QuerRegedit(RegPath, L"i18n", Safe_SetRegedit_i18h, 0);	//判断使用哪个主动防御进程通讯
			Safe_EnumerateValueKey(RegPath, 1);
			Safe_QuerRegedit(RegPath, L"TextOutCache", Safe_SetRegedit_TextOutCache, 0);
			Safe_QuerRegedit(RegPath, L"SpShadow0", Safe_SetRegedit_SpShadow0, 0);
			Safe_QuerRegedit(RegPath, L"DisableDPHotPatch", Safe_SetRegedit_DisableDPHotPatch, 0);
			//初始化链表，保存拦截和放行进程信息的（R3和R0交互）
			Safe_Initialize_List();
			//永恒之蓝的那个漏洞
			if (Safe_HookSrvTransactionNotImplemented())
			{
				//开关置1，标识初始化
				g_HookSrvTransactionNotImplementedFlag = 1;
			}
			//Win10_14393版本以上
			if (g_VersionFlag == ‬WINDOWS_VERSION_10 && osverinfo.dwBuildNumber >= 14393)
			{
				RtlInitUnicodeString(&RtlGetActiveConsoleIdString, L"RtlGetActiveConsoleId");
				g_dynData->pRtlGetActiveConsoleId_Win10_14393 = (ULONG)MmGetSystemRoutineAddress(&RtlGetActiveConsoleIdString);
			}
		}
		else
		{
			ExFreePool(g_dynData);
			g_dynData = NULL;
			ExFreePool(g_ThreadID_Table);
			g_ThreadID_Table = NULL;
			ObfDereferenceObject(FileObject);
			IoDeleteDevice(Global_SpShadowDeviceObject);
			IoDeleteDevice(Global_SelfProtectionDeviceObject);
			IoDeleteSymbolicLink(&SymbolicLinkName);
			IoDeleteSymbolicLink(&SymbolicLinkName1);
			Global_SpShadowDeviceObject = NULL;
			Global_SelfProtectionDeviceObject = NULL;
			return STATUS_UNSUCCESSFUL;
		}
		KdPrint(("360SelfProtection驱动加载成功\t\n"));
	}
	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}