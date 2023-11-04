#include "WinKernel.h"


//************************************     
// 函数名称: PageProtectOn     
// 函数说明：恢复内存保护    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值: VOID     
//************************************  
VOID PageProtectOn()
{
	__asm{//恢复内存保护  
		mov  eax, cr0
		or   eax, 10000h
		mov  cr0, eax
		sti
	}
}

//************************************     
// 函数名称: PageProtectOff     
// 函数说明：关闭保护    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值: VOID     
//************************************  
VOID PageProtectOff()
{
	__asm{//去掉内存保护
		cli
		mov  eax, cr0
		and  eax, not 10000h
		mov  cr0, eax
	}
}


//************************************     
// 函数名称: HookPort_GetModuleBaseAddress     
// 函数说明：根据函数名获取指定内核基址    
// IDA地址 ：sub_16E2C
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/05     
// 返 回 值: BOOLEAN NTAPI     
// 参    数: CONST CHAR * ModuleName    模块名 
// 参    数: PVOID * pModuleBase        模块基址
// 参    数: ULONG * ModuleSize         模块大小
// 参    数: USHORT * LoadOrderIndex    
//************************************  
BOOLEAN NTAPI HookPort_GetModuleBaseAddress(IN CONST CHAR *ModuleName, OUT PVOID *pModuleBase, OUT ULONG *ModuleSize, OUT USHORT *LoadOrderIndex)
{

	NTSTATUS status; // eax@5

	ULONG    uCount; // eax@8  
	PSYSTEM_MODULE_INFORMATION    pSysModule;

	ULONG ReturnLength; // [sp+Ch] [bp-14h]@5  
	PCHAR  pModuleInfo = NULL; // [sp+10h] [bp-10h]@8
	size_t	BufLen = 4096; // [sp+14h] [bp-Ch]@12

	PCHAR            pName = NULL;
	ULONG            ui;

	do {

		if (pModuleInfo)
			ExFreePool(pModuleInfo);

		pModuleInfo = ExAllocatePoolWithTag(NonPagedPool, BufLen, SELFPROTECTION_POOLTAG);

		if (!pModuleInfo) {

			return 0;

		}

		status = ZwQuerySystemInformation(SystemModuleInformation, pModuleInfo, BufLen, &ReturnLength);
		if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH) {
			ExFreePool(pModuleInfo);
			return 0;
		}

		BufLen += 4096;

	} while (!NT_SUCCESS(status));


	uCount = (ULONG)*(ULONG *)pModuleInfo;
	pSysModule = (PSYSTEM_MODULE_INFORMATION)(pModuleInfo + sizeof(ULONG));

	if (!ModuleName)
	{

		*pModuleBase = pSysModule->Base;
		*ModuleSize = pSysModule->Size;
		ExFreePool(pModuleInfo);
		return TRUE;
	}

	for (ui = 0; ui < uCount; ui++)
	{

		pName = strrchr(pSysModule->ImageName, '\\');
		if (pName) {
			++pName;
		}
		else {
			pName = pSysModule->ImageName;
		}
		if (!_stricmp(pName, ModuleName))
			break;

		pSysModule++;

	}


	if (ui >= uCount)
	{
		ExFreePool(pModuleInfo);
		return 0;
	}
	if (pModuleBase)
	{
		*pModuleBase = pSysModule->Base;
	}
	if (ModuleSize)
	{
		*ModuleSize = pSysModule->Size;
	}
	if (LoadOrderIndex)
	{
		*LoadOrderIndex = pSysModule->LoadOrderIndex;
	}
	ExFreePool(pModuleInfo);
	return TRUE;
}


PVOID HookPort_GetSymbolAddress(PANSI_STRING SymbolName, PVOID NtImageBase)
{
	PVOID SymbolAddr, result = NULL;
	result = HookPort_GetAndReplaceSymbol(NtImageBase, SymbolName, NULL, &SymbolAddr);
	return result;
}

//************************************     
// 函数名称: HookPort_GetAndReplaceSymbol     
// 函数说明：此函数分析PE文件获取其导出符号的地址 
//			 如指定了ReplaceValue，则用ReplaceValue替换查找到的符号的值
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值: PVOID NTAPI     
// 参    数: PVOID ImageBase     
// 参    数: PANSI_STRING SymbolName     
// 参    数: PVOID ReplaceValue     
// 参    数: PVOID * SymbolAddr     
//************************************  
PVOID NTAPI HookPort_GetAndReplaceSymbol(PVOID ImageBase, PANSI_STRING SymbolName, PVOID ReplaceValue, PVOID *SymbolAddr)
{

	PCHAR	AddressOfNames, pSymbolName;
	PVOID symbol_address, result;
	ULONG Size, func_index;
	DWORD NameOrdinals, NumberOfNames, Low, Mid, High;
	long	ret;

	PIMAGE_EXPORT_DIRECTORY pIED;


	pIED = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &Size);
	if (!pIED)
		return NULL;

	AddressOfNames = (CHAR *)ImageBase + pIED->AddressOfNames;
	NameOrdinals = (DWORD)((CHAR *)ImageBase + pIED->AddressOfNameOrdinals);
	NumberOfNames = pIED->NumberOfNames;

	Low = 0;
	High = NumberOfNames - 1;
	if ((long)High < 0)
		return NULL;

	while (TRUE)
	{
		Mid = (Low + High) >> 1;
		pSymbolName = (PCHAR)ImageBase + *(PULONG)&AddressOfNames[4 * Mid];
		ret = strcmp(SymbolName->Buffer, pSymbolName);
		if (!ret)
			break;

		if (ret > 0)
		{
			Low = Mid + 1;
		}
		else
		{
			High = Mid - 1;
		}
		if (High < Low)
			break;
	}

	result = NULL;

	if (High >= Low && (func_index = *(WORD *)(NameOrdinals + 2 * Mid), func_index < pIED->NumberOfFunctions))
	{

		symbol_address = (PVOID)((PCHAR)ImageBase + 4 * func_index + pIED->AddressOfFunctions);

		result = (CHAR *)ImageBase + *(PULONG)symbol_address;

		*SymbolAddr = symbol_address;

		if (ReplaceValue)
		{
			//关闭保护
			PageProtectOff();

			InterlockedExchange(symbol_address, (PCHAR)ReplaceValue - (PCHAR)ImageBase);

			//开启保护
			PageProtectOn();
		}

		return result;
	}

	return result;

}

//释放MDL
VOID  HookPort_RemoveLockMemory(PMDL pmdl)
{
	MmUnlockPages(pmdl);
	IoFreeMdl(pmdl);
}

//************************************     
// 函数名称: HookPort_LockMemory     
// 函数说明：通过编程方式使用 MDL 绕过 KiServiceTable 的只读属性，需要借助 Windows 执行体组件中的 I/O 管理器以及
//			 内存管理器导出的一些函数，大致流程如下：
//           IoAllocateMdl() 分配一个 MDL 来描述 KiServiceTable->MmProbeAndLockPages() 把该 MDL 描述的 KiServiceTable 所
//           属物理页锁定在内存中，并赋予对这张页面的读写访问权限（实际是将描述该页面的 PTE 内容中的 “R” 标志位修改成 “W”）
//           ->MmGetSystemAddressForMdlSafe() 将 KiServiceTable 映射到另一片内核虚拟地址区域（一般而言，位于 rootkit 被加载
//           到的内核地址范围内）。
// IDA地址 ：sub_15A28
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/25     
// 返 回 值: PVOID     
// 参    数: PVOID VirtualAddress     
// 参    数: ULONG Length     
// 参    数: PVOID *Mdl_a3  
// 参    数: ULONG Version_Win10_Flag
//************************************  
PVOID HookPort_LockMemory(PVOID VirtualAddress, ULONG Length, PVOID *Mdl_a3,ULONG Version_Win10_Flag)
{
	PMDL Mdl_v3; // eax@1
	PMDL Mdl_v4; // eax@2
	PVOID result; // eax@3
	
	Mdl_v3 = IoAllocateMdl(VirtualAddress, Length, 0, FALSE, NULL);
	*Mdl_a3 = Mdl_v3;
	if (Mdl_v3)
	{
		MmProbeAndLockPages(Mdl_v3, KernelMode, (Version_Win10_Flag != 0 ? IoReadAccess : IoModifyAccess));
		Mdl_v4 = Mdl_v3;
		if (Mdl_v3->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL))		//仅当 _MDL 的 MdlFlags 字段内设置了 MDL_MAPPED_TO_SYSTEM_VA 或  MDL_SOURCE_IS_NONPAGED_POOL 比特位，MappedSystemVa 字段才有效。
			result = Mdl_v4->MappedSystemVa;
		else
			result = MmMapLockedPagesSpecifyCache(Mdl_v4, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	}
	else
	{
		result = 0;
	}
	return result;
}


//************************************     
// 函数名称: HookPort_CheckCpuNumber     
// 函数说明：获取CPU数目    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 参    数：IN RTL_OSVERSIONINFOEXW osverinfo
// 返 回 值: ULONG     
//************************************  
ULONG HookPort_CheckCpuNumber(IN RTL_OSVERSIONINFOEXW osverinfo)
{
	ULONG(NTAPI *pKeQueryActiveProcessorCountEx)(ULONG); // eax@3
	ULONG result; // eax@5
	UNICODE_STRING SystemRoutineName;
	RtlInitUnicodeString(&SystemRoutineName, L"KeQueryActiveProcessorCountEx");
	ULONG BuildNumber = osverinfo.dwBuildNumber;
	ULONG MinorVersion = osverinfo.dwMinorVersion;
	ULONG MajorVersion = osverinfo.dwMajorVersion;
	if (MajorVersion == 6
		&& MinorVersion >= 1)
	{
		pKeQueryActiveProcessorCountEx = MmGetSystemRoutineAddress(&SystemRoutineName);
		if (MmIsAddressValid(pKeQueryActiveProcessorCountEx))
		{
			result = pKeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) > 32;
		}
		else
		{
			result = 0;
		}
	}
	else
	{
		result = 0;
	}
	return result;
}

PVOID NTAPI HookPort_QuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass)
{

	SIZE_T i;
	PVOID pbuff;
	NTSTATUS status;
	ULONG HookPortTag = 0x494E4654;
	for (i = 0x4000;; i *= 2)
	{
		pbuff = ExAllocatePoolWithTag(NonPagedPool, i, HookPortTag);
		if (!pbuff)
			break;

		status = ZwQuerySystemInformation(SystemInformationClass, pbuff, i, 0);
		if (status != STATUS_INFO_LENGTH_MISMATCH)
		{
			if (STATUS_SUCCESS == status)
				return pbuff;

			ExFreePool(pbuff);
			return NULL;
		}
		ExFreePool(pbuff);
	}
	return NULL;
}


//
// 此函数查找或修改ModuleName指定的模块中的FunctionName指定的函数
//
//sub_105AA
PULONG NTAPI HookPort_HookImportedFunction(PVOID pModuleBase,
	ULONG ModuleSize,
	CONST CHAR *FunctionName,
	CONST CHAR *ModuleName,
	PVOID *RetValue)
{

	PULONG						pOriginalProc = NULL;
	ULONG   					VirtualAddress = NULL;
	ULONG   					Size, i;
	PCHAR						pName;
	PIMAGE_DOS_HEADER  			pDH = NULL;
	PIMAGE_NT_HEADERS			pNtH = NULL;
	PIMAGE_IMPORT_DESCRIPTOR 	pImportTable;
	PIMAGE_THUNK_DATA			pIAT, pINT;
	ULONG                       Count;
	PIMAGE_IMPORT_BY_NAME		pIIBN;

	if (sizeof(IMAGE_DOS_HEADER) > ModuleSize)
		return NULL;

	pDH = (PIMAGE_DOS_HEADER)pModuleBase;

	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	if (pDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) > ModuleSize)
		return NULL;

	pNtH = (PIMAGE_NT_HEADERS)((PCHAR)pModuleBase + pDH->e_lfanew);
	if (pNtH->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}
	//1. 获取导入表
	// 1.1 获取导入表的RVA与大小
	VirtualAddress = pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	Size = pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (!VirtualAddress || !Size)
	{
		return NULL;
	}
	//2. 遍历导入表块
	//  因为一个exe可能会导入多个DLL，而每一个Dll对应着一个导入表
	//  多个导入表就形成一个导入表块
	//  这个导入表块是以全0结尾(全0结尾指的是整个结构体都是0)
	for (pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((PCHAR)pModuleBase + VirtualAddress); pImportTable->FirstThunk; pImportTable++)
	{
		if (!ModuleName || !_stricmp((const CHAR*)(pImportTable->Name + (ULONG)pModuleBase), ModuleName))
		{
			//得到导入名称表的地址
			pINT = (PIMAGE_THUNK_DATA)(pImportTable->OriginalFirstThunk + (ULONG)pModuleBase);
			Count = 0;
			while (pINT->u1.AddressOfData != 0)
			{
				if (pINT->u1.AddressOfData <= (ULONG)pModuleBase || pINT->u1.AddressOfData >= (ULONG)pModuleBase + ModuleSize)
				{
					pIIBN = (PIMAGE_IMPORT_BY_NAME)((PCHAR)pModuleBase + pINT->u1.AddressOfData);
				}
				else
				{
					pIIBN = (PIMAGE_IMPORT_BY_NAME)(pINT->u1.AddressOfData);
				}
				pName = pIIBN->Name;
				if (!strcmp(pName, FunctionName))
				{
					Count = Count * 4;
					pIAT = (PIMAGE_THUNK_DATA)((pImportTable->FirstThunk + (ULONG)pModuleBase) + Count);
					*RetValue = &pIAT->u1.Function;
					return pIAT->u1.Function;
				}
				++pINT;
				++Count;
			}
		}
	}
	return NULL;

}

BOOLEAN  HookPort_FindModuleBaseAddress(ULONG func_addr, PVOID *pModuleBase_a2, ULONG *ModuleSize_a3, PVOID *FilterRuleName, ULONG RuleNameLen)
{
	NTSTATUS status; // eax@5

	ULONG    uCount; // eax@8  
	PSYSTEM_MODULE_INFORMATION    pSysModule;

	ULONG ReturnLength; // [sp+Ch] [bp-14h]@5  
	PCHAR  pModuleInfo = NULL; // [sp+10h] [bp-10h]@8
	size_t	BufLen = 4096; // [sp+14h] [bp-Ch]@12
	ULONG ModuleBase;
	PCHAR            pName = NULL;
	ULONG            ui = 0;
	ULONG HookPortTag = 0x494E4654;
	//1、获取所有模块内容
	do {

		if (pModuleInfo)
			ExFreePool(pModuleInfo);

		pModuleInfo = ExAllocatePoolWithTag(NonPagedPool, BufLen, HookPortTag);

		if (!pModuleInfo) {

			return 0;

		}

		status = ZwQuerySystemInformation(SystemModuleInformation, pModuleInfo, BufLen, &ReturnLength);
		if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH) {
			ExFreePool(pModuleInfo);
			return 0;
		}

		BufLen += 4096;

	} while (!NT_SUCCESS(status));

	uCount = (ULONG)*(ULONG *)pModuleInfo;
	pSysModule = (PSYSTEM_MODULE_INFORMATION)(pModuleInfo + sizeof(ULONG));

	//2、找到指定模块
	while (1)
	{
		ModuleBase = pSysModule->Base;
		if (func_addr >= ModuleBase && func_addr <= ModuleBase + pSysModule->Size)
		{
			break;
		}
		if (++ui >= uCount)
		{
			ExFreePool(pModuleInfo);
			return 0;
		}
		pSysModule++;
	}
	*pModuleBase_a2 = pSysModule->Base;
	*ModuleSize_a3 = pSysModule->Size;

	//3、将驱动自身名字设置为规则名字(没用的部分)
	if (FilterRuleName)
	{
		pName = strrchr(pSysModule->ImageName, '\\');
		if (pName)
		{
			++pName;
		}
		else
		{
			pName = pSysModule->ImageName;
		}
		if (RuleNameLen <= strlen(pName))
		{
			RtlCopyMemory(FilterRuleName, pName, RuleNameLen - 1);
			FilterRuleName[RuleNameLen - 1] = 0;
		}
	}
	ExFreePool(pModuleInfo);
	return 1;

}

//************************************     
// 函数名称: HookPort_GetModuleLoadOrderIndex     
// 函数说明：根据本驱动对象的成员(DriverObject->DriverStart)获取自身LoadOrderIndex 
// IDA地址 ：sub_16E2C
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/05     
// 返 回 值: BOOLEAN NTAPI     
// 参    数: PVOID   pModuleBase       【In】 DriverObject->DriverStart
// 参    数: ULONG * LoadOrderIndex    【Out】加载顺序
//************************************  
BOOLEAN  HookPort_GetModuleLoadOrderIndex(IN PVOID pModuleBase, OUT ULONG *LoadOrderIndex)
{
	NTSTATUS status; // eax@5

	ULONG    uCount; // eax@8  
	PSYSTEM_MODULE_INFORMATION    pSysModule;

	ULONG  ReturnLength; // [sp+Ch] [bp-14h]@5  
	PCHAR  pModuleInfo = NULL; // [sp+10h] [bp-10h]@8
	size_t BufLen = 4096; // [sp+14h] [bp-Ch]@12
	ULONG  HookPortTag = 0x494E4654;
	PCHAR  pName = NULL;
	ULONG  ui;

	do {

		if (pModuleInfo)
			ExFreePool(pModuleInfo);

		pModuleInfo = ExAllocatePoolWithTag(NonPagedPool, BufLen, HookPortTag);

		if (!pModuleInfo)
		{
			return 0;
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, pModuleInfo, BufLen, &ReturnLength);
		if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH) {
			ExFreePool(pModuleInfo);
			return 0;
		}

		BufLen += 4096;

	} while (!NT_SUCCESS(status));


	uCount = (ULONG)*(ULONG *)pModuleInfo;
	pSysModule = (PSYSTEM_MODULE_INFORMATION)(pModuleInfo + sizeof(ULONG));


	for (ui = 0; ui < uCount; ui++)
	{
		if (pSysModule->Base == pModuleBase)
			break;
		pSysModule++;
	}


	if (ui >= uCount)
	{
		ExFreePool(pModuleInfo);
		return 0;
	}
	if (LoadOrderIndex)
	{
		*LoadOrderIndex = pSysModule->LoadOrderIndex;
	}
	ExFreePool(pModuleInfo);
	return TRUE;
}

ULONG HookPort_CheckSysVersion(IN RTL_OSVERSIONINFOEXW osverinfo, IN PVOID *NtImageBase)
{
	ULONG result;
	ULONG i_v1;
	IMAGE_DOS_HEADER* pDosHeader;
	IMAGE_NT_HEADERS* pNtHander;
	ULONG NT_TimeDateStamp;
	UNICODE_STRING SystemRoutineName;
	PVOID pNtBuildLab;
	//Nt内核合法的创建时间（）与上面的Global_CheckBuildNumberBuff是一一对应关系
	ULONG CheckTimeDateStampBuff[] = {
		0x51FC72EC,		//NT 5.1 - Windows XP - 2600   08 / 03 / 2013 03 : 03 : 08
		0x5201A540,		//vista 6000                   02 / 17 / 2014 05 : 59 : 28
		0x5201A540,     //vista sp1 6001               02 / 17 / 2014 05 : 59 : 28
		0x5201A540,     //vista sp2 6002               02 / 17 / 2014 05 : 59 : 28
		0x533D2D08,		//Win7 7600                    04 / 03 / 2014 09 : 42 : 32
		0x533D2D08,     //Win7 7601                    04 / 03 / 2014 09 : 42 : 32
		0x538BEBD2,		//‭Win8 9200‬                    06 / 02 / 2014 03 : 13 : 22
		0x53F84463		//Win8 9600                    08 / 23 / 2014 07 : 36 : 03
	};
	//合法的版本号
	ULONG CheckBuildNumberBuff[] = {
		0x0A28,			//NT 5.1 - Windows XP - 2600
		0x1770,			//vista 6000
		0x1771,			//vista sp1 6001
		0x1772,			//vista sp2 6002
		0x1DB0,			//Win7 7600
		0x1DB1,			//Win7 7601
		0x23F0,			//‭Win8 9200‬	
		0x2580			//Win8 9600
	};
	ULONG BuildNumber = osverinfo.dwBuildNumber;
	ULONG MinorVersion = osverinfo.dwMinorVersion;
	ULONG MajorVersion = osverinfo.dwMajorVersion;
	result = dword_1B170;
	if (!dword_1B170 && NtImageBase)
	{
		//1、判断合法的版本号
		for (i_v1 = 0; i_v1 < sizeof(CheckBuildNumberBuff) / sizeof(ULONG); i_v1++)
		{
			//1、1 找到合法的即退出
			if (BuildNumber == CheckBuildNumberBuff[i_v1])
			{
				break;
			}
		}
		//1、2 版本不合法则退出
		if (i_v1 == 8)
		{
			dword_1B170 = 2;
			result = 2;
			return result;
		}
		//2、PE文件所有的结构体都是以IMAGE_开头
		IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)NtImageBase;
		//2、1 判断第一个字节是否是MZ头
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			dword_1B170 = 2;
			result = 2;
			return result;
		}
		//2、2 判断是否是有效的NT头
		pNtHander = (IMAGE_NT_HEADERS*)((DWORD)pDosHeader + pDosHeader->e_lfanew);
		if ((pNtHander->Signature != IMAGE_NT_SIGNATURE))
		{
			dword_1B170 = 2;
			result = 2;
			return result;
		}
		//3、 判断NT内核版本是否在于XXX时间之前创建
		NT_TimeDateStamp = pNtHander->FileHeader.TimeDateStamp;
		if (NT_TimeDateStamp > CheckTimeDateStampBuff[i_v1])
		{
			dword_1B170 = 2;
			result = 2;
			return result;
		}
		if (BuildNumber < 6000)
		{
			//VISTA之前
			KeSetSystemAffinityThread(1);
			ULONG KdVersionBlockAddress = 0;
			//主要是定位到NtBuildLab
			_asm
			{
					pushfd
					pushad
					mov eax, fs:[0x1c]		//_KPCR
					mov eax, [eax + 34h]	//KdVersionBlock
					mov KdVersionBlockAddress, eax
					popad
					popfd
			}
			if (KdVersionBlockAddress)
			{
				//ntkrnlpa.exe
				//.text:004424C0 B1 1D 00 F0 00 00 00 00                             _NtBuildNumber  dd 0F0001DB1h, 0
				pNtBuildLab = ((UCHAR)KdVersionBlockAddress + 0x230);
			}
			KeRevertToUserAffinityThread();
			if (!pNtBuildLab || !MmIsAddressValid(pNtBuildLab))
			{
				dword_1B170 = 2;
				result = 2;
				return result;
			}
		}
		else
		{
			//VISTA之后
			RtlInitUnicodeString(&SystemRoutineName, L"NtBuildLab");
			pNtBuildLab = MmGetSystemRoutineAddress(&SystemRoutineName);
			if (!pNtBuildLab || !MmIsAddressValid(pNtBuildLab))
			{
				dword_1B170 = 2;
				result = 2;
				return result;
			}
		}
		ULONG NtBuildLadLen = strlen(pNtBuildLab);
		if ((NtBuildLadLen < 0xB) || (NtBuildLadLen == 0xB))
		{
			dword_1B170 = 2;
			result = 2;
			return result;
		}

		//后面判断没什么用懒得写了
		dword_1B170 = 1;
		result = 1;
	}
	return result;
}