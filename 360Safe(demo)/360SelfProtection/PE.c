#include "PE.h"


PVOID Safe_GetSymbolAddress(PANSI_STRING SymbolName, PVOID NtImageBase)
{

	PVOID pModuleBase;
	ULONG ModuleSize;

	PVOID SymbolAddr, result = NULL;
	result = Safe_GetAndReplaceSymbol(NtImageBase, SymbolName, NULL, &SymbolAddr);

	return result;
}

//************************************     
// 函数名称: Safe_GetAndReplaceSymbol     
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
PVOID NTAPI Safe_GetAndReplaceSymbol(PVOID ImageBase, PANSI_STRING SymbolName, PVOID ReplaceValue, PVOID *SymbolAddr)
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

		return result;
	}

	return result;

}

ULONG NTAPI Safe_RvaToVa(IN PVOID pModuleBase, ULONG dwRva)
{
	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)pModuleBase;

	IMAGE_NT_HEADERS *pNtHeader =   /*换行*/
		(IMAGE_NT_HEADERS*)((DWORD)pDosHeader + pDosHeader->e_lfanew);

	// 得到区段个数
	ULONG   dwSectionNumber = pNtHeader->FileHeader.NumberOfSections;

	// 得到第一个区段
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	// 遍历区段表，找到RVA所在的区段
	/*
	* 每个偏移，不管是在文件中，还是在内存中，它们距离区段开始位置的距离
	* 总是相等的。
	* 而且，区段表中，保存着两个开始偏移：
	*  1. 文件中的开始偏移
	*  2. 内存中的开始偏移
	* 具体过程：
	*  找到RVA所在区段， 然后计算出这个RVA到区段在内存中的开始位置的距离。
	*  用这个距离加上区段在文件中的开始位置就得到文件偏移了
	*/

	for (ULONG i = 0; i < dwSectionNumber; ++i) {

		// 判断RVA是否在当前的区段中

		DWORD dwSectionEndRva =   /*换行*/
			pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData;

		if (dwRva >= pSectionHeader[i].VirtualAddress
			&& dwRva <= dwSectionEndRva) {

			// 计算出RVA对应的内存偏移
			// 公式：
			// 文件偏移  =  RVA - 区段的起始RVA + 区段的起始文件偏移
			// 内存偏移  =  文件偏移 + pModuleBase
			ULONG dwTemp = dwRva - pSectionHeader[i].VirtualAddress;
			ULONG dwOffset = dwTemp + pSectionHeader[i].PointerToRawData;
			ULONG dwVa = dwOffset + (ULONG)pModuleBase;
			return dwVa;
		}
	}
	return 0;
}



//检查PE文件基本信息
BOOLEAN NTAPI Safe_CheckPeFile(IN PVOID pModuleBase)
{
	// PE文件所有的结构体都是以 IMAGE_ 开头
	//PIMAGE_DOS_HEADER => IMAGE_DOS_HEADER*
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pModuleBase;

	// 判断第一个字段是否MZ
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// 判断是否是有效的NT头
	IMAGE_NT_HEADERS* pNtHeader =
		(IMAGE_NT_HEADERS*)(pDosHeader->e_lfanew + (DWORD)pDosHeader);

	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	//节区不能为0
	if (!pNtHeader->FileHeader.NumberOfSections)
	{
		return FALSE;
	}
	return TRUE;
}

//废弃。
BOOLEAN NTAPI Safe_17C8A(IN PVOID pModuleBase, IN ULONG ModuleSize)
{
	PIMAGE_DOS_HEADER  			pDH = NULL;
	PIMAGE_NT_HEADERS			pNtH = NULL;
	PIMAGE_DATA_DIRECTORY       pDataDirectory = NULL;
	//1、PE标志位判断
	if (!Safe_CheckPeFile(pModuleBase))
	{
		return FALSE;
	}
	// 得到DOS头
	pDH = (PIMAGE_DOS_HEADER)pModuleBase;
	// 得到Nt头（为了得到扩展头得先找到Nt头）
	pNtH = (PIMAGE_NT_HEADERS)((PCHAR)pModuleBase + pDH->e_lfanew);

	//2、获取资源表地址和大小
    pDataDirectory = (IMAGE_DATA_DIRECTORY*)&pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	//RVA转换成Va
	PIMAGE_RESOURCE_DIRECTORY pRoot = Safe_RvaToVa(pModuleBase, pDataDirectory->VirtualAddress);
	IMAGE_RESOURCE_DIRECTORY*    pDir2;// 资源目录
	IMAGE_RESOURCE_DIRECTORY*    pDir3;// 资源目录

	IMAGE_RESOURCE_DIRECTORY_ENTRY* pEntry1;//目录入口
	IMAGE_RESOURCE_DIRECTORY_ENTRY* pEntry2;//目录入口
	IMAGE_RESOURCE_DIRECTORY_ENTRY* pEntry3;//目录入口

	IMAGE_RESOURCE_DATA_ENTRY*      pDataEntry;// 资源数据入口
	IMAGE_RESOURCE_DIR_STRING_U*    pIdString; // 保存Id的字符串

	// +----------------+
	// |    目录        |
	// +----------------+
	//    +-------------+      |- id(有字符串型的ID,和整型的ID)
	//    |   目录入口   | ==> |
	//    +-------------+      |- 偏移(可能偏移到目录,可能偏移到数据)
	//    +-------------+ 
	//    |   目录入口   | 
	//    +-------------+ 
	//    +-------------+ 
	//    |   目录入口   | 
	//    +-------------+ 
	/* 把第一层所有的目录入口都遍历出来 */
	// 得到第一个目录入口的地址,第一个目录紧跟着IMAGE_RESOURCE_DIRECTORY后面
	pEntry1 = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pRoot + 1);
	for (ULONG i = 0;
		i < pRoot->NumberOfIdEntries + pRoot->NumberOfNamedEntries;
		i++, pEntry1++) {

	}
	return TRUE;
}
