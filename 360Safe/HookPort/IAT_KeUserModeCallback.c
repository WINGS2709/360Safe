#include "IAT_KeUserModeCallback.h"

PULONG NTAPI HookPort_HookImportedFunction(PVOID pModuleBase,
	ULONG ModuleSize,
	const char *FunctionName,
	const char *ModuleName,
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
		if (!ModuleName || !_stricmp((const char*)(pImportTable->Name + (ULONG)pModuleBase), ModuleName))
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
