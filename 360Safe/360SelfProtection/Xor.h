#pragma once
#include <ntifs.h>
#include "Data.h"
#include "ZwNtFunc.h"


NTSTATUS NTAPI Safe_KernelCreateFile(IN PANSI_STRING SymbolName, OUT PSYSTEM_INFORMATIONFILE_XOR System_Information);

//获取文件的基本信息，类似于文件信息校验之类的，后期用来二次校验
//一般打开文件时候会调用保存一次原始信息，后期二次调用检查
NTSTATUS NTAPI Safe_GetInformationFile(IN HANDLE Handle, OUT PSYSTEM_INFORMATIONFILE_XOR System_Information, IN KPROCESSOR_MODE AccessMode);
