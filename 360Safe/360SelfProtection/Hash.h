#pragma once
#include <ntifs.h>
#include "defs.h"

/******************************计算******************************/
//计算哈希的函数
ULONG NTAPI Safe_15846_Hash(OUT ULONG Out_KeyBuff, IN PVOID In_pBuff, IN SIZE_T BuffSize);

ULONG NTAPI Safe_158F8_Hash(ULONG a1, ULONG a2);

ULONG NTAPI Safe_14FB0_Hash(ULONG result, ULONG a2, ULONG a3);

ULONG NTAPI Safe_14FE6_Hash(PCHAR pBuff, ULONG a2);
/******************************计算******************************/

/*****************************初始化*****************************/
ULONG NTAPI Safe_14F7C_Hash(OUT ULONG Out_pBuff);
/*****************************初始化*****************************/