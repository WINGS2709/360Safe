#pragma once
#include <ntddk.h>
#include "FilterHook.h"

//dword_1B0F8
PVOID		pOriginalKeUserModeCallbackAddr;

typedef
NTSTATUS
(NTAPI *pKeUserModeCallback)(
IN ULONG ApiNumber,
IN PVOID InputBuffer,
IN ULONG InputLength,
OUT PVOID *OutputBuffer,
IN PULONG OutputLength
);
//dword_1B0FC
pKeUserModeCallback OriginalKeUserModeCallback;

NTSTATUS NTAPI Filter_KeUserModeCallbackDispatcher(ULONG ApiNumber, PVOID InputBuffer, ULONG InputLength, PVOID *OutputBuffer, PULONG OutputLength);

//拦截DLL注入的
#define	ClientLoadLibrary_FilterIndex	0x4B
NTSTATUS NTAPI Filter_ClientLoadLibrary(IN ULONG ApiNumber, IN PVOID InputBuffer, IN ULONG InputLength, OUT PVOID *OutputBuffer, IN PULONG OutputLength);


//这个不清楚
#define	fnHkOPTINLPEVENTMSG_XX1_FilterIndex 0x7A  //不知道具体含义，待后续逆向
#define	fnHkOPTINLPEVENTMSG_XX2_FilterIndex 0x60  //不知道具体含义，待后续逆向
NTSTATUS NTAPI Filter_fnHkOPTINLPEVENTMSG(IN ULONG ApiNumber, IN PVOID InputBuffer, IN ULONG InputLength, OUT PVOID *OutputBuffer, IN PULONG OutputLength);

//拦截键盘消息的
#define	fnHkINLPKBDLLHOOKSTRUCT_FilterIndex 0x7B  
NTSTATUS NTAPI Filter_fnHkINLPKBDLLHOOKSTRUCT(IN ULONG ApiNumber, IN PVOID InputBuffer, IN ULONG InputLength, OUT PVOID *OutputBuffer, IN PULONG OutputLength);

//拦截模块加载的
#define	ClientImmLoadLayout_XX1_FilterIndex 0x61  //不知道具体含义，待后续逆向
#define	ClientImmLoadLayout_XX2_FilterIndex 0x7  //不知道具体含义，待后续逆向
NTSTATUS NTAPI Filter_ClientImmLoadLayout(IN ULONG ApiNumber, IN PVOID InputBuffer, IN ULONG InputLength, OUT PVOID *OutputBuffer, IN PULONG OutputLength, PULONG Result);
