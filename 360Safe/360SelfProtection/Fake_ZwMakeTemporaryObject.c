/*
参考资料：
1、浅析windows对象管理            
网址：https://bbs.pediy.com/thread-74430-1.htm
*/
#include "Fake_ZwMakeTemporaryObject.h"

#define WHILEDEVICENUMBER_ZWMAKETEMPORARYOBJECT 0xD
//要拦截的白名单设备名称
PWCHAR g_WhiteDeviceName_ZwMakeTemporaryObject[WHILEDEVICENUMBER_ZWMAKETEMPORARYOBJECT + 1] = {
	L"\\Device\\360AntiHacker",
	L"\\Device\\360Camera",
	L"\\Device\\360HookPort",
	L"\\Device\\360SelfProtection",
	L"\\Device\\360SearchHotkey",
	L"\\Device\\360SpShadow0",
	L"\\Device\\360TdiFilter",
	L"\\Device\\BAPI",
	L"\\Device\\DsArk",
	L"\\Device\\DsArk",
	L"\\Device\\qutmipc",
	L"\\FileSystem\\Filters\\qutmdrv",			//sFilters
	L"\\Device\\360AntiHijack",
};


//************************************     
// 函数名称: Fake_ZwMakeTemporaryObject     
// 函数说明：防止恶意删除受保护的永久对象  
//           驱动程序删除一个持久对象的惟一方法, 是通过调用ZwMakeTemporaryObject例程, 将对象转换为临时对象
//           InitializeObjectAttributes创建对象OBJ_PERMANENT标识，那它就是永久对象
//           删除一个永久性的对象, 需要经过下列步骤:
//           1调用ObDereferenceObject 把一个永久性的对象的引用记数减少到0
//           2调用ZwOpenXxx orZwCreateXxx 来获得该永久性对象的一个句柄
//           3或得句柄后调用ZwMakeTemporaryObject 把一个永久性的对象转化成一个临时的对象
//           4用得到的句柄调用ZwClose 删除该对象
//           所以确定一个对象是临时的和永久的由InitializeObjectAttributes 宏的Attributes 决定
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 返 回 值: NTSTATUS  NTAPI     
// 参    数: IN ULONG  CallIndex     
// 参    数: IN PVOID  ArgArray     
// 参    数: IN PULONG ret_func     
// 参    数: IN PULONG ret_arg     
//************************************  
NTSTATUS NTAPI Fake_ZwMakeTemporaryObject(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	PVOID		   Object = NULL;
	HANDLE         Out_Handle = NULL;
	UNICODE_STRING OutDestinationString = { 0 };					//Safe_ZwQuerySymbolicLinkObject函数的查找的符号链接路径
	UNICODE_STRING TempString1 = { 0 };
	BOOLEAN        ZwClose_Flag = FALSE;       
	//0、获取ZwMakeTemporaryObject原始参数
	HANDLE  In_Handle = *(ULONG*)((ULONG)ArgArray);
	//1、必须是应用层调用
	if (!ExGetPreviousMode())
	{
		return result;
	}
	//2、过滤掉非SymbolicLink类型
	if (!Safe_QueryObjectType(In_Handle, L"SymbolicLink"))
	{
		return result;
	}
	//3、调用者是保护进程：直接放行
	//   调用者非保护进程：防止删除受保护对象
	if (Safe_QueryWhitePID(PsGetCurrentProcessId()))
	{
		return result;
	}
	//4、Win7或则Win7+成立
	if (g_HighgVersionFlag)
	{
		Status = ObReferenceObjectByHandle(In_Handle, NULL, NULL, UserMode, &Object, NULL);
		if (!NT_SUCCESS(Status))
		{
			return result;
		}
		Status = ObOpenObjectByPointer(Object, OBJ_KERNEL_HANDLE, NULL, NULL, NULL, KernelMode, &Out_Handle);
		ObfDereferenceObject(Object);
		if (NT_SUCCESS(Status))
		{
			//标志位置1，表示In_HANDLE是ObOpenObjectByPointer返回的
			ZwClose_Flag = TRUE;
			In_Handle = Out_Handle;
		}
		else
		{
			return result;
		}
	}
	//5、根据句柄找到对应的符号链接路径
	if (!Safe_ZwQuerySymbolicLinkObject(In_Handle, &OutDestinationString))
	{
		//找不到符号链接路径直接返回
		return result;
	}
	//释放ObOpenObjectByPointer获取的句柄
	if (ZwClose_Flag)
	{
		ZwClose_Flag = FALSE;
		ZwClose(Out_Handle);
		Out_Handle = NULL;
	}
	//6、防止恶意删除受保护的对象
	for (ULONG i = 0; i < WHILEDEVICENUMBER_ZWMAKETEMPORARYOBJECT; i++)
	{
		//因为DriverName是UUNICODE_STRING类型所以我们要转换下
		RtlInitUnicodeString(&TempString1, g_WhiteDeviceName_ZwMakeTemporaryObject[i]);
		if (RtlEqualUnicodeString(&OutDestinationString, &TempString1, TRUE))
		{
			//找到了错误返回
			result = STATUS_ACCESS_DENIED;
			break;
		}
	}
	//记得释放分配空间
	ExFreePool(OutDestinationString.Buffer);
	return result;
}