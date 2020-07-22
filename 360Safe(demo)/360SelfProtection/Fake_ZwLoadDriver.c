/*
1、问题 在ZwLoadDriver中 如果是用SCM加载驱动,那么得到的进程路径是server.exe,解决的方法是hook下面的函数
XP：
NtRequestWaitReplyPort 
Win7:
ZwAlpcSendWaitReceivePort 
*/
#include "Fake_ZwLoadDriver.h"


//加载驱动
NTSTATUS NTAPI Fake_ZwLoadDriver(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	LUID		   SeDebugPrivilege = { 0 };
	NTSTATUS       Status, result;
	HANDLE         CurrentProcessId = NULL;
	HANDLE         CurrentThreadId = NULL;
	HANDLE         KeyHandle = NULL;
	BOOLEAN        Flag = TRUE;							//判断services.exe是否被修改
	ULONG		   Tag = 0x206B6444u;
	SIZE_T		   NumberOfBytes = NULL;				//要new的大小
	UNICODE_STRING TestDriverServiceName;
	result = STATUS_SUCCESS;
	//系统加载驱动要调用ZwLoadDriver或者ZwSetSystemInformation函数来实现。而这两个函数又都必调用SeSinglePrivilegeCheck来检查权限
	//进程/线程有特权加载驱动程序
	SeDebugPrivilege = RtlConvertLongToLuid(SE_LOAD_DRIVER_PRIVILEGE);
	//0、获取ZwAllocateVirtualMemory原始函数
	PUNICODE_STRING In_DriverServiceName = *(ULONG*)((ULONG)ArgArray);
	if (myProbeRead(In_DriverServiceName, sizeof(UNICODE_STRING), sizeof(CHAR)) && !In_DriverServiceName->Length)
	{
		KdPrint(("ProbeRead(Fake_ZwLoadDriver：In_DriverServiceName) error \r\n"));
		return result;
	}
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//进程/线程有特权加载驱动程序
		//HOOK这个函数可以拦截驱动加载
		if (SeSinglePrivilegeCheck(SeDebugPrivilege, ExGetPreviousMode()))
		{
			//防止系统进程被修改
			if (Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_SERVICES_EXE, g_VersionFlag))
			{
				//发起来源信息（谁加载这个驱动）Fake_ZwRequestWaitReplyPort(WIN7) or Fake_ZwRequestWaitReplyPort(XP) 函数进行获取
				if (g_SourceDrivenLoad_CurrentProcessId && g_SourceDrivenLoad_CurrentThreadId)
				{
					//替换掉真实加载驱动意图者进程ID跟线程ID
					CurrentProcessId = g_SourceDrivenLoad_CurrentProcessId;
					CurrentThreadId = g_SourceDrivenLoad_CurrentThreadId;
				}
				else
				{
					//找不到默认就说发起源是services.exe
					CurrentProcessId = PsGetCurrentProcessId();
					CurrentThreadId = PsGetCurrentThreadId();
				}
				Flag = FALSE;
			}
			else
			{
				//被修改了默认就说发起源是services.exe
				CurrentProcessId = PsGetCurrentProcessId();
				CurrentThreadId = PsGetCurrentThreadId();
				Flag = TRUE;
			}
			//将参数In_DriverServiceName拷贝到一个临时变量存储，安全起见
			NumberOfBytes = In_DriverServiceName->Length * 2;
			TestDriverServiceName.Buffer = Safe_AllocBuff(NonPagedPool, NumberOfBytes, Tag);
			RtlCopyUnicodeString(&TestDriverServiceName, In_DriverServiceName);
			TestDriverServiceName.MaximumLength = In_DriverServiceName->MaximumLength;
			if (!TestDriverServiceName.Length)
			{
				return result;
			}
			//初始化OBJECT_ATTRIBUTES的内容
			OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
			ULONG             ulAttributes =
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
			InitializeObjectAttributes(
				&ObjectAttributes,								 // 返回初始化完毕的结构体
				&TestDriverServiceName,							 // 文件对象名称
				ulAttributes,									 // 对象属性
				NULL, NULL);									 // 一般为NULL
			Status = ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &ObjectAttributes);
			ExFreePool(TestDriverServiceName.Buffer);
			if (NT_SUCCESS(Status))
			{
				//拦截还是放行加载驱动
				result = Safe_CheckSys(KeyHandle, CurrentProcessId, CurrentThreadId, Flag);
				if (KeyHandle)
				{
					ZwClose(KeyHandle);
					KeyHandle = NULL;
				}
			}
		}
	}
	return result;
}