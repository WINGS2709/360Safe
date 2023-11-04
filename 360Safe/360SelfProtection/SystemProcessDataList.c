/*
文件说明：
以下两个结构体是数组序号对应的
SystemInformationList保存PID信息
SYSTEM_INFORMATIONFILE_XOR保存文件信息
struct
{
ULONG SystemListPID[SYSTEMNUMBER];							//系统进程的PID
ULONG SystemListEprocess[SYSTEMNUMBER];						//系统进程的Eprocess
}SystemInformationList;										//与g_System_InformationFile_Data是一致的，g_System_InformationFile_Data保存文件信息，这个结构保存PID跟Eprocess

typedef struct _SYSTEM_INFORMATIONFILE_XOR
{
ULONG IndexNumber_LowPart;									//该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
union {														//判断条件        if ((FileInformation.IndexNumber.HighPart) || (FileInformation.IndexNumber.HighPart == FastfatFlag))
ULONG IndexNumber_HighPart;									//该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
ULONG XorResult;											//秘制操作        FileBasicInformation FILE_BASIC_INFORMATION FileBaInformation.CreationTime.LowPart ^ FileBaInformation.ChangeTime.HighPart;
} u;
ULONG VolumeSerialNumber;									//序列号体积      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
}SYSTEM_INFORMATIONFILE_XOR, *PSYSTEM_INFORMATIONFILE_XOR;
*/
#include "SystemProcessDataList.h"


//判断是否存在
BOOLEAN NTAPI Safe_QuerySystemInformationList(IN PEPROCESS Process, IN ULONG Index)
{
	return ((g_dynData->SystemInformationList.SystemListEprocess[Index] == Process
		|| !Index)
		&& (g_dynData->SystemInformationList.SystemListEprocess[0x15] == Process,
		g_dynData->SystemInformationList.SystemListEprocess[0x16] == Process,
		g_dynData->SystemInformationList.SystemListEprocess[0x17] == Process)
		);
}

//功能：
//如果打开的是指定的系统进程，并且文件信息校验正确，就设置对应的PID和Eprocess
//返回值：
//0：非法序号、获取文件信息失败、cmp比较非系统进程
//1、其他返回
BOOLEAN NTAPI Safe_InsertSystemInformationList(IN PEPROCESS Process, IN ULONG Index, IN ULONG Version_Flag)
{
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN Result = NULL;
	HANDLE HandleToProcess = NULL;
	PVOID  pProcessImageFileNameBuff = NULL;
	ULONG ProcessImageFileNameBuffLen = 0x1256;							//路径地址最大长度	
	ULONG ReturnLength = NULL;
	ULONG Tag = 0x206B6444u;
	SYSTEM_INFORMATIONFILE_XOR System_InformationFile = { 0 };			//文件信息
	//1、去除重复操作，是否存在或则Index为0
	if (Safe_QuerySystemInformationList(Process, Index))
	{
		return TRUE;
	}
	//2、判断版本
	if (Version_Flag == WINDOWS_VERSION_2K)
	{
		//低版本无视，懒的逆没有对应的虚拟机
		KdPrint(("低版本无视，懒的逆没有对应的虚拟机\t\n"));
		return FALSE;
	}
	//3、判断是不是自身
	if (Process == IoGetCurrentProcess())
	{
		HandleToProcess = NtCurrentProcess();
	}
	else if (!NT_SUCCESS(ObOpenObjectByPointer(Process, OBJ_FORCE_ACCESS_CHECK, NULL, PROCESS_ALL_ACCESS, (PVOID)*PsProcessType, KernelMode, &HandleToProcess)))
	{
		return TRUE;
	}
	//4、new空间，然后获取路径地址
	pProcessImageFileNameBuff = Safe_AllocBuff(NonPagedPool, ProcessImageFileNameBuffLen, Tag);
	if (!pProcessImageFileNameBuff)
	{
		//4、1 !=-1表示用ObOpenObjectByPointer获取的，需要释放
		if (HandleToProcess != NtCurrentProcess())
		{
			ZwClose(HandleToProcess);
		}
		return TRUE;
	}
	Status = ZwQueryInformationProcess(HandleToProcess, ProcessImageFileName, pProcessImageFileNameBuff, ProcessImageFileNameBuffLen, &ReturnLength);
	//4、2 使用完毕记得释放ObOpenObjectByPointer获取的句柄
	if (HandleToProcess != NtCurrentProcess())
	{
		ZwClose(HandleToProcess);
	}
	if (!NT_SUCCESS(Status))
	{
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			Result = 0;
		}
		else
		{
			Result = 1;
		}
		ExFreePool(pProcessImageFileNameBuff);
		return Result;
	}
	//5、对ProcessImageFileName信息进行文件信息校验（其实是异或）
	Status = Safe_KernelCreateFile(pProcessImageFileNameBuff, (ULONG)&System_InformationFile);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(pProcessImageFileNameBuff);
		return FALSE;
	}
	ExFreePool(pProcessImageFileNameBuff);
	if (!System_InformationFile.IndexNumber_LowPart && !System_InformationFile.VolumeSerialNumber && !System_InformationFile.u.IndexNumber_HighPart)
	{
		return TRUE;
	}
	//6、后面就是填充系统进程信息
	if (Index <= SYSTEMNUMBER)
	{
		//7、判断打开的是不是系统进程，并且未被修改过的
		//Safe_InitializeSystemInformationFile函数记录着g_System_InformationFile_Data的24个进程详细信息
		if ((System_InformationFile.IndexNumber_LowPart == g_System_InformationFile_Data[Index].IndexNumber_LowPart) &&
			(System_InformationFile.VolumeSerialNumber == g_System_InformationFile_Data[Index].VolumeSerialNumber) &&
			(System_InformationFile.u.IndexNumber_HighPart == g_System_InformationFile_Data[Index].u.IndexNumber_HighPart)
			)
		{
			//8、非零填充对应的PID和Eprocess
			if (Index)
			{
				g_dynData->SystemInformationList.SystemListEprocess[Index] = (ULONG)Process;
				g_dynData->SystemInformationList.SystemListPID[Index] = Safe_pPsGetProcessId(Process);
			}
			else if (g_dynData->SystemInformationList.SystemListEprocess[0])
			{
				if (g_dynData->SystemInformationList.SystemListEprocess[0x15])
				{
					if (g_dynData->SystemInformationList.SystemListEprocess[0x16])
					{
						if (!g_dynData->SystemInformationList.SystemListEprocess[0x17])
						{
							g_dynData->SystemInformationList.SystemListEprocess[0x17] = (ULONG)Process;
							g_dynData->SystemInformationList.SystemListPID[0x17] = Safe_pPsGetProcessId((PVOID)Process);
						}
					}
					else
					{
						g_dynData->SystemInformationList.SystemListEprocess[0x16] = (ULONG)Process;
						g_dynData->SystemInformationList.SystemListPID[0x16] = Safe_pPsGetProcessId((PVOID)Process);
					}
				}
				else
				{
					g_dynData->SystemInformationList.SystemListEprocess[0x15] = (ULONG)Process;
					g_dynData->SystemInformationList.SystemListPID[0x15] = Safe_pPsGetProcessId((PVOID)Process);
				}
			}
			else
			{
				g_dynData->SystemInformationList.SystemListEprocess[0] = (ULONG)Process;
				g_dynData->SystemInformationList.SystemListPID[0] = Safe_pPsGetProcessId(Process);
			}
			return TRUE;
		}
	}
	return FALSE;
}

//Safe_Initialize_Data函数里面的
//初始化系统进程函数
NTSTATUS Safe_InitializeSystemInformationFile()
{
	UNICODE_STRING DestinationString;
	//1、初始化g_System_InformationFile_Data数组
	RtlZeroMemory(g_System_InformationFile_Data, sizeof(SYSTEM_INFORMATIONFILE_XOR)*SYSTEMNUMBER);
	//2、填充g_System_InformationFile_Data数组保存各种系统进程信息
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\csrss.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[0]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\explorer.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[1]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\svchost.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[2]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\ctfmon.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[3]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\msctf.dll");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[4]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\services.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[5]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\browseui.dll");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[6]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\convert.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[7]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\autochk.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[8]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\autoconv.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[9]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\chkdsk.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[10]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\autofmt.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[11]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\chkntfs.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[12]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\lsass.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[13]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\dllhost.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[14]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\ieframe.dll");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[15]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\mshtml.dll");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[16]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\riched20.dll");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[17]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\smss.exe");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[18]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\uxtheme.dll");
	Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[19]);
	RtlInitUnicodeString(&DestinationString, L"\\SystemRoot\\System32\\wininit.exe");
	return Safe_KernelCreateFile(&DestinationString, (ULONG)&g_System_InformationFile_Data[20]);
}

//核对csrss.exe、svchost.exe、dllhost.exe合法性
BOOLEAN NTAPI Safe_CheckSysProcess()
{
	BOOLEAN Result = FALSE;
	if (Safe_QuerySystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_DLLHOST_EXE)
		|| g_Win2K_XP_2003_Flag
		&& ((Safe_QuerySystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_SVCHOST_EXE, g_VersionFlag))
		|| (g_VersionFlag == WINDOWS_VERSION_8_9600 || g_VersionFlag == ‬WINDOWS_VERSION_10) && (Safe_QuerySystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_CSRSS_EXE, g_VersionFlag))
		|| (Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_SVCHOST_EXE, g_VersionFlag))
		|| (g_VersionFlag == WINDOWS_VERSION_8_9600 || g_VersionFlag == ‬WINDOWS_VERSION_10) && (Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_CSRSS_EXE, g_VersionFlag))))
	{
		Result = TRUE;
	}
	else
	{
		Result = Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_DLLHOST_EXE,g_VersionFlag) != 0;
	}
	return Result;
}


//过滤掉csrss.exe和lsass.exe
BOOLEAN NTAPI Safe_CheckSysProcess_Csrss_Lsass(IN HANDLE In_Handle)
{
	BOOLEAN		Result = TRUE;
	NTSTATUS    Status = STATUS_SUCCESS;
	PEPROCESS   pPeprocess = NULL;
	UCHAR		ImageFileNameBuff[0x356] = { 0 };
	Status = ObReferenceObjectByHandle(In_Handle, NULL, PsProcessType, UserMode, &pPeprocess, 0);
	if (NT_SUCCESS(Status))
	{
		//获取要打开句柄的路径
		Safe_PsGetProcessImageFileName(pPeprocess, &ImageFileNameBuff, sizeof(ImageFileNameBuff));
		ObfDereferenceObject(pPeprocess);
		//过滤掉csrss.exe和lsass.exe
		if (_stricmp(&ImageFileNameBuff,"csrss.exe"))			//打开句柄进程名是"csrss.exe"返回TRUE
		{
			if (_stricmp(&ImageFileNameBuff, "lsass.exe")		//打开句柄进程名非"lsass.exe"返回FALSE
				|| !g_dynData->SystemInformation.Userinit_Flag	//打开句柄进程名是"lsass.exe" 并且 userinit.exe进程未启动
				&& g_Win2K_XP_2003_Flag							//低版本
				&& (Safe_QuerySystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_WININIT_EXE, g_VersionFlag))
				|| (Safe_QuerySystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_DLLHOST_EXE, g_VersionFlag))
				|| (Safe_QuerySystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_CSRSS_EXE, g_VersionFlag))
				|| !g_dynData->SystemInformation.Userinit_Flag
				&& g_Win2K_XP_2003_Flag
				&& (Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_WININIT_EXE, g_VersionFlag))
				|| (Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_DLLHOST_EXE, g_VersionFlag))
				|| (Safe_InsertSystemInformationList(IoGetCurrentProcess(), SYSTEMROOT_SYSTEM32_CSRSS_EXE, g_VersionFlag)))
			{
				Result = FALSE;
			}
		}
	}
	else
	{
		Result = FALSE;
	}
	return Result;
}

//coherence.exe
BOOLEAN NTAPI Safe_CheckSysProcess_Coherence()
{
	BOOLEAN					  Result = FALSE;
	NTSTATUS				  Status = STATUS_SUCCESS;
	ULONG					  ReturnLength = NULL;
	PROCESS_BASIC_INFORMATION ProcessInfo = { 0 };
	PEPROCESS				  Process = NULL;

	//1、获取进程信息
	Status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, (PVOID)&ProcessInfo, sizeof(PROCESS_BASIC_INFORMATION), &ReturnLength);
	//由coherence.exe调用
	if (Safe_CmpImageFileName("coherence.exe") && NT_SUCCESS(Status))
	{
		//2、根据ID获取对应的Eprocess结构
		Status = PsLookupProcessByProcessId(ProcessInfo.InheritedFromUniqueProcessId, &Process);
		if (NT_SUCCESS(Status))
		{
			if (Safe_InsertSystemInformationList(Process, SYSTEMROOT_SYSTEM32_SERVICES_EXE,g_VersionFlag))
			{
				Result = TRUE;
			}
			//引用计数-1
			ObfDereferenceObject(Process);
		}
	}
	return Result;
}