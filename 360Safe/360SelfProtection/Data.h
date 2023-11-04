#pragma once
#include <ntddk.h>

#define DOSPATHSIZE	 520                    //Dos路径最大长度不超过520
#define PAGESIZE	 1024					//1页=1024
#define SAFEWHITEPROCESSNUMBER 0x7			//特殊白名单进程个数
#define SPECIALSIGN 0x3600FFFF				//特殊白名单的进程的终端ID(SessionId): pbi.InheritedFromUniqueProcessId 的进程名 == "services.exe"就等于3600FFFF，否则等于SessionId
#define THREADID_TABLE_MAXSIZE 0x11			//一共有0x11张这样的表 : 0x11 * 0x7d4 = 0x8514   _UNKNOWN_THREADID_TABLE
#define ILLEGALITYDLLPATHMAXSIZE 0XFFFF		//R3传递黑名单DLL路径最大长度0xFFFF

//系统进程列表个数
#define SYSTEMNUMBER						0x18						
#define SYSTEMNUMBERMAXIMUM					0x1A	

//文件信息列表个数
#define CRCLISTNUMBERMAXIMUM				0X2000		//最大容量

PDRIVER_OBJECT Global_DriverObject;

PDEVICE_OBJECT Global_SpShadowDeviceObject;

PDEVICE_OBJECT Global_SelfProtectionDeviceObject;

struct _DRIVER_OBJECT *Global_HookPort_DriverObject;			//HookPortDeviceObject->DriverObject ，检查驱动合法性MmIsDriverVerifying（Global_HookPort_DriverObject）

//未知
CHAR  g_UnknownBuffPath[0x100];
ULONG g_dword_34D60_Swtich;					//标记，填充置1，否则为0

ULONG g_dword_34678;						//用处未知

ULONG g_dword_3467C;						//用处未知

//IRP传递过来的,违规DLL路径
//在ClientLoadLibrary使用
UNICODE_STRING g_IllegalityDllPath;

//HookPort版本
ULONG g_HookPort_Version;					//我逆向的版本是0x3F1

//使用的全局变量
ULONG g_Win2K_XP_2003_Flag;					//Win2K、XP、2003成立置0，默认是1

//win7或则Win7以上版本成立
BOOLEAN g_HighgVersionFlag;						

//真实加载驱动意图者
ULONG g_SourceDrivenLoad_CurrentProcessId;	//真实加载驱动意图者进程ID
ULONG g_SourceDrivenLoad_CurrentThreadId;	//真实加载驱动意图者线程ID

//控制设置Fake函数的开关Safe_Initialize_SetFilterSwitchFunction();
//1清零，0重新挂钩
ULONG g_x360SelfProtection_Switch;			//ZwQuerySystemInformation函数使用，默认是1，会在Safe_IRP_Device_Control修改
//
ULONG g_SystemHotpatchInformation_Switch;		//ZwSetSystemInformation函数使用，默认是1，会在Safe_IRP_Device_Control修改

//dword_38720 
ULONG g_VersionFlag;						//版本标记

//当前驱动的Eprocess
PEPROCESS g_CurrentProcess;

//各种SpinLock	
KSPIN_LOCK g_SpinLock_34F50;				//无用的

//获取原始SrvTransaction2DispatchTable地址（不轻易改动）
NTSTATUS(NTAPI *g_OriginalSrvTransactionNotImplementedPtr)(PVOID);		//保存原始的g_OriginalSrvTransaction2DispatchTable[0xE]，因为要hook替换掉	
volatile ULONG g_HookSrvTransactionNotImplementedFlag;					//hook开关

//初始化部分关于符号链接的
//ArcName
UNICODE_STRING g_SystemBootDevice_SymLink;
UNICODE_STRING g_FirmwareBootDevice_SymLink;

//最后一组？？？？？？
UNICODE_STRING g_SystemBootDeviceMax_SymLink;
UNICODE_STRING g_FirmwareBootDeviceMax_SymLink;

typedef struct _WAITFOR_INFO
{
	LIST_ENTRY list;
	KEVENT Event;
	HANDLE tid;
	ULONG bypass_or_not;
}WAITFOR_INFO, *PWAITFOR_INFO;

/*********************主动拦截提示时与应用层的通信交互***********************/
//双向链表
WAITFOR_INFO g_wait_info_list;
KSPIN_LOCK   g_SpinLock_wait_info_list;
KSPIN_LOCK   g_request_list_lock;

LIST_ENTRY   g_can_check_hook_request_list_added_by_r3;
LIST_ENTRY   g_request_list;
ULONG	     g_request_counter;			//计数器
ULONG	     g_Addend;
/*********************主动拦截提示时与应用层的通信交互***********************/

//保存注册表信息的
typedef struct _REGEDIT_DATA
{
	ULONG g_i18n_Data_DWORD;						 //Safe_SetRegedit_i18h				  REG_DWORD类型信息
	ULONG g_SpShadow0_Data_DWORD;					 //Safe_SetRegedit_SpShadow0		  REG_DWORD类型信息
	WCHAR g_TextOutCache_REG_SZ[DOSPATHSIZE];		 //Safe_SetRegedit_TextOutCache       REG_SZ类型信息，实际保存\\??\\C:\\Program Files\\360\\360Safe\\Safemon\\drvmk.dat
	WCHAR g_360Safe_REG_SZ[DOSPATHSIZE];			 //Safe_SetRegedit_RULE_360Safe       REG_SZ类型信息，实际保存\\??\\C:\\Program Files\\360\\360Safe\\Safemon\\360u.dat
	//标志开关相关的
	struct
	{
	ULONG RULE_360SafeBox_Flag;				 // == RULE_360SafeBox置1
	ULONG RULE_360Safe_Flag;				 // == RULE_360Safe置1
	ULONG RULE_360sd_Flag;					 // == RULE_360sd置1
	ULONG RULE_TextOutCache_Flag;			 // g_TextOutCache_REG_SZ的标志位，成功置1
	ULONG RULE_360u_Flag;				     // g_360Safe_REG_SZ的标志位，成功置1
	}Flag;
}REGEDIT_DATA, *PREGEDIT_DATA;
REGEDIT_DATA g_Regedit_Data;




//保存系统进程信息的
//数组大小24个，但实际使用只有20个
typedef enum SYS_PROCESS_DETAIL {
	SYSTEMROOT_SYSTEM32_CSRSS_EXE,		   //0、\\SystemRoot\\System32\\csrss.exe");
	SYSTEMROOT_EXPLORER_EXE,               //1、\\SystemRoot\\explorer.exe");
	SYSTEMROOT_SYSTEM32_SVCHOST_EXE,       //2、\\SystemRoot\\System32\\svchost.exe");
	SYSTEMROOT_SYSTEM32_CTFMON_EXE,        //3、\\SystemRoot\\System32\\ctfmon.exe");
	SYSTEMROOT_SYSTEM32_MSCTF_DLL,         //4、\\SystemRoot\\System32\\msctf.dll");
	SYSTEMROOT_SYSTEM32_SERVICES_EXE,      //5、\\SystemRoot\\System32\\services.exe");
	SYSTEMROOT_SYSTEM32_BROWSEUI_DLL,      //6、\\SystemRoot\\System32\\browseui.dll");
	SYSTEMROOT_SYSTEM32_CONVERT_EXE,       //7、\\SystemRoot\\System32\\convert.exe");
	SYSTEMROOT_SYSTEM32_AUTOCHK_EXE,       //8、\\SystemRoot\\System32\\autochk.exe");
	SYSTEMROOT_SYSTEM32_AUTOCONV_EXE,      //9、\\SystemRoot\\System32\\autoconv.exe");
	SYSTEMROOT_SYSTEM32_CHKDSK_EXE,        //10、\\SystemRoot\\System32\\chkdsk.exe");
	SYSTEMROOT_SYSTEM32_AUTOFMT_EXE,       //11、\\SystemRoot\\System32\\autofmt.exe");
	SYSTEMROOT_SYSTEM32_CHKNTFS_EXE,       //12、\\SystemRoot\\System32\\chkntfs.exe");
	SYSTEMROOT_SYSTEM32_LSASS_EXE,         //13、\\SystemRoot\\System32\\lsass.exe");
	SYSTEMROOT_SYSTEM32_DLLHOST_EXE,       //14、\\SystemRoot\\System32\\dllhost.exe");
	SYSTEMROOT_SYSTEM32_IEFRAME_DLL,       //15、\\SystemRoot\\System32\\ieframe.dll");
	SYSTEMROOT_SYSTEM32_MSHTML_DLL,        //16、\\SystemRoot\\System32\\mshtml.dll");
	SYSTEMROOT_SYSTEM32_RICHED20_DLL,      //17、\\SystemRoot\\System32\\riched20.dll");
	SYSTEMROOT_SYSTEM32_SMSS_EXE,          //18、\\SystemRoot\\System32\\smss.exe");
	SYSTEMROOT_SYSTEM32_UXTHEME_DLL,       //19、\\SystemRoot\\System32\\uxtheme.dll");
	SYSTEMROOT_SYSTEM32_WININIT_EXE        //20、\\SystemRoot\\System32\\wininit.exe");
} SYS_PROCESS_DETAIL;

//版本信息的缩写
typedef enum WIN_VER_DETAIL {
	WINDOWS_VERSION_NONE,       //  0
	WINDOWS_VERSION_2K,
	WINDOWS_VERSION_XP,
	WINDOWS_VERSION_2K3,
	WINDOWS_VERSION_2K3_SP1_SP2,
	WINDOWS_VERSION_VISTA_2008,
	WINDOWS_VERSION_7,			//Win7  7100、7600、7601
	WINDOWS_VERSION_8_9200‬,
	WINDOWS_VERSION_8_9600,
	‬WINDOWS_VERSION_10			//Win10 10240、10586、>10586
} WIN_VER_DETAIL;



//nt内核与win32k基地址
typedef struct _HOOKPORT_NT_WIN32K_DATA
{
	//NT内核基地址与大小
	struct
	{
		PVOID NtImageBase;
		ULONG NtImageSize;
	}NtData;
	//ShadowSSDT表信息
	struct
	{
		//win10_14316版本之前
		PVOID ShadowSSDT_GuiServiceTableBase;
		ULONG ShadowSSDT_GuiNumberOfServices;
		PVOID ShadowSSDT_GuiParamTableBase;
		//win10_14316版本之后
		PVOID ShadowSSDT_GuiServiceTableBase_Win10_14316;
		ULONG ShadowSSDT_GuiNumberOfServices_Win10_14316;
		PVOID ShadowSSDT_GuiParamTableBase_Win10_14316;
	}ShadowSSDTTable_Data;
	//SSDT表信息
	struct
	{
		PVOID SSDT_KeServiceTableBase;
		ULONG SSDT_KeNumberOfServices;
		PVOID SSDT_KeParamTableBase;
	}SSDTTable_Data;
}HOOKPORT_NT_WIN32K_DATA, *PHOOKPORT_NT_WIN32K_DATA;

HOOKPORT_NT_WIN32K_DATA g_HookPort_Nt_Win32k_Data;

//偷懒写的贯穿所有的结构体
typedef struct _DYNAMIC_DATA
{
	ULONG dword_34DAC[0x20];									//未知，不知道装的是什么进程
	ULONG dword_34EA0[0x20];									//未知，不知道装的是什么进程
	ULONG dword_34D64;											//未知，不知道装的是什么进程
	ULONG dword_3323C;											//地址0x7F8000
	PVOID pCreateProcessAsUserW;								//LDR链方式获取的API函数地址
	PVOID pCreateProcessW;										//LDR链方式获取的API函数地址
	POBJECT_TYPE(*pObGetObjectType)(IN PVOID pObject);
	NTSTATUS(*pRtlFormatCurrentUserKeyPath)(_Out_ PUNICODE_STRING CurrentUserKeyPath);
	NTSTATUS(*pObDuplicateObject)(IN PEPROCESS SourceProcess,IN HANDLE SourceHandle,IN PEPROCESS TargetProcess OPTIONAL,OUT PHANDLE TargetHandle OPTIONAL,IN ACCESS_MASK DesiredAccess,IN ULONG HandleAttributes,IN ULONG Options,IN KPROCESSOR_MODE PreviousMode);						//NTSTATUS ObDuplicateObject(xxx);
	HANDLE(*pPsGetThreadProcessId)(IN PETHREAD Thread);			//HANDLE   PsGetThreadProcessId(PETHREAD Thread);
	HANDLE(*pPsGetProcessId)(IN PEPROCESS Process);				//HANDLE   PsGetProcessId(PEPROCESS Process);
	UCHAR *(*pPsGetProcessImageFileName)(IN PEPROCESS Process);	//UCHAR   *PsGetProcessImageFileName(PEPROCESS Process);
	ULONG (*pRtlGetActiveConsoleId_Win10_14393)(VOID);			
	PPEB(*pPsGetProcessPeb)(IN PEPROCESS Process);
	HANDLE(*pPsGetProcessInheritedFromUniqueProcessId)(IN PEPROCESS Process);
	NTSTATUS(*pPsGetProcessExitStatus)(__in PEPROCESS Process);
	struct 
	{
		ULONG dword_34DF4;										//+0x22c SecurityPort : (null) 
		ULONG _Eprocess_UniqueProcessIdIndex;					//_Eprocess->UniqueProcessId
		ULONG _Eprocess_ImageFileNameIndex;						//_Eprocess->ImageFileName
	}Eprocess_Offset;
	struct
	{
		ULONG dword_34E0C;
		ULONG dword_34E10;
		ULONG dword_34E14;
		ULONG dword_34E28;
		ULONG dword_34E2C;
		ULONG dword_34E30;
		ULONG dword_34E34;
		ULONG dword_34E18;
		ULONG dword_34E1C;
		ULONG dword_34E20;
		ULONG dword_34E24;
	}Int2E_Index;													//Int2E调用号
	struct                                                          //CreateProcessNotifyRoutine回调创建进程时保存信息(explorer.exe、userinit.exe、userinit.exe、userinit.exe)
	{
		ULONG Userinit_Flag;										//!stricmp(&v11, "userinit.exe") = 1;
		ULONG Explorer_Flag;										//!dword_34DE4 && !stricmp(&v11, "explorer.exe")
		ULONG Explorer_ProcessId;									//explorer.exe PID
		PROCESS_SESSION_INFORMATION Explorer_SessionId;					
		ULONG Winlogon_ProcessId;
		ULONG Wininit_ProcessId;									//wininit.exe
	}SystemInformation;
	struct 
	{
		ULONG SystemListPID[SYSTEMNUMBERMAXIMUM];					//系统进程的PID
		ULONG SystemListEprocess[SYSTEMNUMBERMAXIMUM];				//系统进程的Eprocess
	}SystemInformationList;											//与g_System_InformationFile_Data是一致的，g_System_InformationFile_Data保存文件信息，这个结构保存PID跟Eprocess
} DYNAMIC_DATA, *PDYNAMIC_DATA;

PDYNAMIC_DATA g_dynData;

//专门保存例如：
//\\SystemRoot\\System32\\csrss.exe、\\SystemRoot\\System32\\svchost.exe等系统进程的信息
//简单异或校验，初次打开记录值，后期二次校验
//防止恶意修改系统dll躲避检查，用来二次校验的判断有没有被修改
typedef struct _SYSTEM_INFORMATIONFILE_XOR
{
	ULONG IndexNumber_LowPart;				//该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
	union {									//判断条件        if ((FileInformation.IndexNumber.HighPart) || (FileInformation.IndexNumber.HighPart == FastfatFlag))
		ULONG IndexNumber_HighPart;			//该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
		ULONG XorResult;					//秘制操作        FileBasicInformation FILE_BASIC_INFORMATION FileBaInformation.CreationTime.LowPart ^ FileBaInformation.ChangeTime.HighPart;
	} u;
	ULONG VolumeSerialNumber;				//序列号体积      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
}SYSTEM_INFORMATIONFILE_XOR, *PSYSTEM_INFORMATIONFILE_XOR;

//0、\\SystemRoot\\System32\\csrss.exe");
//1、\\SystemRoot\\explorer.exe");
//2、\\SystemRoot\\System32\\svchost.exe");
//3、\\SystemRoot\\System32\\ctfmon.exe");
//4、\\SystemRoot\\System32\\msctf.dll");
//5、\\SystemRoot\\System32\\services.exe");
//6、\\SystemRoot\\System32\\browseui.dll");
//7、\\SystemRoot\\System32\\convert.exe");
//8、\\SystemRoot\\System32\\autochk.exe");
//9、\\SystemRoot\\System32\\autoconv.exe");
//10、\\SystemRoot\\System32\\chkdsk.exe");
//11、\\SystemRoot\\System32\\autofmt.exe");
//12、\\SystemRoot\\System32\\chkntfs.exe");
//13、\\SystemRoot\\System32\\lsass.exe");
//14、\\SystemRoot\\System32\\dllhost.exe");
//15、\\SystemRoot\\System32\\ieframe.dll");
//16、\\SystemRoot\\System32\\mshtml.dll");
//17、\\SystemRoot\\System32\\riched20.dll");
//18、\\SystemRoot\\System32\\smss.exe");
//19、\\SystemRoot\\System32\\uxtheme.dll");
//20、\\SystemRoot\\System32\\wininit.exe");
SYSTEM_INFORMATIONFILE_XOR g_System_InformationFile_Data[SYSTEMNUMBER];

//360Safe特殊进程
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
typedef struct _SAFE_WHITEPROCESS_DATA
{
	SYSTEM_INFORMATIONFILE_XOR SafeCrc;						//0-0x8      文件信息
	PVOID FileObject;										//0x0xC		 FILE_OBJECT文件对象信息
	ULONG SafeMonIndex;										//0x10	     SafeMon,查找该dos路径在列表第几项，ret_arg = 返回数组下标	
	UNICODE_STRING32 SafeName;							    //0x14-0x1c  对应的进程名称
	ULONG Flag;												//0x20		 执行到就置1
}SAFE_WHITEPROCESS_DATA, *PSAFE_WHITEPROCESS_DATA;

SAFE_WHITEPROCESS_DATA g_SafeWhiteProcess[SAFEWHITEPROCESSNUMBER];


//保存线程信息的
typedef struct _THREAD_INFORMATION
{
	ULONG	 Eprocess_PEB_Index;				//+0        _eprocess Peb              : Ptr32 _PEB									//Safe_Setoffset
	ULONG    Flag;								//+4        标识Eprocess_PEB_Index获取成功											//Safe_Setoffset
	PKTHREAD ValidSigna_THandle;				//+8		保存KeGetCurrentThread的返回值   二选一赋值：签名验证成功
	PKTHREAD InvaliditySigna_THandle;			//+0xc		保存KeGetCurrentThread的返回值   二选一赋值：签名验证失败
	PVOID    pPsDereferencePrimaryToken;		//+0x10		PsDereferencePrimaryToken函数地址
	PVOID    pZwQueryInformationToken;			//+0x14		ZwQueryInformationToken函数地址
	PVOID    pObGetObjectType;					//+0x18		ObGetObjectType函数地址	
	ULONG    ThreadContext_Eip;					//+0x1c		Fake_ZwCreateThread
	ULONG    UniqueProcessId;					//+0x20		Fake_ZwCreateThread
	HANDLE   CurrentProcessId_0;				//+0x24		PsGetCurrentProcessId				//二选一赋值,赋值函数：Fake_ZwWriteFile
	HANDLE   CurrentProcessId_1;				//+0x28		PsGetCurrentProcessId				//二选一赋值,赋值函数：Fake_ZwWriteFile
	PVOID    pIoGetDiskDeviceObjectPtr;			//+0x2C     Safe_IoGetDiskDeviceObject
	ULONG    Unknown12;						    //+0x30     
	ULONG    Unknown13;						    //+0x34     sub_1AB72
	ULONG    Unknown14;							//+0x38
	ULONG    Unknown15;							//+0x3C
}THREAD_INFORMATION,*PTHREAD_INFORMATION;

THREAD_INFORMATION g_Thread_Information;



//未命名的结构体_2
//目前了解的是：
//初始化线程ID表
//一共有0x11张这样的表 : 0x11 * 0x7d4 = 0x8514   
//每张表意义好像不一样的，后期待定把
//{
//		ULONG  ThreadIDNumber;  +0  < 0x1F2
//		Handle ThreadID[0x1F4]; +4
//}
typedef struct _UNKNOWN_THREADID_TABLE
{
	ULONG ThreadIDNumber;								// +0  < 0x1F2
	ULONG ThreadID[0x1F4];								// +4  线程句柄
}UNKNOWN_THREADID_TABLE, *PUNKNOWN_THREADID_TABLE;

PUNKNOWN_THREADID_TABLE g_ThreadID_Table;



//保存文件文件信息校验信息
//文件信息校验的SYSTEM_INFORMATIONFILE_XOR
typedef struct _ALL_INFORMATIONFILE_CRC
{
	ULONG FileCRCListNumber;										// +0   保存个数的东西
	SYSTEM_INFORMATIONFILE_XOR FileBuff[CRCLISTNUMBERMAXIMUM];		// +4   填充，后续知道再加
	KSPIN_LOCK	SpinLock;											// 末尾 自旋锁 
}ALL_INFORMATIONFILE_CRC, *P_ALL_INFORMATIONFILE_CRC;

P_ALL_INFORMATIONFILE_CRC g_All_InformationFile_CRC;



//主动防御拦截保存进程信息的结构体,R0保存拦截数据发送给R3显示
typedef struct _QUERY_PASS_R0SENDR3_DATA
{
	LIST_ENTRY Entry;								//0x0~0x4                    解释：指向g_request_list
	ULONG  Unknown_Flag_2;							//0x8					     解释：标志，作用未知
	HANDLE CheckWhitePID;							//0xC						 解释：判断是否是白名单进程   PsGetCurrentProcessId()
	HANDLE Unknown_CurrentThreadId_4;				//0x10                       解释：未知                   PsGetCurrentThreadId()
	HANDLE Unknown_CurrentThreadId_5;				//0x14                       解释：未知                   PsGetCurrentThreadId()
	HANDLE Unknown_Flag_6;							//0x18                       解释：标志，作用未知
	HANDLE Unknown_7;								//0x1C
	CHAR   ImagePathBuff[520];						//0x20~0x228				 解释：拦截的路径
	ULONG  Unknown_Flag_8A;							//0x228					     解释：标志，作用未知
	ULONG  Unknown_Flag_8B;							//0x22C					     解释：标志，作用未知
	PVOID  ApcContext;								//0x230					     解释：ZwWriteFile的参数4
	ULONG  UnknownBuff_234[0x17F];					//0x234~0x82C			     解释：未知
	ULONG  Error_Flag;								//0x830						 解释：错误码,R3负责显示对应的错误信息
	ULONG  Hash[4];									//0x834~0x840				 解释：哈希值
	ULONG  FileSize;								//0x844						 解释：专门保存拦截的白名单或则黑名单的文件大小
}QUERY_PASS_R0SENDR3_DATA, *PQUERY_PASS_R0SENDR3_DATA;

//dps srv!SrvTransaction2DispatchTable
////永恒之蓝漏洞
//kd> dps srv!SrvTransaction2DispatchTable
//a716f4e8  a71976de srv!SrvSmbOpen2
//a716f4ec  a7192153 srv!SrvSmbFindFirst2
//a716f4f0  a71921dc srv!SrvSmbFindNext2
//a716f4f4  a7194bf8 srv!SrvSmbQueryFsInformation
//a716f4f8  a7195462 srv!SrvSmbSetFsInformation
//a716f4fc  a718bff3 srv!SrvSmbQueryPathInformation
//a716f500  a718cd02 srv!SrvSmbSetPathInformation
//a716f504  a718b80a srv!SrvSmbQueryFileInformation
//a716f508  a718c5eb srv!SrvSmbSetFileInformation
//a716f50c  a7195654 srv!SrvSmbFindNotify
//a716f510  a7192ae9 srv!SrvSmbIoctl2
//a716f514  a7195654 srv!SrvSmbFindNotify
//a716f518  a7195654 srv!SrvSmbFindNotify
//a716f51c  a718d75e srv!SrvSmbCreateDirectory2
//a716f520  a719809a srv!SrvTransactionNotImplemented
//a716f524  a719809a srv!SrvTransactionNotImplemented
//a716f528  a717e18f srv!SrvSmbGetDfsReferral
//a716f52c  a717e07f srv!SrvSmbReportDfsInconsistency
//a716f530  00000000

typedef struct _SRVTRANSACTION2DISPATCHTABLE
{
	PVOID   srv_SrvSmbOpen2;
	PVOID   srv_SrvSmbFindFirst2;
	PVOID   srv_SrvSmbFindNext2;
	PVOID   srv_SrvSmbQueryFsInformation;
	PVOID   srv_SrvSmbSetFsInformation;
	PVOID   srv_SrvSmbQueryPathInformation;
	PVOID   srv_SrvSmbSetPathInformation;
	PVOID   srv_SrvSmbQueryFileInformation;
	PVOID   srv_SrvSmbSetFileInformation;
	PVOID   srv_SrvSmbFindNotify;
	PVOID   srv_SrvSmbIoctl2;
	PVOID   srv_SrvSmbFindNotify_;
	PVOID   srv_SrvSmbFindNotify__;
	PVOID   srv_SrvSmbCreateDirectory2;
	PVOID   srv_SrvTransactionNotImplemented;			//0xe替换这个
	PVOID   srv_SrvTransactionNotImplemented_;			//其实这两个地址都是一样的
	PVOID   srv_SrvSmbGetDfsReferral;
	PVOID   srv_SrvSmbReportDfsInconsistency;
}SRVTRANSACTION2DISPATCHTABLE, *PSRVTRANSACTION2DISPATCHTABLE;

SRVTRANSACTION2DISPATCHTABLE g_MdlSrvTransaction2DispatchTable;					//专门用来MDL映射的
PSRVTRANSACTION2DISPATCHTABLE g_OriginalSrvTransaction2DispatchTable;			//原始的
LARGE_INTEGER qword_38480;														//判断