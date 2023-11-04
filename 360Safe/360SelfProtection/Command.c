#include "Command.h"


//不感兴趣的通用处理
NTSTATUS Safe_CommonProc(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	//直接完成，返回成功
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS Safe_Shutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DeviceObject);
	//略
	Irp->IoStatus.Status = Status;							//表示IRP完成状态
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS Safe_CreateCloseCleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DeviceObject);
	//略
	Irp->IoStatus.Status = Status;							//表示IRP完成状态
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS Safe_Read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DeviceObject);
	//略
	Irp->IoStatus.Status = Status;							//表示IRP完成状态
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}


NTSTATUS Safe_DeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;  //返回值
	PIO_STACK_LOCATION	IrpStack;			      //当前的pIrp栈
	//PVOID				Type3InputBuffer = NULL;  //用户态输入地址
	PVOID				ioBuf = NULL;			  //SystemBuff可以当做输入、输出 
	ULONG				inBufLength = NULL;       //输入缓冲区的大小
	ULONG               outBufLength = NULL;      //输出缓冲区的大小 
	ULONG				ioControlCode = NULL;	  //DeviceIoControl的控制号
	ULONG				Tag = 0x206B6444;		  //pool tag
	//UNICODE_STRING      ObjectNameString = { 0 };
	SIZE_T              x360sdu_dat_Len = 0xA;	  //360sdu.dat 字符串长度
	SIZE_T              xboxu_dat_Len = 0x8;      //boxu.dat   字符串长度
	Irp->IoStatus.Information = 0;
	IrpStack = IoGetCurrentIrpStackLocation(Irp);
	ioBuf = Irp->AssociatedIrp.SystemBuffer;	  //驱动程序可以将SystemBuffer视为输入数据，也可以将SystemBuffer视为输出数据
	inBufLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	ioControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;
	//1、检查调用者,必须是保护进程
	if (Safe_QueryWhitePID(PsGetCurrentProcessId()))
	{
		//根据控制号执行不同命令
		switch (ioControlCode)
		{
			case SAFE_UNKNOWN:
			{
				//函数功能：检查进程路径合法性，禁止访问敏感受保护文件名
				//控制号：0x222000
				//buff:       sizeof=0xN
				//+00 WCHAR   ProcessPath[X]
				if (inBufLength)
				{
					ULONG BuffPathLen = 0;
					BuffPathLen = 2 * wcslen(ioBuf) + 2;
					Status = Safe_2555E(ioBuf, 1, BuffPathLen, 0);
					if (NT_SUCCESS(Status))
					{
						if (!_wcsnicmp(((PWCHAR)ioBuf + BuffPathLen - 0x16), L"360sdu.dat", x360sdu_dat_Len))
						{
							g_Regedit_Data.Flag.RULE_360sd_Flag = 1;
						}
						else if (!_wcsnicmp(((PWCHAR)ioBuf + BuffPathLen - 0x12), L"boxu.dat", xboxu_dat_Len))
						{
							g_Regedit_Data.Flag.RULE_360SafeBox_Flag = 1;
						}
						else
						{
							//正常退出
						}
					}
				}
				break;
			}
			case SAFE_UNKNOWN1:
			{
				//函数功能：检查进程路径合法性
				//控制号：0x222004
				//buff:     sizeof=0xN
				//+00 WCHAR ProcessPath[X]

				if (inBufLength)
				{
					Status = Safe_2555E(ioBuf, 1, inBufLength, 2);
				}
				else
				{
					//输入长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_UNKNOWN2:
			{
				//函数功能：检查进程路径合法性，然后非访问敏感受保护文件名
				//控制号：0x222008
				//buff:     sizeof=0xN
				//+00 WCHAR ProcessPath[X]
				if (inBufLength)
				{
					ULONG BuffPathLen = 0;
					BuffPathLen = 2 * wcslen(ioBuf) + 2;
					Status = Safe_2555E(ioBuf, 1, BuffPathLen, 1);
					if (NT_SUCCESS(Status))
					{
						if (!_wcsnicmp(((PWCHAR)ioBuf + BuffPathLen - 0x16), L"360sdu.dat", x360sdu_dat_Len))
						{
							g_Regedit_Data.Flag.RULE_360sd_Flag = 1;
						}
						else if (!_wcsnicmp(((PWCHAR)ioBuf + BuffPathLen - 0x12), L"boxu.dat", xboxu_dat_Len))
						{
							g_Regedit_Data.Flag.RULE_360SafeBox_Flag = 1;
						}
						else
						{
							//正常退出
						}
					}
				}
				break;
			}
			case SAFE_INSERTWHITELIST__PID_2003:	
			{
				//函数功能：添加指定白名单进程PID(Win_2003) 
				//控制号：0x22200C
				//buff:     sizeof=0x4
				//+00 DWORD ProcessId        In

				if (inBufLength == sizeof(ULONG))
				{
					//输入应该是一个4字节PID
					ULONG User_In_InsertPID = *(ULONG*)ioBuf;
					Safe_InsertWhiteList_PID_Win2003((HANDLE)User_In_InsertPID, 0);
				}
				else
				{
					//输入长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_DELETEWHITELIST_PID:			
			{
				//函数功能：删除指定白名单进程PID
				//控制号：0x222010
				//buff:     sizeof=0x4
				//+00 DWORD ProcessId        In
				if (inBufLength == sizeof(ULONG))
				{
					//输入应该是一个4字节PID
					ULONG User_In_DeletePID = *(ULONG*)ioBuf;
					Safe_DeleteWhiteList_PID((HANDLE)User_In_DeletePID);
				}
				else
				{
					//输入长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_GETVER:
			{
				//函数功能：返回R3一个版本号
				//控制号：0x222014
				//buff:     sizeof=0x4
				//+00 DWORD GetVersions        Out
				if (outBufLength == sizeof(ULONG))
				{
					*(ULONG*)ioBuf = 0x3ED;							//版本号？？？？？？
					Irp->IoStatus.Information = sizeof(ULONG);		//这个好像填不填没多大影响
				}
				else
				{
					//输入长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_INSERTSPECIALWHITELIST_PID:
			{
				//函数功能：将调用者进程添加进特殊白名单进程
				//控制号：0x222018
				//无参数
				if (Global_SpShadowDeviceObject == DeviceObject)
				{
					Status = Safe_InsertSpecialWhiteList_PID();
				}
				else
				{
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_INITIALIZE_SETEVENT:
			{
				//函数功能：主动拦截提示时与应用层的通信交互的初始化事件
				//控制号：0x22201C
				//buff:     sizeof=0x8
				//+00 HANDLE ThreadID		   In
				//+00 DWORD  bypass_or_not     In
				if (Global_SpShadowDeviceObject == DeviceObject)
				{
					if (inBufLength == 8)
					{
						ULONG User_In_ThreadID = *(ULONG*)((ULONG)ioBuf);
						ULONG  User_In_bypass_or_not = *(ULONG*)((ULONG)ioBuf + 4);
						//SafeWarning里面的函数都没实际测试，不要使用
						Safe_setevent_called_by_iodispatcher((HANDLE)User_In_ThreadID, User_In_bypass_or_not);
					}
					else
					{
						Status = STATUS_INVALID_PARAMETER;
					}
				}
				break;
			}
			case SAFE_SET_FAKEFUNCTION:
			{
				//函数功能：设置or清零FAKE函数
				//控制号：0x222020
				//buff:     sizeof=0x4
				//+00 DWORD FakeFunSwitch        In
				if (inBufLength == sizeof(ULONG))
				{
					//Buff有值，重新设置一遍  多此一举？？？？  开局就填充好了？？？？？？
					ULONG User_In_Switch = *(ULONG*)ioBuf;
					if (User_In_Switch)
					{
						//重新挂钩
						if (!g_x360SelfProtection_Switch)
						{
							Safe_Initialize_SetFilterSwitchFunction();
							g_x360SelfProtection_Switch = TRUE;
						}
					}
					//去除大部分Fake函数
					else if (g_x360SelfProtection_Switch)
					{
						//一共有0x9E个Fake函数
						for (ULONG Index = 0; Index < FILTERFUNCNT; Index++)
						{
							if (Index != CreateProcessNotifyRoutine_FilterIndex,
								Index != ZwCreateProcess_FilterIndex,
								Index != ZwCreateSection_FilterIndex,
								Index != ZwCreateProcessEx_FilterIndex,
								Index != ZwCreateUserProcess_FilterIndex,
								Index != ZwAlpcSendWaitReceivePort_FilterIndex,
								Index != ZwRequestWaitReplyPort_FilterIndex,
								Index != ZwLoad_Un_Driver_FilterIndex,
								Index != ZwQuerySystemInformation_FilterIndex,
								Index != ZwWriteFile_FilterIndex
								)
							{
								//Fake函数置0
								Safe_Run_SetFilterSwitchFunction(g_FilterFun_Rule_table_head_Temp, Index, 0);
							}
						}
						g_x360SelfProtection_Switch = FALSE;
					}
					else
					{
						//找不到正常退出
					}
				}
				else
				{
					//输入长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_GET_FAKEFUNCTION_SWITCH:
			{
				//函数功能：获取Fake函数填充状态：1清除、0挂钩
				//控制号：0x222024
				//buff:     sizeof=0x4
				//+00 DWORD GetFakeSwitch        Out
				if (outBufLength == sizeof(ULONG))
				{
					*(ULONG*)ioBuf = g_x360SelfProtection_Switch;
					Irp->IoStatus.Information = sizeof(ULONG);
				}
				else
				{
					//输出长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_DELETEDRVMKDATALIST:
			{
				//函数功能：删除黑白名单驱动信息
				//控制号：0x222028
				//buff:     sizeof=0x18
				//保存PE哈希值、文件大小、放行or拦截标志位
				//大小0x18个字节
				//typedef struct _PE_HASH_DATA
				//{
				//	ULONG  Hash[4];									//哈希值
				//	ULONG  PESize;									//文件大小
				//	ULONG  LoadDriver_Flag;							//驱动 拦截or放行标识   1拦截 0放行
				//}PE_HASH_DATA, *PPE_HASH_DATA;

				if (Global_SpShadowDeviceObject == DeviceObject)
				{
					if (inBufLength == sizeof(PE_HASH_DATA))
					{
						PPE_HASH_DATA User_In_DeleteDrvmkDataList = ioBuf;
						Safe_DeleteDrvmkDataList(User_In_DeleteDrvmkDataList);
					}
					else
					{
						//输出长度非法
						Status = STATUS_INVALID_PARAMETER;
					}
				}
				break;
			}
			case SAFE_INSERTDRVMKDATALIST:
			{
				//函数功能：添加黑白名单驱动信息
				//控制号：0x22202C
				//buff:     sizeof=0x18
				//保存PE哈希值、文件大小、放行or拦截标志位
				//大小0x18个字节
				//typedef struct _PE_HASH_DATA
				//{
				//	ULONG  Hash[4];									//哈希值
				//	ULONG  PESize;									//文件大小
				//	ULONG  LoadDriver_Flag;							//驱动 拦截or放行标识   1拦截 0放行
				//}PE_HASH_DATA, *PPE_HASH_DATA;
				if (Global_SpShadowDeviceObject == DeviceObject)
				{
					if (inBufLength == sizeof(PE_HASH_DATA))
					{
						PPE_HASH_DATA User_In_InsertDrvmkDataList = ioBuf;
						Safe_InsertDrvmkDataList(User_In_InsertDrvmkDataList);
					}
					else
					{
						//输出长度非法
						Status = STATUS_INVALID_PARAMETER;
					}
				}
				break;
			}
			case SAFE_OFF_360SAFEBOX_SWITCH:
			{
				//函数功能：关闭360SafeBox选项
				//控制号：0x222034
				//buff:     sizeof=0x0
				g_Regedit_Data.Flag.RULE_360SafeBox_Flag = 0;
				break;
			}
			case SAFE_CHECK_INSERTWHITELIST__PID:
			{
				//函数功能：先检查进程路径，合法后才添加白名单进程
				//控制号：0x222038
				//buff:     sizeof=0xN
				//+00 WCHAR ProcessPath[X]
				if (inBufLength)
				{
					Status = Safe_2555E(ioBuf, 1, inBufLength, 3);
					if (NT_SUCCESS(Status))
					{
						//将调用者进程添加进白名单
						Safe_InsertWhiteList_PID(PsGetCurrentProcessId(), 0xFFFFFFF0);
					}
				}
				else
				{
					//返回错误值
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_DELETEWHITELIST_PID_SESSIONID:
			{
				//函数功能：指定删除白名单进程
				//控制号：0x22203C
				//buff:     sizeof=0x4
				//+00 DWORD ProcessId        In

				if (inBufLength == sizeof(ULONG))
				{
					//输入应该是一个4字节PID
					ULONG User_In_DeletePID = *(ULONG*)ioBuf;
					Safe_DeleteWhiteList_PID_SessionId((HANDLE)User_In_DeletePID);
				}
				else
				{
					//输出长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_INSERTWHITELIST__PID:
			{
				//添加指定白名单进程PID
				//控制号：0x222040
				//buff:     sizeof=0x4
				//+00 DWORD ProcessId        In

				if (inBufLength == sizeof(ULONG))
				{
					ULONG User_In_InsertPID = *(ULONG*)ioBuf;
					Safe_InsertWhiteList_PID((HANDLE)User_In_InsertPID, 0);
				}
				else
				{
					//输入 or 输出长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_NO_360SAFEBOX_SWITCH:
			{
				//函数功能：开启360SafeBox选项
				//控制号：0x222044
				//buff:     sizeof=0x0

				g_Regedit_Data.Flag.RULE_360SafeBox_Flag = 1;
				break;
			}
			case SAFE_SET_SPSHADOW0_DATA_DWORD:
			{
				//函数功能：设置Safe_SetRegedit_SpShadow0开关
				//控制号：0x222048
				//buff:     sizeof=0x4
				//+00 DWORD SpShadow0_Switch     In

				if (inBufLength == sizeof(ULONG))
				{
					g_Regedit_Data.g_SpShadow0_Data_DWORD = *(ULONG*)ioBuf;
				}
				else
				{
					//输入 or 输出长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_QUERYWHITE_PID:
			{
				//函数功能：查询指定PID，结果返回给R3
				//控制号：  0x22204C
				//buff:     sizeof=0x4
				//+00 DWORD ProcessPID     In
				//+00 DWORD QueryResult    Out

				if (outBufLength == sizeof(ULONG) && inBufLength == sizeof(ULONG))
				{
					ULONG User_In_QueryPID = *(ULONG*)ioBuf;
					//返回值：找到1，找不到0
					*(ULONG*)ioBuf = Safe_QueryWhitePID((HANDLE)User_In_QueryPID);		//后续待分析___漏洞
					Irp->IoStatus.Information = sizeof(ULONG);
				}
				else
				{
					//输入 or 输出长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_UNKNOWN7:
			{
				//函数功能：置1数组内容
				//控制号：0x222050
				//buff:     sizeof=0x0

				g_dynData->dword_34DAC[9] = 1;
				break;
			}
			case SAFE_UNKNOWN8:
			{
				//函数功能：置0数组内容
				//控制号：0x222054
				//buff:     sizeof=0x0

				g_dynData->dword_34DAC[9] = 0;
				break;
			}
			case SAFE_RESETDRVMKDATALIST:
			{
				//函数功能：重置黑白驱动名单，数据清零
				//控制号：0x222064
				//buff:     sizeof=0x0

				g_Drvmk_List = NULL;
				break;
			}
			case SAFE_SET_DWORD_34678:
			{
				//函数功能：R0传递R3  输出
				//控制号：0x222080
				//buff:     sizeof=0x4
				//+00 DWORD OutUnknown  In 

				if (outBufLength == sizeof(ULONG))
				{
					*(ULONG*)ioBuf = g_dword_34678;
					Irp->IoStatus.Information = sizeof(ULONG);
				}
				else
				{
					//输出长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_GET_DWORD_34678:
			{
				//函数功能：R3传递R0  输入
				//控制号：0x222084
				//buff:     sizeof=0x4
				//+00 DWORD OutUnknown  Out

				if (inBufLength == sizeof(ULONG))
				{
					g_dword_34678 = *(ULONG*)ioBuf;
				}
				else
				{
					//输出长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_UNKNOWN9:
			{
				//函数功能：设置dword_34DAC[10]数组内容
				//控制号：0x22208C
				//buff:     sizeof=0x4        
				//+00 DWORD InSwitch  In 
				if (inBufLength < sizeof(ULONG))
				{
					//输出长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				else
				{
					
					g_dword_3467C = *(ULONG*)ioBuf;
					g_dynData->dword_34DAC[0xA] = *(ULONG*)ioBuf;

				}
				break;
			}
			case SAFE_UNKNOWN6:
			{
				//函数功能：R3传递字符串给R0某个全局变量,用处未知
				//控制号：0x222094
				//buff:     sizeof=0xN
				//+00 WCHAR BuffPath[X]

				if (inBufLength >= 0x50)
				{
					//清零
					RtlZeroMemory(g_UnknownBuffPath, 0x50);
					//复制R3数据
					RtlCopyMemory(g_UnknownBuffPath, ioBuf, 0x50);
					//成功置1
					g_dword_34D60_Swtich = 1;
				}
				else
				{
					//输入长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_GET_SYSTEMHOTPATCHINFORMATION_SWITCH:
			{
				//代码说明部分：
				//Fake_ZwSetSystemInformation函数里面的
				//if ( a2->SystemInformationClass == 0x45 && g_SystemHotpatchInformation_Switch && VersionFlag == 2 )

				//函数功能：开启 or 关闭SystemHotpatchInformation检查部分，与Fake_ZwSetSystemInformation函数联动
				//控制号：0x222098
				//buff:     sizeof=0x4
				//+00 DWORD SystemHotpatchInformation_Switch  In 	

				if (inBufLength == sizeof(ULONG))
				{
					//用户决定 开启 or 关闭SystemHotpatchInformation检查
					ULONG User_In_SystemHotpatchInformation_Switch = *(ULONG*)ioBuf;
					g_SystemHotpatchInformation_Switch = User_In_SystemHotpatchInformation_Switch;
				}
				else
				{
					//输入长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			case SAFE_UNKNOWN3:
			{
				//函数功能：白名单进程个数清零，重新检查\Registry\Machine\SYSTEM\CurrentControlSet\Services\360SelfProtection路径下的字段是否存在？
				//控制号：0x22209C
				//buff:     sizeof=0x0
				if (g_x360SelfProtection_Switch)
				{
					Status = STATUS_ACCESS_DENIED;
				}
				else
				{
					UNICODE_STRING RegPath = { 0 };
					RtlInitUnicodeString(&RegPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\360SelfProtection");
					Status = Safe_EnumerateValueKey(&RegPath, 0);
				}
				break;
			}
			case SAFE_UNKNOWN4:
			{
				//函数功能：清零数组内容
				//控制号：0x2220A0
				//buff:     sizeof=0x0
				g_dynData->dword_34DAC[0] = 0;
				g_dynData->dword_34DAC[1] = 0;
				break;
			}
			case SAFE_UNKNOWN5:
			{
				//函数功能：清零数组内容
				//控制号：0x2220A4
				//buff:     sizeof=0x0
				g_dynData->dword_34DAC[2] = 0;
				g_dynData->dword_34DAC[3] = 0;
				break;
			}
			case SAFE_SET_ILLEGALITYDLLPATH:
			{
				//函数功能：设置一个黑名单DLL路径，在ClientLoadLibrary拦截时候判断
				//控制号：0x2220A8
				//buff:     sizeof=0xN
				//CHAR		DllPath[X]

				//1、检查R3传递的字符串输入长度，最大不超过0xFFFF
				if (inBufLength && inBufLength <= ILLEGALITYDLLPATHMAXSIZE)
				{
					//已存在则退出（只能设置一次？？？？）
					if (g_IllegalityDllPath.Buffer)
					{
						Status = STATUS_OBJECT_NAME_COLLISION;
					}
					else
					{
						//2、分配空间存储R3传递的DLL路径
						g_IllegalityDllPath.Buffer = Safe_AllocBuff(NonPagedPool, inBufLength, Tag);
						if (g_IllegalityDllPath.Buffer)
						{
							RtlCopyMemory(g_IllegalityDllPath.Buffer,ioBuf, inBufLength);
							g_IllegalityDllPath.Length = inBufLength;
							g_IllegalityDllPath.MaximumLength = inBufLength + 2;
						}
						else
						{
							Status = STATUS_NO_MEMORY;
						}
					}
				}
				else
				{
					//输入长度非法
					Status = STATUS_BUFFER_TOO_SMALL;
				}
				break;
			}
			case SAFE_GET_ISFILTERFUNFILLEDREADY:
			{
				//函数功能：获取过滤函数表状态：置1所有Fake函数启动、置0所有Fake函数关闭。可以理解为电源总闸
				//控制号：0x2220AC
				//buff:     sizeof=0x4
				//+00 DWORD Get_IsFilterFunFilledReady  Out
				if (outBufLength == sizeof(ULONG))
				{
					*(ULONG*)ioBuf = g_FilterFun_Rule_table_head_Temp->IsFilterFunFilledReady;
					Irp->IoStatus.Information = sizeof(ULONG);
				}
				else
				{
					//输出长度非法
					Status = STATUS_INVALID_PARAMETER;
				}
				break;
			}
			default:
			{
				//错误返回，控制码是无效的
				KdPrint(("Unknown ioControlCode:%X\t\n", ioControlCode));
				Status = STATUS_INVALID_DEVICE_REQUEST;
				break;
			}
		}
	}
	else
	{
		//非保护进程调用 直接错误返回
		Status = STATUS_ACCESS_DENIED;
	}
	Irp->IoStatus.Status = Status;							//表示IRP完成状态
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}