#include "Xor.h"

NTSTATUS NTAPI Safe_KernelCreateFile(IN PANSI_STRING SymbolName, OUT PSYSTEM_INFORMATIONFILE_XOR System_Information)
{
	HANDLE          hFile = NULL;
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK StatusBlock = { 0 };
	ULONG           ulShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	ULONG           ulCreateOpt = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE;
	// 1. 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES objAttrib = { 0 };
	ULONG             ulAttributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	InitializeObjectAttributes(
		&objAttrib,		 // 返回初始化完毕的结构体
		SymbolName,      // 文件对象名称
		ulAttributes,   // 对象属性
		NULL,           // 根目录(一般为NULL)
		NULL);          // 安全属性(一般为NULL)
	//2、创建文件对象,比ZwCreateFile更加底层
	Status = IoCreateFile(
		&hFile,							// 返回文件句柄
		FILE_READ_ATTRIBUTES,			// 文件操作描述
		&objAttrib,						// OBJECT_ATTRIBUTES
		&StatusBlock,					// 接受函数的操作结果
		0,								// 初始文件大小
		FILE_ATTRIBUTE_NORMAL,			// 新建文件的属性
		ulShareAccess,				    // 文件共享方式
		FILE_OPEN,						// 打开文件
		ulCreateOpt,					// 打开操作的附加标志位
		NULL,							// 扩展属性区
		NULL,							// 扩展属性区长度
		CreateFileTypeNone,				// 必须是CreateFileTypeNone
		NULL,							// InternalParameters
		IO_NO_PARAMETER_CHECKING		// Options
		);
	//假设失败调用ZwCreateFile
	if (!NT_SUCCESS(Status))
	{
		Status = ZwCreateFile(
			&hFile,                // 返回文件句柄
			GENERIC_ALL,           // 文件操作描述
			&objAttrib,            // OBJECT_ATTRIBUTES
			&StatusBlock,          // 接受函数的操作结果
			0,                     // 初始文件大小
			FILE_ATTRIBUTE_NORMAL, // 新建文件的属性
			ulShareAccess,         // 文件共享方式
			FILE_OPEN_IF,          // 文件存在则打开不存在则创建
			ulCreateOpt,           // 打开操作的附加标志位
			NULL,                  // 扩展属性区
			0);                    // 扩展属性区长度
		if (!NT_SUCCESS(Status))
		{
			//失败返回
			return Status;
		}
	}
	//3、打开文件成功查询文件信息
	Status = Safe_GetInformationFile(hFile, System_Information, KernelMode);
	//4、释放句柄
	ZwClose(hFile);
	return Status;
}


//************************************     
// 函数名称: Safe_GetInformationFile     
// 函数说明：获取卷信息跟文件信息    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址： 
// 返 回 值: NTSTATUS NTAPI     
// 参    数: IN HANDLE Handle                                      [In]目录句柄
// 参    数: OUT PSYSTEM_INFORMATIONFILE_XOR System_Information    [Out]输出文件信息
// 参    数: IN KPROCESSOR_MODE AccessMode                         [In]用户层or内核层
//************************************  
NTSTATUS NTAPI Safe_GetInformationFile(IN HANDLE Handle, OUT PSYSTEM_INFORMATIONFILE_XOR System_Information, IN KPROCESSOR_MODE AccessMode)
{
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK StatusBlock = { 0 };
	PFILE_OBJECT    FileObject = NULL;
	ULONG			DeviceType = 0;
	ULONG           FastfatFlag = 0;
	FILE_FS_VOLUME_INFORMATION FsInformation = { 0 };
	FILE_INTERNAL_INFORMATION  FileInformation = { 0 };
	FILE_BASIC_INFORMATION	   FileBaInformation = { 0 };
	struct _DRIVER_OBJECT *DriverObject;
	//1、判断句柄的合法性4的倍数
	if (((ULONG)Handle & 3) == 3 || !Handle)// 判断句柄合法性
	{
		return Status;
	}
	//2、得到文件对象指针
	Status = ObReferenceObjectByHandle(Handle, FILE_ANY_ACCESS, *IoFileObjectType, AccessMode, (PVOID*)&FileObject, NULL);
	//2、1判断操作是否成功
	if (!NT_SUCCESS(Status) && !FileObject)
	{
		return Status;
	}
	//2、2 判断设备对象
	if (!FileObject->DeviceObject)
	{
		//关闭设备句柄
		ObfDereferenceObject(FileObject);
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}
	//3、过滤掉特定文件设备类型
	DeviceType = FileObject->DeviceObject->DeviceType;
	if (DeviceType != FILE_DEVICE_DISK_FILE_SYSTEM    &&   //磁盘文件系统设备
		DeviceType != FILE_DEVICE_DISK			      &&   //磁盘设备
		DeviceType != FILE_DEVICE_FILE_SYSTEM	      &&   //文件系统设备
		DeviceType != FILE_DEVICE_UNKNOWN		      &&   //未知类型
		DeviceType != FILE_DEVICE_CD_ROM		      &&   //CD光驱设备
		DeviceType != FILE_DEVICE_CD_ROM_FILE_SYSTEM  &&   //CD光驱文件系统设备
		DeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM      //网络文件系统设备
		)
	{
		if (DeviceType != FILE_DEVICE_NETWORK_REDIRECTOR)  //网卡设备
		{
			//关闭设备句柄
			ObfDereferenceObject(FileObject);
			Status = STATUS_UNSUCCESSFUL;
			return Status;
		}
	}
	if (DeviceType == FILE_DEVICE_MULTI_UNC_PROVIDER)	   //多UNC设备
	{
		if (!FileObject->FileName.Buffer || !FileObject->FileName.Length)
		{
			//关闭设备句柄
			ObfDereferenceObject(FileObject);
			Status = STATUS_UNSUCCESSFUL;
			return Status;
		}
	}
	//判断DriverName
	DriverObject = FileObject->DeviceObject->DriverObject;
	if (DriverObject)
	{
		//文件系统
		if (_wcsnicmp(DriverObject->DriverName.Buffer, L"\\Driver\\Fastfat", 0xF) == 0)
		{
			FastfatFlag = 1;
		}
	}
	//关闭设备句柄
	ObfDereferenceObject(FileObject);
	//4、根据KernelMode or UserMode判断使用哪个函数
	//查询卷的信息
	//AccessMode == 1执行Safe_UserModexxx,否则ZwQueryVolumeInformationFile
	Status = AccessMode ? Safe_UserMode_ZwQueryVolumeInformationFile(Handle, &StatusBlock, (PVOID)&FsInformation, sizeof(FILE_FS_VOLUME_INFORMATION), FileFsVolumeInformation, g_HighgVersionFlag) : ZwQueryVolumeInformationFile(Handle, &StatusBlock, (PVOID)&FsInformation, sizeof(FILE_FS_VOLUME_INFORMATION), FileFsVolumeInformation);
	if (NT_SUCCESS(Status))
	{
		//AccessMode == 1执行Safe_UserModexxx,否则ZwQueryInformationFile
		//获取该文件唯一ID
		Status = AccessMode ? Safe_UserMode_ZwQueryInformationFile(Handle, &StatusBlock, (PVOID)&FileInformation, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation, g_HighgVersionFlag) : ZwQueryInformationFile(Handle, &StatusBlock, (PVOID)&FileInformation, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation, g_HighgVersionFlag);
		if (NT_SUCCESS(Status))
		{
			if ((FileInformation.IndexNumber.HighPart) || (FileInformation.IndexNumber.HighPart == FastfatFlag))
			{
				System_Information->u.IndexNumber_HighPart = FileInformation.IndexNumber.HighPart;	//保存该进程唯一标识ID
				System_Information->IndexNumber_LowPart = FileInformation.IndexNumber.LowPart;	    //保存该进程唯一标识ID
				System_Information->VolumeSerialNumber = FsInformation.VolumeSerialNumber;			//保存序列号体积
			}
			else
			{
				//AccessMode == 1执行Safe_UserModexxx,否则ZwQueryInformationFile
				Status = AccessMode ? Safe_UserMode_ZwQueryInformationFile(Handle, &StatusBlock, (PVOID)&FileBaInformation, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation, g_HighgVersionFlag) : ZwQueryInformationFile(Handle, &StatusBlock, (PVOID)&FileBaInformation, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation, g_HighgVersionFlag);
				if (NT_SUCCESS(Status))
				{
					System_Information->u.XorResult = FileBaInformation.CreationTime.LowPart ^ FileBaInformation.ChangeTime.HighPart;		//看不懂蜜汁操作
					System_Information->IndexNumber_LowPart = FileInformation.IndexNumber.LowPart;	//保存该进程唯一标识ID
					System_Information->VolumeSerialNumber = FsInformation.VolumeSerialNumber;		//保存序列号体积
					return STATUS_SUCCESS;
				}
			}
		}
	}
	return Status;

}