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
	PIO_STACK_LOCATION	IrpStack;
	UNREFERENCED_PARAMETER(DeviceObject);
	//略
	Irp->IoStatus.Status = Status;							//表示IRP完成状态
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS Safe_CreateCloseCleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	IrpStack;
	UNREFERENCED_PARAMETER(DeviceObject);
	//略
	Irp->IoStatus.Status = Status;							//表示IRP完成状态
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS Safe_Read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	IrpStack;
	UNREFERENCED_PARAMETER(DeviceObject);
	//略
	Irp->IoStatus.Status = Status;							//表示IRP完成状态
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS Safe_DeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	IrpStack;
	UNREFERENCED_PARAMETER(DeviceObject);
	IrpStack = IoGetCurrentIrpStackLocation(Irp);
	//1、检查调用者,必须是保护进程
	if (Safe_QueryWhitePID(PsGetCurrentProcessId()))
	{
		//略
	}
	Irp->IoStatus.Status = Status;							//表示IRP完成状态
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}