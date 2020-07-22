#include "Fake_ZwSetSystemTime.h"

//保护系统时间
//1、本地时间超过2030年直接返回错误
NTSTATUS NTAPI Fake_ZwSetSystemTime(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	TIME_FIELDS    Out_TimeFields = { 0 };
	LARGE_INTEGER  Out_LocalTime = { 0 };
	ULONG          SpecialWhiteNumber = NULL;
	ULONG          Tag = 0x206B6444;
	ULONG          Flag_v6 = NULL;
	PQUERY_PASS_R0SENDR3_DATA  pQuery_Pass = NULL;
	SpecialWhiteNumber = g_SpecialWhite_List.SpecialWhiteListNumber;
	//0、获取ZwSetSystemTime原始函数
	PLARGE_INTEGER In_NewTime = *(ULONG*)((ULONG)ArgArray);
	if (In_NewTime)
	{
		//判断参数合法性
		if (myProbeRead(In_NewTime, sizeof(LARGE_INTEGER), sizeof(CHAR)))
		{
			KdPrint(("ProbeRead(Fake_ZwSetSystemTime：In_NewTime) error \r\n"));
			return result;
		}
		//获取本地时间
		ExSystemTimeToLocalTime(In_NewTime, &Out_LocalTime);
		//将系统时间转换成一个TIME_FIELDS结构
		RtlTimeToTimeFields(&Out_LocalTime, &Out_TimeFields);
		//时间超过XXX年直接报错
		if (Out_TimeFields.Year > MAXYEAR
			&& SpecialWhiteNumber							//判断R3交互界面必须存在
			)
		{
			//new空间，保存传递给R3的进程数据
			pQuery_Pass = (PQUERY_PASS_R0SENDR3_DATA)Safe_AllocBuff(NonPagedPool, sizeof(QUERY_PASS_R0SENDR3_DATA), Tag);
			if (!pQuery_Pass)
			{
				result = STATUS_ACCESS_DENIED;
			}
			//填充内容，后续发送R3弹对话框，让用户决定 放行or拦截
			pQuery_Pass->Unknown_CurrentThreadId_5 = PsGetCurrentThreadId();
			pQuery_Pass->Unknown_Flag_2 = 0xA;
			pQuery_Pass->CheckWhitePID = PsGetCurrentProcessId();
			pQuery_Pass->Unknown_CurrentThreadId_4 = PsGetCurrentThreadId();
			pQuery_Pass->Unknown_Flag_6 = 1;
			//Flag_v6 = Safe_push_request_in_and_waitfor_finish(pQuery_Pass, 1);
			//返回：0 放行，1 or 2 拦截
			if (Flag_v6 == 1 || Flag_v6 == 2)
			{
				result = STATUS_ACCESS_DENIED;
			}
			else
			{
				result = STATUS_SUCCESS;
			}
		}

	}
	return result;
}