#include "MemCheck.h"
LONG ExSystemExceptionFilter()
{
	return ExGetPreviousMode() != KernelMode ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

NTSTATUS NTAPI myProbeRead(PVOID Address, SIZE_T Size, ULONG Alignment)
{
	NTSTATUS result = STATUS_SUCCESS;
	if (ExGetPreviousMode() != KernelMode && KeGetCurrentIrql() <= APC_LEVEL)
	{
		try
		{
			if (Size == 0)
			{
				result = STATUS_UNSUCCESSFUL;
				return result;
			}
			ProbeForRead(Address, Size, Alignment);
		}
		except(ExSystemExceptionFilter())
		{
			result = GetExceptionCode();
			return result;
		}
	}
	else
	{
		result = STATUS_UNSUCCESSFUL;
	}
	return result;
}

NTSTATUS NTAPI myProbeWrite(PVOID Address, SIZE_T Size, ULONG Alignment)
{
	NTSTATUS result = STATUS_SUCCESS;
	if (ExGetPreviousMode() != KernelMode && KeGetCurrentIrql() <= APC_LEVEL)
	{
		try
		{
			if (Size == 0)
			{
				result = STATUS_UNSUCCESSFUL;
				return result;
			}
			ProbeForWrite(Address, Size, Alignment);
		}
		except(ExSystemExceptionFilter())
		{
			result = GetExceptionCode();
			return result;
		}
	}
	else
	{
		result = STATUS_UNSUCCESSFUL;
	}
	return result;
}