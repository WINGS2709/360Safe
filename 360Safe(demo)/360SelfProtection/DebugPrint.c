#include "DebugPrint.h"

NTSTATUS NTAPI HookPort_RtlWriteRegistryValue(CHAR ValueData)
{
	WCHAR ValueName[0x20] = L"HookFeil";
	return RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, L"HookPort", &ValueName, REG_DWORD_LITTLE_ENDIAN, &ValueData, 4u);
}