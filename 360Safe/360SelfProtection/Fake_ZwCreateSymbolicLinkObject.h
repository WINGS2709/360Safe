#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "WhiteList.h"
//´´½¨·ûºÅÁ´½Ó
NTSTATUS NTAPI Fake_ZwCreateSymbolicLinkObject(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);