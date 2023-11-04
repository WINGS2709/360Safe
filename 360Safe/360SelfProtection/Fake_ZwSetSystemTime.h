#pragma once
#include <ntifs.h>
#include "MemCheck.h"
#include "Data.h"
#include "WhiteList.h"

#define MAXYEAR		0x7EE		//防止恶意修改本地时间，这里设置最大年份不能超过2030年

//保护系统时间
//1、本地时间超过2030年直接返回错误
NTSTATUS NTAPI Fake_ZwSetSystemTime(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);