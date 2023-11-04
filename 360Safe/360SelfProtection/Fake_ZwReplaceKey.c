/*
参考资料：
1、disallowrun 禁止软件运行
网址：http://www.cppblog.com/nt05/archive/2008/06/16/53490.html
2、autorun.inf病毒与杀毒软件无法启动,及映像劫持（Image File Execution Options）解决办法
网址：https://blog.csdn.net/ananias/article/details/1642375?utm_medium=distribute.pc_relevant.none-task-blog-baidujs-3
*/
#include "Fake_ZwReplaceKey.h"



//取代注册表值键
NTSTATUS NTAPI Fake_ZwReplaceKey(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	result = STATUS_SUCCESS;
	//0、获取ZwReplaceKey原始参数
	HANDLE      In_KeyHandle = *(ULONG*)((ULONG)ArgArray + 4);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//禁止修改受保护注册表子项
		//返回值：合法返回TRUE，不合法返回FALSE
		result = Safe_ProtectRegKey(In_KeyHandle, 0, 0, 0, 0, 0) != STATUS_SUCCESS ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
	}
	else
	{
		result = STATUS_SUCCESS;
	}
	return result;
}