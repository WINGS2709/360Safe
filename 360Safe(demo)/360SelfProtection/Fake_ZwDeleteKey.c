/*
参考资料：
1、disallowrun 禁止软件运行                                                              
网址：http://www.cppblog.com/nt05/archive/2008/06/16/53490.html
2、autorun.inf病毒与杀毒软件无法启动,及映像劫持（Image File Execution Options）解决办法  
网址：https://blog.csdn.net/ananias/article/details/1642375?utm_medium=distribute.pc_relevant.none-task-blog-baidujs-3
*/
#include "Fake_ZwDeleteKey.h"


//删除注册表值键
NTSTATUS NTAPI Fake_ZwDeleteKey(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{

}