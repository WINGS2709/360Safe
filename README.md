# 360Safe
逆向大数字驱动源码（阉割版）  
通讯部分和Shadow SSDT不感兴趣都没逆向。

HookPort：
负责构造Hook框架导出给其他驱动使用，自身不负责填写对应的Fake函数

SelfProtection：
负责填写对应的Fake函数

Code：
代码部分自己写的很蛇皮偷懒了，后面学习发现V校的帖子零地址妙用。     
if(XXX =NULL)     
{     
   放行    
}    

构建工具：
VS2013 + WDK8.1

