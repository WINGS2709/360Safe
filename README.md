# 360Safe
逆向大数字驱动代码                    
通讯部分和Shadow SSDT不感兴趣都没逆向（只分析了感兴趣的SSDT函数）        

HookPort：      
负责构造Hook框架导出给其他驱动使用，自身不负责填写对应的Fake函数

SelfProtection：     
负责填写对应的Fake函数

使用：          
先加载HookPort再加载SelfProtection    

Code：      
代码部分自己写的很蛇皮偷懒了，后面学习发现V校的帖子零地址妙用。     
if(XXX =NULL)     
{     
   放行    
}    

构建工具：    
VS2013 + WDK8.1

支持版本：                  
原版：Win2k~Win10（32位）                    
逆向代码版本：Win7 SP3（32位）                 

作者：         
跳刀跳刀丶Blink                               

免责声明：                     
此文件是由逆向分析取得，只可用于学习研究之用途。本人对他人使用本文件中的代码所引起的后果概不负责。           
  
 
