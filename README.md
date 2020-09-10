# 360Safe
逆向大数字驱动代码                    
通讯部分和Shadow SSDT不感兴趣都没逆向（只分析了感兴趣的SSDT函数）        

HookPort：      
负责构造Hook框架导出给其他驱动使用，自身不负责填写对应的Fake函数

SelfProtection：     
负责填写对应的Fake函数


# 使用：          
先加载HookPort再加载SelfProtection    


# 构建工具：    
VS2013 + WDK8.1


# 支持版本：                  
原版：Win2k~Win10（32位）                    
逆向代码版本：Win7 SP3（32位） 


# 作者：         
跳刀跳刀丶Blink    

# 免责声明：                     
此文件是由逆向分析取得，只可用于学习研究之用途。本人对他人使用本文件中的代码所引起的后果概不负责。           
  
# 参考文献：
 1、发一个可编译，可替换的hookport代码                  
 网址：https://bbs.pediy.com/thread-157472.htm                       
 2、腾讯管家攻防驱动分析-TsFltMgr               
 网址：https://www.jianshu.com/p/718dd8a1dd27               
 3、总结一把，较为精确判断SCM加载                
 网址：https://bbs.pediy.com/thread-135988.htm      
