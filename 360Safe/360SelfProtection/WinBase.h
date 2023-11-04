/*
内核不能使用windows.h头文件，所以copy的部分宏过来
*/
#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  
//
// Process dwCreationFlag values
//

#define DEBUG_PROCESS                     0x00000001
#define DEBUG_ONLY_THIS_PROCESS           0x00000002
#define CREATE_SUSPENDED                  0x00000004
#define DETACHED_PROCESS                  0x00000008

#define CREATE_NEW_CONSOLE                0x00000010
#define NORMAL_PRIORITY_CLASS             0x00000020
#define IDLE_PRIORITY_CLASS               0x00000040
#define HIGH_PRIORITY_CLASS               0x00000080

#define REALTIME_PRIORITY_CLASS           0x00000100
#define CREATE_NEW_PROCESS_GROUP          0x00000200
#define CREATE_UNICODE_ENVIRONMENT        0x00000400
#define CREATE_SEPARATE_WOW_VDM           0x00000800

#define CREATE_SHARED_WOW_VDM             0x00001000
#define CREATE_FORCEDOS                   0x00002000
#define BELOW_NORMAL_PRIORITY_CLASS       0x00004000
#define ABOVE_NORMAL_PRIORITY_CLASS       0x00008000

#define INHERIT_PARENT_AFFINITY           0x00010000
#define INHERIT_CALLER_PRIORITY           0x00020000    // Deprecated
#define CREATE_PROTECTED_PROCESS          0x00040000
#define EXTENDED_STARTUPINFO_PRESENT      0x00080000

#define PROCESS_MODE_BACKGROUND_BEGIN     0x00100000
#define PROCESS_MODE_BACKGROUND_END       0x00200000

#define CREATE_BREAKAWAY_FROM_JOB         0x01000000
#define CREATE_PRESERVE_CODE_AUTHZ_LEVEL  0x02000000
#define CREATE_DEFAULT_ERROR_MODE         0x04000000
#define CREATE_NO_WINDOW                  0x08000000

#define PROFILE_USER                      0x10000000
#define PROFILE_KERNEL                    0x20000000
#define PROFILE_SERVER                    0x40000000
#define CREATE_IGNORE_SYSTEM_DEFAULT      0x80000000


//
// Section object type.
//

extern POBJECT_TYPE MmSectionObjectType;


//
//
//
#define THREAD_TERMINATE                 (0x0001)  
#define THREAD_SUSPEND_RESUME            (0x0002)  
#define THREAD_GET_CONTEXT               (0x0008)  
#define THREAD_SET_CONTEXT               (0x0010)  
#define THREAD_QUERY_INFORMATION         (0x0040)  
#define THREAD_SET_INFORMATION           (0x0020)  
#define THREAD_SET_THREAD_TOKEN          (0x0080)
#define THREAD_IMPERSONATE               (0x0100)
#define THREAD_DIRECT_IMPERSONATION      (0x0200)


//
// Service object specific access type
//
#define SERVICE_QUERY_CONFIG           0x0001
#define SERVICE_CHANGE_CONFIG          0x0002
#define SERVICE_QUERY_STATUS           0x0004
#define SERVICE_ENUMERATE_DEPENDENTS   0x0008
#define SERVICE_START                  0x0010
#define SERVICE_STOP                   0x0020
#define SERVICE_PAUSE_CONTINUE         0x0040
#define SERVICE_INTERROGATE            0x0080
#define SERVICE_USER_DEFINED_CONTROL   0x0100

#define SERVICE_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED     | \
                                        SERVICE_QUERY_CONFIG         | \
                                        SERVICE_CHANGE_CONFIG        | \
                                        SERVICE_QUERY_STATUS         | \
                                        SERVICE_ENUMERATE_DEPENDENTS | \
                                        SERVICE_START                | \
                                        SERVICE_STOP                 | \
                                        SERVICE_PAUSE_CONTINUE       | \
                                        SERVICE_INTERROGATE          | \
                                        SERVICE_USER_DEFINED_CONTROL)




