#pragma once
#include <ntifs.h>
#include "Data.h"


//���������̸���
#define SAFEMODMMDATALISTNUMBER				 0x7CE
//���������̸���				       
#define SAFEMODMMDATALISTNUMBERMAXIMUM       0x7D0

//������·������
#define SAFEMONPATHNUMBER	                 0x1FE
//������·������ 
#define SAFEMONPATHNUMBERMAXIMUM             0x200

//C:\Program Files\360\360safe\SAFEMON
typedef struct _SAFEMONPATH_DIRECTORY
{
	ULONG ListNumber;											// +0       ���� <=0x1FE   
	WCHAR DosPath[SAFEMONPATHNUMBERMAXIMUM][DOSPATHSIZE / 2];	// +4       Dos·�����飬һ��200����ÿ����󳤶�520 / 2
	ULONG ArrayIndex[SAFEMONPATHNUMBERMAXIMUM];					// +0x41004 ���û���ã�����DosPath������ڼ���о�����ģ���1��ʼ��
	KSPIN_LOCK	SpinLock;										// ĩβ ������ 
}SAFEMONPATH_DIRECTORY, *PSAFEMONPATH_DIRECTORY;

PSAFEMONPATH_DIRECTORY g_SafeMonPath_List;



//��SafeMod�ṹ���ƣ�ÿ��SAFEMONPATH_DIRECTORY�ṹ��Ӧһ��SAFEMONDATA_DIRECTORY�ṹ��������ͬʹ��
typedef struct _SAFEMONDATA_DIRECTORY {
	ULONG     ListNumber;											  //���� <=0x7CE 
	HANDLE    SafeMonSectionHandle[SAFEMODMMDATALISTNUMBERMAXIMUM];	  //��ʼƫ��0000*4,����SafeMod��SectionHandle 
	PVOID     SafeMonSectionObject[SAFEMODMMDATALISTNUMBERMAXIMUM];   //��ʼƫ��2002*4,����SectionObject
	ULONG	  SafeMonIndex[SAFEMODMMDATALISTNUMBERMAXIMUM];			  //��ʼƫ��4003*4,����SafeMon,���Ҹ�dos·�����б��ڼ��ret_arg = ���������±�
	PEPROCESS SafeMonProcess[SAFEMODMMDATALISTNUMBERMAXIMUM];		  //��ʼƫ��6001*4,����SafeMod��Eprocess�ṹ
	KSPIN_LOCK	SpinLock;										      //������ 
}SAFEMONDATA_DIRECTORY, *PSAFEMONDATA_DIRECTORY;
PSAFEMONDATA_DIRECTORY   g_SafeMonData_List;

//
// Section object type.
//
extern POBJECT_TYPE MmSectionObjectType;

/*****************************ɾ��*****************************/
//ɾ������������Ϣ
//�ɹ����ض�Ӧ���±꣬ʧ�ܷ���0
//Fake_ZwCreateProcessɾ��
ULONG NTAPI Safe_DeleteSafeMonDataList(_In_ HANDLE SafeMonSectionHandle);


/*****************************ɾ��*****************************/

/*****************************��ѯ*****************************/
//��ѯ��DosPath�Ƿ����б��У�����Ƿ���Index
ULONG NTAPI Safe_QuerSafeMonPathList(IN PWCHAR DosPath, OUT ULONG ret_arg);
/*****************************��ѯ*****************************/

/*****************************����*****************************/
//��������������Ϣ
// �ɹ�����1��ʧ�ܷ���0
//After_ZwCreateSection_Func����
BOOLEAN Safe_InsertSafeMonDataList(_In_ HANDLE SafeMonSectionHandle, _In_ ULONG SafeMonIndex);
/*****************************����*****************************/