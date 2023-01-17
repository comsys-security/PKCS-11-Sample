// This application is provided WITHOUT WARRANTY either expressed or implied.
//
// Notes: 
//		This program is used for demonstrating finding key by nShield
//		This program requires :
//		- AES key is exist in security world
//



#include <stdio.h>
#include <string.h>
#include <dlfcn.h>


#include "cryptoki.h"
#include "pkcs11.h"



#define MAJOR_VERSION 0
#define MINOR_VERSION 2


/* Defines */
#define MAX_OBJS	(128)
#define MAX_SLOTS	(128)
#define MAX_DEVS	(128)

#define MAX_PASSWORD_LENGTH (128)

#define MAX_KEY_LABEL_SIZE (128)

int main(int argc, char **argv[])
{



	printf("For testing only\nFinding application key by nShield\n");
	void *pDll = NULL;
	CK_RV rv = CKR_OK;
	CK_FUNCTION_LIST_PTR pFuncList = NULL;
	typedef CK_RV (*LPFNDLL_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
	LPFNDLL_GetFunctionList pGetFunctionList = NULL;
	
	pDll = dlopen("/opt/nfast/toolkits/pkcs11/libcknfast.so", RTLD_LAZY);
	if(!pDll)
	{
		fputs (dlerror(), stderr);
		printf("/opt/nfast/toolkits/pkcs11/libcknfast.so library load file.\n");
		return;
	}
	/* 라이브러리에서 PKCS 함수 테이블에 대한 포인터를 구합니다.*/
	pGetFunctionList = dlsym(pDll, "C_GetFunctionList");
	if(!pGetFunctionList)
	{
		printf("C_GetFunctionList() get function failed.\n");
		return;
	}

	rv = pGetFunctionList(&pFuncList);
	if(!pFuncList)
	{
		printf("C_GetFunctionList() error --- (rv : %x)\n");
		return;
	}
	
	/* nShield PKCS#11 code */


	CK_C_INITIALIZE_ARGS lib_init_args =
	{
		NULL_PTR,	/*use default locking */
		NULL_PTR,	/*mechanisms for */
		NULL_PTR,	/*multithreaded access */
		NULL_PTR,
		CKF_OS_LOCKING_OK, /* yes, multithreaded */
		NULL_PTR
	};

	printf("Starting to initialize PKCS #11 library...\n");

	// initialize the pkcs#11 library
	rv = pFuncList->C_Initialize(&lib_init_args);
	if (rv != CKR_OK)
	{
		printf("Error: cannot initialize PKCS#11 library - %X\n", rv);
		return 1;
	}
	else printf("Initialization of PKCS#11 library completed\n");


	//slot list
	CK_SLOT_ID slotID_List[MAX_SLOTS];
	CK_ULONG numSlots = MAX_SLOTS;

	// get the list of slots in the system
	rv = pFuncList->C_GetSlotList(CK_FALSE, slotID_List, &numSlots);
	if (rv != CKR_OK)
	{
		printf("Error: cannot get slot list - %X\n", rv);
		return 1;
	}

	if (numSlots <= 0) {
		printf("There is no slot in the system\n");
	}
	else {
		printf("\nNumber of slots: %i\n", numSlots);
	}
	int slotNumberLogin;
	char c;


	printf("Please enter slot ID to be used : ");
	c = getchar();
	slotNumberLogin = atoi(&c);
	printf("\n");

	// open session
	CK_SESSION_HANDLE	sessionHandle;

	// initialize session handle
	sessionHandle = NULL_PTR;

	rv = pFuncList->C_OpenSession(slotID_List[slotNumberLogin], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &sessionHandle);
	if (rv != CKR_OK)
	{
		printf("Error: cannot open session - %X\n", rv);
		return 1;
	}
	else {

		// login to session; otherwise, it is impossible to perform crypto operation

		// login to the session/slot
		// prompt user to input password of OCS or softcard  or use fixed password "1234"
		/*CK_CHAR password[MAX_PASSWORD_LENGTH+1];
		printf("Please input password to login slot: ");
		gets_s((char *)password, 10);
		*/
		CK_CHAR password[] = "1234";

		rv = pFuncList->C_Login(sessionHandle, CKU_USER, password, /*(CK_ULONG)*/strlen((char *)password));
		if (rv != CKR_OK)
		{
			printf("Error: cannot login slot - %X\n", rv);
			return 1;
		}

		printf("Lgoin to slot %i \n\n", slotNumberLogin);

		// perform crypto operation

		// define variables for key object handle and attribute template for key searching
		CK_OBJECT_HANDLE	hKeyObject[MAX_OBJS];
		CK_ULONG NumAESKeyObject;
		NumAESKeyObject = 0;
		CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
		CK_KEY_TYPE keyType = CKK_AES;
		char KeyLabel[MAX_KEY_LABEL_SIZE];

		CK_CHAR label []= "AESKey";
		
		CK_ATTRIBUTE	pAESKeyAttribtueTemplate[] = {
			{ CKA_CLASS, &keyClass, sizeof(keyClass) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_LABEL, KeyLabel, MAX_KEY_LABEL_SIZE}
		};
		unsigned int i;
		

		for (i = 0; i < MAX_OBJS; i++)
			hKeyObject[i] = CK_INVALID_HANDLE;

		(void)memset(KeyLabel, '\0', MAX_KEY_LABEL_SIZE);   // zeroize the label buffer


		// find key

		rv = pFuncList->C_FindObjectsInit(sessionHandle, pAESKeyAttribtueTemplate, 2);
		if (rv != CKR_OK)
		{
			printf("Error: cannot find objects init - %X\n", rv);
			return 1;
		}

		rv = pFuncList->C_FindObjects(sessionHandle, hKeyObject, MAX_OBJS, &NumAESKeyObject);
		if (rv != CKR_OK)
		{
			printf("Error: cannot find objects - %X\n", rv);
			return 1;
		}

		rv = pFuncList->C_FindObjectsFinal(sessionHandle);
		if (rv != CKR_OK)
		{
			printf("Error: cannot find objects final - %X\n", rv);
			return 1;
		}

		if (NumAESKeyObject == 0)
		{ // AES Key is not exist.
			printf("There is no AES Key object.\n");
		}
		else {  // AES key exist
			printf("There is %i AES Key object.\n", NumAESKeyObject);

			for (i = 0; i < NumAESKeyObject; i++)
			{
				
				// get key attribute
				rv = pFuncList->C_GetAttributeValue(sessionHandle, hKeyObject[i], &pAESKeyAttribtueTemplate[2], 1);								
				if (rv != CKR_OK)
				{
					printf("Error: cannot get lable of key - %X\n", rv);
					return 1;
				}
				else {
					//printf("ECDSA Key -> Label : %s\n", Label);
					if(strcmp((CK_CHAR_PTR)KeyLabel, label)==0){
						printf("Find ECDSA Key!!! -> Label : %s\n", label);
						break;
					}
					
					if(pAESKeyAttribtueTemplate[2].pValue){
						pAESKeyAttribtueTemplate[2].ulValueLen = MAX_KEY_LABEL_SIZE;
						(void)memset(KeyLabel, '\0', MAX_KEY_LABEL_SIZE);
					}
					
				}
				if(i==NumAESKeyObject-1){
					printf("Can not Find (%s)ECDSA Key. \n", label);
				}
			}
		}

		// close session
		if (sessionHandle != NULL_PTR) pFuncList->C_CloseSession(sessionHandle);
	}



	// close the pkcs#11 library
	pFuncList->C_Finalize(NULL_PTR);

	return 0;
}

