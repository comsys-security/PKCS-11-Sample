
// This is for testing  only.

// Notes: 
//		This program is used for demonstrating generation of AES key by nShield
//		This program requires :
//		- nShield with OCS or softcard with password "1234"


#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include "cryptoki.h"
#include "pkcs11.h"


#define MAJOR_VERSION 0
#define MINOR_VERSION 1


/* Defines */
#define MAX_OBJS	(128)
#define MAX_SLOTS	(128)
#define MAX_DEVS	(128)

#define MAX_PASSWORD_LENGTH (128)

#define MAX_KEY_LABEL_SIZE (128)

#define AES_KEY_LENGTH (32)


int main(int argc, char **argv[])
{
	void *pDll = NULL;
	CK_RV rv = CKR_OK;
	CK_FUNCTION_LIST_PTR pFuncList = NULL;
	typedef CK_RV (*LPFNDLL_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
	LPFNDLL_GetFunctionList pGetFunctionList = NULL;
	
	pDll = dlopen("/opt/nfast/toolkits/pkcs11/libcknfast.so", RTLD_LAZY);
	if(!pDll)
	{
		fputs (dlerror(), stderr);
		printf("/opt/nfast/toolkits/pkcs11/libcknfast.so 파일을 로드하지 못하였습니다.\n");
		return;
	}
	/* 라이브러리에서 PKCS 함수 테이블에 대한 포인터를 구합니다.*/
	pGetFunctionList = dlsym(pDll, "C_GetFunctionList");
	if(!pGetFunctionList)
	{
		printf("C_GetFunctionList() 포인터를 획득하지 못하였습니다.\n");
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
			//CK_CHAR password[MAX_PASSWORD_LENGTH+1];
			//printf("Please input password to login slot: ");
			//gets_s((char *)password, 10);
			

			CK_CHAR password[] = "1234";

			rv = pFuncList->C_Login(sessionHandle, CKU_USER, password, strlen((char *)password));
			if (rv != CKR_OK)
			{
				printf("Error: cannot login slot - %X\n", rv);
				return 1;
			}

			printf("Login to slot %i \n\n", slotNumberLogin);

			// perform crypto operation

			// define variables for key object handle and attribute template for key generation
			CK_OBJECT_HANDLE	hAESKeyObject;
			CK_ULONG aesKeyLength;  // define AES key length in bytes
			aesKeyLength = AES_KEY_LENGTH;
			CK_KEY_TYPE keyType = CKK_AES;
			char aesKeyLabel[MAX_KEY_LABEL_SIZE];
			(void)memset(aesKeyLabel, '\0', MAX_KEY_LABEL_SIZE);   // zeroize the label buffer
			CK_OBJECT_CLASS aesKeyClass = CKO_SECRET_KEY;
			CK_BYTE aesKeyValue[24] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
			CK_BBOOL trueValue = TRUE;
			CK_BBOOL falseValue = FALSE;

			hAESKeyObject = CK_INVALID_HANDLE;


			CK_ATTRIBUTE	pAESKeyAttribtueTemplate[] = {
				{ CKA_CLASS, &aesKeyClass, sizeof(aesKeyClass) },  // fixed value
				{ CKA_TOKEN, &trueValue, sizeof(trueValue) },       /* if true and CKNFAST_OVERRIDE_SECURITY_ASSURANCES=tokenkeys or all in cknfastrc, key will be generated and key blob file will be created    *
																	* if true and no definitonal of CKNFAST_OVERRIDE_SECURITY_ASSURANCES in cknfastrc, key generation will return error.   *
																	* if false, key will be generated but key blob file will not be created   */
				{ CKA_PRIVATE, &trueValue, sizeof(trueValue) },     // fixed value; private object
				{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },   // fixed value; ; must include in key generation
				{ CKA_LABEL, "aestestkey", sizeof("Test AES Key") },  // key label; ; must include in key generation
				{ CKA_VALUE_LEN, &aesKeyLength, sizeof(aesKeyLength) },  // AES key length in bytes
				{ CKA_ENCRYPT, &trueValue, sizeof(trueValue) },     // encrypt function
				{ CKA_DECRYPT, &trueValue, sizeof(trueValue) },     // decrypt function
				{ CKA_UNWRAP, &trueValue, sizeof(trueValue) },     // unwrap function
				{ CKA_WRAP, &trueValue, sizeof(trueValue) }     // wrap function
			};


			CK_MECHANISM mechanismAESKey = { CKM_AES_KEY_GEN, NULL_PTR, 0 };   // AES key generation mechanism


			// generate RSA key
			rv = pFuncList->C_GenerateKey(sessionHandle, &mechanismAESKey, pAESKeyAttribtueTemplate, 10, &hAESKeyObject);
			if (rv != CKR_OK)
			{
				printf("Error: cannot generate AES key - %X\n", rv);
				return 1;
			}

			printf("AES key is generated. \n");

			
			// close session
			if (sessionHandle != NULL_PTR) rv = pFuncList->C_CloseSession(sessionHandle);
		}
	}


	// close the pkcs#11 library
	rv = pFuncList->C_Finalize(NULL_PTR);

	return 0;
}

