// nShieldPKCS11Login.cpp : Defines the entry point for the console application.



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

	/* initialize the variable */
	CK_INFO	libraryInfo;
	(void)memset(libraryInfo.libraryDescription, '\0', sizeof(libraryInfo.libraryDescription));
	(void)memset(libraryInfo.manufacturerID, '\0', sizeof(libraryInfo.manufacturerID));

	//get pkcs#11 library informaton
	rv = pFuncList->C_GetInfo(&libraryInfo);
	if (rv != CKR_OK)
	{
		printf("Error: cannot get PKCS#11 library information - %x\n", rv);
		return 1;
	}
	else {
		printf("\nLibrary Information\n");
		printf("-cryptoki Version: %i.%i\n", libraryInfo.cryptokiVersion.major, libraryInfo.cryptokiVersion.minor);
		libraryInfo.manufacturerID[31] = '\0';
		printf("-manufacturer ID: %s\n", libraryInfo.manufacturerID);
		libraryInfo.libraryDescription[31] = '\0';
		printf("-library Description: %s\n", libraryInfo.libraryDescription);
		printf("-library Version: %i.%i\n", libraryInfo.libraryVersion.major, libraryInfo.libraryVersion.minor);
	}

	//printf("\nPress any key to continue...\n");
	//_gettch();



	//slot list
	CK_SLOT_ID slotID_List[MAX_SLOTS];
	CK_ULONG numSlots = MAX_SLOTS;

	CK_SLOT_INFO slotInfo[MAX_SLOTS];
	CK_TOKEN_INFO tokenInfo[MAX_SLOTS];
	CK_ULONG i = 0;

	// initialize the slot and token info array
	for (i = 0; i < MAX_SLOTS; i++)
	{
		(void)memset(slotInfo[i].slotDescription, '\0', sizeof(slotInfo[i].slotDescription));
		(void)memset(slotInfo[i].manufacturerID, '\0', sizeof(slotInfo[i].manufacturerID));

		(void)memset(tokenInfo[i].label, '\0', sizeof(tokenInfo[i].label));
		(void)memset(tokenInfo[i].manufacturerID, '\0', sizeof(tokenInfo[i].manufacturerID));
		(void)memset(tokenInfo[i].model, '\0', sizeof(tokenInfo[i].model));
		(void)memset(tokenInfo[i].serialNumber, '\0', sizeof(tokenInfo[i].serialNumber));
		(void)memset(tokenInfo[i].utcTime, '\0', sizeof(tokenInfo[i].utcTime));
	}


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

		for (i = 0; i<numSlots; i++)
		{
			//get slot information
			rv = pFuncList->C_GetSlotInfo(slotID_List[i], &slotInfo[i]);
			if ((rv != CKR_OK) && (rv != CKR_SLOT_ID_INVALID))
			{
				printf("Error: cannot get slot information - %X\n", rv);
				return 1;
			}
			else if (rv == CKR_SLOT_ID_INVALID)
			{
				printf("\nSlot %i is invalid\n", slotID_List[i]);
			}
			else {
				printf("\nSlot %i Information\n", i);
				printf("Slot ID: %ul\n", slotID_List[i]);
				slotInfo[i].slotDescription[63] = '\0';
				printf("-slot Description: %s", slotInfo[i].slotDescription);
				slotInfo[i].manufacturerID[31] = '\0';
				printf("-manufacturer ID: %s\n", slotInfo[i].manufacturerID);
				printf("-hardware Version: %i.%i\n", slotInfo[i].hardwareVersion.major, slotInfo[i].hardwareVersion.minor);
				printf("-firmware Version: %i.%i\n", slotInfo[i].firmwareVersion.major, slotInfo[i].firmwareVersion.minor);
				if (slotInfo[i].flags & CKF_TOKEN_PRESENT) printf("-device is in slot\n");
				if (slotInfo[i].flags & CKF_REMOVABLE_DEVICE) printf("-reader supports removeable devices\n");
				if (slotInfo[i].flags & CKF_HW_SLOT) printf("-slot is a hardware slot\n");

				// determine slot type

				if (!(slotInfo[i].flags & CKF_HW_SLOT))
				{
					// this is SoftCard slot
					printf("==>This is SoftCard Slot.\n");
					//read token information
					rv = pFuncList->C_GetTokenInfo(slotID_List[i], &tokenInfo[i]);
					if (rv != CKR_OK)
					{
						printf("Error: cannot get token information - %X\n", rv);
						return 1;
					}
					else {
						printf("\nToken Information for Slot %i\n", i);
						tokenInfo[i].label[31] = '\0';
						printf("label: %s\n", tokenInfo[i].label);
						tokenInfo[i].manufacturerID[31] = '\0';
						printf("manufacturer ID: %s\n", tokenInfo[i].manufacturerID);
						tokenInfo[i].model[15] = '\0';
						printf("model: %s\n", tokenInfo[i].model);
						tokenInfo[i].serialNumber[15] = '\0';
						printf("serial Number: %s\n", tokenInfo[i].serialNumber);
						printf("hardware Version: %i.%i\n", tokenInfo[i].hardwareVersion.major, tokenInfo[i].hardwareVersion.minor);
						printf("firmware Version: %i.%i\n", tokenInfo[i].firmwareVersion.major, tokenInfo[i].firmwareVersion.minor);
						tokenInfo[i].utcTime[15] = '\0';
						printf("utcTime:%s\n", tokenInfo[i].utcTime);
						printf("TotalPublicMemory: %ul\n", tokenInfo[i].ulTotalPublicMemory);
						printf("FreePublicMemory: %ul\n", tokenInfo[i].ulFreePublicMemory);
						printf("TotalPrivateMemory: %ul\n", tokenInfo[i].ulTotalPrivateMemory);
						printf("FreePrivateMemory: %ul\n", tokenInfo[i].ulFreePrivateMemory);
					}

				}
				else if (!(slotInfo[i].flags & CKF_REMOVABLE_DEVICE))
				{
					// read token information
					rv = pFuncList->C_GetTokenInfo(slotID_List[i], &tokenInfo[i]);
					if (rv != CKR_OK)
					{
						printf("Error: cannot get token information - %X\n", rv);
						return 1;
					}
					else {
						printf("\nToken Information for Slot %i\n", i);
						tokenInfo[i].label[31] = '\0';
						printf("label: %s\n", tokenInfo[i].label);
						tokenInfo[i].manufacturerID[31] = '\0';
						printf("manufacturer ID: %s\n", tokenInfo[i].manufacturerID);
						tokenInfo[i].model[15] = '\0';
						printf("model: %s\n", tokenInfo[i].model);
						tokenInfo[i].serialNumber[15] = '\0';
						printf("serial Number: %s\n", tokenInfo[i].serialNumber);
						printf("hardware Version: %i.%i\n", tokenInfo[i].hardwareVersion.major, tokenInfo[i].hardwareVersion.minor);
						printf("firmware Version: %i.%i\n", tokenInfo[i].firmwareVersion.major, tokenInfo[i].firmwareVersion.minor);
						tokenInfo[i].utcTime[15] = '\0';
						printf("utcTime:%s\n", tokenInfo[i].utcTime);
						printf("TotalPublicMemory: %ul\n", tokenInfo[i].ulTotalPublicMemory);
						printf("FreePublicMemory: %ul\n", tokenInfo[i].ulFreePublicMemory);
						printf("TotalPrivateMemory: %ul\n", tokenInfo[i].ulTotalPrivateMemory);
						printf("FreePrivateMemory: %ul\n", tokenInfo[i].ulFreePrivateMemory);
					}
				}
				else if ((slotInfo[i].hardwareVersion.major == 0) && (slotInfo[i].hardwareVersion.minor == 0))
				{
					// this is OCS slot
					printf("==>This is OCS Slot.\n");
					// prompt to insert OCS card
					//printf("==>Please insert OCS card and press enter...\n");
					//_getch();

					//read token information
					rv = pFuncList->C_GetTokenInfo(slotID_List[i], &tokenInfo[i]);
					if (rv != CKR_OK)
					{
						printf("Error: cannot get token information - %X\n", rv);
						return 1;
					}
					else {
						printf("\nToken Information for Slot %i\n", i);
						tokenInfo[i].label[31] = '\0';
						printf("label: %s\n", tokenInfo[i].label);
						tokenInfo[i].manufacturerID[31] = '\0';
						printf("manufacturer ID: %s\n", tokenInfo[i].manufacturerID);
						tokenInfo[i].model[15] = '\0';
						printf("model: %s\n", tokenInfo[i].model);
						tokenInfo[i].serialNumber[15] = '\0';
						printf("serial Number: %s\n", tokenInfo[i].serialNumber);
						printf("hardware Version: %i.%i\n", tokenInfo[i].hardwareVersion.major, tokenInfo[i].hardwareVersion.minor);
						printf("firmware Version: %i.%i\n", tokenInfo[i].firmwareVersion.major, tokenInfo[i].firmwareVersion.minor);
						tokenInfo[i].utcTime[15] = '\0';
						printf("utcTime:%s\n", tokenInfo[i].utcTime);
						printf("TotalPublicMemory: %ul\n", tokenInfo[i].ulTotalPublicMemory);
						printf("FreePublicMemory: %ul\n", tokenInfo[i].ulFreePublicMemory);
						printf("TotalPrivateMemory: %ul\n", tokenInfo[i].ulTotalPrivateMemory);
						printf("FreePrivateMemory: %ul\n", tokenInfo[i].ulFreePrivateMemory);
					}
				}


				printf("\n");
			}

		}

	}

	if (numSlots > 0) {
		int slotNumberLogin;
		char c;
		
		printf("There is %i slot in the system\n", numSlots);
		printf("Please enter slot number to login: ");
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
			
			// login to the slot
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
			
			// close session
			if (sessionHandle != NULL_PTR) pFuncList->C_CloseSession(sessionHandle);
		}
	}


	// close the pkcs#11 library
	pFuncList->C_Finalize(NULL_PTR);

	return 0;

}

