/*
 * exerMain.c
 *
 *  Created on: Mar 4, 2014
 *      Author: root
 */

// All Keys should be transfered to PKCS11 Key handles.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dlfcn.h>
#include "crypt.h"
#include "util.h"

CK_RV get_slot(int private_objects, int print_used, CK_SLOT_ID *hSlot);
CK_RV ocs_login(CK_SESSION_HANDLE hSession);

static char *message = "This is sample message.";

void *pDll = NULL;
CK_FUNCTION_LIST_PTR gFunctionList = NULL;
typedef CK_RV (*LPFNDLL_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
LPFNDLL_GetFunctionList pGetFunctionList = NULL;

int main(int argc, char **argv)
{
	CK_SLOT_ID hSlot = 0;
	CK_RV rv = CKR_OK;
	CK_SESSION_HANDLE hSession;

	/* 라이브러리를 로드합니다.*/
	pDll = dlopen("/opt/nfast/toolkits/pkcs11/libcknfast.so", RTLD_LAZY);
	if(!pDll)
	{
		printf("libcknfast.so 파일을 로드하지 못하였습니다.\n");
		return;
	}
	
	/* 라이브러리에서 PKCS 함수 테이블에 대한 포인터를 구합니다.*/
	pGetFunctionList = dlsym(pDll, "C_GetFunctionList");
	if(!pGetFunctionList)
	{
		printf("C_GetFunctionList() 포인터를 획득하지 못하였습니다.\n");
		return;
	}

	rv = pGetFunctionList(&gFunctionList);
	if(!gFunctionList)
	{
		printf("C_GetFunctionList() error --- (rv : %x)\n");
		return;
	}

	//Init Token
	rv = gFunctionList->C_Initialize(NULL_PTR);
	if (rv != CKR_OK)
		goto err;

	//get slot and token
	int private_objects = 1;
	int print_used = 1;
	rv = get_slot(private_objects, print_used, &hSlot);
	if (rv != CKR_OK)
		goto err;

	//open session
	rv = gFunctionList->C_OpenSession(hSlot,
			CKF_RW_SESSION | CKF_SERIAL_SESSION,
			NULL, NULL,
			&hSession);
	if (rv != CKR_OK){
		fprintf(stderr, "Failed to open session\n");
		goto err;
	}

	//login
	rv = ocs_login(hSession);
	if (rv != CKR_OK){
		fprintf(stderr, "Failed to login\n");
		goto err;
	}

	//testing for ECDSA key import
	int ret = 1;
	CK_OBJECT_HANDLE hPrK, hPuK, hImportedPuK, hImportedPrK;
	ret = nCipher_SEC_ecdsa_keypair_gen(hSession, &hPuK, &hPrK);
	if(ret != 1)
		goto err;

	CK_BYTE_PTR pPuKVal, pPrKVal;
	CK_ULONG PuKValLen = 0, PrKValLen = 0;
	ret = nCipher_SEC_get_ecdsa_key_value(hSession, hPuK, hPrK, &pPuKVal, &PuKValLen, &pPrKVal, &PrKValLen);
	if(ret != 1)
	{
		fprintf(stderr, "Failed to get ecdsa key\n");
		goto err;
	}
	ret = nCipher_SEC_ecdsa_keypair_import(hSession, pPuKVal, PuKValLen, pPrKVal, PrKValLen,
			&hImportedPuK, &hImportedPrK);
	if(ret != 1)
		goto err;
	
	//Sign
	uchar *ecdsa_sig;
	CK_ULONG ecdsa_sig_len = 0;
	ret = nCipher_SEC_ecdsa_sign(hSession, (uchar*)message, strlen(message)+1, hImportedPrK, &ecdsa_sig, &ecdsa_sig_len);
	if(ret != 1)
	{
		fprintf(stderr, "Failed to Sign-!\n");
		rv = CKR_FUNCTION_FAILED; goto err;
	}

	//Verify
	ret = nCipher_SEC_ecdsa_verify(hSession, (uchar*)message, strlen(message)+1, ecdsa_sig, ecdsa_sig_len, hImportedPuK);
	if(ret == 1)
		printf("Verify Success-!\n");
	else
		printf("Verify Fail-!\n");





	err:
	if (rv == CKR_OK)
		fprintf(stdout, "OK\n");
	else
		fprintf(stderr, "failed rv = %08lX\n", rv);

	gFunctionList->C_Finalize(NULL_PTR);

	SAFE_FREE(pPuKVal);
	SAFE_FREE(pPrKVal);
	SAFE_FREE(ecdsa_sig);

	return rv;
}

CK_RV get_slot(int private_objects, int print_used, CK_SLOT_ID *hSlot)
{
	CK_ULONG i, islot, nslots = 0;
	CK_SLOT_ID_PTR pslots = NULL;
	CK_RV rv;
	CK_TOKEN_INFO tinfo;
	char label_padded[32]; /* same size as tinfo.label */

	// Get OCS Name
	char *label = (char*)calloc(sizeof(tinfo.label), sizeof(char));
	if (private_objects)
	{
		printf("Input OCS NAME: ");
		if(fgets(label, sizeof(tinfo.label), stdin) == NULL_PTR)
			return CK_FALSE;
		fputc('\n', stdin);
		short lasti = strlen(label);
		label[lasti-1] = '\0';
	}

	assert(sizeof(tinfo.label) == sizeof(label_padded));
	if (label) {
		if (strlen(label) > sizeof(tinfo.label)) {
			fprintf(stderr, "Label can only be %ld chars long",
					(long)sizeof(label_padded));
			return CKR_ARGUMENTS_BAD;
		}
		memset(label_padded, ' ', sizeof(label_padded));
		memcpy(label_padded, label, strlen(label));
	}

	rv = gFunctionList->C_GetSlotList(0, NULL_PTR, &nslots);
	if (rv != CKR_OK) goto err;
	if (nslots == 0) {
		rv = CKR_TOKEN_NOT_PRESENT;
		goto err;
	}

	pslots = malloc(sizeof(CK_SLOT_ID) * nslots);
	if (!pslots) {
		fprintf(stderr, "failed to malloc %ld slotIDs", nslots);
		rv = CKR_HOST_MEMORY; goto err;
	}
	rv = gFunctionList->C_GetSlotList(1, pslots, &nslots);
	if (rv != CKR_OK) goto err;

	if(private_objects == 0){
		*hSlot = pslots[0];
		goto err;
	}


	for (islot = 0; islot < nslots; islot++) {
		rv = gFunctionList->C_GetTokenInfo(pslots[islot], &tinfo);

		if (rv == CKR_TOKEN_NOT_PRESENT) {
			/* Could have been removed since the C_GetSlotList call. */
			continue;
		}

		if (rv != CKR_OK) goto err;

		if (private_objects &&
				!(tinfo.flags & CKF_USER_PIN_INITIALIZED))
			continue;

		if (label &&
				strncmp(label_padded,
						(char *)tinfo.label,
						sizeof(tinfo.label)))
			continue;

		if (print_used) {
			/* islot not very meaningful with tokenPresent used */
			printf("Using token with label \"");
			for (i = 0; i < sizeof(tinfo.label); i++)
				printf("%c", tinfo.label[i]);
			printf("\"\n");
		}

		break;
	}
	if (islot < nslots) {
		rv = CKR_OK;
		*hSlot = pslots[islot];
	} else
		rv = CKR_TOKEN_NOT_PRESENT;

	err:
	SAFE_FREE(label);
	SAFE_FREE(pslots);
	return rv;
}

CK_RV ocs_login(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CK_TRUE;
	char *passphrase = (char*)calloc(20, sizeof(char));

	printf("Input Password: ");
	if(fgets(passphrase, 20, stdin) == NULL_PTR)
		return CK_FALSE;

	fputc('\n', stdin);

	short lasti = strlen(passphrase);
	passphrase[lasti-1] = '\0';

	if (passphrase != NULL_PTR)
		rv = gFunctionList-> C_Login(hSession, CKU_USER,
				(CK_UTF8CHAR*)passphrase, (CK_ULONG)strlen((char *)passphrase));

	SAFE_FREE(passphrase);

	return rv;
}

