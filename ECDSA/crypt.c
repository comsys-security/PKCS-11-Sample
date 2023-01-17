
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "crypt.h"
#include "keyTemplate.h"
#include "ecparams.h"
#include "util.h"


int nCipher_SEC_ecdsa_keypair_gen(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *hPuK, CK_OBJECT_HANDLE *hPrK)
{
	CK_RV rv = CKR_OK;

	//Set Object Template
	CK_BBOOL true = CK_TRUE;
	CK_BBOOL false = CK_FALSE;
	CK_OBJECT_CLASS class_public = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS class_private = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type_ec = CKK_ECDSA;
	CK_BYTE ecParams[] = {};
	CK_BYTE ecPoint[] = {};

	CK_ATTRIBUTE ecPKTemplate[] = {
			{CKA_CLASS, &class_public, sizeof(class_public)},
			{CKA_PRIVATE, &false, sizeof(CK_BBOOL)},
			{CKA_MODIFIABLE, &false, sizeof(CK_BBOOL)},
			{CKA_TOKEN, &false, sizeof(CK_BBOOL)},
			{CKA_LABEL, NULL_PTR, 0},
			{CKA_KEY_TYPE, &key_type_ec, sizeof(key_type_ec)},
			{CKA_ID, NULL_PTR, 0},
			{CKA_SUBJECT, NULL_PTR, 0},
			{CKA_ENCRYPT, &false, sizeof(CK_BBOOL)},
			{CKA_VERIFY, &true, sizeof(CK_BBOOL)},
			{CKA_EC_PARAMS, ecParams, sizeof(ecParams)}
	};

	CK_ATTRIBUTE ecRKTemplate[] = {
			{CKA_CLASS, &class_private, sizeof(class_private)},
			{CKA_PRIVATE, &true, sizeof(CK_BBOOL)},
			{CKA_MODIFIABLE, &false, sizeof(CK_BBOOL)},
			{CKA_TOKEN, &false, sizeof(CK_BBOOL)},
			{CKA_LABEL, NULL_PTR, 0},
			{CKA_KEY_TYPE, &key_type_ec, sizeof(key_type_ec)},
			{CKA_ID, NULL_PTR, 0},
			{CKA_SUBJECT, NULL_PTR, 0},
			{CKA_SENSITIVE, &false, sizeof(CK_BBOOL)},
			{CKA_DECRYPT, &false, sizeof(CK_BBOOL)},
			{CKA_SIGN, &true, sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE, &true, sizeof(CK_BBOOL)}
	};

	//Label Setting
	char *ecPKLabel = "ECDSA_PK#1";
	if(ecPKTemplate[4].type == CKA_LABEL){
		ecPKTemplate[4].ulValueLen = (CK_ULONG)strlen(ecPKLabel)+1;
		ecPKTemplate[4].pValue = (void*)ecPKLabel;
	}else
		fprintf(stderr, "Failed to set ECDSA Public Key Label");

	char *ecRKLabel = "ECDSA_RK#1";
	if(ecRKTemplate[4].type == CKA_LABEL){
		ecRKTemplate[4].ulValueLen = (CK_ULONG)strlen(ecRKLabel)+1;
		ecRKTemplate[4].pValue = (void*)ecRKLabel;
	}else
		fprintf(stderr, "Failed to set ECDSA Public Key Label");

	//Curve Setting
	if(ecPKTemplate[10].type == CKA_EC_PARAMS){
		ecPKTemplate[10].ulValueLen = sizeof(NISTP256);
		ecPKTemplate[10].pValue = (void*)NISTP256;
	}

	//Generate EC Keypair
	CK_MECHANISM ec_keypair_gen_mech = {CKM_ECDSA_KEY_PAIR_GEN, NULL_PTR, 0};
	rv = gFunctionList->C_GenerateKeyPair(hSession, &ec_keypair_gen_mech, ecPKTemplate, NUM(ecPKTemplate),
			ecRKTemplate, NUM(ecRKTemplate), hPuK, hPrK);

	printf("EC Public KEY HANDLE: %lu\n", *hPuK);
	printf("EC Private KEY HANDLE: %lu\n", *hPrK);

	if(rv == CKR_OK)
		return 1;
	else
		return 0;
}

int nCipher_SEC_get_ecdsa_key_value(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPuK, CK_OBJECT_HANDLE hPrK,
		CK_BYTE_PTR* ppPuKVal, CK_ULONG_PTR pPuKValLen, CK_BYTE_PTR* ppPrKVal, CK_ULONG_PTR pPrKValLen)
{
	CK_RV rv = CKR_OK;

	//Get EC Public Key Value
	CK_ATTRIBUTE ecPuKValTemplate[] = {
			{CKA_EC_POINT, NULL_PTR, 0}
	};

	rv = gFunctionList->C_GetAttributeValue(hSession,
			hPuK,
			ecPuKValTemplate,
			NUM(ecPuKValTemplate));

	if(rv != CKR_OK)
		return 0;

	ecPuKValTemplate[0].pValue = (CK_BYTE_PTR)malloc(ecPuKValTemplate[0].ulValueLen);
	if (!ecPuKValTemplate[0].pValue) {
		fprintf(stderr, "failed to malloc data length %ld", ecPuKValTemplate[0].ulValueLen);
		rv = CKR_HOST_MEMORY; return 0;
	}
	rv = gFunctionList->C_GetAttributeValue(hSession,
			hPuK,
			ecPuKValTemplate,
			NUM(ecPuKValTemplate));
	if (rv != CKR_OK)
		return 0;

	*ppPuKVal = ecPuKValTemplate[0].pValue;
	*pPuKValLen = ecPuKValTemplate[0].ulValueLen;

	char* pECPKHexStr;
	binToHex(ecPuKValTemplate[0].pValue, ecPuKValTemplate[0].ulValueLen, &pECPKHexStr);
	printf("EC Public Key Hex String:\n%s\n", pECPKHexStr);




	//Get EC Private Key Value
	CK_ATTRIBUTE ecPrKValTemplate[] = {
			{CKA_VALUE, NULL_PTR, 0}
	};

	rv = gFunctionList->C_GetAttributeValue(hSession,
			hPrK,
			ecPrKValTemplate,
			NUM(ecPrKValTemplate));

	if(rv != CKR_OK)
		return 0;

	ecPrKValTemplate[0].pValue = (CK_BYTE_PTR)malloc(ecPrKValTemplate[0].ulValueLen);
	if (!ecPrKValTemplate[0].pValue) {
		fprintf(stderr, "failed to malloc data length %ld", ecPrKValTemplate[0].ulValueLen);
		rv = CKR_HOST_MEMORY; return 0;
	}
	rv = gFunctionList->C_GetAttributeValue(hSession,
			hPrK,
			ecPrKValTemplate,
			NUM(ecPrKValTemplate));
	if (rv != CKR_OK)
		return 0;

	*ppPrKVal = ecPrKValTemplate[0].pValue;
	*pPrKValLen = ecPrKValTemplate[0].ulValueLen;

	char* pECRKHexStr;
	binToHex(ecPrKValTemplate[0].pValue, ecPrKValTemplate[0].ulValueLen, &pECRKHexStr);
	printf("EC Private Key Hex String:\n%s\n", pECRKHexStr);


	return 1;
}

int nCipher_SEC_ecdsa_keypair_import(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPuKVal, CK_ULONG PuKLen, CK_BYTE_PTR pPrKVal, CK_ULONG PrKLen,
		CK_OBJECT_HANDLE *hPuK, CK_OBJECT_HANDLE *hPrK)
{
	CK_RV rv = CKR_OK;

	//Set Object Template
	CK_BBOOL true = CK_TRUE;
	CK_BBOOL false = CK_FALSE;
	CK_OBJECT_CLASS class_public = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS class_private = CKO_PRIVATE_KEY;
	CK_KEY_TYPE key_type_ec = CKK_ECDSA;
	CK_BYTE ecParams[] = {};

	CK_ATTRIBUTE ecPKTemplate[] = {
			{CKA_CLASS, &class_public, sizeof(class_public)},
			{CKA_PRIVATE, &false, sizeof(CK_BBOOL)},
			{CKA_MODIFIABLE, &false, sizeof(CK_BBOOL)},
			{CKA_TOKEN, &false, sizeof(CK_BBOOL)},
			{CKA_LABEL, NULL_PTR, 0},
			{CKA_KEY_TYPE, &key_type_ec, sizeof(key_type_ec)},
			{CKA_ID, NULL_PTR, 0},
			{CKA_SUBJECT, NULL_PTR, 0},
			{CKA_ENCRYPT, &false, sizeof(CK_BBOOL)},
			{CKA_VERIFY, &true, sizeof(CK_BBOOL)},
			{CKA_EC_PARAMS, ecParams, sizeof(ecParams)},
			{CKA_EC_POINT, pPuKVal, PuKLen}
	};

	CK_ATTRIBUTE ecRKTemplate[] = {
			{CKA_CLASS, &class_private, sizeof(class_private)},
			{CKA_PRIVATE, &true, sizeof(CK_BBOOL)},
			{CKA_MODIFIABLE, &false, sizeof(CK_BBOOL)},
			{CKA_TOKEN, &false, sizeof(CK_BBOOL)},
			{CKA_LABEL, NULL_PTR, 0},
			{CKA_KEY_TYPE, &key_type_ec, sizeof(key_type_ec)},
			{CKA_ID, NULL_PTR, 0},
			{CKA_SUBJECT, NULL_PTR, 0},
			{CKA_SENSITIVE, &true, sizeof(CK_BBOOL)},
			{CKA_DECRYPT, &false, sizeof(CK_BBOOL)},
			{CKA_SIGN, &true, sizeof(CK_BBOOL)},
			{CKA_EXTRACTABLE, &false, sizeof(CK_BBOOL)},
			{CKA_EC_PARAMS, ecParams, sizeof(ecParams)},
			{CKA_VALUE, pPrKVal, PrKLen}
	};

	//Label Setting
	char *ecPKLabel = "EXT_ECDSA_PK#1";
	if(ecPKTemplate[4].type == CKA_LABEL){
		ecPKTemplate[4].ulValueLen = (CK_ULONG)strlen(ecPKLabel)+1;
		ecPKTemplate[4].pValue = (void*)ecPKLabel;
	}else
		fprintf(stderr, "Failed to set ECDSA Public Key Label");

	char *ecRKLabel = "EXT_ECDSA_RK#1";
	if(ecRKTemplate[4].type == CKA_LABEL){
		ecRKTemplate[4].ulValueLen = (CK_ULONG)strlen(ecRKLabel)+1;
		ecRKTemplate[4].pValue = (void*)ecRKLabel;
	}else
		fprintf(stderr, "Failed to set ECDSA Public Key Label");

	//Curve Setting
	if(ecPKTemplate[10].type == CKA_EC_PARAMS){
		ecPKTemplate[10].ulValueLen = sizeof(NISTP256);
		ecPKTemplate[10].pValue = (void*)NISTP256;
	}
	if(ecRKTemplate[12].type == CKA_EC_PARAMS){
		ecRKTemplate[12].ulValueLen = sizeof(NISTP256);
		ecRKTemplate[12].pValue = (void*)NISTP256;
	}

	//Import EC Public Key
	rv = gFunctionList->C_CreateObject(hSession, ecPKTemplate, NUM(ecPKTemplate), hPuK);
	//Import EC Private Key
	rv = gFunctionList->C_CreateObject(hSession, ecRKTemplate, NUM(ecRKTemplate), hPrK);

	printf("EC Public KEY HANDLE: %lu\n", *hPuK);
	printf("EC Private KEY HANDLE: %lu\n", *hPrK);

	if(rv == CKR_OK)
		return 1;
	else
		return 0;
}

int nCipher_SEC_ecdsa_sign(CK_SESSION_HANDLE hSession, uchar *msg, CK_ULONG msg_len, CK_OBJECT_HANDLE hPrK, uchar **sig, CK_ULONG *sig_len)
{
	CK_ULONG rv;
	CK_MECHANISM rsa_sign_mech = {CKM_ECDSA_SHA1, NULL_PTR, 0};

	rv = gFunctionList->C_SignInit(hSession, &rsa_sign_mech, hPrK);
	if(rv == CKR_OK){
		rv = gFunctionList->C_Sign(hSession, msg, msg_len, NULL_PTR, sig_len);
		if(rv == CKR_OK)
		{
			*sig = (CK_BYTE*)malloc(sizeof(uchar)*(*sig_len));
			rv = gFunctionList->C_Sign(hSession, msg, msg_len, *sig, sig_len);
		}
	}

	if(rv == CKR_OK)
		return 1;
	else
		return 0;
}

int nCipher_SEC_ecdsa_verify(CK_SESSION_HANDLE hSession, uchar *msg, CK_ULONG msg_len, uchar *sig, CK_ULONG sig_len,  CK_OBJECT_HANDLE hPuK)
{
	CK_ULONG rv;
	CK_MECHANISM rsa_verify_mech = {CKM_ECDSA_SHA1, NULL_PTR, 0};

	rv = gFunctionList->C_VerifyInit(hSession, &rsa_verify_mech, hPuK);
	if(rv == CKR_OK)
		rv = gFunctionList->C_Verify(hSession, msg, msg_len, sig, sig_len);

	if(rv == CKR_OK)
		return 1;
	else
		return 0;
}

