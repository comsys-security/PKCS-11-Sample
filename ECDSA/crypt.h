#ifndef _CRYPT_H_
#define _CRYPT_H_

#include "cryptoki.h"

//#define FALSE 0
//#define TRUE 1

#define SK_SIZE 128     // 128 bits (for AES)
#define SK_BYTE_SIZE 16     // 16 byte (for AES)
#define RSA_MOD_SIZE 1024    // RSA key size
#define SHA256_BYTELEN 32

#define NUM(a) (sizeof(a) / sizeof((a)[0]))

typedef unsigned char uchar;
typedef unsigned int uint;

extern CK_FUNCTION_LIST *gFunctionList;

int nCipher_SEC_ecdsa_keypair_gen(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *hPuK, CK_OBJECT_HANDLE *hPrK);
int nCipher_SEC_get_ecdsa_key_value(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPuK, CK_OBJECT_HANDLE hPrK,
		CK_BYTE_PTR* ppPuKVal, CK_ULONG_PTR pPuKValLen, CK_BYTE_PTR* ppPrKVal, CK_ULONG_PTR pPrKValLen);
int nCipher_SEC_ecdsa_keypair_import(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPuKVal, CK_ULONG PuKLen, CK_BYTE_PTR pPrKVal, CK_ULONG PrKLen,
		CK_OBJECT_HANDLE *hPuK, CK_OBJECT_HANDLE *hPrK);
int nCipher_SEC_ecdsa_sign(CK_SESSION_HANDLE hSession, uchar *msg, CK_ULONG msg_len, CK_OBJECT_HANDLE hPrK, uchar **sig, CK_ULONG *sig_len);
int nCipher_SEC_ecdsa_verify(CK_SESSION_HANDLE hSession, uchar *msg, CK_ULONG msg_len, uchar *sig, CK_ULONG sig_len,  CK_OBJECT_HANDLE hPuK);

#endif
