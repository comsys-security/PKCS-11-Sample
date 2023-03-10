/*
 * (c) Thales UK Limited 2015
 * 
 * The copyright in this software is the property of Thales UK Limited. This
 * software may not be used, sold, licensed, disclosed, transferred, copied,
 * modified or reproduced in whole or in part or in any manner or form other
 * than in accordance with the licence agreement provided with this software
 * or otherwise without the prior written consent of Thales UK Limited.
 * 
 */

/* Equivalent of pkcs11f.h, defining new functions used by
   the nCipher specific K-of-N login extension.
*/

/* C_LoginBegin logs a user into a token. */
CK_PKCS11_FUNCTION_INFO(C_LoginBegin)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_ULONG_PTR      pulK,      /* cards required to load logical token. */
  CK_ULONG_PTR      pulN       /* Number of cards in set */
);
#endif

/* C_LoginNext logs a user into a token. */
CK_PKCS11_FUNCTION_INFO(C_LoginNext)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_CHAR_PTR       pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen,   /* the length of the PIN */
  CK_ULONG_PTR      pulSharesLeft /* Number of remaining shares */
);
#endif

/* C_LoginEnd logs a user into a token. */
CK_PKCS11_FUNCTION_INFO(C_LoginEnd)
#ifdef CK_NEED_ARG_LIST
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType  /* the user type */
);
#endif
