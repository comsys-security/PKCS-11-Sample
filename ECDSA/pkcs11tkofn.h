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

/* Equivalent of pkcs11t.h, defining new types used by
   the nCipher specific K-of-N login extension.
*/

#ifndef _PKCS11TKOFN_H_
#define _PKCS11TKOFN_H_ 1

typedef struct CK_FUNCTION_LIST_EX CK_FUNCTION_LIST_EX;

typedef CK_FUNCTION_LIST_EX CK_PTR CK_FUNCTION_LIST_EX_PTR;

typedef CK_FUNCTION_LIST_EX_PTR CK_PTR CK_FUNCTION_LIST_EX_PTR_PTR;

#endif /* _PKCS11TKOFN_H_ */
