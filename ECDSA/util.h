/*
 * util.h
 *
 *  Created on: Aug 12, 2014
 *      Author: root
 */

#ifndef UTIL_H_
#define UTIL_H_

void SAFE_FREE(void* ptr);
void binToHex(unsigned char* src, unsigned int	srcsz, char** dst);
long hexToBin( const char* hex, long length, unsigned char* binrary, long binrary_cap );
void binToHex_S(unsigned char* src, unsigned int	srcsz, char** dst);

#endif /* UTIL_H_ */
