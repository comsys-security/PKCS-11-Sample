/*
 * util.c
 *
 *  Created on: Aug 12, 2014
 *      Author: root
 */


#include "util.h"

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

void SAFE_FREE(void* ptr)
{
	if(ptr != NULL)
		free(ptr);
	else
		fprintf(stderr, "free is failed : mem indicates null pointer.!");
}

void binToHex(unsigned char* src, unsigned int	srcsz, char** dst)
{
	char          hex_str[]= "0123456789abcdef";
	unsigned int	i;


	*dst = (char *)malloc(srcsz * 6);
	(*dst)[srcsz * 6] = 0;

	if (!srcsz)
		return;

	for (i = 0; i < srcsz; i++)
	{
		(*dst)[i * 6 + 0] = '0';
		(*dst)[i * 6 + 1] = 'x';
		(*dst)[i * 6 + 2] = hex_str[src[i] >> 4  ];
		(*dst)[i * 6 + 3] = hex_str[src[i] & 0x0F];
		(*dst)[i * 6 + 4] = ',';

		if(((i+1)%8) == 0){
			(*dst)[i * 6 + 5] = '\n';
		}else
			(*dst)[i * 6 + 5] = ' ';
	}
	(*dst)[(srcsz-1) * 6 + 4] = '\0';
}

void binToHex_S(unsigned char* src, unsigned int	srcsz, char** dst)
{
	char          hex_str[]= "0123456789abcdef";
	unsigned int	i;


	*dst = (char *)malloc(srcsz * 2);
	(*dst)[srcsz * 2] = 0;

	if (!srcsz)
		return;

	for (i = 0; i < srcsz; i++)
	{
		(*dst)[i * 2 + 0] = hex_str[src[i] >> 4  ];
		(*dst)[i * 2 + 1] = hex_str[src[i] & 0x0F];
	}
}

char HexToChar(char c)
{
    if ('0' <= c && c <= '9')
    {
        return c - '0';
    }
    else if ('a' <= c && c <= 'f')
    {
        return c + 10 - 'a';
    }
    else if ('A' <= c && c <= 'F')
    {
        return c + 10 - 'A';
    }

    return -1;
}

long hexToBin( const char* hex, long length, unsigned char* binrary, long binrary_cap )
{
    if (length % 2 != 0 || binrary_cap < length / 2)
    {
        return 0;
    }

    //memset(binrary, 0, binrary_cap);
    long i, n = 0;
    for (i = 0; i < length; i += 2, ++n)
    {
        char high = HexToChar(hex[i]);
        if (high < 0)
        {
            return 0;
        }

        char low = HexToChar(hex[i + 1]);
        if (low < 0)
        {
            return 0;
        }

        binrary[n] = high << 4 | low;
    }
    return n;
}
