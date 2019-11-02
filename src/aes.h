#pragma once
#include <stdint.h>
#include <limits.h>
#ifdef __GNUC__
#include <stddef.h>
#endif

#define AES_BLOCKSIZE			(128 / CHAR_BIT)							/* AES block size, in bytes.			*/
#define AES_BLOCKLEN			(AES_BLOCKSIZE / sizeof(uint32_t))			/* AES block length.					*/

#define AES_128_KBLOCKSIZE		(sizeof(uint32_t) * 4)						/* AES-128 key block size, in bytes.	*/
#define AES_128_SUBKEYS_COUNT	44											/* AES-128 subkeys count.				*/
#define AES_192_KBLOCKSIZE		(sizeof(uint32_t) * 6)						/* AES-192 key block size, in bytes.	*/
#define AES_192_SUBKEYS_COUNT	52											/* AES-192 subkeys count.				*/
#define AES_256_KBLOCKSIZE		(sizeof(uint32_t) * 8)						/* AES-256 key block size, in bytes.	*/
#define AES_256_SUBKEYS_COUNT	60											/* AES-256 subkeys count.				*/

#define AES_MAX_SUBKEYS_COUNT	AES_256_SUBKEYS_COUNT						/* AES max subkeys count.				*/
#define AES_MAX_SUBKEYS_SIZE	(sizeof(uint32_t) * AES_MAX_SUBKEYS_COUNT)	/* AES max subkeys size, in bytes.		*/
#define AES_MAX_KBLOCK_COUNT	AES_256_KBLOCKSIZE / sizeof(uint32_t)		/* AES max key block count.				*/
#define AES_MAX_KBLOCKSIZE		AES_256_KBLOCKSIZE							/* AES max key block size, in bytes.	*/

typedef struct
{
	/* 
	 * Source buffer.
	 * It is an union so we can access it as 32 bit words or bytes.
	 */
	union
	{
		uint32_t* buff32;
		uint8_t* buff8;
	};	

	/* The size of the source buffer.	*/
	size_t ptcSz;

	/* The size of the key				*/
	size_t keySize;
}AES_CONTEXT;

/* AES-128 key expansion.				*/
void KeySchedule128(
	uint32_t* subKeys,
	uint32_t* cKey);

/* AES-192 key expansion.				*/
void KeySchedule192(
	uint32_t* subKeys,
	uint32_t* cKey);

/* AES-256 key expansion.				*/
void KeySchedule256(
	uint32_t* subKeys, 
	uint32_t* cKey);

/* Encrypts a 128-bit block.			*/
void AesEncryptBlock(
	uint32_t* state, 
	uint32_t* subKeys,
	const size_t subKeysCount, 
	const size_t nRounds);

/* Decrypts a 128-bit block.			*/
void AesDecryptBlock(
	uint32_t* state, 
	uint32_t* subKeys, 
	const size_t subKeysCount, 
	const size_t nRounds);