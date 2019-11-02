#include "aesom.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <wmmintrin.h>
#include "helper.h"

#ifdef _MSC_VER
typedef union
{
	__declspec(align(16)) uint32_t buff32[4];
	__declspec(align(16)) uint8_t buff8[16];
}AES_BLOCK;
#elif defined(__GNUC__)
typedef union
{
	uint32_t buff32[4] __attribute__((aligned(16)));
	uint8_t buff8[16] __attribute__((aligned(16)));
}AES_BLOCK;
#endif

/* XOR 128-bit block. */
#define XOR128(a,b)					{						\
										a[0] ^= b[0];		\
										a[1] ^= b[1];		\
										a[2] ^= b[2];		\
										a[3] ^= b[3];		\
									}
/* Validate the GCM tag. */
#define VALIDATE_GCMTAG(tag1, tag2)((memcmp(tag1,tag2, sizeof(AES_BLOCK))) ? AES_ERR_INVALIDTAG : AES_ERR_OK)

AesCode AesCbcEncrypt(
	AES_CONTEXT* ctx,
	uint32_t* iVec,
	uint32_t* subKeys)
{
	if (!ctx || !ctx->buff32 || !iVec || !subKeys)
	{
		return AES_ERR_INVALIDPARAM;
	}
	else if (!ctx->ptcSz)
	{
		return AES_ERR_INVALIDSIZE;
	}

	const size_t blockCount = ctx->ptcSz / AES_BLOCKSIZE;
	const size_t lBlockSz = ctx->ptcSz % AES_BLOCKSIZE;
	const size_t nRounds = (ctx->keySize >> 2) + 6 - 1;
	const size_t subKeysCount = ((nRounds + 1) + 1) << 2;
	uint32_t* pBlock = ctx->buff32;
	uint32_t tBlock1[4] = { 0 };
	uint32_t tBlock2[4] = { 0 };

	if (!blockCount)
	{
		memcpy(tBlock1, ctx->buff32, ctx->ptcSz);
		memcpy(tBlock2, iVec, AES_BLOCKSIZE);
		XOR128(tBlock1, tBlock2);

		AesEncryptBlock(tBlock1, subKeys, subKeysCount, nRounds);
		memcpy(iVec, tBlock1, AES_BLOCKSIZE);
		memcpy(pBlock, tBlock2, sizeof(uint8_t) * lBlockSz);
		return AES_ERR_OK;
	}

	XOR128(pBlock, iVec);

	if (blockCount == 1 && !lBlockSz)
	{
		AesEncryptBlock(pBlock, subKeys, subKeysCount, nRounds);
		return AES_ERR_OK;
	}
	
	for (size_t i = 0; i < (blockCount - 1); i++)
	{
		AesEncryptBlock(pBlock, subKeys, subKeysCount, nRounds);
		XOR128((&pBlock[4]), pBlock);

		pBlock = &ctx->buff32[(i + 1) << 2];
	}

	if (!lBlockSz)
	{
		AesEncryptBlock(pBlock, subKeys, subKeysCount, nRounds);
		return AES_ERR_OK;
	}

	// Copies the last two blocks
	memcpy(tBlock1, pBlock, AES_BLOCKSIZE);
	AesEncryptBlock(tBlock1, subKeys, subKeysCount, nRounds);
	memcpy(tBlock2, &pBlock[4], lBlockSz);


#ifndef __GNUC__
#pragma warning(disable:6385)
#endif 
	XOR128(tBlock2, tBlock1);
#ifndef __GNUC__
#pragma warning(default:6385)
#endif

	AesEncryptBlock(tBlock2, subKeys, subKeysCount, nRounds);
	memcpy(pBlock, tBlock2, AES_BLOCKSIZE);
	memcpy(&pBlock[4], tBlock1, sizeof(uint8_t) * lBlockSz);

	return AES_ERR_OK;
}

AesCode AesCbcEncryptStream(
	FILE* destFile,
	FILE* srcFile,
	AES_CONTEXT* ctx,
	uint32_t* iVec,
	uint32_t* subKeys)
{
	if (!ctx || !iVec || !subKeys)
	{
		return AES_ERR_INVALIDPARAM;
	}
	else if (!ctx->ptcSz)
	{
		return AES_ERR_INVALIDSIZE;
	}

	const size_t blockCount = ctx->ptcSz / AES_BLOCKSIZE;
	const size_t lBlockSz = ctx->ptcSz % AES_BLOCKSIZE;
	const size_t nRounds = (ctx->keySize >> 2) + 6 - 1;
	const size_t subKeysCount = ((nRounds + 1) + 1) << 2;
	
	AES_BLOCK buff;
	AES_BLOCK tBuff;

	if (!blockCount)
	{
		if (fread(buff.buff8, ctx->ptcSz, 1, srcFile) != 1)
		{
			return AES_ERR_READFAILED;
		}

		memcpy(tBuff.buff8, iVec, AES_BLOCKSIZE);
		XOR128(buff.buff32, tBuff.buff32);

		AesEncryptBlock(buff.buff32, subKeys, subKeysCount, nRounds);
		memcpy(iVec, buff.buff8, AES_BLOCKSIZE);

		if (fwrite(tBuff.buff8, sizeof(uint8_t) * lBlockSz, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}

		return AES_ERR_OK;
	}

	if (fread(buff.buff8, AES_BLOCKSIZE, 1, srcFile) != 1)
	{
		return AES_ERR_READFAILED;
	}

	XOR128(buff.buff32, iVec);

	if (blockCount == 1 && !lBlockSz)
	{
		AesEncryptBlock(buff.buff32, subKeys, subKeysCount, nRounds);

		if (fwrite(buff.buff8, AES_BLOCKSIZE, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}

		return AES_ERR_OK;
	}
	
	for (size_t i = 0; i < (blockCount - 1); i++)
	{
		AesEncryptBlock(buff.buff32, subKeys, subKeysCount, nRounds);

		if (fwrite(buff.buff8, AES_BLOCKSIZE, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}

		if (fread(tBuff.buff8, AES_BLOCKSIZE, 1, srcFile) != 1)
		{
			return AES_ERR_READFAILED;
		}

		XOR128(tBuff.buff32, buff.buff32);
		memcpy(buff.buff8, tBuff.buff8, AES_BLOCKSIZE);
	}

	AesEncryptBlock(buff.buff32, subKeys, subKeysCount, nRounds);	

	if (!lBlockSz)
	{
		if (fwrite(buff.buff8, AES_BLOCKSIZE, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}
		return AES_ERR_OK;
	}

	memset(tBuff.buff8, 0, sizeof(tBuff));
	if (fread(tBuff.buff8, sizeof(uint8_t) * lBlockSz, 1, srcFile) != 1)
	{
		return AES_ERR_READFAILED;
	}

	XOR128(tBuff.buff32, buff.buff32);
	AesEncryptBlock(tBuff.buff32, subKeys, subKeysCount, nRounds);

	if (fwrite(tBuff.buff8, AES_BLOCKSIZE, 1, destFile) != 1)
	{
		return AES_ERR_WRITEFAILED;
	}

	if (fwrite(buff.buff8, sizeof(uint8_t) * lBlockSz, 1, destFile) != 1)
	{
		return AES_ERR_WRITEFAILED;
	}

	return AES_ERR_OK;
}

AesCode AesCbcDecrypt(
	AES_CONTEXT* ctx,
	uint32_t* iVec,
	uint32_t* subKeys)
{
	if (!ctx || !ctx->buff32 || !iVec || !subKeys)
	{
		return AES_ERR_INVALIDPARAM;
	}
	else if (!ctx->ptcSz)
	{
		return AES_ERR_INVALIDSIZE;
	}

	const size_t blockCount = ctx->ptcSz / AES_BLOCKSIZE;
	const size_t lBlockSz = ctx->ptcSz % AES_BLOCKSIZE;
	const size_t nRounds = (ctx->keySize >> 2) + 6 - 1;
	const size_t subKeysCount = ((nRounds + 1) + 1) << 2;
	uint32_t* pBlock = ctx->buff32;
	AES_BLOCK tBlock1 = { 0 };
	AES_BLOCK tBlock2 = { 0 };

	if (!blockCount)
	{
		memcpy(tBlock1.buff32, ctx->buff32, lBlockSz);
		memcpy(tBlock2.buff32, iVec, AES_BLOCKSIZE);
		AesDecryptBlock(tBlock2.buff32, subKeys, subKeysCount, nRounds);
		XOR128(tBlock2.buff32, tBlock1.buff32);

		memcpy(pBlock, tBlock2.buff32, ctx->ptcSz);
		return AES_ERR_OK;
	}

	memcpy(tBlock1.buff32, pBlock, AES_BLOCKSIZE);

	if (blockCount == 1 && lBlockSz)
	{
		AesDecryptBlock(tBlock1.buff32, subKeys, subKeysCount, nRounds);
		memcpy(tBlock2.buff32, &ctx->buff32[4], lBlockSz);
		memcpy(&tBlock2.buff8[lBlockSz], &tBlock1.buff8[lBlockSz], AES_BLOCKSIZE - lBlockSz);
		XOR128(tBlock1.buff32, tBlock2.buff32);

		AesDecryptBlock(tBlock2.buff32, subKeys, subKeysCount, nRounds);
		XOR128(tBlock2.buff32, iVec);

		memcpy(pBlock, tBlock2.buff32, AES_BLOCKSIZE);
		memcpy(&ctx->buff32[4], tBlock1.buff32, lBlockSz);
		return AES_ERR_OK;
	}

	AesDecryptBlock(pBlock, subKeys, subKeysCount, nRounds);
	XOR128(pBlock, iVec);

	pBlock = &ctx->buff32[4];

	if (blockCount == 1 && !lBlockSz)
	{
		return AES_ERR_OK;
	}

	for (size_t i = 1; i < (blockCount - 1); i++)
	{
		memcpy(tBlock2.buff32, pBlock, AES_BLOCKSIZE);
		AesDecryptBlock(pBlock, subKeys, subKeysCount, nRounds);
		XOR128(pBlock, tBlock1.buff32);

		memcpy(tBlock1.buff32, tBlock2.buff32, AES_BLOCKSIZE);
		pBlock = &ctx->buff32[(i + 1) << 2];
	}

	if (!lBlockSz)
	{
		AesDecryptBlock(pBlock, subKeys, subKeysCount, nRounds);
		XOR128(pBlock, tBlock1.buff32);
		return AES_ERR_OK;
	}

	memcpy(tBlock2.buff32, pBlock, AES_BLOCKSIZE);
	AesDecryptBlock(tBlock2.buff32, subKeys, subKeysCount, nRounds);
	memcpy(pBlock, &pBlock[4], sizeof(uint8_t) * lBlockSz);

	memcpy(&((uint8_t*)pBlock)[lBlockSz], &tBlock2.buff8[lBlockSz], sizeof(uint8_t) * (AES_BLOCKSIZE - lBlockSz));

#ifndef __GNUC__
#pragma warning(disable:6385)
#endif 
	XOR128(tBlock2.buff32, pBlock);
#ifndef __GNUC__
#pragma warning(default:6385)
#endif

	AesDecryptBlock(pBlock, subKeys, subKeysCount, nRounds);
	XOR128(pBlock, tBlock1.buff32);

	memcpy(((uint8_t*)&pBlock[4]), tBlock2.buff8, sizeof(uint8_t) * lBlockSz);

	return AES_ERR_OK;
}

AesCode AesCbcDecryptStream(
	FILE* destFile,
	FILE* srcFile,
	AES_CONTEXT* ctx,
	uint32_t* iVec,
	uint32_t* subKeys)
{
	if (!ctx || !iVec || !subKeys)
	{
		return AES_ERR_INVALIDPARAM;
	}
	else if (!ctx->ptcSz)
	{
		return AES_ERR_INVALIDSIZE;
	}

	const size_t blockCount = ctx->ptcSz / AES_BLOCKSIZE;
	const size_t lBlockSz = ctx->ptcSz % AES_BLOCKSIZE;
	const size_t nRounds = (ctx->keySize >> 2) + 6 - 1;
	const size_t subKeysCount = ((nRounds + 1) + 1) << 2;
	AES_BLOCK buff = { 0 };
	AES_BLOCK tBlock1 = { 0 };
	AES_BLOCK tBlock2 = { 0 };

	if (!blockCount)
	{
		if(fread(tBlock1.buff8, lBlockSz, 1, srcFile) != 1)
		{
			return AES_ERR_READFAILED;
		}
		
		memcpy(tBlock2.buff32, iVec, AES_BLOCKSIZE);
		AesDecryptBlock(tBlock2.buff32, subKeys, subKeysCount, nRounds);
		XOR128(tBlock2.buff32, tBlock1.buff32);

		if (fwrite(tBlock2.buff8, ctx->ptcSz, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}
		
		return AES_ERR_OK;
	}

	if (fread(tBlock1.buff8, AES_BLOCKSIZE, 1, srcFile) != 1)
	{
		return AES_ERR_READFAILED;
	}	

	if (blockCount == 1 && lBlockSz)
	{
		AesDecryptBlock(tBlock1.buff32, subKeys, subKeysCount, nRounds);

		if (fread(tBlock2.buff8, lBlockSz, 1, srcFile) != 1)
		{
			return AES_ERR_READFAILED;
		}

		memcpy(&tBlock2.buff8[lBlockSz], &tBlock1.buff8[lBlockSz], AES_BLOCKSIZE - lBlockSz);
		XOR128(tBlock1.buff32, tBlock2.buff32);

		AesDecryptBlock(tBlock2.buff32, subKeys, subKeysCount, nRounds);
		XOR128(tBlock2.buff32, iVec);

		if (fwrite(tBlock2.buff8, AES_BLOCKSIZE, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}

		if (fwrite(tBlock1.buff8, lBlockSz, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}		
		
		return AES_ERR_OK;
	}

	memcpy(tBlock2.buff8, tBlock1.buff8, AES_BLOCKSIZE);
	AesDecryptBlock(tBlock2.buff32, subKeys, subKeysCount, nRounds);
	XOR128(tBlock2.buff32, iVec);

	if (fwrite(tBlock2.buff8, AES_BLOCKSIZE, 1, destFile) != 1)
	{
		return AES_ERR_WRITEFAILED;
	}	

	if (blockCount == 1 && !lBlockSz)
	{
		return AES_ERR_OK;
	}

	if (fread(buff.buff8, AES_BLOCKSIZE, 1, srcFile) != 1)
	{
		return AES_ERR_READFAILED;
	}

	for (size_t i = 1; i < (blockCount - 1); i++)
	{
		memcpy(tBlock2.buff8, buff.buff8, AES_BLOCKSIZE);
		AesDecryptBlock(buff.buff32, subKeys, subKeysCount, nRounds);
		XOR128(buff.buff32, tBlock1.buff32);		

		memcpy(tBlock1.buff8, tBlock2.buff8, AES_BLOCKSIZE);

		if (fwrite(buff.buff8, AES_BLOCKSIZE, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}

		if (fread(buff.buff8, AES_BLOCKSIZE, 1, srcFile) != 1)
		{
			return AES_ERR_READFAILED;
		}
	}

	if (!lBlockSz)
	{		
		AesDecryptBlock(buff.buff32, subKeys, subKeysCount, nRounds);
		XOR128(buff.buff32, tBlock1.buff32);		

		if (fwrite(buff.buff8, AES_BLOCKSIZE, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}

		return AES_ERR_OK;
	}

	memcpy(tBlock2.buff8, buff.buff8, AES_BLOCKSIZE);
	AesDecryptBlock(tBlock2.buff32, subKeys, subKeysCount, nRounds);
	
	if (fread(buff.buff8, sizeof(uint8_t) * lBlockSz, 1, srcFile) != 1)
	{
		return AES_ERR_READFAILED;
	}

	memcpy(&buff.buff8[lBlockSz], &tBlock2.buff8[lBlockSz], sizeof(uint8_t) * (AES_BLOCKSIZE - lBlockSz));
	XOR128(tBlock2.buff32, buff.buff32);

	AesDecryptBlock(buff.buff32, subKeys, subKeysCount, nRounds);
	XOR128(buff.buff32, tBlock1.buff32);

	if (fwrite(buff.buff8, AES_BLOCKSIZE, 1, destFile) != 1)
	{
		return AES_ERR_WRITEFAILED;
	}

	if (fwrite(tBlock2.buff8, sizeof(uint8_t) * lBlockSz, 1, destFile) != 1)
	{
		return AES_ERR_WRITEFAILED;
	}

	return AES_ERR_OK;
}

AesCode AesCtrCrypt(
	AES_CONTEXT* ctx,
	uint32_t* iVec,
	uint32_t* subKeys)
{
	if (!ctx || !ctx->buff32 || !iVec || !subKeys)
	{
		return AES_ERR_INVALIDPARAM;
	}
	else if (!ctx->ptcSz)
	{
		return AES_ERR_INVALIDSIZE;
	}

	AES_BLOCK counter = { 0 };
	const size_t blockCount = ctx->ptcSz / AES_BLOCKSIZE;
	const size_t lBlockSz = ctx->ptcSz % AES_BLOCKSIZE;
	const size_t nRounds = (ctx->keySize >> 2) + 6 - 1;
	const size_t subKeysCount = ((nRounds + 1) + 1) << 2;
	uint32_t* const pCounter = &counter.buff32[2];

	memcpy(counter.buff32, iVec, sizeof(uint64_t));

	for (uint64_t i = 0; i < blockCount; i++)
	{
		AesEncryptBlock(counter.buff32, subKeys, subKeysCount, nRounds);
		XOR128((&ctx->buff32[i << 2]), counter.buff32);		

		memcpy(counter.buff32, iVec, sizeof(uint64_t));
		uint64_t tmp = bswap_64(i + 1);
		memcpy(pCounter, &tmp, sizeof(uint64_t));
	}

	if (lBlockSz)
	{
		AesEncryptBlock(counter.buff32, subKeys, subKeysCount, nRounds);		
		for (size_t j = 0; j < lBlockSz; j++)
		{
			ctx->buff8[(blockCount << 4) + j] ^= counter.buff8[j];
		}
	}	

	/* Wipe counter */
	memset(counter.buff32, 0, sizeof(counter));

	return AES_ERR_OK;
}


//			|--------|
//			|-------------------------------

AesCode AesCtrCryptStream(
	FILE* destFile,
	FILE* srcFile,
	AES_CONTEXT* ctx,
	uint32_t* iVec,
	uint32_t* subKeys)
{
	if (!ctx || !destFile || !srcFile || !iVec || !subKeys)
	{
		return AES_ERR_INVALIDPARAM;
	}
	else if (!ctx->ptcSz)
	{
		return AES_ERR_INVALIDSIZE;
	}

	AES_BLOCK buff;

	AES_BLOCK counter = { 0 };
	const size_t blockCount = ctx->ptcSz / AES_BLOCKSIZE;
	const size_t lBlockSz = ctx->ptcSz % AES_BLOCKSIZE;
	const size_t nRounds = (ctx->keySize >> 2) + 6 - 1;
	const size_t subKeysCount = ((nRounds + 1) + 1) << 2;
	uint32_t* const pCounter = &counter.buff32[2];

	memcpy(counter.buff32, iVec, sizeof(uint64_t));

	for (uint64_t i = 0; i < blockCount; i++)
	{
		AesEncryptBlock(counter.buff32, subKeys, subKeysCount, nRounds);

		if (fread(buff.buff8, AES_BLOCKSIZE, 1, srcFile) != 1)
		{
			return AES_ERR_READFAILED;
		}

		XOR128(buff.buff32, counter.buff32);
		if (fwrite(buff.buff8, AES_BLOCKSIZE, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}

		memcpy(counter.buff32, iVec, sizeof(uint64_t));
		uint64_t tmp = bswap_64(i + 1);
		memcpy(pCounter, &tmp, sizeof(uint64_t));
	}

	AesEncryptBlock(counter.buff32, subKeys, subKeysCount, nRounds);

	if (lBlockSz)
	{
		if (fread(buff.buff8, lBlockSz, 1, srcFile) != 1)
		{
			return AES_ERR_READFAILED;
		}

		XOR128(buff.buff32, counter.buff32);

		if (fwrite(buff.buff8, lBlockSz, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}
	}

	/* Wipe counter */
	memset(counter.buff32, 0, sizeof(counter));
	return AES_ERR_OK;
}

/* Galois field multiplication (GF(2^128)) implementation. */
void GcmMul(
	__m128i a,
	__m128i b,
	__m128i* res)
{
	__m128i tmp0, tmp1, tmp2, tmp3,
		tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;
	__m128i XMMMASK = _mm_setr_epi32(0xffffffff, 0x0, 0x0, 0x0);
	tmp0 = _mm_clmulepi64_si128(a, b, 0x00);
	tmp3 = _mm_clmulepi64_si128(a, b, 0x11);
	tmp1 = _mm_shuffle_epi32(a, 78);
	tmp2 = _mm_shuffle_epi32(b, 78);
	tmp1 = _mm_xor_si128(tmp1, a);
	tmp2 = _mm_xor_si128(tmp2, b);
	tmp1 = _mm_clmulepi64_si128(tmp1, tmp2, 0x00);
	tmp1 = _mm_xor_si128(tmp1, tmp0);
	tmp1 = _mm_xor_si128(tmp1, tmp3);
	tmp2 = _mm_slli_si128(tmp1, 8);
	tmp1 = _mm_srli_si128(tmp1, 8);
	tmp0 = _mm_xor_si128(tmp0, tmp2);
	tmp3 = _mm_xor_si128(tmp3, tmp1);
	tmp4 = _mm_srli_epi32(tmp3, 31);
	tmp5 = _mm_srli_epi32(tmp3, 30);
	tmp6 = _mm_srli_epi32(tmp3, 25);
	tmp4 = _mm_xor_si128(tmp4, tmp5);
	tmp4 = _mm_xor_si128(tmp4, tmp6);
	tmp5 = _mm_shuffle_epi32(tmp4, 147);
	tmp4 = _mm_and_si128(XMMMASK, tmp5);
	tmp5 = _mm_andnot_si128(XMMMASK, tmp5);
	tmp0 = _mm_xor_si128(tmp0, tmp5);
	tmp3 = _mm_xor_si128(tmp3, tmp4);
	tmp7 = _mm_slli_epi32(tmp3, 1);
	tmp0 = _mm_xor_si128(tmp0, tmp7);
	tmp8 = _mm_slli_epi32(tmp3, 2);
	tmp0 = _mm_xor_si128(tmp0, tmp8);
	tmp9 = _mm_slli_epi32(tmp3, 7);
	tmp0 = _mm_xor_si128(tmp0, tmp9);
	*res = _mm_xor_si128(tmp0, tmp3);
}

/* GHash function used in GCM.*/
AesCode GHash(
	AES_CONTEXT* ctx,
	uint32_t* tag,
	uint32_t* iVec,
	uint32_t* subKeys,
	const uint8_t* ad,
	const uint64_t adSz)
{
	if (!ctx || !tag || !iVec || !ad)
	{
		return AES_ERR_INVALIDPARAM;
	}

	uint64_t tmp;

	AES_BLOCK hKey = { 0 };
	AES_BLOCK t0 = { 0 };
	AES_BLOCK tagCmp = { 0 };
	AES_BLOCK adTmp = { 0 };
	const size_t blockCount = ctx->ptcSz / AES_BLOCKSIZE;
	const size_t lBlockSz = ctx->ptcSz % AES_BLOCKSIZE;
	const size_t lAdBlockSz = adSz % AES_BLOCKSIZE;
	const size_t nRounds = (ctx->keySize >> 2) + 6 - 1;
	const size_t subKeysCount = ((nRounds + 1) + 1) << 2;
	const uint64_t maxAdLen = ULLONG_MAX - ctx->ptcSz;

	if ((unsigned long long)(adSz) > maxAdLen)
	{
		return AES_ERR_INVALIDSIZE;
	}

	memcpy(t0.buff32, iVec, sizeof(uint64_t));
	AesEncryptBlock(t0.buff32, subKeys, subKeysCount, nRounds);
	AesEncryptBlock(hKey.buff32, subKeys, subKeysCount, nRounds);

	memcpy(adTmp.buff32, ad, AES_BLOCKSIZE);
	GcmMul(_mm_load_si128((__m128i const*) & adTmp.buff32), _mm_load_si128((__m128i const*) & hKey.buff32), (__m128i*)tagCmp.buff32);

	for (size_t i = 1; i < adSz / AES_BLOCKSIZE; i++)
	{
		memcpy(adTmp.buff32, &ad[i * AES_BLOCKSIZE], AES_BLOCKSIZE);
		XOR128(tagCmp.buff32, adTmp.buff32);
		GcmMul(_mm_load_si128((__m128i const*) & tagCmp.buff32), _mm_load_si128((__m128i const*) & hKey.buff32), (__m128i*)tagCmp.buff32);
	}

	if (lAdBlockSz && adSz > AES_BLOCKSIZE)
	{
		memset(adTmp.buff32, 0, AES_BLOCKSIZE);
		memcpy(adTmp.buff32, &ad[adSz - lAdBlockSz], lAdBlockSz);
		for (size_t i = 0; i < lAdBlockSz; i++)
		{
			tagCmp.buff8[i] ^= adTmp.buff8[i];
		}
		GcmMul(_mm_load_si128((__m128i const*) & tagCmp.buff32), _mm_load_si128((__m128i const*) & hKey.buff32), (__m128i*)tagCmp.buff32);
	}

	for (uint64_t i = 0; i < blockCount; i++)
	{
		tagCmp.buff32[0] ^= ctx->buff32[(i << 2)];
		tagCmp.buff32[1] ^= ctx->buff32[(i << 2) + 1];
		tagCmp.buff32[2] ^= ctx->buff32[(i << 2) + 2];
		tagCmp.buff32[3] ^= ctx->buff32[(i << 2) + 3];
		GcmMul(_mm_load_si128((__m128i const*) & tagCmp.buff32), _mm_load_si128((__m128i const*) & hKey.buff32), (__m128i*)tagCmp.buff32);
	}

	if (lBlockSz)
	{
		for (size_t j = 0; j < lBlockSz; j++)
		{
			tagCmp.buff8[j] ^= ctx->buff8[(blockCount << 4) + j];
		}

		GcmMul(_mm_load_si128((__m128i const*) & tagCmp.buff32), _mm_load_si128((__m128i const*) & hKey.buff32), (__m128i*)tagCmp.buff32);
	}	

	tmp = adSz * CHAR_BIT;
	memcpy(tag, &tmp, sizeof(tmp));
	tmp = (uint64_t)ctx->ptcSz * CHAR_BIT;
	memcpy(&tag[2], &tmp, sizeof(tmp));

#ifndef __GNUC__
#pragma warning(disable:6385)
#endif 
	XOR128(tagCmp.buff32, tag);
#ifndef __GNUC__
#pragma warning(default:6385)
#endif
	GcmMul(_mm_load_si128((__m128i const*) & tagCmp.buff32), _mm_load_si128((__m128i const*) & hKey.buff32), (__m128i*)tagCmp.buff32);

	XOR128(tagCmp.buff32, t0.buff32);
	memcpy(tag, tagCmp.buff32, AES_BLOCKSIZE);

	memset(t0.buff32, 0, sizeof(AES_BLOCK));
	memset(hKey.buff32, 0, sizeof(AES_BLOCK));
	memset(tagCmp.buff32, 0, sizeof(AES_BLOCK));
	tmp = 0ULL;
	return AES_ERR_OK;
}

/* Stream version of the GHash function used in GCM.*/
AesCode GHashStream(
	FILE* cFile,
	AES_CONTEXT* ctx,
	uint32_t* tag,
	uint32_t* iVec,
	uint32_t* subKeys,
	const uint8_t* ad,
	const uint64_t adSz)
{
	if (!cFile || !ctx || !tag || !iVec || !ad)
	{
		return AES_ERR_INVALIDPARAM;
	}

	uint64_t tmp;
	AES_BLOCK buff;

	AES_BLOCK hKey = { 0 };
	AES_BLOCK t0 = { 0 };
	AES_BLOCK tagCmp = { 0 };
	AES_BLOCK adTmp = { 0 };
	const size_t blockCount = ctx->ptcSz / AES_BLOCKSIZE;
	const size_t lBlockSz = ctx->ptcSz % AES_BLOCKSIZE;
	const size_t lAdBlockSz = adSz % AES_BLOCKSIZE;
	const size_t nRounds = (ctx->keySize >> 2) + 6 - 1;
	const size_t subKeysCount = ((nRounds + 1) + 1) << 2;
	const uint64_t maxAdLen = ULLONG_MAX - ctx->ptcSz;

	if ((unsigned long long)(adSz) > maxAdLen)
	{
		return AES_ERR_INVALIDSIZE;
	}

	memcpy(t0.buff32, iVec, sizeof(uint64_t));
	AesEncryptBlock(t0.buff32, subKeys, subKeysCount, nRounds);
	AesEncryptBlock(hKey.buff32, subKeys, subKeysCount, nRounds);

	memcpy(adTmp.buff32, ad, AES_BLOCKSIZE);
	GcmMul(_mm_load_si128((__m128i const*) & adTmp.buff32), _mm_load_si128((__m128i const*) & hKey.buff32), (__m128i*)tagCmp.buff32);

	for (size_t i = 1; i < adSz / AES_BLOCKSIZE; i++)
	{
		memcpy(adTmp.buff32, &ad[i * AES_BLOCKSIZE], AES_BLOCKSIZE);
		tagCmp.buff32[0] ^= adTmp.buff32[0];
		tagCmp.buff32[1] ^= adTmp.buff32[1];
		tagCmp.buff32[2] ^= adTmp.buff32[2];
		tagCmp.buff32[3] ^= adTmp.buff32[3];
		GcmMul(_mm_load_si128((__m128i const*) & tagCmp.buff32), _mm_load_si128((__m128i const*) & hKey.buff32), (__m128i*)tagCmp.buff32);
	}

	if (lAdBlockSz && adSz > AES_BLOCKSIZE)
	{
		memset(adTmp.buff32, 0, AES_BLOCKSIZE);
		memcpy(adTmp.buff32, &ad[adSz - lAdBlockSz], lAdBlockSz);
		for (size_t i = 0; i < lAdBlockSz; i++)
		{
			tagCmp.buff8[i] ^= adTmp.buff8[i];
		}
		GcmMul(_mm_load_si128((__m128i const*) & tagCmp.buff32), _mm_load_si128((__m128i const*) & hKey.buff32), (__m128i*)tagCmp.buff32);
	}

	for (uint64_t i = 0; i < blockCount; i++)
	{
		if (fread(buff.buff8, AES_BLOCKSIZE, 1, cFile) != 1)
		{
			return AES_ERR_READFAILED;
		}
		XOR128(tagCmp.buff32, buff.buff32);		
		GcmMul(
			_mm_load_si128((__m128i const*) & tagCmp.buff32),
			_mm_load_si128((__m128i const*) & hKey.buff32),
			(__m128i*)tagCmp.buff32);
	}

	if (lBlockSz)
	{
		if (fread(buff.buff8, lBlockSz, 1, cFile) != 1)
		{
			return AES_ERR_READFAILED;
		}

		for (size_t j = 0; j < lBlockSz; j++)
		{
			tagCmp.buff8[j] ^= buff.buff8[j];
		}

		GcmMul(
			_mm_load_si128((__m128i const*) & tagCmp.buff32),
			_mm_load_si128((__m128i const*) & hKey.buff32),
			(__m128i*)tagCmp.buff32);
	}

	tmp = adSz * CHAR_BIT;
	memcpy(tag, &tmp, sizeof(tmp));
	tmp = (uint64_t)ctx->ptcSz * CHAR_BIT;
	memcpy(&tag[2], &tmp, sizeof(tmp));

#ifndef __GNUC__
#pragma warning(disable:6385)
#endif 
	XOR128(tagCmp.buff32, tag);
#ifndef __GNUC__
#pragma warning(default:6385)
#endif

	GcmMul(_mm_load_si128(
		(__m128i const*) & tagCmp.buff32),
		_mm_load_si128((__m128i const*) & hKey.buff32),
		(__m128i*)tagCmp.buff32);

	XOR128(tagCmp.buff32, t0.buff32);
	memcpy(tag, tagCmp.buff32, AES_BLOCKSIZE);

	memset(t0.buff32, 0, sizeof(AES_BLOCK));
	memset(hKey.buff32, 0, sizeof(AES_BLOCK));
	memset(tagCmp.buff32, 0, sizeof(AES_BLOCK));
	tmp = 0ULL;

	return AES_ERR_OK;
}

AesCode AesGcmEncrypt(
	AES_CONTEXT* ctx,
	uint32_t* tag,
	uint32_t* iVec,
	uint32_t* subKeys,
	const uint8_t* ad,
	const uint64_t adSz)
{
	AesCode res;
	if ((res = AesCtrCrypt(ctx, iVec, subKeys)) != AES_ERR_OK)
	{
		return res;
	}
	return GHash(ctx, tag, iVec, subKeys, ad, adSz);
}

AesCode AesGcmEncryptStream(
	FILE* destFile,
	FILE* srcFile,
	AES_CONTEXT* ctx,
	uint32_t* tag,
	uint32_t* iVec,
	uint32_t* subKeys,
	const uint8_t* ad,
	const uint64_t adSz)
{
	AesCode res;
	if ((res = AesCtrCryptStream(destFile, srcFile, ctx, iVec, subKeys)) != AES_ERR_OK)
	{
		return res;
	}

	if (fseek(destFile, -(long)(ctx->ptcSz), SEEK_CUR))
	{
		return AES_ERR_INVALIDFILEOFFSET;
	}

	return GHashStream(destFile, ctx, tag, iVec, subKeys, ad, adSz);
}

AesCode AesGcmDecrypt(
	AES_CONTEXT* ctx,
	uint32_t* tag,
	uint32_t* iVec,
	uint32_t* subKeys,
	const uint8_t* ad,
	const uint64_t adSz)
{
	AesCode res;

	AES_BLOCK cTag = { 0 };
	AES_BLOCK rTag = { 0 };

	memcpy(rTag.buff32, tag, sizeof(AES_BLOCK));
	if ((res = GHash(ctx, cTag.buff32, iVec, subKeys, ad, adSz)) == AES_ERR_OK)
	{
		if ((res = VALIDATE_GCMTAG(tag, cTag.buff32)) == AES_ERR_OK)
		{
			res = AesCtrCrypt(ctx, iVec, subKeys);
		}
	}
	return res;
}

AesCode AesGcmDecryptStream(
	FILE* destFile,
	FILE* srcFile,
	AES_CONTEXT* ctx,
	uint32_t* tag,
	uint32_t* iVec,
	uint32_t* subKeys,
	const uint8_t* ad,
	const uint64_t adSz)
{
	AesCode res;

	AES_BLOCK cTag = { 0 };
	AES_BLOCK rTag = { 0 };

	memcpy(rTag.buff32, tag, sizeof(AES_BLOCK));
	if ((res = GHashStream(srcFile, ctx, cTag.buff32, iVec, subKeys, ad, adSz)) == AES_ERR_OK)
	{
		if ((res = VALIDATE_GCMTAG(tag, cTag.buff32)) == AES_ERR_OK)
		{
			if (fseek(srcFile, -(long)(ctx->ptcSz), SEEK_END))
			{
				return AES_ERR_INVALIDFILEOFFSET;
			}

			res = AesCtrCryptStream(destFile, srcFile, ctx, iVec, subKeys);
		}
	}
	return res;
}

AesCode AesEcbEncrypt(
	AES_CONTEXT* ctx,
	uint32_t* subKeys)
{
	if (!ctx || !ctx->buff32 || !subKeys)
	{
		return AES_ERR_INVALIDPARAM;
	}
	else if (ctx->ptcSz < AES_BLOCKSIZE)
	{
		return AES_ERR_INVALIDSIZE;
	}

	uint8_t tmpBlock[AES_BLOCKSIZE];

	const size_t nRounds = (ctx->keySize >> 2) + 6 - 1;
	const size_t subKeysCount = ((nRounds + 1) + 1) << 2;
	const size_t blockheadSz = ctx->ptcSz % AES_BLOCKSIZE;
	const size_t blockCount = (blockheadSz) ? ctx->ptcSz / AES_BLOCKSIZE - 1 : ctx->ptcSz / AES_BLOCKSIZE;

	for (size_t i = 0; i < blockCount; i++)
	{
		AesEncryptBlock(&ctx->buff32[i << 2], subKeys, subKeysCount, nRounds);
	}

	if (!blockheadSz)
	{
		return AES_ERR_OK;
	}

	/* Encrypts second-last block */
	AesEncryptBlock(&ctx->buff32[(blockCount) << 2], subKeys, subKeysCount, nRounds);

	/* Copies the last block to tmpBlock */
	memcpy(tmpBlock, &ctx->buff32[(blockCount + 1) << 2], blockheadSz);

	/* Copies the second-last block (already encrypted) to the last block */
	memcpy(&ctx->buff32[(blockCount + 1) << 2], &ctx->buff32[(blockCount) << 2], blockheadSz);

	/* Copies the second-last block tail's to the tmpBlock tail */
	memcpy(&tmpBlock[blockheadSz], &((uint8_t*)&ctx->buff32[(blockCount) << 2])[blockheadSz], AES_BLOCKSIZE - blockheadSz);

	/* Encrypts tmpBlock */
	AesEncryptBlock((uint32_t*)tmpBlock, subKeys, subKeysCount, nRounds);

	/* Copies tmpBlock to the second-last block */
	memcpy(&ctx->buff32[(blockCount) << 2], tmpBlock, sizeof(tmpBlock));

	return AES_ERR_OK;
}

AesCode AesEcbEncryptStream(
	FILE* destFile,
	FILE* srcFile,
	AES_CONTEXT* ctx,
	uint32_t* subKeys)
{
	if (!srcFile || !destFile || !ctx || !subKeys)
	{
		return AES_ERR_INVALIDPARAM;
	}
	else if (ctx->ptcSz < AES_BLOCKSIZE)
	{
		return AES_ERR_INVALIDSIZE;
	}

	AES_BLOCK buff;
	AES_BLOCK tmpBlock;	

	const size_t nRounds = (ctx->keySize >> 2) + 6 - 1;
	const size_t subKeysCount = ((nRounds + 1) + 1) << 2;
	const size_t blockheadSz = ctx->ptcSz % AES_BLOCKSIZE;
	const size_t blockCount = (blockheadSz) ? ctx->ptcSz / AES_BLOCKSIZE - 1 : ctx->ptcSz / AES_BLOCKSIZE;

	for (size_t i = 0; i < blockCount; i++)
	{
		if (fread(buff.buff8, AES_BLOCKSIZE, 1, srcFile) != 1)
		{
			return AES_ERR_READFAILED;
		}

		AesEncryptBlock(buff.buff32, subKeys, subKeysCount, nRounds);

		if (fwrite(buff.buff8, AES_BLOCKSIZE, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}
	}

	if (!blockheadSz)
	{
		return AES_ERR_OK;
	}

	/* Reads second-last block */
	if (fread(buff.buff8, AES_BLOCKSIZE, 1, srcFile) != 1)
	{
		return AES_ERR_READFAILED;
	}
	/* Reads last block */	
	if (fread(tmpBlock.buff8, blockheadSz, 1, srcFile) != 1)
	{
		return AES_ERR_READFAILED;
	}

	/* Encrypts second-last block */
	AesEncryptBlock(buff.buff32, subKeys, subKeysCount, nRounds);

	/* Copies the second-last block tail's to the last block tail's */
	memcpy(&tmpBlock.buff8[blockheadSz], &buff.buff8[blockheadSz], AES_BLOCKSIZE - blockheadSz);

	/* Encrypts tmpBlock */
	AesEncryptBlock(tmpBlock.buff32, subKeys, subKeysCount, nRounds);

	/* Writes as second-last block */
	if (fwrite(tmpBlock.buff8, AES_BLOCKSIZE, 1, destFile) != 1)
	{
		return AES_ERR_WRITEFAILED;
	}

	/* Writes as last block */
	if (fwrite(buff.buff8, blockheadSz, 1, destFile) != 1)
	{
		return AES_ERR_WRITEFAILED;
	}

	return AES_ERR_OK;
}

AesCode AesEcbDecrypt(
	AES_CONTEXT* ctx,
	uint32_t* subKeys)
{
	if (!ctx || !ctx->buff32 || !subKeys)
	{
		return AES_ERR_INVALIDPARAM;
	}
	else if (ctx->ptcSz < AES_BLOCKSIZE)
	{
		return AES_ERR_INVALIDSIZE;
	}

	uint8_t tmpBlock[AES_BLOCKSIZE];

	const size_t nRounds = (ctx->keySize >> 2) + 6 - 1;
	const size_t subKeysCount = ((nRounds + 1) + 1) << 2;
	const size_t blockheadSz = ctx->ptcSz % AES_BLOCKSIZE;
	const size_t blockCount = (blockheadSz) ? ctx->ptcSz / AES_BLOCKSIZE - 1 : ctx->ptcSz / AES_BLOCKSIZE;

	for (size_t i = 0; i < blockCount; i++)
	{
		AesDecryptBlock(&ctx->buff32[i << 2], subKeys, subKeysCount, nRounds);
	}

	if (!blockheadSz)
	{
		return AES_ERR_OK;
	}

	/* Decrypt the last second-last block */
	AesDecryptBlock(&ctx->buff32[(blockCount) << 2], subKeys, subKeysCount, nRounds);

	/* Copy the last block to tmpBlock */
	memcpy(tmpBlock, &ctx->buff32[(blockCount + 1) << 2], blockheadSz);

	/* Copy the second-last block (already decrypted) to the last block */
	memcpy(&ctx->buff32[(blockCount + 1) << 2], &ctx->buff32[(blockCount) << 2], blockheadSz);

	/* Copy the first second-last tail to tmpBlock tail  */
	memcpy(&tmpBlock[blockheadSz], &((uint8_t*)&ctx->buff32[(blockCount) << 2])[blockheadSz], AES_BLOCKSIZE - blockheadSz);

	/* Decrypt tmpBlock */
	AesDecryptBlock((uint32_t*)tmpBlock, subKeys, subKeysCount, nRounds);

	/* Copy tmpBlock to the second-last block */
	memcpy(&ctx->buff32[(blockCount) << 2], tmpBlock, AES_BLOCKSIZE);

	return AES_ERR_OK;
}

AesCode AesEcbDecryptStream(
	FILE* destFile,
	FILE* srcFile,
	AES_CONTEXT* ctx,
	uint32_t* subKeys)
{
	if (!srcFile || !destFile || !ctx || !subKeys)
	{
		return AES_ERR_INVALIDPARAM;
	}
	else if (ctx->ptcSz < AES_BLOCKSIZE)
	{
		return AES_ERR_INVALIDSIZE;
	}

	uint8_t tmpBlock[AES_BLOCKSIZE];
	uint8_t buff8[AES_BLOCKSIZE];

	const size_t nRounds = (ctx->keySize >> 2) + 6 - 1;
	const size_t subKeysCount = ((nRounds + 1) + 1) << 2;
	const size_t blockheadSz = ctx->ptcSz % AES_BLOCKSIZE;
	const size_t blockCount = (blockheadSz) ? ctx->ptcSz / AES_BLOCKSIZE - 1 : ctx->ptcSz / AES_BLOCKSIZE;

	for (size_t i = 0; i < blockCount; i++)
	{
		if (fread(buff8, AES_BLOCKSIZE, 1, srcFile) != 1)
		{
			return AES_ERR_READFAILED;
		}

		AesDecryptBlock((uint32_t*)buff8, subKeys, subKeysCount, nRounds);

		if (fwrite(buff8, AES_BLOCKSIZE, 1, destFile) != 1)
		{
			return AES_ERR_WRITEFAILED;
		}
	}

	if (!blockheadSz)
	{
		return AES_ERR_OK;
	}

	if (fread(buff8, AES_BLOCKSIZE, 1, srcFile) != 1)
	{
		return AES_ERR_READFAILED;
	}
	if (fread(tmpBlock, blockheadSz, 1, srcFile) != 1)
	{
		return AES_ERR_READFAILED;
	}

	/* Decrypt the last second-last block */
	AesDecryptBlock((uint32_t*)buff8, subKeys, subKeysCount, nRounds);

	/* Copies secon-last block tail's to last block tail's */
	memcpy(&tmpBlock[blockheadSz], &buff8[blockheadSz], AES_BLOCKSIZE - blockheadSz);

	/* Decrypt tmpBlock */
	AesDecryptBlock((uint32_t*)tmpBlock, subKeys, subKeysCount, nRounds);

	/* Writes as second-last block */
	if (fwrite(tmpBlock, AES_BLOCKSIZE, 1, destFile) != 1)
	{
		return AES_ERR_WRITEFAILED;
	}

	/* Writes as last block */
	if (fwrite(buff8, blockheadSz, 1, destFile) != 1)
	{
		return AES_ERR_WRITEFAILED;
	}

	return AES_ERR_OK;
}

void ReleaseAesContext(
	AES_CONTEXT* ctx)
{
	if (ctx->buff32)
	{
		memset(ctx->buff32, 0, ctx->ptcSz);
		free(ctx->buff32);
		ctx->buff32 = NULL;
	}

	ctx->ptcSz = 0;
	ctx->keySize = 0;
}