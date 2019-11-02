#include <string.h> 
#include "sha256.h"
#include "helper.h"

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z))) 
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))) 
#define SIGMA_UP0(x) (_ROTR(x, 2) ^ _ROTR(x, 13) ^ _ROTR(x, 22)) 
#define SIGMA_UP1(x) (_ROTR(x, 6) ^ _ROTR(x, 11) ^ _ROTR(x, 25)) 
#define SIGMA_LO0(x) (_ROTR(x, 7) ^ _ROTR(x, 18) ^ (x >> 3)) 
#define SIGMA_LO1(x) (_ROTR(x, 17) ^ _ROTR(x, 19) ^ (x >> 10)) 

/*
 * These words represent the first thirty-two bits of the fractional parts of  
 * the cube roots of the first sixty-four prime numbers".
 */
static const uint32_t k[64] =
{
   0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
   0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
   0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
   0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
   0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
   0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
   0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
   0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

/* To ensure data is multiple of 64 bytes, extra processing is done inside Sha256Final() */
static const uint8_t padding[64] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Initialize the SHA256 context. */
void Sha256Init(
	SHA256_CONTEXT* ctx)
{
	ctx->h[0] = 0x6A09E667;
	ctx->h[1] = 0xBB67AE85;
	ctx->h[2] = 0x3C6EF372;
	ctx->h[3] = 0xA54FF53A;
	ctx->h[4] = 0x510E527F;
	ctx->h[5] = 0x9B05688C;
	ctx->h[6] = 0x1F83D9AB;
	ctx->h[7] = 0x5BE0CD19;

	/* No bytes in the buffer */
	ctx->sz = 0;

	/* No data was processed so far */
	ctx->totalSz = 0;
}

/* Process a block. */
static void Sha256ProcessBlock(
	SHA256_CONTEXT* ctx)
{
	/* Message schedule */
	uint32_t w[64];     

	/* 1. Prepare the message schedule, {Wt} */
	for (size_t t = 0; t <= 63; t++)
	{
		if (t <= 15)
		{
			w[t] = bswap_32(ctx->w[t]);
		}			
		else
		{
			w[t] = SIGMA_LO1(w[t - 2]) + w[t - 7] + SIGMA_LO0(w[t - 15]) + w[t - 16];
		}
			
	}	

   /* 2. Initialize the eight working variables, a, b, c, d, e, f, g, and h, 
    * with the (i-1)st hash value: 
	*/
	uint32_t a = ctx->h[0];
	uint32_t b = ctx->h[1];
	uint32_t c = ctx->h[2];
	uint32_t d = ctx->h[3];
	uint32_t e = ctx->h[4];
	uint32_t f = ctx->h[5];
	uint32_t g = ctx->h[6];
	uint32_t h = ctx->h[7];

	/* 3. Loop 64 times */
	for (size_t t = 0; t < 64; t++)
	{
		/* Calculate T1 and T2 */
		uint32_t temp1 = h + SIGMA_UP1(e) + CH(e, f, g) + k[t] + w[t];
		uint32_t temp2 = SIGMA_UP0(a) + MAJ(a, b, c);

		/* Update working registers */
		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	/* 4. Compute the ith intermediate hash value H(i): */
	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
	ctx->h[5] += f;
	ctx->h[6] += g;
	ctx->h[7] += h;
}

/* Processes partial message to be composed with the digest. */
void Sha256Update(
	SHA256_CONTEXT* ctx,
	const void* data,
	const size_t dataSz)
{
	size_t k = dataSz;

	while (k > 0)
	{
		size_t n = min(k, 64 - ctx->sz);
		memcpy(ctx->buff + ctx->sz, data, n);
		ctx->sz += n;
		ctx->totalSz += n;
		data = (uint8_t*)data + n;
		k -= n;

		if (ctx->sz == 64)
		{
			Sha256ProcessBlock(ctx);
			ctx->sz = 0;
		}
	}
}

/* Final function to be used. Add padding and return the message digest. */
void Sha256Final(
	SHA256_CONTEXT* ctx,
	uint8_t* digest)
{
	/* Length of the original message, in bits */
	uint64_t l = ctx->totalSz * CHAR_BIT;
	size_t k = 0;

	/* The length of the message must be congruent to 448 modulo 512.
	 * Otherwise, the message needs to be padded.
	 */
	if ((l % 512) < 448)
	{
		k = 448 - l % 512;
	}
	else
	{
		k = 512 + 448 - l % 512;
	}

	/* Append padding */
	Sha256Update(ctx, padding, k / CHAR_BIT); /* k is a counter of bits */

	/* Append the length of the original message */
	ctx->w[14] = bswap_32((uint32_t)(l >> (sizeof(uint32_t) * CHAR_BIT)));
	ctx->w[15] = bswap_32((uint32_t)l);

	/* Calculation of the digest */
	Sha256ProcessBlock(ctx);

	/* Host byte order to big-endian byte order */
	for (size_t i = 0; i < CHAR_BIT; i++)
	{
		ctx->h[i] = bswap_32(ctx->h[i]);
	}

	/* Copy the result to the buffer */
	if (digest != NULL)
	{
		memcpy(digest, ctx->digest, SHA256_DIGEST_SIZE);
	}
}

void Sha256(
	uint8_t* digest, 
	const void* data, 
	const size_t dataSz)
{
	SHA256_CONTEXT Context;

	Sha256Init(&Context);
	Sha256Update(&Context, data, dataSz);
	Sha256Final(&Context, digest);
}

int Sha256Stream(
	uint8_t* digest, 
	FILE* pFile,
	const size_t sz)
{
	SHA256_CONTEXT Context;
	uint8_t buff[16];
	
	const size_t lBlockSz = sz % 16U;
	const size_t t = sz / 16U;

	Sha256Init(&Context);

	for (size_t i = 0; i < t; i++)
	{
		if (fread(buff, 16U, 1, pFile) != 1)
		{
			return 1;
		}

		Sha256Update(&Context, buff, 16U);
	}

	if (lBlockSz)
	{
		if (fread(buff, lBlockSz, 1, pFile) != 1)
		{
			return 1;
		}

		Sha256Update(&Context, buff, lBlockSz);
	}

	Sha256Final(&Context, digest);
	
	/* Wipe buffer */
	memset(buff, 0, sizeof(buff));
	return 0;
}

void Sha256Cat(
	uint8_t* digest,
	const void* data1,
	const void* data2,
	const size_t data1Sz,
	const size_t data2Sz)
{
	SHA256_CONTEXT Context;
	Sha256Init(&Context);
	Sha256Update(&Context, data1, data1Sz);
	Sha256Update(&Context, data2, data2Sz);
	Sha256Final(&Context, digest);
}

int Sha256StreamCat(
	uint8_t* digest, 
	const void* data1,
	FILE* data2,
	const size_t data1Sz, 
	const size_t data2Sz)
{
	SHA256_CONTEXT Context;
	uint8_t buff[16];
	
	const size_t lBlockSz = data2Sz % 16U;
	const size_t t = data2Sz / 16U;

	Sha256Init(&Context);
	Sha256Update(&Context, data1, data1Sz);

	for (size_t i = 0; i < t; i++)
	{
		if (fread(buff, 16U, 1, data2) != 1)
		{
			return 1;
		}

		Sha256Update(&Context, buff, 16U);
	}

	if (lBlockSz)
	{
		if (fread(buff, lBlockSz, 1, data2) != 1)
		{
			return 1;
		}

		Sha256Update(&Context, buff, lBlockSz);
	}

	Sha256Final(&Context, digest);

	/* Wipe buffer */
	memset(buff, 0, sizeof(buff));
	return 0;
}