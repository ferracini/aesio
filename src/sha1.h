#pragma once
#include <limits.h>
#include "stdint.h"
#ifdef __GNUC__
#include <stddef.h>
#endif

/* Numer of bits in a SHA1 block. */
#define SHA1_BIT         160
/* SHA256 outputs 256 bits digest */
#define SHA1_DIGEST_SIZE (SHA1_BIT/CHAR_BIT)

typedef struct
{
  uint32_t state[5];
  size_t count[2];
  uint8_t buffer[64];
} SHA1_CONTEXT;

/* Calculates the SHA1 hash of the message that is presented in a raw buffer. */
void Sha1(
  uint8_t* digest,
  const void* rData,
  size_t dataSz);

/* Calculates the SHA1 hash of a file. */
int Sha1Stream(
  uint8_t* digest, 
  FILE* pFile, 
  const size_t sz);

/* Concatenates two messages and calculates the SHA1 hash. */
void Sha1Cat(
  uint8_t* digest,
  const void* data1, 
  const void* data2, 
  size_t data1Sz,
  size_t data2Sz);

/* Concatenates two messages and calculates the SHA1 hash, using a uint8_t pointer and a FILE pointer. */
int Sha1StreamCat(
  uint8_t* digest, 
  const void* data1,
  FILE* data2, 
  size_t data1Sz,
  size_t data2Sz);