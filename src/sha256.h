#pragma once
#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#ifdef __GNUC__
#include <stddef.h>
#endif

/* Numer of bits in a SHA256 block. */
#define SHA256_BIT          256
/* SHA256 outputs 256 bits digest */
#define SHA256_DIGEST_SIZE  (SHA256_BIT/CHAR_BIT)

/* SHA256 context for processing pieces of data. */
typedef struct
{
  union
  {
    /* Current digest. It is an union so we can access it as bytes or 32 bit words. */
    uint32_t h[SHA256_DIGEST_SIZE / sizeof(uint32_t)];
    uint8_t digest[SHA256_DIGEST_SIZE];
  };

  /*
   * SHA256 only runs on 64 bytes blocks, data is added to this buffer and 
   * a SHA256 pass runs once this buffer is full.
   */
  union
  {
    uint32_t  w[16];
    uint8_t buff[64];
  };

  /* Number of bytes in the buffer. */
  size_t  sz;

  /* Total Number of bytes processed so far. */
  uint64_t totalSz;
}SHA256_CONTEXT;


/* Calculates the SHA256 hash of the message that is presented in a raw buffer. */
void Sha256(
  uint8_t* digest, 
  const void* data,
  const size_t dataSz);

/* Calculates the SHA256 hash of a file. */
int Sha256Stream(
  uint8_t* digest, 
  FILE* pFile, 
  const size_t sz);

/* Concatenates two messages and calculates the SHA256 hash. */
void Sha256Cat(
  uint8_t* digest,
  const void* data1, 
  const void* data2,
  const size_t data1Sz,
  const size_t data2Sz);

/* Concatenates two messages and calculates the SHA256 hash, using a uint8_t pointer and a FILE pointer. */
int Sha256StreamCat(
  uint8_t* digest, 
  const void* data1,
  FILE* data2, 
  const size_t data1Sz,
  const size_t data2Sz);