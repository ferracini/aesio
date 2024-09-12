#ifndef MINBASE64_H
#define MINBASE64_H
#include <stdlib.h>

#define MINBASE64_VER   1.0

size_t Base64Encode(
  char **ppDest,
  const void *pSrc,
  size_t szSrc);

size_t Base64Decode(
  void **ppDest,
  const char *pSrc,
  size_t szSrc);
#endif
