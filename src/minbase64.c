#include <stdint.h>
#include "minbase64.h"

static const char g_encodingTable[64] =
{
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};

static const uint8_t g_decodingTable[80] =
{
  0x3E, 0x00, 0x00, 0x00, 0x3F, 0x34, 0x35, 0x36,
  0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
  0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x1B,
  0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
  0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
  0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33
};

size_t Base64Encode(
  char **ppDest,
  const void *pSrc,
  size_t szSrc)
{ 
  const uint8_t paddingTable[3] = {0x00, 0x02, 0x01};
  const size_t szDest = ((szSrc + 2) / 3) << 2;
  uint8_t *pBuffer = NULL;
  uint8_t *pData = (uint8_t *)(pSrc);
  size_t i = 0;
  size_t j = 0;
  uint8_t a;
  uint8_t b;
  uint8_t c;
  uint32_t v;
  
  if (ppDest == NULL || pData == NULL || szSrc == 0)
  {
    return 0;
  }

  *ppDest = NULL;
  pBuffer = malloc(sizeof(char) * (szDest + 1));
  if(pBuffer == NULL)
  {
    return 0;
  }

  while(i < szSrc)
  {
    a = pData[i++];
    b = i < szSrc ? pData[i++] : 0;
    c = i < szSrc ? pData[i++] : 0;
    v = (a << 0x10) + (b << 0x08) + c;
    
    pBuffer[j++] = g_encodingTable[(v >> 3 * 6) & 0x3F];
    pBuffer[j++] = g_encodingTable[(v >> 2 * 6) & 0x3F];
    pBuffer[j++] = g_encodingTable[(v >> 1 * 6) & 0x3F];
    pBuffer[j++] = g_encodingTable[(v >> 0 * 6) & 0x3F];
  }

  for (i = 0; i < paddingTable[szSrc % 3]; i++)
  {
    pBuffer[szDest - 1 - i] = '=';
  }

  pBuffer[szDest] = '\0';
  *ppDest = (char*)(pBuffer);

  return szDest;
}

size_t Base64Decode(
  void **ppDest,
  const char *pSrc,
  size_t szSrc)
{
  uint8_t *pBuffer = NULL;
  size_t szDest = szSrc / 4 * 3;
  size_t i = 0;
  size_t j = 0;
  uint8_t a;
  uint8_t b;
  uint8_t c;
  uint8_t d;
  uint32_t v;

  if(ppDest == NULL)
  {
    return 0;
  }

  *ppDest = NULL;

  if (szSrc % 4 != 0)
  {
    return 0;
  }
  
  if (pSrc[szSrc - 1] == '=')
  {
     szDest--;
  }
  
  if (pSrc[szSrc - 2] == '=')
  {
     szDest--;
  }

  pBuffer = malloc(szDest);
  if (pBuffer == NULL)
  {
    return 0;
  }

  while(i < szSrc)
  {
    a = pSrc[i] == '=' || pSrc[i] < 43 || pSrc[i] > 122 ? 0 & i++ : g_decodingTable[pSrc[i++] - 43];
    b = pSrc[i] == '=' || pSrc[i] < 43 || pSrc[i] > 122 ? 0 & i++ : g_decodingTable[pSrc[i++] - 43];
    c = pSrc[i] == '=' || pSrc[i] < 43 || pSrc[i] > 122 ? 0 & i++ : g_decodingTable[pSrc[i++] - 43];
    d = pSrc[i] == '=' || pSrc[i] < 43 || pSrc[i] > 122 ? 0 & i++ : g_decodingTable[pSrc[i++] - 43];
    v = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);    

    if (j < szDest)
    {
      pBuffer[j++] = (v >> 2 * 8) & 0xFF;
    }

    if (j < szDest)
    {
      pBuffer[j++] = (v >> 1 * 8) & 0xFF;
    }

    if (j < szDest)
    {
      pBuffer[j++] = (v >> 0 * 8) & 0xFF;
    }
  }

  *ppDest = pBuffer;
  return szDest;
}