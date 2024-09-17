#include "aesio.h"
#include <string.h>
#include <sys/stat.h>
#ifdef _MSC_VER
/* 
 * The rand_s function requires that constant _CRT_RAND_S
 * be defined before including stdlib.h. 
*/
#define _CRT_RAND_S
#define FILENO(file)  (_fileno(file))
#elif defined(__GNUC__)
#include <fcntl.h>
#include <unistd.h>
#define FILENO(file)  (fileno(file))
#endif
#include <stdlib.h>

/* Constants for HMAC calculation. */
#define IPAD  0x36
#define OPAD  0x5C

void ReleaseAesioContext(
  AESIO_CONTEXT * ctx,
  _Bool freeAesBuff)
{
  if (freeAesBuff)
  {
    ReleaseAesContext(&ctx->ctx);
  }
  
  /* Wipe structure */
  memset(ctx, 0, sizeof(AESIO_CONTEXT));
}

AesioCode InitRandVec(
  uint32_t* iVec)
{
#ifdef _MSC_VER
  for (size_t i = 0; i < AES_BLOCKLEN; i++)
  {
    if (rand_s(&iVec[i]))
    {
      return AESIO_ERR_RANDFAILED;
    }
  }
  return AESIO_ERR_OK;
#elif defined(__GNUC__)
  AesioCode res = AESIO_ERR_OK;

  int randData;
  if ((randData = open("/dev/urandom", O_RDONLY)) < 0)
  {
    res = AESIO_ERR_RANDFAILED;
    goto cleanup;
  }
  
  size_t rDataLen = 0;
  while (rDataLen < AES_BLOCKSIZE)
  {
    size_t result = read(randData, iVec + rDataLen, AES_BLOCKSIZE - rDataLen);
    if (result < 0)
    {
      res = AESIO_ERR_RANDFAILED;
      goto cleanup;
    }
    rDataLen += result;
  }

cleanup:
  close(randData);
  return res;
#endif
}

/* Password padding. */
#ifdef AESIO_USEPWDPADDING
inline static void PwdPadding(
  uint8_t* key,
  const size_t kBlockSize,
  const size_t paddingSz)
{
  uint8_t kPad[SHA256_DIGEST_SIZE];

  Sha256(kPad, key, paddingSz);
  memcpy(&key[(kBlockSize - paddingSz) / sizeof(uint8_t)], kPad, paddingSz);
  /* Wipe variables */
  memset(kPad, 0, SHA256_DIGEST_SIZE);
}
#endif // AESIO_USEPWDPADDING

AesioCode KeySchedule(
  uint32_t* subKeys,
  const char* pwd, 
  const size_t pwdLen,
  size_t kBlockSize)
{
  uint32_t fPwd[AES_MAX_KBLOCK_COUNT] = { 0 };
  AesioCode  res;

  memcpy(fPwd, pwd, pwdLen);
#ifdef AESIO_USEPWDPADDING
  if (pwdLen < kBlockSize)
  {
    PwdPadding((uint8_t*)fPwd, kBlockSize, kBlockSize - pwdLen);
  }
#endif // AESIO_USEPWDPADDING
  
  switch (kBlockSize * CHAR_BIT)
  {  
  case 128:
    KeySchedule128(subKeys, fPwd);
    res = AESIO_ERR_OK;
    break;
  case 192:
    KeySchedule192(subKeys, fPwd);
    res = AESIO_ERR_OK;
    break;
  case 256:
    KeySchedule256(subKeys, fPwd);
    res = AESIO_ERR_OK;
    break;
  default: res = AESIO_ERR_INVALIDKEYSIZE;
    break;
  }

  /* Wipe password data */
  memset(fPwd, 0, sizeof(fPwd));
  return res;
}

AesioCode AesioErrorHandle(
  AesCode aesError)
{
  switch (aesError)
  {
  default:
  case AES_ERR_OK: return AESIO_ERR_OK;
  case AES_ERR_INVALIDSIZE: return AESIO_ERR_INVALIDSIZE;
  case AES_ERR_INVALIDTAG: return AESIO_ERR_MACNOTMATCH;
  case AES_ERR_INVALIDPARAM: return AESIO_ERR_INVALIDPARAM;
  case AES_ERR_INVALIDFILEOFFSET: return AESIO_ERR_INVALIDFILEOFFSET;
  case AES_ERR_READFAILED: return AESIO_ERR_READFAILED;
  case AES_ERR_WRITEFAILED: return AESIO_ERR_WRITEFAILED;
  }
}

AesioCode AesEncrypt(
  AESIO_CONTEXT* ctx, 
  uint32_t* subKeys,
  uint32_t* tag,
  const uint8_t* ad, 
  const uint64_t adSz)
{
  AesioCode res = AESIO_ERR_OK;
  switch (ctx->bFlags & AESIO_BMASK_MO)
  {
  case AESIO_MO_ECB:
    res = AesioErrorHandle(AesEcbEncrypt(&ctx->ctx, subKeys));
    break;
  case AESIO_MO_CBC:
    res = AesioErrorHandle(AesCbcEncrypt(&ctx->ctx, ctx->iVec, subKeys));
    break;
  default:
  case AESIO_MO_CTR:
    res = AesioErrorHandle(AesCtrCrypt(&ctx->ctx, ctx->iVec, subKeys));
    break;
  case AESIO_MO_GCM:
    res = AesioErrorHandle(AesGcmEncrypt(&ctx->ctx, tag, ctx->iVec, subKeys, ad, adSz));
    break;
  }
  return res;
}

AesioCode AesEncryptStream(
  FILE* destFile,
  FILE* srcFile,
  AESIO_CONTEXT* ctx,
  uint32_t* subKeys,
  uint32_t* tag,
  const uint8_t* ad,
  const uint64_t adSz)
{
  AesioCode res = AESIO_ERR_OK;
  switch (ctx->bFlags & AESIO_BMASK_MO)
  {
  case AESIO_MO_ECB:
    res = AesioErrorHandle(AesEcbEncryptStream(destFile, srcFile, &ctx->ctx, subKeys));
    break;
  case AESIO_MO_CBC:
    res = AesioErrorHandle(AesCbcEncryptStream(destFile, srcFile, &ctx->ctx, ctx->iVec, subKeys));
    break;
  default:
  case AESIO_MO_CTR:
    res = AesioErrorHandle(AesCtrCryptStream(destFile, srcFile, &ctx->ctx, ctx->iVec, subKeys));
    break;
  case AESIO_MO_GCM:
    res = AesioErrorHandle(AesGcmEncryptStream(destFile, srcFile, &ctx->ctx, tag, ctx->iVec, subKeys, ad, adSz));
    break;
  }
  return res;
}

AesioCode AesDecrypt(
  AESIO_CONTEXT* ctx, 
  uint32_t* subKeys, 
  uint32_t* tag, 
  const uint8_t* ad, 
  const uint64_t adSz)
{
  switch (ctx->bFlags & AESIO_BMASK_MO)
  {
  case AESIO_MO_ECB: return AesioErrorHandle(AesEcbDecrypt(&ctx->ctx, subKeys));
  case AESIO_MO_CBC: return AesioErrorHandle(AesCbcDecrypt(&ctx->ctx, ctx->iVec, subKeys));
  default:
  case AESIO_MO_CTR: return AesioErrorHandle(AesCtrCrypt(&ctx->ctx, ctx->iVec, subKeys));
  case AESIO_MO_GCM: return AesioErrorHandle(AesGcmDecrypt(&ctx->ctx, tag, ctx->iVec, subKeys, ad, adSz));
  }
}

AesioCode AesDecryptStream(
  FILE* destFile,
  FILE* srcFile,
  AESIO_CONTEXT* ctx,
  uint32_t* subKeys,
  uint32_t* tag,
  const uint8_t* ad,
  const uint64_t adSz)
{
  switch (ctx->bFlags & AESIO_BMASK_MO)
  {
  case AESIO_MO_ECB: return AesioErrorHandle(AesEcbDecryptStream(destFile, srcFile, &ctx->ctx, subKeys));
  case AESIO_MO_CBC: return AesioErrorHandle(AesCbcDecryptStream(destFile, srcFile, &ctx->ctx, ctx->iVec, subKeys));
  default:
  case AESIO_MO_CTR: return AesioErrorHandle(AesCtrCryptStream(destFile, srcFile, &ctx->ctx, ctx->iVec, subKeys));
  case AESIO_MO_GCM: return AesioErrorHandle(AesGcmDecryptStream(destFile, srcFile, &ctx->ctx, tag, ctx->iVec, subKeys, ad, adSz));
  }
}

/* Selects a hash function and computes the hash. */
void Hash(
  uint8_t* digest,  
  const void* data,  
  size_t dataSz,    
  uint32_t hmFlag)  
{
  switch (hmFlag & AESIO_BMASK_HM)
  {
  default:
  case AESIO_HM_SHA1:
    Sha1(digest, data, dataSz);
    break;
  case AESIO_HM_SHA2:
    Sha256(digest, data, dataSz);
    break;
  }
}

/* Stream version of Hash. */
AesioCode HashStream(
  uint8_t* digest,  
  FILE* fData,    
  size_t dataSz,    
  uint32_t hmFlag)  
{
  int res;

  switch (hmFlag & AESIO_BMASK_HM)
  {
  default:
  case AESIO_HM_SHA1:
    res = Sha1Stream(digest, fData, dataSz);
    break;
  case AESIO_HM_SHA2:
    res = Sha256Stream(digest, fData, dataSz);
    break;
  }

  if (res)
  {
    return AESIO_ERR_READFAILED;
  }
  else
  {
    return AESIO_ERR_OK;
  }
}

/* Hash a concatenation of two messages. */
void HashCat(
  uint8_t* digest,
  const void* data1,
  const void* data2,
  size_t dataSz1,
  size_t dataSz2,
  uint32_t hmFlag)
{
  switch (hmFlag & AESIO_BMASK_HM)
  {
  default:
  case AESIO_HM_SHA1:
    Sha1Cat(digest, data1, data2, dataSz1, dataSz2);
    break;
  case AESIO_HM_SHA2:
    Sha256Cat(digest, data1, data2, dataSz1, dataSz2);
    break;
  }
}

/* Stream version of HashCat. */
int HashStreamCat(
  uint8_t* digest,
  const void* data1,
  FILE* data2,
  size_t dataSz1,
  size_t dataSz2,
  uint32_t hmFlag)
{
  int res;

  switch (hmFlag & AESIO_BMASK_HM)
  {
  default:
  case AESIO_HM_SHA1:
    res = Sha1StreamCat(digest, data1, data2, dataSz1, dataSz2);
    break;
  case AESIO_HM_SHA2:
    res = Sha256StreamCat(digest, data1, data2, dataSz1, dataSz2);
    break;
  }

  if (res)
  {
    return AESIO_ERR_READFAILED;
  }
  else
  {
    return AESIO_ERR_OK;
  }
}

void GenHmac(
  AESIO_CONTEXT* ctx,
  uint32_t* subKeys)
{
  uint8_t kPlus[MAX_DIGEST_SIZE];
  uint8_t digest[MAX_DIGEST_SIZE];
  uint8_t s[AES_BLOCKSIZE];

  if (ctx->ctx.keySize > AES_BLOCKSIZE)
  {
    Hash(kPlus, subKeys, ctx->ctx.keySize, ctx->bFlags);
  }
  else
  {
    memcpy(kPlus, subKeys, AES_BLOCKSIZE);
  }

  for (int i = 0; i < AES_BLOCKSIZE; i++)
  {
    s[i] = kPlus[i] ^ IPAD;
  }

  HashCat(ctx->mCtx.buff8, s, ctx->ctx.buff32, AES_BLOCKSIZE, ctx->ctx.ptcSz, ctx->bFlags);

  for (int i = 0; i < AES_BLOCKSIZE; i++)
  {
    s[i] = kPlus[i] ^ OPAD;
  }

  HashCat(digest, s, ctx->mCtx.buff8, AES_BLOCKSIZE, ctx->mCtx.size, ctx->bFlags);
  memcpy(ctx->mCtx.buff8, digest, ctx->mCtx.size);
}

void GenHmacStream(
  FILE* pFile,
  AESIO_CONTEXT* ctx,
  uint32_t* subKeys)
{
  uint8_t kPlus[MAX_DIGEST_SIZE];
  uint8_t digest[MAX_DIGEST_SIZE];
  uint8_t s[AES_BLOCKSIZE];

  if (ctx->ctx.keySize > AES_BLOCKSIZE)
  {
    Hash(kPlus, subKeys, ctx->ctx.keySize, ctx->bFlags);
  }
  else
  {
    memcpy(kPlus, subKeys, AES_BLOCKSIZE);
  }

  for (int i = 0; i < AES_BLOCKSIZE; i++)
  {
    s[i] = kPlus[i] ^ IPAD;
  }

  HashStreamCat(ctx->mCtx.buff8, s, pFile, AES_BLOCKSIZE, ctx->ctx.ptcSz, ctx->bFlags);

  for (int i = 0; i < AES_BLOCKSIZE; i++)
  {
    s[i] = kPlus[i] ^ OPAD;
  }

  HashCat(digest, s, ctx->mCtx.buff8, AES_BLOCKSIZE, ctx->mCtx.size, ctx->bFlags);
  memcpy(ctx->mCtx.buff8, digest, ctx->mCtx.size);
}

/* Reads a file into a buffer or opens a file. */
AesioCode AesioReadFile(
  AESIO_FILEINFO* fh,
  _Bool isEncrypted,
  const char* path,
  FILE** pFile)
{
  struct stat stat;
  FILE* file;    

  if (!path || !fh)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

#if defined(_MSC_VER)
  fopen_s(&file, path, "rb");
#else
  file = fopen(path, "rb");
#endif

  if (!file)
  {
    return AESIO_ERR_READFAILED;
  }

  if (fstat(FILENO(file), &stat))
  {
    fclose(file);
    return AESIO_ERR_READFAILED;
  }

  if (isEncrypted)
  {
    if (fread(&fh->ih, sizeof(AESIO_INFOHEADER), 1, file) != 1)
    {
      fclose(file);
      return AESIO_ERR_READFAILED;
    }

    if (!ISSIGVALID(fh->ih.signature))
    {
      fclose(file);
      return AESIO_ERR_INVALIDFILESIGNATURE;
    }    
    
    if (FVERCMP(fh->ih.version) > 0)
    {
      /*
       * Reserved for future use. 
       * We will provide backward compatibility here. 
       * For now, just returns an error message.
       */
      fclose(file);
      return AESIO_ERR_INVALIDFILEVERSION;

    }
    else if (FVERCMP(fh->ih.version) < 0)
    {
      fclose(file);
      return AESIO_ERR_INVALIDFILEVERSION;
    }

    fh->mCtx.size = GETMACSIZE(fh->ih.bFlags);

    memset(fh->mCtx.buff8, 0, sizeof(fh->mCtx.buff8));
    if (fread(fh->mCtx.buff8, sizeof(uint8_t), fh->mCtx.size, file) != fh->mCtx.size)
    {
      fclose(file);
      return AESIO_ERR_READFAILED;
    }

    if (!(fh->ih.bFlags & AESIO_MO_ECB))
    {
      if (fread(fh->iVec, sizeof(uint32_t), 4, file) != 4)
      {
        fclose(file);
        return AESIO_ERR_READFAILED;
      }
    }
    
    fh->cSz = stat.st_size - GETFILEHEADERSIZE(fh->ih.bFlags);
    
    if (!pFile)
    {
      if (!(fh->cBuff = malloc(fh->cSz)))
      {
        fclose(file);
        fh->cSz = 0;
        return AESIO_ERR_OUTOFMEMORY;
      }

      if (fread(fh->cBuff, sizeof(uint8_t), fh->cSz, file) != fh->cSz)
      {
        fclose(file);
        free(fh->cBuff);
        memset(fh, 0, sizeof(AESIO_FILEINFO));
        return AESIO_ERR_READFAILED;
      }
    }
    else
    {
      fh->cBuff = NULL;
    }        
  }
  else
  {
    if (!pFile)
    {
      if (!(fh->cBuff = malloc(stat.st_size)))
      {
        fclose(file);
        return AESIO_ERR_OUTOFMEMORY;
      }

      if (fread(fh->cBuff, sizeof(uint8_t), stat.st_size, file) != stat.st_size)
      {
        free(fh->cBuff);
        memset(fh, 0, sizeof(AESIO_FILEINFO));
        fclose(file);
        return AESIO_ERR_READFAILED;
      }
    }
    else
    {
      fh->cBuff = NULL;
    }    

    fh->cSz = stat.st_size;
  }

  if (!pFile)
  {
    fclose(file);
  }
  else
  {
    *pFile = file;
  }

  return AESIO_ERR_OK;
}

/* Reads a buffer into a buffer. */
AesioCode AesioReadBuffer(
  AESIO_FILEINFO* fh,
  _Bool isEncrypted,
  const char* pBuffer,
  const size_t szBufferSize)
{
  size_t szAux;

  if (pBuffer == NULL || fh == NULL)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  szAux = 0;

  if (isEncrypted)
  {
    if(szAux + sizeof(AESIO_INFOHEADER) > szBufferSize)
    {
      return AESIO_ERR_INVALIDINPUT;
    }
    
    memcpy(&fh->ih, &pBuffer[szAux], sizeof(AESIO_INFOHEADER));
    szAux += sizeof(AESIO_INFOHEADER);
    if(szAux + GETIVECSIZE(fh->ih.bFlags) + GETMACSIZE(fh->ih.bFlags) > szBufferSize)
    {
      return AESIO_ERR_INVALIDINPUT;
    }

    if (!ISSIGVALID(fh->ih.signature))
    {
      return AESIO_ERR_INVALIDFILESIGNATURE;
    }    
    
    if (FVERCMP(fh->ih.version) > 0)
    {
      /*
       * Reserved for future use. 
       * We will provide backward compatibility here. 
       * For now, just returns an error message.
       */
      return AESIO_ERR_INVALIDFILEVERSION;
    }
    else if (FVERCMP(fh->ih.version) < 0)
    {
      return AESIO_ERR_INVALIDFILEVERSION;
    }

    fh->mCtx.size = GETMACSIZE(fh->ih.bFlags);

    memset(fh->mCtx.buff8, 0, sizeof(fh->mCtx.buff8));
    memcpy(fh->mCtx.buff8, &pBuffer[szAux], fh->mCtx.size);
    szAux += fh->mCtx.size;

    if ((fh->ih.bFlags & AESIO_MO_ECB) == 0)
    {      
      memcpy(fh->iVec, &pBuffer[szAux], 4 * sizeof(uint32_t));
      szAux +=  4 * sizeof(uint32_t);
    }
    
    fh->cSz = szBufferSize - GETFILEHEADERSIZE(fh->ih.bFlags);    
    if (!(fh->cBuff = malloc(fh->cSz)))
    {
      fh->cSz = 0;
      return AESIO_ERR_OUTOFMEMORY;
    }

    memcpy(fh->cBuff, &pBuffer[szAux], fh->cSz);
    szAux += fh->cSz;       
  }
  else
  {
    if (!(fh->cBuff = malloc(szBufferSize)))
    {
      return AESIO_ERR_OUTOFMEMORY;
    }

    memcpy(fh->cBuff, pBuffer, szBufferSize);
    szAux += szBufferSize;
    fh->cSz = szBufferSize;
  }

  return AESIO_ERR_OK;
}

/* Opens a file. */
AesioCode AesioOpenFile(
  AESIO_CONTEXT* ioCtx,
  const char* path,
  FILE** pFile,
  _Bool offsetted)
{
#if defined(_MSC_VER)
  fopen_s(pFile, path, "wb+");
#else
  *pFile = fopen(path, "wb+");
#endif
  if ((*pFile) == NULL)
  {
    return AESIO_ERR_WRITEFAILED;
  }

  if (offsetted)
  {
    if (fseek(*pFile, GETFILEHEADERSIZE(ioCtx->bFlags), SEEK_SET))
    {
      fclose(*pFile);
      *pFile = NULL;
      return AESIO_ERR_INVALIDFILEOFFSET;
    }
  }
  
  return AES_ERR_OK;
}

/* Writes the file header. */
AesioCode AesioWriteFileHeader(
  FILE* pFile,
  _Bool seekToBeginning,
  AESIO_CONTEXT* ioCtx)
{
  if (!pFile || !ioCtx)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  AESIO_INFOHEADER fh;

  fh.bFlags = ioCtx->bFlags;
  fh.version = AESIO_FILEVERSION;
  memcpy(fh.signature, AESIO_FSIG, AESIO_SIGNATURESIZE);  

  if (seekToBeginning)
  {
    if (fseek(pFile, 0, SEEK_SET))
    {
      return AESIO_ERR_INVALIDFILEOFFSET;
    }
  }  

  if (fwrite(&fh, sizeof(AESIO_INFOHEADER), 1, pFile) != 1)
  {    
    return AESIO_ERR_WRITEFAILED;
  }

  if (fwrite(ioCtx->mCtx.buff8, sizeof(uint8_t), ioCtx->mCtx.size, pFile) != ioCtx->mCtx.size)
  {    
    return AESIO_ERR_WRITEFAILED;
  }

  if (!(ioCtx->bFlags & AESIO_MO_ECB))
  {
    if (fwrite(ioCtx->iVec, sizeof(uint32_t), 4, pFile) != 4)
    {      
      return AESIO_ERR_WRITEFAILED;
    }
  }

  return AESIO_ERR_OK;
}

/* Writes the file header. */
char* AesioWriteBufferHeader(
  char* pBuffer,
  const size_t szBufferSize,
  AESIO_CONTEXT* ioCtx)
{
  if (pBuffer == NULL || ioCtx == NULL)
  {
    return NULL;
  }

  AESIO_INFOHEADER fh;
  size_t szAux;
  size_t szInitVecSize;

  fh.bFlags = ioCtx->bFlags;
  fh.version = AESIO_FILEVERSION;
  memcpy(fh.signature, AESIO_FSIG, AESIO_SIGNATURESIZE);
  
  szAux = 0;
  szInitVecSize = (ioCtx->bFlags & AESIO_MO_ECB) == 0 ? 4 * sizeof(uint32_t) : 0;
    
  if(sizeof(AESIO_INFOHEADER) + ioCtx->mCtx.size + szInitVecSize > szBufferSize)
  {
    return NULL;
  }
  
  memcpy(&pBuffer[szAux], &fh, sizeof(AESIO_INFOHEADER));
  szAux += sizeof(AESIO_INFOHEADER);

  memcpy(&pBuffer[szAux], ioCtx->mCtx.buff8, ioCtx->mCtx.size);
  szAux += ioCtx->mCtx.size;

  if (szInitVecSize > 0)
  {
    memcpy(&pBuffer[szAux], ioCtx->iVec, szInitVecSize);
    szAux += szInitVecSize;
  }

  return &pBuffer[szAux];
}

/* Writes the data contained in the AESIO context into a file. */
AesioCode AesioWriteFile(
  AESIO_CONTEXT* ioCtx,
  _Bool isEncrypted,
  const char* path)
{
  FILE* file;

  if (!ioCtx || !path)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

#if defined(_MSC_VER)
  fopen_s(&file, path, "wb+");
#else
  file = fopen(path, "wb+");
#endif
  if (file == NULL)
  {
    return AESIO_ERR_WRITEFAILED;
  }

  if (isEncrypted)
  {
    AesioWriteFileHeader(file, FALSE, ioCtx);
  }

  if (fwrite(ioCtx->ctx.buff32, ioCtx->ctx.ptcSz, 1 , file) != 1)
  {
    fclose(file);
    return AESIO_ERR_WRITEFAILED;
  }

  fclose(file);
  return AESIO_ERR_OK;
}

/* Writes the data contained in the AESIO context into a buffer. */
AesioCode AesioWriteBuffer(
  AESIO_CONTEXT* ioCtx,
  _Bool isEncrypted,
  char** ppBufer,
  size_t* pSzBufferSize)
{
  char* pBuffer;
  char* pAux;
  size_t szHeaderSize;
  size_t szBufferSize;

  if (ioCtx == NULL || ppBufer == NULL || pSzBufferSize == NULL)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  *ppBufer = NULL;
  *pSzBufferSize = 0;
    
  szHeaderSize = isEncrypted ? GETFILEHEADERSIZE(ioCtx->bFlags) : 0;
  szBufferSize = szHeaderSize + ioCtx->ctx.ptcSz;
  pBuffer = malloc(szBufferSize);
  if(pBuffer == NULL)
  {
    return AESIO_ERR_OUTOFMEMORY;
  }

  pAux = pBuffer;

  if (isEncrypted)
  {
    pAux = AesioWriteBufferHeader(pBuffer, szBufferSize, ioCtx);
  }

  memcpy(pAux, ioCtx->ctx.buff8, ioCtx->ctx.ptcSz);
  *ppBufer = pBuffer;
  *pSzBufferSize = szBufferSize;

  return AESIO_ERR_OK;
}

AesioCode AesioEncryptFile(
  const char* destPath,
  const char* srcPath, 
  const char* pwd, 
  const size_t pwdLen,
  uint32_t* subKeys, 
  uint8_t* aad,
  const uint64_t aadSz,
  const int moFlags)
{
  if (!destPath || !srcPath || !pwd)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  AESIO_CONTEXT ioCtx = { 0 };

  AesioCode res;  
  AESIO_FILEINFO fh;
  uint32_t sk[AES_MAX_SUBKEYS_COUNT];  

  /* Generate subkeys */
  if (!subKeys)
  {
    subKeys = sk;
    if ((res = KeySchedule(subKeys, pwd, pwdLen, GETKEYBLOCKSIZE(moFlags))) != AESIO_ERR_OK)
    {
      goto cleanup;
    }
  }

  if ((res = AesioReadFile(&fh, FALSE, srcPath, NULL)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }  

  if ((res = AesioInit(&ioCtx, fh.cBuff, fh.cSz, moFlags, NULL)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  /* Encrypts the buffer */
  if ((res = AesEncrypt(&ioCtx, subKeys, ioCtx.mCtx.buff32, aad, aadSz)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  if (!(ioCtx.bFlags & AESIO_MO_GCM) && (ioCtx.bFlags & AESIO_BMASK_HM))
  {
    /* HMAC creation */
    GenHmac(&ioCtx, subKeys);
  }

  /* Writes the buffer into the file */
  res = AesioWriteFile(&ioCtx, TRUE, destPath);

cleanup:
  /* Wipe local variables */
  memset(sk, 0, AES_MAX_SUBKEYS_SIZE);
  /* Release AESIO context */
  ReleaseAesioContext(&ioCtx, TRUE);
  return res;
}

AesioCode AesioEncryptFileToBuffer(
  char** ppBuffer,
  size_t* pSzBufferSize,
  const char* srcPath, 
  const char* pwd, 
  const size_t pwdLen,
  uint32_t* subKeys, 
  const uint8_t* aad,
  const uint64_t aadSz,
  const int moFlags)
{
  if (ppBuffer == NULL || pSzBufferSize == NULL || srcPath == NULL || pwd == NULL)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  AESIO_CONTEXT ioCtx = { 0 };

  AesioCode res;  
  AESIO_FILEINFO fh;
  uint32_t sk[AES_MAX_SUBKEYS_COUNT];  

  *ppBuffer = NULL;
  *pSzBufferSize = 0;

  /* Generate subkeys */
  if (!subKeys)
  {
    subKeys = sk;
    if ((res = KeySchedule(subKeys, pwd, pwdLen, GETKEYBLOCKSIZE(moFlags))) != AESIO_ERR_OK)
    {
      goto cleanup;
    }
  }

  if ((res = AesioReadFile(&fh, FALSE, srcPath, NULL)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }  

  if ((res = AesioInit(&ioCtx, fh.cBuff, fh.cSz, moFlags, NULL)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  /* Encrypts the buffer */
  if ((res = AesEncrypt(&ioCtx, subKeys, ioCtx.mCtx.buff32, aad, aadSz)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  if (((ioCtx.bFlags & AESIO_MO_GCM) == 0) && ((ioCtx.bFlags & AESIO_BMASK_HM) != 0))
  {
    /* HMAC creation */
    GenHmac(&ioCtx, subKeys);
  }

  /* Writes the encrypted data into the buffer */
  res = AesioWriteBuffer(&ioCtx, TRUE, ppBuffer, pSzBufferSize);

cleanup:
  /* Wipe local variables */
  memset(sk, 0, AES_MAX_SUBKEYS_SIZE);
  /* Release AESIO context */
  ReleaseAesioContext(&ioCtx, TRUE);
  return res;
}

AesioCode AesioEncryptFileStream(
  const char* destPath,
  const char* srcPath,
  const char* pwd,
  const size_t pwdLen,
  uint32_t* subKeys,
  uint8_t* aad,
  const uint64_t aadSz,
  const int moFlags)
{
  if (!destPath || !srcPath || !pwd )
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  AESIO_CONTEXT ioCtx = { 0 };
  FILE* srcFile = NULL;
  FILE* destFile = NULL;

  AesioCode res;  
  AESIO_FILEINFO fh;
  uint32_t sk[AES_MAX_SUBKEYS_COUNT];

  /* Generate subkeys */
  if (!subKeys)
  {
    subKeys = sk;
    if ((res = KeySchedule(subKeys, pwd, pwdLen, GETKEYBLOCKSIZE(moFlags))) != AESIO_ERR_OK)
    {
      goto cleanup;
    }
  }

  if ((res = AesioReadFile(&fh, FALSE, srcPath, &srcFile)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }
  
  if ((res = AesioInit(&ioCtx, NULL, fh.cSz, moFlags, NULL)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  if ((res = AesioOpenFile(&ioCtx, destPath, &destFile, TRUE)))
  {
    goto cleanup;
  }

  /* Encrypts the buffer */
  if ((res = AesEncryptStream(destFile, srcFile, &ioCtx, subKeys, ioCtx.mCtx.buff32, aad, aadSz)) != AESIO_ERR_OK)
  {    
    goto cleanup;
  }

  if (fseek(destFile, -(long)(ioCtx.ctx.ptcSz), SEEK_CUR))
  {
    res = AESIO_ERR_INVALIDFILEOFFSET;
    goto cleanup;
  }

  if (!(ioCtx.bFlags & AESIO_MO_GCM) && (ioCtx.bFlags & AESIO_BMASK_HM))
  {
    /* HMAC creation */
    GenHmacStream(destFile, &ioCtx, subKeys);
  }

  /* Writes the file header */  
  res = AesioWriteFileHeader(destFile, TRUE, &ioCtx);

cleanup:
  /* Wipe local variables */
  memset(sk, 0, AES_MAX_SUBKEYS_SIZE);
  /* Release AESIO context and close opened files */
  ReleaseAesioContext(&ioCtx, FALSE);
  if (srcFile)
  {
    fclose(srcFile);
  }    
  if (destFile)
  {
    fclose(destFile);
  }
  /* Remove the destination file if something goes wrong */
  if (res != AESIO_ERR_OK)
  {
    remove(destPath);
  }
  
  return res;
}

AesioCode AesioDecryptFile(
  const char* destPath, 
  const char* srcPath, 
  const char* pwd, 
  const size_t pwdLen,
  uint32_t* subKeys, 
  uint8_t* aad, 
  const uint64_t aadSz)
{
  if (!destPath || !srcPath || !pwd)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  AESIO_CONTEXT ioCtx = { 0 };

  AesioCode res;    
  AESIO_FILEINFO fh;
  uint32_t sk[AES_MAX_SUBKEYS_COUNT];  

  /* File reading process */
  if ((res = AesioReadFile(&fh, TRUE, srcPath, NULL)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  if ((res = AesioInit(&ioCtx, fh.cBuff, fh.cSz, fh.ih.bFlags, fh.iVec)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  /* Key schedule */
  if (!subKeys)
  {
    subKeys = sk;
    if ((res = KeySchedule(subKeys, pwd, pwdLen, ioCtx.ctx.keySize)) != AESIO_ERR_OK)
    {
      goto cleanup;
    }
  }

  if (!(ioCtx.bFlags & AESIO_MO_GCM) && (ioCtx.bFlags & AESIO_BMASK_HM))
  {
    /* HMAC creation */
    GenHmac(&ioCtx, subKeys);

    /* HMAC validation */
    if (!VALIDATEMAC(fh.mCtx.buff32, ioCtx.mCtx.buff32))
    {
      res = AESIO_ERR_MACNOTMATCH;
      goto cleanup;
    }
  }

  /* Decrypt */
  if ((res = AesDecrypt(&ioCtx, subKeys, fh.mCtx.buff32, aad, aadSz)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  /* Writes decrypted data to a file */
  res = AesioWriteFile(&ioCtx, FALSE, destPath);

cleanup:
  /* Wipe variables */
  memset(sk, 0, AES_MAX_SUBKEYS_SIZE);
  memset(&fh, 0, sizeof(AESIO_FILEINFO));
  /* Release AESIO context */
  ReleaseAesioContext(&ioCtx, TRUE);
  return res;
}

AesioCode AesioDecryptFileStream(
  const char* destPath,
  const char* srcPath,
  const char* pwd,
  const size_t pwdLen,
  uint32_t* subKeys,
  uint8_t* aad,
  const uint64_t aadSz)
{
  if (!destPath || !srcPath || !pwd)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  AesioCode res;    
  AESIO_FILEINFO fh;
  uint32_t sk[AES_MAX_SUBKEYS_COUNT];

  AESIO_CONTEXT ioCtx = { 0 };  
  FILE* srcFile = NULL;
  FILE* destFile = NULL;

  /* File reading process */
  if ((res = AesioReadFile(&fh, TRUE, srcPath, &srcFile)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  if ((res = AesioInit(&ioCtx, fh.cBuff, fh.cSz, fh.ih.bFlags, fh.iVec)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  if ((res = AesioOpenFile(&ioCtx, destPath, &destFile, FALSE)))
  {
    goto cleanup;
  }

  /* Key schedule */
  if (!subKeys)
  {
    subKeys = sk;
    if ((res = KeySchedule(subKeys, pwd, pwdLen, ioCtx.ctx.keySize)) != AESIO_ERR_OK)
    {
      goto cleanup;
    }
  }

  if (!(ioCtx.bFlags & AESIO_MO_GCM) && (ioCtx.bFlags & AESIO_BMASK_HM))
  {
    /* HMAC creation */
    GenHmacStream(srcFile, &ioCtx, subKeys);

    /* HMAC validation */
    if (!VALIDATEMAC(fh.mCtx.buff32, ioCtx.mCtx.buff32))
    {
      res = AESIO_ERR_MACNOTMATCH;
      goto cleanup;
    }

    if (fseek(srcFile, -(long)(ioCtx.ctx.ptcSz), SEEK_CUR))
    {
      res = AESIO_ERR_INVALIDFILEOFFSET;
      goto cleanup;
    }
  }  

  /* Decrypt */
  if ((res = AesDecryptStream(destFile, srcFile, &ioCtx, subKeys, fh.mCtx.buff32, aad, aadSz)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }  

cleanup:
  /* Wipe variables */
  memset(sk, 0, AES_MAX_SUBKEYS_SIZE);
  memset(&fh, 0, sizeof(AESIO_FILEINFO));
  /* Release AESIO context and close opened files */
  ReleaseAesioContext(&ioCtx, FALSE);
  if (srcFile)
  {
    fclose(srcFile);
  }
  if (destFile)
  {
    fclose(destFile);
  }
  /* Remove destination file if something goes wrong */
  if (res != AESIO_ERR_OK)
  {
    remove(destPath);
  }
  return res;
}

AesioCode AesioEncryptData(
  AESIO_CONTEXT* ioCtx,
  uint32_t* subKeys,
  const char* pwd,
  size_t pwdLen,
  uint8_t* aad,
  const uint64_t aadSz)
{
  if (!ioCtx || (!pwd && !subKeys))
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  AesioCode res;
  uint32_t sk[AES_MAX_SUBKEYS_COUNT];

  /* Generate subkeys */
  if (!subKeys)
  {
    subKeys = sk;    
    if ((res = KeySchedule(subKeys, pwd, pwdLen, ioCtx->ctx.keySize)) != AESIO_ERR_OK)
    {
      goto cleanup;
    }
  }  

  /* Encrypts the buffer */
  if ((res = AesEncrypt(ioCtx, subKeys, ioCtx->mCtx.buff32, aad, aadSz)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  /* HMAC creation */
  if (!(ioCtx->bFlags & AESIO_MO_GCM) && (ioCtx->bFlags & AESIO_BMASK_HM))
  {    
    GenHmac(ioCtx, subKeys);
  }

cleanup:
  /* Wipe local variables */
  memset(sk, 0, AES_MAX_SUBKEYS_SIZE);
  return res;
}

AesioCode AesioEncryptDataToFile(
  const char* destPath,
  const char* pData,
  const size_t szData,
  const char* pwd, 
  const size_t pwdLen,
  uint32_t* subKeys, 
  uint8_t* aad,
  const uint64_t aadSz,
  const int moFlags)
{
  if (destPath == NULL || pData == NULL || szData == 0 || pwd == NULL)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  AESIO_CONTEXT ioCtx = { 0 };

  AesioCode res;  
  AESIO_FILEINFO fh;
  uint32_t sk[AES_MAX_SUBKEYS_COUNT];  

  /* Generate subkeys */
  if (!subKeys)
  {
    subKeys = sk;
    if ((res = KeySchedule(subKeys, pwd, pwdLen, GETKEYBLOCKSIZE(moFlags))) != AESIO_ERR_OK)
    {
      goto cleanup;
    }
  }

  if ((res = AesioReadBuffer(&fh, FALSE, pData, szData)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }  

  if ((res = AesioInit(&ioCtx, fh.cBuff, fh.cSz, moFlags, NULL)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  /* Encrypts the buffer */
  if ((res = AesEncrypt(&ioCtx, subKeys, ioCtx.mCtx.buff32, aad, aadSz)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  if (((ioCtx.bFlags & AESIO_MO_GCM) == 0) && ((ioCtx.bFlags & AESIO_BMASK_HM) != 0))
  {
    /* HMAC creation */
    GenHmac(&ioCtx, subKeys);
  }

  /* Writes the buffer into the file */
  res = AesioWriteFile(&ioCtx, TRUE, destPath);

cleanup:
  /* Wipe local variables */
  memset(sk, 0, AES_MAX_SUBKEYS_SIZE);
  /* Release AESIO context */
  ReleaseAesioContext(&ioCtx, TRUE);
  return res;
}

AesioCode AesioEncryptDataToBuffer(
  char** ppBuffer,
  size_t* pSzBuffer,
  const char* pData,
  const size_t szData,
  const char* pwd, 
  const size_t pwdLen,
  uint32_t* subKeys, 
  uint8_t* aad,
  const uint64_t aadSz,
  const int moFlags)
{
  if (ppBuffer == NULL || pSzBuffer == NULL || pData == NULL || szData == 0 || pwd == NULL)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  AESIO_CONTEXT ioCtx = { 0 };

  AesioCode res;  
  AESIO_FILEINFO fh;
  uint32_t sk[AES_MAX_SUBKEYS_COUNT];  

  /* Generate subkeys */
  if (!subKeys)
  {
    subKeys = sk;
    if ((res = KeySchedule(subKeys, pwd, pwdLen, GETKEYBLOCKSIZE(moFlags))) != AESIO_ERR_OK)
    {
      goto cleanup;
    }
  }

  if ((res = AesioReadBuffer(&fh, FALSE, pData, szData)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }  

  if ((res = AesioInit(&ioCtx, fh.cBuff, fh.cSz, moFlags, NULL)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  /* Encrypts the buffer */
  if ((res = AesEncrypt(&ioCtx, subKeys, ioCtx.mCtx.buff32, aad, aadSz)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  if (((ioCtx.bFlags & AESIO_MO_GCM) == 0) && ((ioCtx.bFlags & AESIO_BMASK_HM) != 0))
  {
    /* HMAC creation */
    GenHmac(&ioCtx, subKeys);
  }

  /* Writes the buffer into the file */
  res = AesioWriteBuffer(&ioCtx, TRUE, ppBuffer, pSzBuffer);

cleanup:
  /* Wipe local variables */
  memset(sk, 0, AES_MAX_SUBKEYS_SIZE);
  /* Release AESIO context */
  ReleaseAesioContext(&ioCtx, TRUE);
  return res;
}

AesioCode AesioDecryptData(
  AESIO_CONTEXT* ioCtx, 
  uint32_t* subKeys,
  const char* pwd,
  size_t pwdLen,
  uint8_t* aad,
  const uint64_t aadSz)
{
  if (!ioCtx || (!pwd && !subKeys))
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  AesioCode res;
  uint32_t sk[AES_MAX_SUBKEYS_COUNT];
  MAC_CONTEXT mCtx;

  mCtx = ioCtx->mCtx;

  /* Key schedule */
  if (!subKeys)
  {
    subKeys = sk;
    if ((res = KeySchedule(subKeys, pwd, pwdLen, ioCtx->ctx.keySize)) != AESIO_ERR_OK)
    {
      goto cleanup;
    }
  }

  /* HMAC creation */
  if (!(ioCtx->bFlags & AESIO_MO_GCM) && (ioCtx->bFlags & AESIO_BMASK_HM))
  {    
    GenHmac(ioCtx, subKeys);
    if (!VALIDATEMAC(mCtx.buff32, ioCtx->mCtx.buff32))
    {
      res = AESIO_ERR_MACNOTMATCH;
      goto cleanup;
    }
  }

  /* Decrypt */
  if ((res = AesDecrypt(ioCtx, subKeys, mCtx.buff32, aad, aadSz)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }  

cleanup:
  /* Wipe local variables */
  memset(sk, 0, AES_MAX_SUBKEYS_SIZE);
  return res;
}

AesioCode AesioDecryptDataToFile(
  const char* destPath,
  const char* pData,
  const size_t szData,
  const char* pwd, 
  const size_t pwdLen,
  uint32_t* subKeys, 
  uint8_t* aad, 
  const uint64_t aadSz)
{
  if (destPath == NULL || pData == NULL || pwd == NULL)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  AESIO_CONTEXT ioCtx = { 0 };

  AesioCode res;    
  AESIO_FILEINFO fh;
  uint32_t sk[AES_MAX_SUBKEYS_COUNT];  

  /* File reading process */
  if ((res = AesioReadBuffer(&fh, TRUE, pData, szData)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  if ((res = AesioInit(&ioCtx, fh.cBuff, fh.cSz, fh.ih.bFlags, fh.iVec)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  /* Key schedule */
  if (!subKeys)
  {
    subKeys = sk;
    if ((res = KeySchedule(subKeys, pwd, pwdLen, ioCtx.ctx.keySize)) != AESIO_ERR_OK)
    {
      goto cleanup;
    }
  }

  if (!(ioCtx.bFlags & AESIO_MO_GCM) && (ioCtx.bFlags & AESIO_BMASK_HM))
  {
    /* HMAC creation */
    GenHmac(&ioCtx, subKeys);

    /* HMAC validation */
    if (!VALIDATEMAC(fh.mCtx.buff32, ioCtx.mCtx.buff32))
    {
      res = AESIO_ERR_MACNOTMATCH;
      goto cleanup;
    }
  }

  /* Decrypt */
  if ((res = AesDecrypt(&ioCtx, subKeys, fh.mCtx.buff32, aad, aadSz)) != AESIO_ERR_OK)
  {
    goto cleanup;
  }

  /* Writes decrypted data to a file */
  res = AesioWriteFile(&ioCtx, FALSE, destPath);

cleanup:
  /* Wipe variables */
  memset(sk, 0, AES_MAX_SUBKEYS_SIZE);
  memset(&fh, 0, sizeof(AESIO_FILEINFO));
  /* Release AESIO context */
  ReleaseAesioContext(&ioCtx, TRUE);
  return res;
}

AesioCode AesioInit(
  AESIO_CONTEXT* ctx,
  uint8_t* buffer, 
  size_t buffSz, 
  uint32_t bFlags,
  uint32_t* iVec)
{
  if (!ctx)
  {
    return AESIO_ERR_INVALIDPARAM;
  }

  ctx->bFlags = bFlags;
  ctx->ctx.buff8 = buffer;
  ctx->ctx.ptcSz = buffSz;
  ctx->ctx.keySize = GETKEYBLOCKSIZE(bFlags);
  ctx->mCtx.size = GETMACSIZE(bFlags);
  memset(ctx->mCtx.buff32, 0, MAX_DIGEST_SIZE);
  
  /* Generates initialization vector */
  if (!iVec)
  {
    if (!(ctx->bFlags & AESIO_MO_ECB))
    {
      return InitRandVec(ctx->iVec);
    }
  }
  else
  {
    memcpy(ctx->iVec, iVec, AES_BLOCKSIZE);
  }
  
  return AESIO_ERR_OK;
}