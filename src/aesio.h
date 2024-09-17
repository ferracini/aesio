#ifndef AESIO_H
#define AESIO_H
#include "aesom.h"
#include "aesiofver.h"
#include "sha1.h"
#include "sha256.h"
#include <stdbool.h>

#ifndef TRUE
#define TRUE  (_Bool)(1)
#ifndef FALSE
#define FALSE  (_Bool)(0)
#endif // !FALSE
#endif // !TRUE

/* AESIO version.                                                     */
#define AESIO_STR_VER             "1.01"

/* Comment the line below if you do not want to use password padding. */
#define AESIO_USEPWDPADDING

/*
 * AESIO option bit flags.
 *
 * AESIO_MO_XXX:  AES operation mode;
 * AESIO_HM_XXXX:  hash algorithm used for HMAC validation;
 * AESIO_KL_XXX:  key length for AES.
 * 
 * Remarks: 
 *
 * If AESIO_MO_GCM flag is specified, the AESIO_HM_XXXX (hmac flags) will be ignored
 * in order to perform the GHash.
 */
#define AESIO_AUTO                (0x00000000)  /* Auto settings.           */
#define AESIO_MO_ECB              (0x00000001)  /* Eletronic Codebook.      */
#define AESIO_MO_CBC              (0x00000002)  /* Cipher Block Chaining.   */
#define AESIO_MO_CTR              (0x00000004)  /* Counter mode.            */
#define AESIO_MO_GCM              (0x00000008)  /* Galois Counter Mode.     */
#define AESIO_MO_RESERVED1        (0x00000010)  /* Reserved.                */
#define AESIO_MO_RESERVED2        (0x00000020)  /* Reserved.                */
#define AESIO_MO_RESERVED3        (0x00000040)  /* Reserved.                */
#define AESIO_MO_RESERVED4        (0x00000080)  /* Reserved.                */
#define AESIO_HM_SHA1             (0x00000100)  /* HMAC-SHA-160.            */
#define AESIO_HM_SHA2             (0x00000200)  /* HMAC-SHA-256.            */
#define AESIO_HM_RESERVED1        (0x00000400)  /* Reserved.                */
#define AESIO_HM_RESERVED2        (0x00000800)  /* Reserved.                */
#define AESIO_HM_RESERVED3        (0x00001000)  /* Reserved.                */
#define AESIO_KL_128              (0x00004000)  /* AES-128 bits key length. */
#define AESIO_KL_192              (0x00006000)  /* AES-192 bits key length. */
#define AESIO_KL_256              (0x00008000)  /* AES-256 bits key length. */

/* AESIO option bitmask */
#define AESIO_BMASK_MO            (0x000000FF)  /* Operation mode bitmask.  */
#define AESIO_BMASK_HM            (0x00001F00)  /* Hash mode bitmask.       */  
#define AESIO_BMASK_KL            (0x0000E000)  /* Key length bitmask.      */

/* Constants */
#define MAX_DIGEST_SIZE           SHA256_DIGEST_SIZE           /* SHA256 max digest size, in bytes.  */
#define AESIO_128_KSZ             (128U / (uint32_t)CHAR_BIT)  /* Key size for AES 128 bits.         */
#define AESIO_192_KSZ             (192U / (uint32_t)CHAR_BIT)  /* Key size for AES 192 bits.         */
#define AESIO_256_KSZ             (256U / (uint32_t)CHAR_BIT)  /* Key size for AES 256 bits.         */

/* Helper macros */
#define GETIVECSIZE(bFlags)       ((bFlags & AESIO_MO_ECB) ? 0 : AES_BLOCKSIZE)
#define GETMACSIZE(moFlags)       ((moFlags & AESIO_BMASK_MO) == AESIO_MO_GCM ? AES_BLOCKSIZE : (((moFlags & AESIO_BMASK_HM) == AESIO_HM_SHA2) ? SHA256_DIGEST_SIZE : SHA1_DIGEST_SIZE))
#define GETFILEHEADERSIZE(flags)  (GETIVECSIZE(flags) + GETMACSIZE(flags) + sizeof(AESIO_INFOHEADER))
#define GETKEYBLOCKSIZE(moFlags)  ((((moFlags & AESIO_BMASK_KL) >> 7) / CHAR_BIT) * sizeof(uint8_t))
#define VALIDATEMAC(hmac1, hmac2) (hmac1[0] == hmac2[0] &&\
                                   hmac1[1] == hmac2[1] &&\
                                   hmac1[2] == hmac2[2] &&\
                                   hmac1[3] == hmac2[3] &&\
                                   hmac1[4] == hmac2[4] &&\
                                   hmac1[5] == hmac2[5] &&\
                                   hmac1[6] == hmac2[6] &&\
                                   hmac1[7] == hmac2[7])

/* AESIO error messages */
typedef enum AesioErrorMessage
{
  AESIO_ERR_OK,                     /* No errors.                       */
  AESIO_ERR_INVALIDPARAM,           /* Invalid parameter.               */
  AESIO_ERR_INVALIDFILEOFFSET,      /* Invalid file offset.             */
  AESIO_ERR_INVALIDSIZE,            /* Invalid input size.              */
  AESIO_ERR_INVALIDKEYSIZE,         /* Invalid key size.                */  
  AESIO_ERR_OUTOFMEMORY,            /* Out of memory.                   */
  AESIO_ERR_READFAILED,             /* Read failed.                     */
  AESIO_ERR_INVALIDINPUT,           /* Invalid input.                   */
  AESIO_ERR_WRITEFAILED,            /* Write failed.                    */
  AESIO_ERR_RANDFAILED,             /* Random number generation failed. */
  AESIO_ERR_MACNOTMATCH,            /* MAC not match.                   */
  AESIO_ERR_INVALIDFILESIGNATURE,   /* Invalid file signature.          */
  AESIO_ERR_INVALIDFILEVERSION      /* Invalid file version.            */
}AesioCode;

typedef struct _MAC_CONTEXT
{
  /*
   * The buffer needs to be large enough to hold
   * the largest possible digest.
  */
  union
  {
    uint8_t  buff8[MAX_DIGEST_SIZE];
    uint32_t buff32[MAX_DIGEST_SIZE / sizeof(int)];
  };
  size_t size;
}MAC_CONTEXT;

typedef struct _AESIO_CONTEXT
{
  uint32_t bFlags;
  AES_CONTEXT ctx;
  MAC_CONTEXT mCtx;
  uint32_t iVec[AES_BLOCKLEN];
}AESIO_CONTEXT;

typedef struct _AESIO_INFOHEADER
{  
  uint8_t signature[AESIO_SIGNATURESIZE];
  uint16_t version;
  uint32_t bFlags;
}AESIO_INFOHEADER;

typedef struct _AESIO_FILEINFO
{
  AESIO_INFOHEADER ih;
  MAC_CONTEXT mCtx;
  uint32_t iVec[4];
  uint8_t* cBuff;
  size_t cSz;
}AESIO_FILEINFO;

/* Write the header of the encrypted file. 
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
*/
AesioCode AesioWriteFileHeader(
  FILE* pFile,            /* Pointer to an opened file.              */
  _Bool seekToBeginning,  /* Seek to beginning of file.              */
  AESIO_CONTEXT* ioCtx);  /* AESIO context.                          */    

/* Encrypts a file. 
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * This function uses malloc to allocate the buffer that will contain the encrypted data. 
 * AesioEncryptFileStream is an equivalent implementation that does not use malloc.
 */
AesioCode AesioEncryptFile(
  const char* destPath,   /* Destination path.                                */
  const char* srcPath,    /* Source path.                                     */
  const char* pwd,        /* User password.                                   */  
  const size_t pwdLen,    /* Password length.                                 */
  uint32_t* subKeys,      /* Key schedule pointer.                            */
  uint8_t* aad,           /* Additional authenticated data for GCM mode.      */
  const uint64_t aadSz,   /* Additional authenticated data size, in bytes.    */
  const int moFlags);     /* AESIO option bit flags.                          */  

/* Encrypts a file into a buffer.
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * This function uses malloc to allocate the buffer that will contain the encrypted data.
 */
AesioCode AesioEncryptFileToBuffer(
  char** ppBuffer,        /* Pointer that receives a pointer to dynamically allocated memory. */
  size_t* pSzBufferSize,  /* Output buffer size, in bytes.                                    */
  const char* srcPath,    /* Source path.                                                     */
  const char* pwd,        /* User password.                                                   */
  const size_t pwdLen,    /* Password length.                                                 */
  uint32_t* subKeys,      /* Key schedule pointer.                                            */
  const uint8_t* aad,     /* Additional authenticated data for GCM mode.                      */
  const uint64_t aadSz,   /* Additional authenticated data size, in bytes.                    */
  const int moFlags);     /* AESIO option bit flags.                                          */

/* Encrypts a file. 
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * This function does not use malloc (dynamic memory allocation). 
 * All input and output operations are performed through streams.
*/
AesioCode AesioEncryptFileStream(
  const char* destPath,   /* Destination path.                                */
  const char* srcPath,    /* Source path.                                     */
  const char* pwd,        /* User password.                                   */  
  const size_t pwdLen,    /* Password length.                                 */
  uint32_t* subKeys,      /* Key schedule pointer.                            */
  uint8_t* aad,           /* Additional authenticated data for GCM mode.      */
  const uint64_t aadSz,   /* Additional authenticated data size, in bytes.    */
  const int moFlags);     /* AESIO option bit flags.                          */  

/* Decrypts a file.
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * This function uses malloc to allocate the buffer that will contain the decrypted data.
 * AesioDecryptFileStream is an equivalent implementation that does not use malloc.
*/
AesioCode AesioDecryptFile(
  const char* destPath,   /* Destination path.                                */
  const char* srcPath,    /* Source path.                                     */
  const char* pwd,        /* User password.                                   */
  const size_t pwdLen,    /* Password length.                                 */
  uint32_t* subKeys,      /* Key schedule pointer.                            */
  uint8_t* aad,           /* Additional authenticated data for GCM mode.      */
  const uint64_t aadSz);  /* Additional authenticated data size, in bytes.    */

/* Decrypts a file.
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * This function does not use malloc (dynamic memory allocation).
 * All input and output operations are performed through streams.
*/
AesioCode AesioDecryptFileStream(
  const char* destPath,   /* Destination path.                                */
  const char* srcPath,    /* Source path.                                     */
  const char* pwd,        /* User password.                                   */
  const size_t pwdLen,    /* Password length.                                 */
  uint32_t* subKeys,      /* Key schedule pointer.                            */
  uint8_t* aad,           /* Additional authenticated data for GCM mode.      */
  const uint64_t adSz);   /* Additional authenticated data size, in bytes.    */

/* Encrypts raw data.
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * The subKeys or pwd pointers can be NULL. 
 * If you pass a pointer to pwd, the subKeys pointer will be ignored.
 * If you pass a pointer to subKeys, the pwd pointer will be ignored.
*/
AesioCode AesioEncryptData(
  AESIO_CONTEXT* ioCtx,   /* AESIO context pointer.                           */
  uint32_t* subKeys,      /* Key schedule pointer.                            */
  const char* pwd,        /* Password. Non-null terminated string.            */
  size_t pwdLen,          /* Password length.                                 */
  uint8_t* aad,           /* Additional authenticated data for GCM mode.      */
  const uint64_t aadSz);  /* Additional authenticated data size in bytes.     */

/* Encrypts raw data into a file.
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * The subKeys pointer can be NULL.
*/
AesioCode AesioEncryptDataToFile(
  const char* destPath,   /* Destination path.                                */
  const char* pData,      /* Pointer to a raw data buffer.                    */
  const size_t szData,    /* Buffer size.                                     */
  const char* pwd,        /* User password.                                   */
  const size_t pwdLen,    /* Password length.                                 */
  uint32_t* subKeys,      /* Key schedule pointer.                            */
  uint8_t* aad,           /* Additional authenticated data for GCM mode.      */
  const uint64_t aadSz,   /* Additional authenticated data size, in bytes.    */
  const int moFlags);     /* AESIO option bit flags.                          */

/* Encrypts raw data into a buffer.
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * The subKeys pointer can be NULL.
 * This function uses malloc to allocate the buffer that will contain the encrypted data.
*/
AesioCode AesioEncryptDataToBuffer(
  char** ppBuffer,        /* Pointer that receives a pointer to dynamically allocated memory. */
  size_t* pSzMem,         /* Output buffer size, in bytes.                                    */
  const char* pData,      /* Pointer to a raw data buffer.                                    */
  const size_t szData,    /* Buffer size.                                                     */
  const char* pwd,        /* User password.                                                   */
  const size_t pwdLen,    /* Password length.                                                 */
  uint32_t* subKeys,      /* Key schedule pointer.                                            */
  uint8_t* aad,           /* Additional authenticated data for GCM mode.                      */
  const uint64_t aadSz,   /* Additional authenticated data size, in bytes.                    */
  const int moFlags);     /* AESIO option bit flags.                                          */

/* Dencrypts raw data.
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * The subKeys or pwd pointers can be NULL.
 * If you pass a pointer to pwd, the subKeys pointer will be ignored.
 * If you pass a pointer to subKeys, the pwd pointer will be ignored.
*/
AesioCode AesioDecryptData(
  AESIO_CONTEXT* ioCtx,   /* AESIO context pointer.                             */
  uint32_t* subKeys,      /* Key schedule pointer.                              */
  const char* pwd,        /* Password. Non-null terminated string.              */    
  size_t pwdLen,          /* Password length.                                   */
  uint8_t* aad,           /* Additional authenticated data (only for GCM mode). */    
  const uint64_t aadSz);  /* Additional authenticated data size in bytes.       */

/* Decrypts data into a file.
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * This function uses malloc to allocate the buffer that will contain the decrypted data.
*/
AesioCode AesioDecryptDataToFile(
  const char* destPath,   /* Destination path.                                          */
  const char* pData,      /* Pointer to a buffer that will contain the encrypted data.  */
  const size_t szData,    /* Buffer size.                                               */
  const char* pwd,        /* User password.                                             */
  const size_t pwdLen,    /* Password length.                                           */
  uint32_t* subKeys,      /* Key schedule pointer.                                      */
  uint8_t* aad,           /* Additional authenticated data for GCM mode.                */
  const uint64_t aadSz);  /* Additional authenticated data size, in bytes.              */

/* Initializes AESIO context.
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * If you pass a pointer to iVec, then iVec will be copied to context.
 * If iVec is NULL, a new initialization vector will be generated.
*/
AesioCode AesioInit(
  AESIO_CONTEXT* ctx, /* AESIO context pointer.                                 */
  uint8_t* buffer,    /* Pointer to a data buffer that contains input.          */
  size_t buffSz,      /* Size of the data buffer, in bytes.                     */
  uint32_t bFlags,    /* AESIO option bit flags.                                */
  uint32_t* iVec);    /* Pointer to a 128-bit IV.                               */

/* Releases AESIO context.
 *
 * Remarks:
 * The AESIO context must be properly initialized
 * before it can be sent into this function.
*/
void ReleaseAesioContext(
  AESIO_CONTEXT* ctx,    /* AESIO context pointer.                             */
  _Bool freeAesBuff);    /* Free AES buffer memory that has been allocated.    */

/* Generates pseudo-random numbers for initialization vector (IV).
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * The IV pointer cannot be NULL.
*/
AesioCode InitRandVec(
  uint32_t* iVec );     /* Pointer to a 128-bit IV.                           */

/* Generates AES subkeys. 
 * 
 * If the function succeeds, the return value is AESIO_ERR_OK.
 * Remarks:
 * Both subKeys and pwd pointers cannot be NULL.
 * kBlockSize must be 16 (AES 128 bits), 24 (AES 192 bits) or 32 (AES 256 bits).
*/
AesioCode KeySchedule(
  uint32_t* subKeys,    /* Subkeys pointer.                                   */
  const char* pwd,      /* Password. Non-null terminated string.              */
  const size_t pwdSz,   /* Size of the password in bytes.                     */
  size_t kBlockSize);   /* The size of the key in bytes.                      */

/* Generates HMAC.
 *
 * Remarks:
 * Both ioCtx and subKeys pointers cannot be NULL.
 * The AESIO context must be properly initialized before it can be sent into this function.
*/
void GenHmac(
  AESIO_CONTEXT* ctx,   /* AESIO context pointer.                             */
  uint32_t* subKeys);   /* Subkeys pointer.                                   */

/* Generates HMAC
 *
 * Remarks:
 * Both ioCtx and subKeys pointers cannot be NULL.
 * The AESIO context ioCtx must be properly initialized before it
 * can be sent into this function.
 * All input and output operations are performed through streams.
*/
void GenHmacStream(
  FILE* pFile,          /* Pointer to an opened file containing the ciphertext. */
  AESIO_CONTEXT* ctx,   /* AESIO context pointer.                               */
  uint32_t* subKeys);   /* Subkeys pointer.                                     */
  #endif
  