#pragma once
#include <stdio.h>
#include "aes.h"

/* AES error messages. */
typedef enum AesErrorMessage
{
  AES_ERR_OK,                 /* No errors.                   */
  AES_ERR_INVALIDSIZE,        /* Invalid size.                */
  AES_ERR_INVALIDTAG,         /* Invalid tag.                 */
  AES_ERR_INVALIDPARAM,       /* Invalid param.               */
  AES_ERR_INVALIDFILEOFFSET,  /* Invalid file offset param.   */
  AES_ERR_READFAILED,         /* Read failed.                 */
  AES_ERR_WRITEFAILED         /* Write failed.                */
}AesCode;

/* Encrypts a plaintext message using cipher block chaining (CBC) with AES. 
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 */
AesCode AesCbcEncrypt(
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to encrypt data.                   */
  uint32_t* iVec,         /* Pointer to the buffer containing the initialization vector.        */
  uint32_t* subKeys);     /* Pointer to the buffer containing the subkeys.                      */      

/* Encrypts a plaintext message using cipher block chaining (CBC) with AES.
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 *
 * Remarks:
 * This function is the stream version of AesCbcEncrypt.
 */
AesCode AesCbcEncryptStream(
  FILE* destFile,         /* Pointer to an opened file to output the ciphertext.                */
  FILE* srcFile,          /* Pointer to an opened file that contain the plaintext.              */
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to encrypt data.                   */
  uint32_t* iVec,         /* Pointer to the buffer containing the initialization vector.        */
  uint32_t* subKeys);     /* Pointer to the buffer containing the subkeys.                      */

/* Decrypts a ciphertext message using Cipher Block Chaining (CBC) with AES.
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 */
AesCode AesCbcDecrypt(
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to decrypt data.                   */
  uint32_t* iVec,         /* Pointer to the buffer containing the initialization vector.        */
  uint32_t* subKeys);     /* Pointer to the buffer containing the subkeys.                      */

/* Decrypts a ciphertext message using Cipher Block Chaining (CBC) with AES.
 * 
 * If the function succeeds, the return value is AES_ERR_OK.
 *
 * Remarks:
 * This function is the stream version of AesCbcDecrypt.
 */
AesCode AesCbcDecryptStream(
  FILE* destFile,         /* Pointer to an opened file to output the plaintext.                 */
  FILE* srcFile,          /* Pointer to an opened file that contain the ciphertext.             */
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to decrypt data.                   */
  uint32_t* iVec,         /* Pointer to the buffer containing the initialization vector.        */
  uint32_t* subKeys);     /* Pointer to the buffer containing the subkeys.                      */

/* Encrypts or decrypts a message using Counter Mode (CTR) with AES.
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 */
AesCode AesCtrCrypt(
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to encrypt or decrypt data.        */
  uint32_t* iVec,         /* Pointer to the buffer containing the initialization vector.        */
  uint32_t* subKeys);     /* Pointer to the buffer containing the subkeys.                      */

/* Encrypts or decrypts a message using Counter Mode (CTR) with AES.
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 *
 * Remarks:
 * This function is the stream version of AesCtrCrypt.
 */
AesCode AesCtrCryptStream(
  FILE* destFile,         /* Pointer to an opened file to output the ciphertext/plaintext.      */
  FILE* srcFile,          /* Pointer to an opened file that contain the plaintext/ciphertext.   */
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to encrypt/decrypt data.           */
  uint32_t* iVec,         /* Pointer to the buffer containing the initialization vector.        */
  uint32_t* subKeys);     /* Pointer to the buffer containing the subkeys.                      */

/* Encrypts a plaintext message using Galois Counter Mode (GCM) with AES.
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 */
AesCode AesGcmEncrypt(
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to encrypt data.                   */
  uint32_t* tag,          /* Pointer to the buffer that will receive the authentication tag.    */
  uint32_t* iVec,         /* Pointer to the buffer containing the initialization vector.        */
  uint32_t* subKeys,      /* Pointer to the buffer containing the subkeys.                      */
  const uint8_t* ad,      /* Pointer to the buffer containing the additional data.              */
  const uint64_t adSz);   /* Additional data size, in bytes.                                    */  

/* Encrypts a plaintext message using Galois Counter Mode (GCM) with AES.
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 *
 * Remarks:
 * This function is the stream version of AesGcmEncrypt.
 */
AesCode AesGcmEncryptStream(
  FILE* destFile,         /* Pointer to an opened file to output the ciphertext.                */
  FILE* srcFile,          /* Pointer to an opened file that contain the plaintext.              */
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to encrypt data.                   */
  uint32_t* tag,          /* Pointer to the buffer that will receive the authentication tag.    */
  uint32_t* iVec,         /* Pointer to the buffer containing the initialization vector.        */
  uint32_t* subKeys,      /* Pointer to the buffer containing the subkeys.                      */
  const uint8_t* ad,      /* Pointer to the buffer containing the additional data.              */
  const uint64_t adSz);   /* Additional data size, in bytes.                                    */

/* Decrypts a ciphertext message using Galois Counter Mode (GCM) with AES.
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 */
AesCode AesGcmDecrypt(
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to decrypt data.                   */
  uint32_t* tag,          /* Pointer to the buffer containing the authentication tag.           */
  uint32_t* iVec,         /* Pointer to the buffer containing the initialization vector.        */
  uint32_t* subKeys,      /* Pointer to the buffer containing the subkeys.                      */
  const uint8_t* ad,      /* Pointer to the buffer containing the additional data.              */
  const uint64_t adSz);   /* Additional data size, in bytes.                                    */

/* Decrypts a ciphertext message using Galois Counter Mode (GCM) with AES.
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 *
 * Remarks:
 * This function is the stream version of AesGcmDecrypt.
 */
AesCode AesGcmDecryptStream(
  FILE* destFile,         /* Pointer to an opened file to output the plaintext.                 */
  FILE* srcFile,          /* Pointer to an opened file that contain the ciphertext.             */
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to decrypt data.                   */
  uint32_t* tag,          /* Pointer to the buffer containing the authentication tag.           */
  uint32_t* iVec,         /* Pointer to the buffer containing the initialization vector.        */
  uint32_t* subKeys,      /* Pointer to the buffer containing the subkeys.                      */
  const uint8_t* ad,      /* Pointer to the buffer containing the additional data.              */
  const uint64_t adSz);   /* Additional data size, in bytes.                                    */

/* Encrypts a plaintext message using Electronic Codebook mode (ECB) with AES.
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 *
 * Remarks:
 * This function will fail if the plaintext size is less than 16 bytes long.
 */
AesCode AesEcbEncrypt(
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to encrypt data.                   */
  uint32_t* subKeys);     /* Pointer to the buffer containing the subkeys.                      */

/* Encrypts a plaintext message using Electronic Codebook mode (ECB) with AES.
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 *
 * Remarks:
 * This function is the stream version of AesEcbEncrypt.
 * This function will fail if the plaintext size is less than 16 bytes long.
 */
AesCode AesEcbEncryptStream(
  FILE* destFile,         /* Pointer to an opened file to output the ciphertext.                */
  FILE* srcFile,          /* Pointer to an opened file that contain the plaintext.              */
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to encrypt data.                   */
  uint32_t* subKeys);     /* Pointer to the buffer containing the subkeys.                      */

/* Decrypts a ciphertext message using Electronic Codebook mode (ECB) with AES.
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 */
AesCode AesEcbDecrypt(
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to decrypt data.                   */
  uint32_t* subKeys);     /* Pointer to the buffer containing the subkeys.                      */

/* Decrypts a ciphertext message using Electronic Codebook mode (ECB) with AES.
 *
 * If the function succeeds, the return value is AES_ERR_OK.
 *
 * Remarks:
 * This function is the stream version of AesEcbDecrypt.
 */
AesCode AesEcbDecryptStream(
  FILE* destFile,         /* Pointer to an opened file to output the plaintext.                 */
  FILE* srcFile,          /* Pointer to an opened file that contain the ciphertext.             */
  AES_CONTEXT* ctx,       /* Pointer to the AES context used to decrypt data.                   */
  uint32_t* subKeys);     /* Pointer to the buffer containing the subkeys.                      */

/* Release AES context
 *
 * Remarks:
 * This function only can be used when the source buffer of the AES context is dynamically allocated.
*/
void ReleaseAesContext(
  AES_CONTEXT* ctx);      /* Pointer to the AES context.                                        */