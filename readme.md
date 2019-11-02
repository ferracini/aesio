# AESIO API

AESIO API is an implementation written in C of the Advanced Encryption Standard (AES) for encryption and decryption of files and raw data.

## Operation modes
+ Eletronic Codebook (ECB)\
```AESIO_MO_ECB```

+ Cipher Block Chaining (CBC)\
```AESIO_MO_CBC```

+ Counter (CTR)\
```AESIO_MO_CTR```

+ Galois/Counter Mode (GCM)\
```AESIO_MO_GCM```

## Key sizes supported
+ 128 bits\
```AESIO_KL_128```

+ 192 bits\
```AESIO_KL_192```

+ 256 bits\
```AESIO_KL_256```

## Message Authentication Code (MAC)
+ HMAC-SHA1\
```AESIO_HM_SHA1```

+ HMAC-SHA256\
```AESIO_HM_SHA256```

+ GMAC\
None.\
GMAC will be automatically generated if the ```AESIO_MO_GCM``` flag is set.

## Ciphertext Stealing (CTS)
No padding is applied  to the message blocks in ECB and CBC modes, instead CTS method is used by default.

## Usage

### AESIO basic interface
```C
/* Encrypts a file. 
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * This function uses malloc to allocate the buffer that will contain the encrypted data. 
 * AesioEncryptFileStream is an equivalent implementation that does not use malloc.
 */
AesioCode AesioEncryptFile(
	const char* destPath,	/* Destination path.					*/
	const char* srcPath,	/* Source path.						*/
	const char* pwd,	/* User password.					*/	
	const size_t pwdLen,	/* Password length.					*/
	uint32_t* subKeys,	/* Key schedule pointer.				*/
	uint8_t* ad,		/* Additional data for GCM mode.			*/
	const uint64_t adSz,	/* Additional data size, in bytes.			*/
	const int moFlags);	/* AESIO option bit flags.				*/	

/* Encrypts a file. 
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * This function does not use malloc (dynamic memory allocation). 
 * All input and output operations are performed through streams.
*/
AesioCode AesioEncryptFileStream(
	const char* destPath,	/* Destination path.					*/
	const char* srcPath,	/* Source path.						*/
	const char* pwd,	/* User password.					*/	
	const size_t pwdLen,	/* Password length.					*/
	uint32_t* subKeys,	/* Key schedule pointer.				*/
	uint8_t* ad,		/* Additional data for GCM mode.			*/
	const uint64_t adSz,	/* Additional data size, in bytes.			*/
	const int moFlags);	/* AESIO option bit flags.				*/	

/* Decrypts a file.
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * This function uses malloc to allocate the buffer that will contain the decrypted data.
 * AesioDecryptFileStream is an equivalent implementation that does not use malloc.
*/
AesioCode AesioDecryptFile(
	const char* destPath,	/* Destination path.					*/
	const char* srcPath,	/* Source path.						*/
	const char* pwd,	/* User password.					*/
	const size_t pwdLen,	/* Password length.					*/
	uint32_t* subKeys,	/* Key schedule pointer.				*/
	uint8_t* ad,		/* Additional data for GCM mode.			*/
	const uint64_t adSz);	/* Additional data size, in bytes.			*/

/* Decrypts a file.
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * This function does not use malloc (dynamic memory allocation).
 * All input and output operations are performed through streams.
*/
AesioCode AesioDecryptFileStream(
	const char* destPath,	/* Destination path.					*/
	const char* srcPath,	/* Source path.						*/
	const char* pwd,	/* User password.					*/
	const size_t pwdLen,	/* Password length.					*/
	uint32_t* subKeys,	/* Key schedule pointer.				*/
	uint8_t* ad,		/* Additional data for GCM mode.			*/
	const uint64_t adSz);	/* Additional data size, in bytes.			*/

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
	AESIO_CONTEXT* ioCtx,	/* AESIO context pointer.				*/
	uint32_t* subKeys,	/* Key schedule pointer. 				*/
	const char* pwd,	/* Password. Non-null terminated string.		*/
	size_t pwdLen,		/* Password length.					*/
	uint8_t* ad,		/* Additional data for GCM mode.			*/
	const uint64_t adSz);	/* Additional data size in bytes.			*/

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
	AESIO_CONTEXT* ioCtx,	/* AESIO context pointer.				*/
	uint32_t* subKeys,	/* Key schedule pointer. 				*/
	const char* pwd,	/* Password. Non-null terminated string.		*/		
	size_t pwdLen,		/* Password length.					*/
	uint8_t* ad,		/* Additional data (only for GCM mode).			*/		
	const uint64_t adSz);	/* Additional data size in bytes.			*/

/* Initializes AESIO context.
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * If you pass a pointer to iVec, then iVec will be copied to context.
 * If iVec is NULL, a new initialization vector will be generated.
*/
AesioCode AesioInit(
	AESIO_CONTEXT* ctx, 	/* AESIO context pointer.				*/
	uint8_t* buffer,	/* Pointer to a data buffer that contains input.	*/
	size_t buffSz,		/* Size of the data buffer, in bytes.			*/
	uint32_t bFlags,	/* AESIO option bit flags.				*/
	uint32_t* iVec);	/* Pointer to a 128 bit IV.				*/

/* Releases AESIO context.
 *
 * Remarks:
 * The AESIO context must be properly initialized
 * before it can be sent into this function.
*/
void ReleaseAesioContext(
	AESIO_CONTEXT* ctx, 	/* AESIO context pointer.				*/
	_Bool freeAesBuff); 	/* Free AES buffer memory that has been allocated.	*/

/* Generates pseudo-random numbers for initialization vector (IV).
 *
 * If the function succeeds, the return value is AESIO_ERR_OK.
 *
 * Remarks:
 * The IV pointer cannot be NULL.
*/
AesioCode InitRandVec(
	uint32_t* iVec );	/* Pointer to a 128 bit IV.				*/

/* Generates AES subkeys. 
 * 
 * If the function succeeds, the return value is AESIO_ERR_OK.
 * Remarks:
 * Both subKeys and pwd pointers cannot be NULL.
 * kBlockSize must be 16 (AES 128 bits), 24 (AES 192 bits) or 32 (AES 256 bits).
*/
AesioCode KeySchedule(
	uint32_t* subKeys,	/* Subkeys pointer.					*/
	const char* pwd,	/* Password. Non-null terminated string.		*/		
	const size_t pwdSz,	/* Size of the password in bytes.			*/	
	size_t kBlockSize);	/* The size of the key in bytes.			*/
```
### Compile

```sh
make
```

## Dependencies

+ The code is written in standard C;
+ No dependencies of other libraries;
+ Only the GCM implementation uses SSE instructions.


## Example
The code below show how to encrypt a string.
```C
char str[] = "This is my cool string to be encrypted and decrypted.";
char pwd[] = "thisismypassword";

AesioCode res;
uint32_t subKeys[AES_128_SUBKEYS_COUNT];
AESIO_CONTEXT ioCtx = { 0 };

/* Initializes the context */
res = AesioInit(&ioCtx, (uint8_t*)str, sizeof(str) - 1, AESIO_MO_CTR | AESIO_HM_SHA1 | AESIO_KL_128, NULL);
if (res != AESIO_ERR_OK)
{
	goto cleanup;
}

/* Key expansion */
re = KeySchedule(subKeys, pwd, strlen(pwd), AESIO_128_KSZ);
if (res != AESIO_ERR_OK)
{
	goto cleanup;
}

/* Encrypts the string */
res = AesioEncryptData(&ioCtx, subKeys, pwd, strlen(pwd), NULL, 0);
if (res != AESIO_ERR_OK)
{
	goto cleanup;
}

/*
 * Do something cool here
 */

/* Decrypts the string when you are done */
res = AesioDecryptData(&ioCtx, subKeys, pwd, strlen(pwd), NULL, 0);
if (res != AESIO_ERR_OK)
{
	goto cleanup;
}

cleanup:
/* Release context */
ReleaseAesioContext(&ioCtx, FALSE);
/* Wipe local variables for security reasons */
memset(subKeys, 0, AESIO_128_KSZ);

```
See the `/src/tests.c` file for more examples.


## Authors

* **Diego Ferracini Bando** - [ferracini](https://github.com/ferracini)

## License

> Copyright (c) 2019 Diego Ferracini Bando
> 
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
> 
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
> 
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.