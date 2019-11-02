#include "aesio.h"

#include <string.h>									/* Included for memset() and strlen().			*/
#define SRCFILENAME		"test.txt"					/* File name of the file to be encrypted.		*/
#define ENCFILENAME		"test_enc.txt"				/* File name of encrypted file.					*/
#define DECFILENAME		"test_dec.txt"				/* File name of decrypted file.					*/
#define SRCPATH			"../assets/" SRCFILENAME	/* Path of the source file.						*/
#define ENCPATH			"../assets/" ENCFILENAME	/* Path of the encoded file.					*/
#define DECPATH			"../assets/" DECFILENAME	/* Path of the decoded file.					*/
#define PASSWORD		"thisismypassword"			/* User password.								*/

void CryptFileTest()
{
	AesioCode re;

	printf("* Encryption\n* Input file: %s\n", SRCPATH);
	re = AesioEncryptFile(
		ENCPATH,
		SRCPATH,
		PASSWORD,
		strlen(PASSWORD),
		NULL,
		NULL,
		0,
		AESIO_MO_CBC | AESIO_HM_SHA1 | AESIO_KL_128);	

	if (re != AESIO_ERR_OK)
	{
		printf("* Encryption failure. Error: %d\n", re);
		return;
	}		

	printf("* Encryption succeeded!\n* Output file: %s\n\n", ENCPATH);
	
	printf("* Decryption\n* Input file: %s\n", ENCPATH);
	re = AesioDecryptFile(
		DECPATH,
		ENCPATH,
		PASSWORD,
		strlen(PASSWORD),
		NULL,
		NULL,
		0);

	if (re != AESIO_ERR_OK)
	{
		printf("* Decryption failure. Error: %d\n", re);
		return;
	}

	printf("* Decryption succeeded!\n* Output file: %s\n\n", DECPATH);
}

void StringExample()
{
	char str[] = "This is my cool string to be encrypted and decrypted.";
	uint8_t aad[] = "Some additional authenticated data used by GCM.";

	AesioCode res;
	uint32_t subKeys[AES_128_SUBKEYS_COUNT];
	AESIO_CONTEXT ioCtx = { 0 };

	/* Initializes the context */
	res = AesioInit(&ioCtx, (uint8_t*)str, sizeof(str) - 1, AESIO_MO_GCM | AESIO_KL_128, NULL);
	if (res != AESIO_ERR_OK)
	{
		goto cleanup;
	}

	/* Key expansion */
	res = KeySchedule(subKeys, PASSWORD, strlen(PASSWORD), AESIO_128_KSZ);
	if (res != AESIO_ERR_OK)
	{
		goto cleanup;
	}

	/* Encrypts the string */
	res = AesioEncryptData(&ioCtx, subKeys, PASSWORD, strlen(PASSWORD), aad, sizeof(aad) -1);
	if (res != AESIO_ERR_OK)
	{
		goto cleanup;
	}

	/*
	 * Do something cool here
	*/

	/* Decrypts the string when you are done */
	res = AesioDecryptData(&ioCtx, subKeys, PASSWORD, strlen(PASSWORD), aad, sizeof(aad) - 1);
	if (res != AESIO_ERR_OK)
	{
		goto cleanup;
	}

cleanup:
	/* Release context */
	ReleaseAesioContext(&ioCtx, FALSE);
	/* Wipe local variables for security reasons */
	memset(subKeys, 0, AESIO_128_KSZ);
}

int main()
{
	CryptFileTest();
	//StringExample();
}
