#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#if defined(_MSC_VER)
#include <conio.h>
#define FILENO(file)                (_fileno(file))
#else
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#define FILENO(file)                (fileno(file))
#endif

#include "aesio.h"
#include "minbase64.h"
#include "helper.h"

/* ---------------------------------------------------------------------------------------------------------------------------------- */
/* Constants.                                                                                                                         */

#define CLI_STR_VER                 "1.00"
#define CLI_STR_AUTHOR              "Diego Ferracini Bando"
#define CLI_STR_MIT                 "Free and open source software under the terms of the MIT license."

#define CLI_DEFAULT_FLAG_KEYLENGTH  (AESIO_KL_256)
#define CLI_DEFAULT_FLAG_HMAC       (AESIO_HM_SHA2)
#define CLI_DEFAULT_FLAG_OPMODE     (AESIO_MO_CTR)
#define CLI_DEFAULT_AESIO_FLAGS     (CLI_DEFAULT_FLAG_KEYLENGTH | CLI_DEFAULT_FLAG_HMAC | CLI_DEFAULT_FLAG_OPMODE)

#define CLI_PASSWORD_MAX_LENGTH     (512)
#define CLI_PASSWORD_EXTRA_CHARS    (2)
#define CLI_PASSWORD_BUFFER_SIZE    (CLI_PASSWORD_MAX_LENGTH + CLI_PASSWORD_EXTRA_CHARS)

#define CLI_PROMPT_PASSWORD         "Password: "
#define CLI_PROMPT_CONFIRM_PASSWORD "Confirm password: "

/* ---------------------------------------------------------------------------------------------------------------------------------- */
/* Enums.                                                                                                                             */

typedef enum OPT_ACTION_TYPE
{
  OPT_ACTION_NONE,
  OPT_ACTION_ENCRYPT,
  OPT_ACTION_DECRYPT
}OPT_ACTION_TYPE;

/* ---------------------------------------------------------------------------------------------------------------------------------- */
/* Data structures.                                                                                                                   */

typedef struct CLI_INPUT
{
  OPT_ACTION_TYPE m_actionType;  
  const char* m_pString;
  const char* m_pSourcePath;
  const char* m_pDestinationPath;
  const char* m_pAAD;
  _Bool m_base64;
  uint32_t m_bAesioFlags;
  _Bool m_deleteInput;
  const char* m_pPasswordFilePath;
  _Bool m_showVer;
}CLI_INPUT;

typedef struct CLI_OPTION
{
  const char* const m_pShort;
  const char* const m_pExtended;
  const char* const m_pValueType;
  const char* const m_pDescription;
  _Bool (*m_pCallBack)(CLI_INPUT* pInput, const char* const pAttribute);
}CLI_OPTION;

typedef struct CLI_DATA
{
  const CLI_OPTION* m_pCommandLineOptions;
  size_t m_szOptionCount;
  CLI_INPUT m_input;
}CLI_DATA;

/* ---------------------------------------------------------------------------------------------------------------------------------- */
/* Function prototypes.                                                                                                               */

_Bool InitCommandLine(
  CLI_DATA* pData,
  const CLI_OPTION* pCommandLineOptions,
  const size_t optionCount);
void PrintCommandLineOptions(
  const CLI_OPTION* const pCommandLineOptions,
  const size_t optionCount);
int ParseCommandLineArgs(
  CLI_DATA* pCmdLineData,
  int argc,
  const char* argv[]);
uint32_t SetDefaultAesioFlags(CLI_INPUT* pInput);
_Bool ReadPasswordFromFile(
  char* pPassword,
  const char* pPasswordFilePath);
_Bool PromptUserPassword(
  char* pPassword,
  size_t szPassword,
  const char* pPrompt);
_Bool GetPassword(
  char* pPassword,
  size_t szPassword,
  const char* pPasswordFilePath,
  const _Bool bConfirmPassword);
_Bool IsPasswordValid(const char* pPassword);
_Bool IsEncryptActionValid(const CLI_INPUT* pInput);
_Bool IsDecryptActionValid(const CLI_INPUT* pInput);
_Bool IsVersionRequested(const CLI_INPUT* pInput);
_Bool IsCommandLineInputValid(const CLI_INPUT* pInput);
int EncryptFileToFile(
  const CLI_INPUT* pInput,
  const char* pPassword);
int EncryptFileToString(
  const CLI_INPUT* pInput,
  const char* pPassword);
int EncryptStringToFile(
  const CLI_INPUT* pInput,
  const char* pPassword);
int EncryptStringToString(
  const CLI_INPUT* pInput,
  const char* pPassword);
int EncryptAction(CLI_INPUT* pInput);
int DecryptFileToFile(
  const CLI_INPUT* pInput,
  const char* pPassword);
int DecryptStringToFile(
  const CLI_INPUT* pInput,
  const char* pPassword);
int DecryptAction(CLI_INPUT* pInput);
_Bool IsBase64(
  const char* pBuffer,
  const size_t szBuffer);
_Bool DeleteInputFile(const char* pSrcPath);
int HandleAesioError(AesioCode res);

/* ---------------------------------------------------------------------------------------------------------------------------------- */
/* Callback function prototypes.                                                                                                      */

_Bool SetEcrypt(
  CLI_INPUT* pInput,
  const char* const pAttribute);
_Bool SetDecrypt(
  CLI_INPUT* pInput,
  const char* const pAttribute);
_Bool SetString(
  CLI_INPUT* pInput, 
  const char* const pAttribute);
_Bool SetSourcePath(
  CLI_INPUT* pInput,
  const char* const pAttribute);
_Bool SetDestinationPath(
  CLI_INPUT* pInput,
  const char* const pAttribute);
_Bool SetAAData(
  CLI_INPUT* pInput,
  const char* const pAttribute);
_Bool SetBase64(
  CLI_INPUT* pInput,
  const char* const pAttribute);
_Bool SetKeyLength(
  CLI_INPUT* pInput,
  const char* const pAttribute);
_Bool SetHMACSHA(
  CLI_INPUT* pInput,
  const char* const pAttribute);
_Bool SetOperationMode(
  CLI_INPUT* pInput,
  const char* const pAttribute);
_Bool SetDeleteInput(
  CLI_INPUT* pInput,
  const char* const pAttribute);
_Bool SetPassword(
  CLI_INPUT* pInput,
  const char* const pAttribute);
_Bool ShowVersion(
  CLI_INPUT* pInput,
  const char* const pAttribute);

/* ---------------------------------------------------------------------------------------------------------------------------------- */
/* Global variables.                                                                                                                  */

static const CLI_OPTION g_commandLineOptions[] =
{
  { "-e", "--encrypt",           NULL,       "Indicates that the input data will be encrypted.",     SetEcrypt },
  { "-d", "--decrypt",           NULL,       "Indicates that the input data will be decrypted.",     SetDecrypt },
  { "-k", "--string",            "<STRING>", "Encrypt or decrypt a string.",                         SetString },
  { "-i", "--source-path",       "<PATH>",   "Source file path.",                                    SetSourcePath },
  { "-o", "--destination-path",  "<PATH>",   "Destination file path.",                               SetDestinationPath },
  { "-a", "--aad",               "<DATA>",   "Additional authenticated data (only for GCM).",        SetAAData },
  { "-b", "--base64",            NULL,       "Encode or decode in Base64 format.",                   SetBase64 },
  { "-l", "--key-length",        "<LENGTH>", "Key length: 128, 192 or 256. (Default: 256)",          SetKeyLength },
  { "-h", "--hmac-sha",          "<SHAX>",   "HMAC hash function: SHA1 or SHA2. (Default: SHA2)",    SetHMACSHA },
  { "-m", "--operation-mode",    "<OPMODE>", "Operation mode: ECB, CBC, CTR or GCM. (Default: CTR)", SetOperationMode },
  { "-r", "--delete-input-file", NULL,       "Delete input file after encrypting or decrypting.",    SetDeleteInput },
  { "-p", "--password-path",     "<PATH>",   "Password file path.",                                  SetPassword },
  { "-v", "--version",           NULL,       "AESIO version.",                                       ShowVersion }
};

/* ---------------------------------------------------------------------------------------------------------------------------------- */
/* Implementation.                                                                                                                    */

_Bool InitCommandLine(
  CLI_DATA* pData,
  const CLI_OPTION* pCommandLineOptions,
  const size_t optionCount)
{
  if(pData == NULL ||
     pCommandLineOptions == NULL ||
     optionCount == 0)
  {
    return 1;
  }

  memset(pData, 0, sizeof(CLI_DATA));

  pData->m_pCommandLineOptions = pCommandLineOptions;
  pData->m_szOptionCount = optionCount;

  return 0;
}

_Bool SetEcrypt(CLI_INPUT* pInput, const char* const pAttribute)
{
  if(pInput->m_actionType != OPT_ACTION_NONE)
  {
    printf("You must specify either the encryption or decryption option.\n");
    return FALSE;
  }
  else if(pInput->m_pString != NULL)
  {
    printf("You must specify either a string or a file path as input.\n");
    return FALSE;
  }

  pInput->m_actionType = OPT_ACTION_ENCRYPT;
  return TRUE;
}

_Bool SetDecrypt(CLI_INPUT* pInput, const char* const pAttribute)
{
  if(pInput->m_actionType != OPT_ACTION_NONE)
  {
    printf("You must specify either the encryption or decryption option.\n");
    return FALSE;
  }

  pInput->m_actionType = OPT_ACTION_DECRYPT;
  return TRUE;
}

_Bool SetString(CLI_INPUT* pInput, const char* const pAttribute)
{
  if(pAttribute == NULL)
  {
    printf("Invalid syntax.\nA string must be specified.\n");
    return FALSE;
  }
  else if(pInput->m_pSourcePath != NULL)
  {
    printf("You must specify either a string or a file path as input.\n");
    return FALSE;
  }

  pInput->m_pString = pAttribute;
  return TRUE;
}

_Bool SetSourcePath(CLI_INPUT* pInput, const char* const pAttribute)
{
  if(pAttribute == NULL)
  {
    printf("Invalid syntax.\nThe source path must be specified.\n");
    return FALSE;
  }

  pInput->m_pSourcePath = pAttribute;
  return TRUE;
}

_Bool SetDestinationPath(CLI_INPUT* pInput, const char* const pAttribute)
{
  if(pAttribute == NULL)
  {
    printf("Invalid syntax.\nThe destination path must be specified.\n");
    return FALSE;
  }

  pInput->m_pDestinationPath = pAttribute;
  return TRUE;
}

_Bool SetAAData(CLI_INPUT* pInput, const char* const pAttribute)
{
  if(pAttribute == NULL)
  {
    printf("Invalid syntax.\nThe Additional Authenticated Data must be specified.\n");
    return FALSE;
  }
  else if(pInput->m_pAAD != NULL)
  {
    printf("Invalid syntax.\nOnly one Additional Authenticated Data is allowed.\n");
    return FALSE;
  }

  pInput->m_pAAD = pAttribute;
  return TRUE;
}

_Bool SetBase64(CLI_INPUT* pInput, const char* const pAttribute)
{
  pInput->m_base64 = TRUE;
  return TRUE;
}

_Bool SetKeyLength(CLI_INPUT* pInput, const char* const pAttribute)
{
  int keyLength;

  if(pAttribute == NULL)
  {
    printf("Invalid syntax.\nA key length must be specified.\n");
    return FALSE;
  }
  else if((pInput->m_bAesioFlags & AESIO_BMASK_KL) != 0)
  {
    printf("Invalid syntax.\nOnly one key length may be specified.\n");
    return FALSE;
  }
  
  keyLength = atoi(pAttribute);

  switch (keyLength)
  {
    case 128:
    {
      pInput->m_bAesioFlags |= AESIO_KL_128;
      break;
    }
    case 192:
    {
      pInput->m_bAesioFlags |= AESIO_KL_192;
      break;
    }
    case 256:
    {
      pInput->m_bAesioFlags |= AESIO_KL_256;
      break;
    }  
    default:
    {
      return FALSE;
    }
  }

  return TRUE;
}

_Bool SetHMACSHA(CLI_INPUT* pInput, const char* const pAttribute)
{
  if(pAttribute == NULL)
  {
    printf("Invalid syntax.\nThe HMAC hash function must be specified.\n");
    return FALSE;
  }
  else if((pInput->m_bAesioFlags & AESIO_BMASK_HM) != 0)
  {
    printf("Invalid syntax.\nOnly one HMAC hash function is allowed.\n");
    return FALSE;
  }

  if(_stricmp("SHA1", pAttribute) == 0)
  {
    pInput->m_bAesioFlags |= AESIO_HM_SHA1;
  }
  else if(_stricmp("SHA2", pAttribute) == 0)
  {
    pInput->m_bAesioFlags |= AESIO_HM_SHA2;
  }
  else
  {
    printf("Invalid HMAC hash function: %s\n", pAttribute);
    return FALSE;
  }

  return TRUE;
}

_Bool SetOperationMode(CLI_INPUT* pInput, const char* const pAttribute)
{
  if(pAttribute == NULL)
  {
    printf("Invalid syntax.\nAn AES operation mode must be specified.\n");
    return FALSE;
  }

  if((pInput->m_bAesioFlags & AESIO_BMASK_MO) != 0)
  {
    printf("Invalid syntax.\nOnly one operation mode is allowed.\n");
    return FALSE;
  }

  if(_stricmp("ECB", pAttribute) == 0)
  {
    pInput->m_bAesioFlags |= AESIO_MO_ECB;
  }
  else if(_stricmp("CBC", pAttribute) == 0)
  {
    pInput->m_bAesioFlags |= AESIO_MO_CBC;
  }
  else if(_stricmp("CTR", pAttribute) == 0)
  {
    pInput->m_bAesioFlags |= AESIO_MO_CTR;
  }
  else if(_stricmp("GCM", pAttribute) == 0)
  {
    pInput->m_bAesioFlags |= AESIO_MO_GCM;
  }
  else
  {
    printf("Invalid operation mode: %s\n", pAttribute);
    return FALSE;
  }

  return TRUE;
}

_Bool SetDeleteInput(CLI_INPUT* pInput, const char* const pAttribute)
{
  pInput->m_deleteInput = TRUE;
  return TRUE;
}

_Bool SetPassword(CLI_INPUT* pInput, const char* const pAttribute)
{
  if(pAttribute == NULL)
  {
    printf("Invalid syntax.\nThe password file path must be specified.\n");
    return FALSE;
  }

  pInput->m_pPasswordFilePath = pAttribute;
  return TRUE;
}

_Bool ShowVersion(CLI_INPUT* pInput, const char* const pAttribute)
{
  pInput->m_showVer = TRUE;
  return TRUE;
}

void PrintCommandLineOptions(
  const CLI_OPTION* const pCommandLineOptions,
  const size_t optionCount)
{
  size_t i;
  int szMaxExtendedParamLength;
  int szMaxTypeValLength;

  szMaxExtendedParamLength = 0;
  szMaxTypeValLength = 0;
  for(i = 0; i < optionCount; i++)
  {
    szMaxExtendedParamLength = max(szMaxExtendedParamLength, (int)(strlen(pCommandLineOptions[i].m_pExtended)));

    if(pCommandLineOptions[i].m_pValueType != NULL)
    {
      szMaxTypeValLength = max(szMaxTypeValLength, (int)(strlen(pCommandLineOptions[i].m_pValueType)));
    }    
  }

  printf("Options:\n");
  for(i = 0; i < optionCount; i++)
  {
    printf("  %s, %-*s%-*s%s",
           pCommandLineOptions[i].m_pShort,
           szMaxExtendedParamLength + 2,
           pCommandLineOptions[i].m_pExtended,
           szMaxTypeValLength + 4,
           pCommandLineOptions[i].m_pValueType == NULL ? "" : pCommandLineOptions[i].m_pValueType,
           pCommandLineOptions[i].m_pDescription);

    printf("\n");
  }
}

int ParseCommandLineArgs(
  CLI_DATA* pCmdLineData,
  int argc,
  const char* argv[])
{
  int i;
  size_t j;
  
  _Bool res = 0;

  if(argc == 1)
  {
    PrintCommandLineOptions(
      pCmdLineData->m_pCommandLineOptions,
      pCmdLineData->m_szOptionCount);    
    return 1;
  }

  for(i = 1; i < argc; i++)
  {
    for(j = 0, res = FALSE; j < pCmdLineData->m_szOptionCount; j++)
    {
      if(strcmp(pCmdLineData->m_pCommandLineOptions[j].m_pShort, argv[i]) == 0 ||
         strcmp(pCmdLineData->m_pCommandLineOptions[j].m_pExtended, argv[i]) == 0)
      { 
        res = pCmdLineData->m_pCommandLineOptions[j].m_pCallBack(
          &pCmdLineData->m_input,
          (pCmdLineData->m_pCommandLineOptions[j].m_pValueType == NULL) ? argv[i] : (++i == argc) ? NULL : argv[i]);

        if(!res)
        {
          return 1;
        }
      }
    }

    if(!res)
    {
      printf("Invalid option: %s\n", argv[i]);
      return 1;
    }
  }

  return 0;
}

uint32_t SetDefaultAesioFlags(CLI_INPUT* pInput)
{
  if(pInput->m_bAesioFlags == 0)
  {
    pInput->m_bAesioFlags = CLI_DEFAULT_AESIO_FLAGS;
  }
  else
  {
    if((pInput->m_bAesioFlags & AESIO_BMASK_HM) == 0)
    {
      pInput->m_bAesioFlags |= CLI_DEFAULT_FLAG_HMAC;
    }

    if((pInput->m_bAesioFlags & AESIO_BMASK_KL) == 0)
    {
      pInput->m_bAesioFlags |= CLI_DEFAULT_FLAG_KEYLENGTH;
    }

    if((pInput->m_bAesioFlags & AESIO_BMASK_MO) == 0)
    {
      pInput->m_bAesioFlags |= CLI_DEFAULT_FLAG_OPMODE;
    }
  }

  return pInput->m_bAesioFlags;
}

_Bool ReadPasswordFromFile(
  char* pPassword,
  const char* pPasswordFilePath)
{
  FILE *pFile;
  struct stat stat;

  if(pPasswordFilePath == NULL)
  {
    return FALSE;
  }

#ifdef _MSC_VER
  fopen_s(&pFile, pPasswordFilePath, "r");
#else
  pFile = fopen(pPasswordFilePath, "r");
#endif

  if(pFile == NULL)
  {
    printf("Unable to open: %s\n", pPasswordFilePath);
    return FALSE;
  }

  if(fstat(FILENO(pFile), &stat))
  {
    fclose(pFile);
    printf("File read failed: %s\n", pPasswordFilePath);
    return FALSE;
  }

  if(stat.st_size == 0)
  {
    fclose(pFile);
    printf("The password file is empty: %s\n", pPasswordFilePath);
  }

  if(stat.st_size > CLI_PASSWORD_MAX_LENGTH)
  {
    fclose(pFile);
    printf("The password exceeds the maximum allowed length of %d characters.\n", CLI_PASSWORD_MAX_LENGTH);
  }

  if(fread(pPassword, sizeof(char), stat.st_size, pFile) != stat.st_size)
  {
    fclose(pFile);
    printf("File read failed: %s\n", pPasswordFilePath);
    return FALSE;
  }

  fclose(pFile);
  return TRUE;
}

_Bool PromptUserPassword(
  char* pPassword,
  size_t szPassword,
  const char* pPrompt)
#if defined _MSC_VER
{
  size_t i;
  int c;

  if(pPassword == NULL || szPassword == 0)
  {
    return FALSE;
  }

  memset(pPassword, '\0', szPassword);
  i = 0;

  printf("%s", pPrompt);
  while (1)
  {
    c = _getch();
    switch (c)
    {
    case '\r':
    case '\n':
    case EOF:
    {
      _putch('\n');
      break;
    }
    default:
    {
      if(c != 0x08)
      {
        if(i < (szPassword - CLI_PASSWORD_EXTRA_CHARS))
        {
          _putch('*');
          pPassword[i] = c;
          i++;
        }
        continue;
      }
      else
      {
        if(i > 0)
        {
          _putch(0x08);
          _putch(' ');
          _putch(0x08);
          i--;
          pPassword[i] = '\0';
        }
        continue;
      }
    }
    }
    break;
  }

  return (i > 0);
}
#else
{
  struct termios oflags, nflags;
  size_t passwordLength;
  _Bool res;

  if(pPassword == NULL || szPassword == 0)
  {
    return FALSE;
  }

  memset(pPassword, '\0', szPassword);
  tcgetattr(fileno(stdin), &oflags);
  nflags = oflags;
  nflags.c_lflag &= ~ECHO;
  nflags.c_lflag |= ECHONL;

  if(tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0)
  {
    memset(pPassword, '\0', szPassword);
    perror("tcsetattr");
    return FALSE;
  }

  printf("%s", pPrompt);
  res = (fgets(pPassword, szPassword, stdin) != NULL);
  passwordLength = strlen(pPassword);

  if(res)
  {
    if(pPassword[passwordLength - 1] != '\n')
    {
      memset(pPassword, '\0', szPassword);
      passwordLength = 0;
      printf("The password exceeds the maximum allowed length of %zu characters.\n", szPassword - CLI_PASSWORD_EXTRA_CHARS);
      res = FALSE;
    }

    if(passwordLength > 0 && passwordLength < szPassword - CLI_PASSWORD_EXTRA_CHARS)
    {
      pPassword[passwordLength - 1] = '\0';
      passwordLength--;
    }
  }

  if(tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0)
  {
    memset(pPassword, '\0', szPassword);
    perror("tcsetattr");
    res = FALSE;
  }
  
  return (res);
}
#endif

_Bool GetPassword(
  char* pPassword,
  size_t szPassword,
  const char* pPasswordFilePath,
  const _Bool bConfirmPassword)
{
  char retypedPassword[CLI_PASSWORD_BUFFER_SIZE];

  if(pPasswordFilePath != NULL)
  {
    return ReadPasswordFromFile(pPassword, pPasswordFilePath);
  }

  if(!PromptUserPassword(pPassword, szPassword, CLI_PROMPT_PASSWORD))
  {
    return FALSE;
  }

  if(bConfirmPassword)
  {
    if(!PromptUserPassword(retypedPassword, sizeof(retypedPassword), CLI_PROMPT_CONFIRM_PASSWORD))
    {
      memset(retypedPassword, '\0', sizeof(retypedPassword));
      return FALSE;
    }

    if(strcmp(pPassword, retypedPassword) != 0)
    {
      memset(pPassword, '\0', szPassword);
      memset(retypedPassword, '\0', sizeof(retypedPassword));
      printf("Passwords do not match.\n");
      return FALSE;
    }

    memset(retypedPassword, '\0', sizeof(retypedPassword));
  }

  return TRUE;
}

_Bool IsPasswordValid(const char* pPassword)
{
  if(strlen(pPassword) == 0)
  {
    printf("No password entered. Please provide a valid password.\n");
    return FALSE;
  }

  return TRUE;
}

_Bool IsEncryptActionValid(const CLI_INPUT* pInput)
{
  if(pInput->m_pSourcePath == NULL && pInput->m_pString == NULL)
  {
    printf("You must specify either a string or a file path as input.\n");
    return FALSE;
  }
  
  if(pInput->m_pDestinationPath == NULL && !pInput->m_base64)
  {
    printf("You must specify Base64 and/or destination file path option as output.\n");
    return FALSE;

  }
  if(pInput->m_pString != NULL && pInput->m_deleteInput)
  {
    printf("Warning: The delete input file option is ignored when encrypting a string.\n");
  }

  return TRUE;
}

_Bool IsDecryptActionValid(const CLI_INPUT* pInput)
{
  if(pInput->m_pDestinationPath == NULL)
  {
    printf("You must specify the destination file path option.\n");
    return FALSE;
  }

  if(pInput->m_pString != NULL && !pInput->m_base64)
  {
    printf("You must specify the Base64 option and ensure the string is in Base64 format to decrypt.\n");
    return FALSE;
  }

  if(pInput->m_pString != NULL && pInput->m_deleteInput)
  {
    printf("Warning: The delete input file option is ignored when decrypting a string.\n");
  }

  if((pInput->m_bAesioFlags & AESIO_BMASK_MO) != 0)
  {
    printf("Warning: The operation mode option is ignored during decryption.\n");
  }

  if((pInput->m_bAesioFlags & AESIO_BMASK_KL) != 0)
  {
    printf("Warning: The key length option is ignored during decryption.\n");
  }

  if((pInput->m_bAesioFlags & AESIO_BMASK_HM) != 0)
  {
    printf("Warning: The HMAC hash function option is ignored during decryption.\n");
  }

  return TRUE;
}

_Bool IsVersionRequested(const CLI_INPUT* pInput)
{
  if(pInput->m_showVer)
  {
    printf(" AESIO-CLI v" CLI_STR_VER " (API v" AESIO_STR_VER ")\n"
           " - " CLI_STR_MIT "\n"
           " - (c) 2024 " CLI_STR_AUTHOR ".\n\n");
  }

  return pInput->m_showVer;
}

_Bool IsCommandLineInputValid(const CLI_INPUT* pInput)
{
  if(pInput->m_actionType == OPT_ACTION_ENCRYPT)
  {
    return IsEncryptActionValid(pInput);
  }
  else if(pInput->m_actionType == OPT_ACTION_DECRYPT)
  {
    return IsDecryptActionValid(pInput);
  }
  else
  {
    printf("An unexpected error has occurred: invalid action.\n");
    return FALSE;
  }
}

int EncryptFileToFile(
  const CLI_INPUT* pInput,
  const char* pPassword)
{
  AesioCode res;
  FILE* pFile;
  char* pBuffer;
  char* pBase64Buffer;
  size_t szBuffer;
  size_t szBase64Buffer;

  if(!pInput->m_base64)
  {
    res = AesioEncryptFile(pInput->m_pDestinationPath,                             
                           pInput->m_pSourcePath,
                           pPassword,
                           strlen(pPassword),
                           NULL,
                           (uint8_t*)(pInput->m_pAAD),
                           pInput->m_pAAD != NULL ? strlen(pInput->m_pAAD) : 0,
                           pInput->m_bAesioFlags);
    
    return HandleAesioError(res);    
  }

  res = AesioEncryptFileToBuffer(&pBuffer,
                                 &szBuffer,
                                 pInput->m_pSourcePath,
                                 pPassword,
                                 strlen(pPassword),
                                 NULL,
                                 (uint8_t*)(pInput->m_pAAD),
                                 pInput->m_pAAD != NULL ? strlen(pInput->m_pAAD) : 0,
                                 pInput->m_bAesioFlags);

  if(HandleAesioError(res) != 0)
  {
    return 1;
  }

  szBase64Buffer = Base64Encode(&pBase64Buffer, pBuffer, szBuffer);
  free(pBuffer);
  if(szBase64Buffer == 0)
  {
    printf("Out of memory during Base64 encoding.\n");
    return 1;
  }

  pBuffer = pBase64Buffer;
  szBuffer = szBase64Buffer;

#if defined (_MSC_VER)
  fopen_s(&pFile, pInput->m_pDestinationPath, "w");
#else
  pFile = fopen(pInput->m_pDestinationPath, "w");
#endif

  if(pFile == NULL)
  {
    free(pBuffer);
    printf("Unable to write file: %s\n", pInput->m_pDestinationPath);
    return 1;
  }

  if(fwrite(pBuffer, 1, szBuffer, pFile) != szBuffer)
  {
    free(pBuffer);
    fclose(pFile);
    printf("Write fail: %s\n", pInput->m_pDestinationPath);
    return 1;
  }

  fclose(pFile);
  free(pBuffer);
  
  return 0;
}

int EncryptFileToString(
  const CLI_INPUT* pInput,
  const char* pPassword)
{
  AesioCode res;
  char* pBuffer;
  char* pBase64Buffer;
  size_t szBufferSize;

  res = AesioEncryptFileToBuffer(&pBuffer,
                                 &szBufferSize,
                                 pInput->m_pSourcePath,
                                 pPassword,
                                 strlen(pPassword),
                                 NULL,
                                 (uint8_t*)(pInput->m_pAAD),
                                 pInput->m_pAAD != NULL ? strlen(pInput->m_pAAD) : 0,
                                 pInput->m_bAesioFlags);  

  if(HandleAesioError(res) != 0)
  {
    return 1;
  }

  if(Base64Encode(&pBase64Buffer, pBuffer, szBufferSize) == 0)
  {
    free(pBuffer);
    printf("Out of memory during Base64 encoding.\n");
    return 1;
  }

  free(pBuffer);
  printf("%s\n", pBase64Buffer);
  free(pBase64Buffer);

  return 0;
}

int EncryptStringToFile(
  const CLI_INPUT* pInput,
  const char* pPassword)
{
  AesioCode res;
  FILE* pFile;
  char* pBuffer;
  char* pBase64Buffer;
  size_t szBuffer;
  size_t szBase64Buffer;

  if(!pInput->m_base64)
  {
    res = AesioEncryptDataToFile(pInput->m_pDestinationPath,
                                 pInput->m_pString,
                                 strlen(pInput->m_pString),
                                 pPassword,
                                 strlen(pPassword),
                                 NULL,
                                 (uint8_t*)(pInput->m_pAAD),
                                 pInput->m_pAAD != NULL ? strlen(pInput->m_pAAD) : 0,
                                 pInput->m_bAesioFlags);  
    
    return HandleAesioError(res);
  }

  res = AesioEncryptDataToBuffer(&pBuffer,
                                 &szBuffer,
                                 pInput->m_pString,
                                 strlen(pInput->m_pString),
                                 pPassword,
                                 strlen(pPassword),
                                 NULL,
                                 (uint8_t*)(pInput->m_pAAD),
                                 pInput->m_pAAD != NULL ? strlen(pInput->m_pAAD) : 0,
                                 pInput->m_bAesioFlags);

  if(HandleAesioError(res) != 0)
  {
    return 1;
  }

  szBase64Buffer = Base64Encode(&pBase64Buffer, pBuffer, szBuffer);
  free(pBuffer);
  
  if(szBase64Buffer == 0)
  {
    printf("Out of memory during Base64 encoding.\n");
    return 1;
  }

  pBuffer = pBase64Buffer;
  szBuffer = szBase64Buffer;

#if defined (_MSC_VER)
  fopen_s(&pFile, pInput->m_pDestinationPath, "w");
#else
  pFile = fopen(pInput->m_pDestinationPath, "w");
#endif

  if(pFile == NULL)
  {
    free(pBuffer);
    printf("Unable to write file: %s\n", pInput->m_pDestinationPath);
    return 1;
  }

  if(fwrite(pBuffer, 1, szBuffer, pFile) != szBuffer)
  {
    free(pBuffer);
    fclose(pFile);
    printf("Write fail: %s\n", pInput->m_pDestinationPath);
    return 1;
  }

  fclose(pFile);
  free(pBuffer);

  return 0;
}

int EncryptStringToString(
  const CLI_INPUT* pInput,
  const char* pPassword)
{
  AesioCode res;
  char* pBuffer;
  char* pBase64Buffer;
  size_t szBuffer;

  res = AesioEncryptDataToBuffer(&pBuffer,
                                 &szBuffer,
                                 pInput->m_pString,
                                 strlen(pInput->m_pString),
                                 pPassword,
                                 strlen(pPassword),
                                 NULL,
                                 (uint8_t*)(pInput->m_pAAD),
                                 pInput->m_pAAD != NULL ? strlen(pInput->m_pAAD) : 0,
                                 pInput->m_bAesioFlags);

  if(HandleAesioError(res) != 0)
  {
    return 1;
  }

  if(Base64Encode(&pBase64Buffer, pBuffer, szBuffer) == 0)
  {
    free(pBuffer);
    printf("Out of memory during Base64 encoding.\n");
    return 1;
  }
  
  free(pBuffer);
  printf("%s\n", pBase64Buffer);  
  free(pBase64Buffer);

  return 0;
}

int EncryptAction(CLI_INPUT* pInput)
{
  char password[CLI_PASSWORD_BUFFER_SIZE];
  
  int res = 1;

  if(!GetPassword(password, sizeof(password), pInput->m_pPasswordFilePath, TRUE))
  {
    return 1;
  }

  if(!IsPasswordValid(password))
  {
    memset(password, '\0', sizeof(password));
    return 1;
  }

  if(pInput->m_pSourcePath != NULL)
  {
    if(pInput->m_pDestinationPath != NULL)
    {
      res = EncryptFileToFile(pInput, password);
    }
    else if(pInput->m_base64)
    {
      res = EncryptFileToString(pInput, password);
    }
    else
    {
      printf("An unexpected error has occurred: missing output parameter.\n");
    }

    if(res == 0 && pInput->m_deleteInput)
    {
      DeleteInputFile(pInput->m_pSourcePath);
    }
  }
  else if(pInput->m_pString != NULL)
  {
    if(pInput->m_pDestinationPath != NULL)
    {
      res = EncryptStringToFile(pInput, password);
    }
    else if(pInput->m_base64)
    {
      res = EncryptStringToString(pInput, password);
    }
    else
    {
      printf("An unexpected error has occurred: missing output parameter.\n");
    }
  }
  else 
  {
    printf("An unexpected error has occurred: missing input parameter.\n");
  }

  memset(password, '\0', sizeof(password));
  return res;
}

_Bool IsBase64(
  const char* pBuffer,
  const size_t szBuffer)
{
  char c;
  size_t i;

  if((szBuffer % 4) != 0)
  {
    return FALSE;
  }

  for(i = 0; i < szBuffer;i++)
  {
    c = pBuffer[i];
    if(!((c >= 'A' && c <= 'Z') ||
         (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') ||
         (c == '+') || (c == '/') || (c == '=')))
    {
      return FALSE;
    }
  }

  return TRUE;
}

int DecryptFileToFile(
  const CLI_INPUT* pInput,
  const char* pPassword)
{
  AesioCode res;
  FILE* pFile;
  char* pBuffer;
  char* pBase64Buffer;
  size_t szBuffer;
  size_t szBase64Buffer;
  struct stat stat;

  if(!pInput->m_base64)
  {
    res = AesioDecryptFile(pInput->m_pDestinationPath,
                           pInput->m_pSourcePath,
                           pPassword,
                           strlen(pPassword),
                           NULL,
                           (uint8_t*)(pInput->m_pAAD),
                           pInput->m_pAAD != NULL ? strlen(pInput->m_pAAD) : 0);

    return HandleAesioError(res);
  }

#if defined (_MSC_VER)
  fopen_s(&pFile, pInput->m_pSourcePath, "r");
#else
  pFile = fopen(pInput->m_pSourcePath, "r");
#endif

  if(pFile == NULL)
  {
    printf("Unable to write file: %s\n", pInput->m_pSourcePath);
    return 1;
  }

  if(fstat(FILENO(pFile), &stat))
  {
    fclose(pFile);
    printf("File read failed: %s\n", pInput->m_pSourcePath);
    return 1;
  }

  szBuffer = stat.st_size;
  if(szBuffer == 0)
  {
    fclose(pFile);
    printf("The input file is empty: %s\n", pInput->m_pSourcePath);
    return 1;
  }

  pBuffer = malloc(szBuffer);
  if(pBuffer == NULL)
  {
    fclose(pFile);
    printf("Out of memory.\n");
    return 1;
  }

  if(fread(pBuffer, 1, szBuffer, pFile) != szBuffer)
  {
    free(pBuffer);
    fclose(pFile);
    printf("Read fail: %s\n", pInput->m_pSourcePath);
    return 1;
  }

  fclose(pFile);

  if(!IsBase64(pBuffer, szBuffer))
  {
    free(pBuffer);
    printf("Invalid Base64 format: %s\n", pInput->m_pSourcePath);
    return 1;
  }

  szBase64Buffer = Base64Decode((void **)(&pBase64Buffer), pBuffer, szBuffer);
  free(pBuffer);
  if(szBase64Buffer == 0)
  {
    printf("Out of memory during Base64 decoding.\n");
    return 1;
  }
  
  pBuffer = pBase64Buffer;
  szBuffer = szBase64Buffer;
  res = AesioDecryptDataToFile(pInput->m_pDestinationPath,
                               pBuffer,
                               szBuffer,
                               pPassword,
                               strlen(pPassword),
                               NULL,
                               (uint8_t*)(pInput->m_pAAD),
                               pInput->m_pAAD != NULL ? strlen(pInput->m_pAAD) : 0);
  
  free(pBuffer);  
  return HandleAesioError(res);
}

int DecryptStringToFile(
  const CLI_INPUT* pInput,
  const char* pPassword)
{
  AesioCode res;
  char* pBuffer;
  size_t szBuffer;

  if(!pInput->m_base64)
  {
    res = AesioDecryptDataToFile(pInput->m_pDestinationPath,
                                 pInput->m_pString,
                                 strlen(pInput->m_pString),
                                 pPassword,
                                 strlen(pPassword),
                                 NULL,
                                 (uint8_t*)(pInput->m_pAAD),
                                 pInput->m_pAAD != NULL ? strlen(pInput->m_pAAD) : 0);

    return HandleAesioError(res);
  }

  if(!IsBase64(pInput->m_pString, strlen(pInput->m_pString)))
  {
    printf("Invalid Base64 format.\n");
    return 1;
  }

  szBuffer = Base64Decode((void**)(&pBuffer), pInput->m_pString, strlen(pInput->m_pString));    
  if(szBuffer == 0)
  {
    printf("Out of memory during Base64 decoding.\n");
    return 1;
  }

  res = AesioDecryptDataToFile(pInput->m_pDestinationPath,
                               pBuffer,
                               szBuffer,
                               pPassword,
                               strlen(pPassword),
                               NULL,
                               (uint8_t*)(pInput->m_pAAD),
                               pInput->m_pAAD != NULL ? strlen(pInput->m_pAAD) : 0);

  free(pBuffer);
  return HandleAesioError(res);
}

int DecryptAction(CLI_INPUT* pInput)
{
  char password[CLI_PASSWORD_BUFFER_SIZE];
  
  int res = 1;

  if(!GetPassword(password, sizeof(password), pInput->m_pPasswordFilePath, FALSE))
  {
    return 1;
  }

  if(!IsPasswordValid(password))
  {
    return 1;
  }

  if(pInput->m_pSourcePath != NULL)
  {
    res = DecryptFileToFile(pInput, password);
    if(res == 0 && pInput->m_deleteInput)
    {
      DeleteInputFile(pInput->m_pSourcePath);
    }
  }
  else if(pInput->m_pString != NULL)
  {
    res = DecryptStringToFile(pInput, password);
  }
  else
  {
    printf("An unexpected error has occurred: invalid input.\n");
  }

  memset(password, '\0', sizeof(password));
  return res;
}

_Bool DeleteInputFile(const char* pSrcPath)
{
  if(pSrcPath == NULL)
  {
    printf("An unexpected error has occurred: missing source path.\n");
    return FALSE;
  }

  if(remove(pSrcPath) != 0)
  {
    printf("Warning: unable to delete file: %s\n", pSrcPath);
    return FALSE;
  }

  return TRUE;
}

int HandleAesioError(AesioCode res)
{
  switch (res)
  {
    case AESIO_ERR_OK:
    {
      /* No error. */
      return 0;
    }
    case AESIO_ERR_INVALIDPARAM:
    {
      printf("Aesio error: Invalid parameter.\n");
      return 1;
    }
    case AESIO_ERR_INVALIDFILEOFFSET:
    {
      printf("Aesio error: Invalid file offset.\n");
      return 1;
    }
    case AESIO_ERR_INVALIDSIZE:
    {
      printf("Aesio error: Invalid input size.\n");
      return 1;
    }
    case AESIO_ERR_INVALIDKEYSIZE:
    {
      printf("Aesio error: Invalid key size.\n");
      return 1;
    }
    case AESIO_ERR_OUTOFMEMORY:
    {
      printf("Aesio error: Out of memory.\n");
      return 1;
    }
    case AESIO_ERR_READFAILED:
    {
      printf("Aesio error: Read failed.\n");
      return 1;
    }
    case AESIO_ERR_INVALIDINPUT:
    {
      printf("Aesio error: Invalid input.\n");
      return 1;
    }
    case AESIO_ERR_WRITEFAILED:
    {
      printf("Aesio error: Write failed.\n");
      return 1;
    }
    case AESIO_ERR_RANDFAILED:
    {
      printf("Aesio error: Random number generation failed.\n");
      return 1;
    }
    case AESIO_ERR_MACNOTMATCH:
    {
      printf("Aesio error: MAC not match.\n");
      return 1;
    }
    case AESIO_ERR_INVALIDFILESIGNATURE:
    {
      printf("Aesio error: Invalid file signature.\n");
      return 1;
    }
    case AESIO_ERR_INVALIDFILEVERSION:
    {
      printf("Aesio error: Invalid file version.\n");
      return 1;
    }
    default:
    {
      printf("Aesio unknown error: %d\n", res);
      return 1;
    }
  }
}

int main(int argc, const char* argv[])
{
  CLI_DATA cld;

  if(InitCommandLine(&cld, g_commandLineOptions, ARRAY_SIZE(g_commandLineOptions)) != 0)
  {
    return 1;
  }
  
  if(ParseCommandLineArgs(&cld, argc, argv) != 0)
  {
    return 1;
  }

  if(IsVersionRequested(&cld.m_input))
  {
    return 0;
  }

  if(!IsCommandLineInputValid(&cld.m_input))
  {
    return 1;
  }

  SetDefaultAesioFlags(&cld.m_input);

  switch (cld.m_input.m_actionType)
  {
    case OPT_ACTION_ENCRYPT:
    {
      return EncryptAction(&cld.m_input);
    }
    case OPT_ACTION_DECRYPT:
    {
      return DecryptAction(&cld.m_input);
    }
    case OPT_ACTION_NONE:
    default:
    {
      printf("An unexpected error has occurred: invalid action.\n");
      return 1;
    }
  }
}