#pragma once
#include <stdint.h>

/* AESIO file signature. */
#define AESIO_FSIG					"AO"
/* AESIO file signature size. */
#define AESIO_SIGNATURESIZE			(sizeof(AESIO_FSIG) - 1)
/* Verify file signature. */
#define ISSIGVALID(sig)				(sig[0] == AESIO_FSIG[0] && sig[1] == AESIO_FSIG[1])
/* AESIO file version. */
#define AESIO_FILEVERSION			(uint16_t)(1)
/* Compares the file version number against those supported by API. */
#define FVERCMP(ver)				(AESIO_FILEVERSION - ver)