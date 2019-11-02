#pragma once
#include <stdlib.h>
#include <limits.h>

#ifdef _MSC_VER
#define bswap_32(x)				_byteswap_ulong(x)
#define bswap_64(x)				_byteswap_uint64(x)
#define _ROTL(_Value, _Shift)	(_rotl(_Value, _Shift))
#define _ROTR(_Value, _Shift)	(_rotr(_Value, _Shift))
#elif defined(__GNUC__)
#include <byteswap.h>
#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif
#ifndef min
#define min(a,b)				( a < b ? a : b )
#endif
#ifndef max
#define max(a,b)				( a > b ? a : b )
#endif
#define _ROTL(_Value, _Shift)	((_Value << (_Shift % 32)) | (_Value >> ((32 - _Shift) % 32)))
#define _ROTR(_Value, _Shift)	((_Value >> (_Shift % 32)) | (_Value << ((32 - _Shift) % 32)))
#endif