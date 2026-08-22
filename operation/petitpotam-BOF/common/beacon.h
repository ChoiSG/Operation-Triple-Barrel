/*
 * Beacon Object Files (BOF)
 * -------------------------
 * Minimal beacon.h for petitpotam-bof.
 * Compatible with Cobalt Strike 4.x and AdaptixC2.
 */
#ifndef _BEACON_H_
#define _BEACON_H_
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* data API */
typedef struct {
	char * original;
	char * buffer;
	int    length;
	int    size;
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap * parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap * parser);

/* format API */
typedef struct {
	char * original;
	char * buffer;
	int    length;
	int    size;
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, const char * text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, const char * fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp * format, int * size);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp * format, int value);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

DECLSPEC_IMPORT void   BeaconOutput(int type, const char * data, int len);
DECLSPEC_IMPORT void   BeaconPrintf(int type, const char * fmt, ...);

/* Token Functions */
DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken();
DECLSPEC_IMPORT BOOL   BeaconIsAdmin();

/* Utility Functions */
DECLSPEC_IMPORT BOOL   toWideChar(char * src, wchar_t * dst, int max);

#ifdef __cplusplus
}
#endif
#endif
