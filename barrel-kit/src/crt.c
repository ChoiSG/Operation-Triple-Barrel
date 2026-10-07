/*
 * crt — freestanding memcpy/memset for the PIC blobs.
 *
 * GCC emits calls to these for large struct copies and zero-initializers.
 * The blobs link without a C runtime, so Crystal Palace has nothing to
 * resolve them against; provide the definitions here.
 */
#include <windows.h>

void * memcpy(void * dst, const void * src, size_t size)
{
    __movsb((unsigned char *) dst, (const unsigned char *) src, size);
    return dst;
}

void * memset(void * dst, int value, size_t size)
{
    __stosb((unsigned char *) dst, (unsigned char) value, size);
    return dst;
}
