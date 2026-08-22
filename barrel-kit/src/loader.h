#ifndef LOADER_H
#define LOADER_H

#define GETRESOURCE(x) (char *)&x

typedef struct {
    int  len;
    char value[];
} RESOURCE;

#endif
