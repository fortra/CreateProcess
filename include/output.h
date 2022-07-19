#pragma once

#include <windows.h>
#include <stdio.h>

#define PRINT(...) { \
    fprintf(stdout, __VA_ARGS__); \
}


#define PRINT_ERR(...) { \
    fprintf(stdout, __VA_ARGS__); \
}

#ifdef DEBUG
 #define DPRINT(...) { \
     fprintf(stderr, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     fprintf(stderr, __VA_ARGS__); \
 }
#else
 #define DPRINT(...)
#endif

#ifdef DEBUG
 #define DPRINT_ERR(...) { \
     fprintf(stderr, "ERROR: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
     fprintf(stderr, __VA_ARGS__); \
 }
#else
 #define DPRINT_ERR(...)
#endif

#define api_not_found(function) \
    DPRINT_ERR( \
        "[-] The address of '%s' was not found\n", \
        function \
    )
