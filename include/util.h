/*
 * Catcrypt, simple RSA/PKE for C
 * Copyright (C) 2023, Oğuzhan Eroğlu <meowingcate@gmail.com> (https://meowingcat.io)
 * Licensed under GPLv3 License
 * See LICENSE for more info
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <execinfo.h>

static bool is_verbose = false;

void catcrypt_util_assert_fail();

#define CATCRYPT_UTIL_ASSERT(condition) \
    { \
        if (!(condition)) { \
            printf("Assertion failed: %s\n", #condition); \
            printf("\tat: %s:%d\n", __FILE__, __LINE__); \
            \
            void* callstack[128]; \
            int frames = backtrace(callstack, sizeof(callstack) / sizeof(void*)); \
            char** lines = backtrace_symbols(callstack, frames); \
            \
            if (lines) { \
                printf("Call Stack:\n"); \
                \
                for (int i = 0; i < frames; i++) { \
                    printf("%s\n", lines[i]); \
                } \
            } \
            catcrypt_util_assert_fail(); \
        }; \
    }

void catcrypt_util_verbose(const char* format, ...);
void catcrypt_util_verbose_set(int p_is_verbose);
int catcrypt_util_msleep(long millis);
uint64_t catcrypt_util_get_time_msec();
int catcrypt_util_int2str(int number, char* target);

char* catcrypt_util_base64_encode(char* str);
char* cebsocket_util_base64_decode(char* str);