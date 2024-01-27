/*
 * Catcrypt, simple RSA/PKE for C
 * Copyright (C) 2023, Oğuzhan Eroğlu <meowingcate@gmail.com> (https://meowingcat.io)
 * Licensed under GPLv3 License
 * See LICENSE for more info
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#include "../include/util.h"

void catcrypt_util_assert_fail() {
    __asm__("nop");
}

void catcrypt_util_verbose(const char* format, ...) {
    if (!is_verbose) {
        return;
    }

    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}

void catcrypt_util_verbose_set(int p_is_verbose) {
    is_verbose = p_is_verbose;
}

int catcrypt_util_msleep(long millis) {
    struct timespec ts;
    int result;

    ts.tv_sec = millis / 1000;
    ts.tv_nsec = (millis % 1000) * 1000000;

    result = nanosleep(&ts, &ts);

    return result;
}

uint64_t catcrypt_util_get_time_msec() {
    struct timeval current_time;
    gettimeofday(&current_time, NULL);

    return current_time.tv_sec * 1000 + current_time.tv_usec / 1000;
}

int catcrypt_util_int2str(int number, char* target) {
    int current = number;
    int str_i = 0;

    char digits[11] = {'\0'};
    
    int length = 0;

    for (int i=9;; i--) {
        int modulo = current % 10;
        current = current / 10;

        digits[i] = '0' + modulo;
        length++;

        if (current < 1) {
            break;
        }
    }

    int j = 0;
    
    for (int i=9; i > 0; i--) {
        target[j++] = digits[i];
    }

    return length;
}