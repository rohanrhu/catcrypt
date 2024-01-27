/*
 * Catcrypt, simple RSA/PKE for C
 * Copyright (C) 2023, Oğuzhan Eroğlu <meowingcate@gmail.com> (https://meowingcat.io)
 * Licensed under GPLv3 License
 * See LICENSE for more info
 */

#pragma once

#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include "ref.h"

/**
 * ! Free by ref counting
 */
typedef struct catcrypt_string {
    char* value;
    unsigned int size;
    unsigned int length;
    unsigned int is_alloc_str;
    catcrypt_ref_counted_t ref_counted;
} catcrypt_string_t;

catcrypt_string_t* catcrypt_string_new();
catcrypt_string_t* catcrypt_string_new__n(int length);
catcrypt_string_t catcrypt_string_from_cstr__copy(char* cstr, ssize_t length);
catcrypt_string_t* catcrypt_string_new_from_cstr__copy(char* cstr, ssize_t length);
catcrypt_string_t* catcrypt_string_new_from_binary__copy(char* data, ssize_t length);
catcrypt_string_t catcrypt_string_from_cstr(char* cstr, ssize_t length);
catcrypt_string_t catcrypt_string_from_binary(char* data, ssize_t length);
catcrypt_string_t* catcrypt_string_new_from_cstr(char* cstr, ssize_t length);
void catcrypt_string_free(catcrypt_string_t* string);
void catcrypt_string_set_value(catcrypt_string_t* string, char* value);
void catcrypt_string_set_value__n(catcrypt_string_t* string, char* value, size_t length);
void catcrypt_string_append__cstr__n(catcrypt_string_t* string, char* value, ssize_t length);

bool catcrypt_string_compare(catcrypt_string_t* string, catcrypt_string_t* other);