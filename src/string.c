/*
 * Catcrypt, simple RSA/PKE for C
 * Copyright (C) 2023, Oğuzhan Eroğlu <meowingcate@gmail.com> (https://meowingcat.io)
 * Licensed under GPLv3 License
 * See LICENSE for more info
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>

#include "../include/string.h"

catcrypt_string_t* catcrypt_string_new() {
    catcrypt_string_t* string = malloc(sizeof(catcrypt_string_t));
    CATCRYPT_REF_COUNTED_INIT(string, catcrypt_string_free);
    string->length = 0;
    string->size = string->length + 1;

    string->is_alloc_str = true;
    string->value = malloc(sizeof(1));
    *string->value = '\0';
    
    return string;
}

catcrypt_string_t* catcrypt_string_new__n(int length) {
    catcrypt_string_t* string = malloc(sizeof(catcrypt_string_t));
    CATCRYPT_REF_COUNTED_INIT(string, catcrypt_string_free);
    string->length = 0;
    string->size = string->length + 1;

    string->is_alloc_str = true;
    string->value = malloc(length+1);
    string->value[length] = '\0';
    
    return string;
}

catcrypt_string_t catcrypt_string_from_cstr__copy(char* cstr, ssize_t length) {
    catcrypt_string_t string;
    string.length = length;
    string.size = string.length + 1;

    string.is_alloc_str = true;
    string.value = strndup(cstr, length);

    string.value[length] = '\0';
    
    return string;
}

catcrypt_string_t* catcrypt_string_new_from_binary__copy(char* data, ssize_t length) {
    catcrypt_string_t* string = malloc(sizeof(catcrypt_string_t));
    CATCRYPT_REF_COUNTED_INIT(string, catcrypt_string_free);
    string->length = length;
    string->size = string->length;

    string->is_alloc_str = true;
    string->value = malloc(length);
    memcpy(string->value, data, length);
    
    return string;
}

catcrypt_string_t* catcrypt_string_new_from_cstr__copy(char* cstr, ssize_t length) {
    catcrypt_string_t* string = malloc(sizeof(catcrypt_string_t));
    CATCRYPT_REF_COUNTED_INIT(string, catcrypt_string_free);
    string->length = length;
    string->size = string->length + 1;

    string->is_alloc_str = true;
    string->value = malloc(length+1);
    memcpy(string->value, cstr, length);
    string->value[length] = '\0';
    
    return string;
}

catcrypt_string_t catcrypt_string_from_cstr(char* cstr, ssize_t length) {
    catcrypt_string_t string;
    string.length = length;
    string.size = string.length + 1;

    string.is_alloc_str = false;
    string.value = cstr;
    string.value[length] = '\0';
    
    return string;
}

catcrypt_string_t catcrypt_string_from_binary(char* data, ssize_t length) {
    catcrypt_string_t string;
    string.length = length;
    string.size = string.length + 1;

    string.is_alloc_str = false;
    string.value = data;
    
    return string;
}

catcrypt_string_t* catcrypt_string_new_from_cstr(char* cstr, ssize_t length) {
    catcrypt_string_t* string = malloc(sizeof(catcrypt_string_t));
    CATCRYPT_REF_COUNTED_INIT(string, catcrypt_string_free);
    string->length = length;
    string->size = string->length + 1;

    string->is_alloc_str = false;
    string->value = cstr;
    
    return string;
}

void catcrypt_string_free(catcrypt_string_t* string) {
    if (string->is_alloc_str) {
        free(string->value);
    }
    free(string);
}

void catcrypt_string_set_value(catcrypt_string_t* string, char* value) {
    void* to_free = string->value;
    string->value =  value;
    if (to_free && string->is_alloc_str) {
        free(to_free);
    }

    size_t length = strlen(string->value);
    string->length = length;
    string->size = string->length + 1;
    string->value[string->length] = '\0';
}

void catcrypt_string_set_value__n(catcrypt_string_t* string, char* value, size_t length) {
    void* to_free = string->value;
    string->value =  value;
    if (to_free && string->is_alloc_str) {
        free(to_free);
    }
    
    string->length = length;
    string->size = string->length + 1;
    string->value[length] = '\0';
}

void catcrypt_string_append__cstr__n(catcrypt_string_t* string, char* value, ssize_t length) {
    if ((string->length + length + 1) > string->size) {
        string->size = string->length + length + 1;
        string->value = realloc(string->value, string->size);
    }
    memcpy(string->value + string->length, value, length);
    string->length += length;
    string->value[string->length] = '\0';
}

bool catcrypt_string_compare(catcrypt_string_t* string, catcrypt_string_t* other) {
    if (string->length != other->length) {
        return false;
    }

    return memcmp(string->value, other->value, string->length) == 0;
}