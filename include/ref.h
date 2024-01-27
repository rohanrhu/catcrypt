/*
 * Catcrypt, simple RSA/PKE for C
 * Copyright (C) 2023, Oğuzhan Eroğlu <meowingcate@gmail.com> (https://meowingcat.io)
 * Licensed under GPLv3 License
 * See LICENSE for more info
 */

#pragma once

#include <stdio.h>

#include "util.h"

typedef void (*catcrypt_ref_free_f_t)(void*);

#define CATCRYPT_REF_COUNTED_INIT(obj, free_f) \
    catcrypt_ref_counted_init(&(obj->ref_counted), (catcrypt_ref_free_f_t) free_f);

#define CATCRYPT_REF_COUNTED_USE(obj) \
    catcrypt_util_verbose("Referencing: %s\n", #obj); \
    \
    catcrypt_ref_counted_use(&(obj->ref_counted));

#define CATCRYPT_REF_COUNTED_LEAVE(obj) \
    catcrypt_util_verbose("Dereferencing: %s\n", #obj); \
    \
    if (obj != NULL) { \
        catcrypt_ref_counted_leave((void **) (&(obj)), &(obj->ref_counted)); \
    }

#define REF_COUNTEDIFY() \
    catcrypt_ref_counted_t ref_counted;
#define CATCRYPT_REF_BY(name) name##_ref
#define CATCRYPT_REF(type, name) \
    type name; \
    catcrypt_ref_t* CATCRYPT_REF_BY(name);
#define CATCRYPT_REF_NEW(path, expr) \
    path = expr; \
    CATCRYPT_REF_BY(path) = catcrypt_ref_new((void *) path, &(path->ref_counted));
#define CATCRYPT_REF_ASSIGN(var, val) \
    catcrypt_ref_assign(&(CATCRYPT_REF_BY(var)), &(CATCRYPT_REF_BY(val))); \
    var = val;
#define CATCRYPT_REF_SET(ref, obj) \
    ref = obj; \
    catcrypt_ref_set(CATCRYPT_REF_BY(ref), (void *) (ref));
#define CATCRYPT_REF_USE(name) catcrypt_ref_use(CATCRYPT_REF_BY(name));
#define CATCRYPT_REF_LEAVE(name) catcrypt_ref_leave(&(CATCRYPT_REF_BY(name)));
#define CATCRYPT_REF_ARG(type, name) type name, catcrypt_ref_t* name##_ref
#define CATCRYPT_REF_PASS(name) catcrypt_ref_new((void *) name, &(name->ref_counted));

typedef struct catcrypt_ref_counted catcrypt_ref_counted_t;
typedef struct catcrypt_ref catcrypt_ref_t;

struct catcrypt_ref_counted {
    int count;
    catcrypt_ref_free_f_t free_f;
};

struct catcrypt_ref {
    int count;
    void* obj;
    catcrypt_ref_counted_t* ref_counted;
};

void catcrypt_ref_counted_init(catcrypt_ref_counted_t* ref_counted, catcrypt_ref_free_f_t free_f);
void catcrypt_ref_counted_use(catcrypt_ref_counted_t* ref_counted);
void catcrypt_ref_counted_leave(void** obj_vp, catcrypt_ref_counted_t* ref_counted);

catcrypt_ref_t* catcrypt_ref_new(void* obj, catcrypt_ref_counted_t* ref_counted);
void catcrypt_ref_free(catcrypt_ref_t* ref);
void catcrypt_ref_use(catcrypt_ref_t* ref);
void catcrypt_ref_leave(catcrypt_ref_t** ref);
void catcrypt_ref_assign(catcrypt_ref_t** dst, catcrypt_ref_t** src);
void catcrypt_ref_set(catcrypt_ref_t* ref, void* obj);