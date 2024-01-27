/*
 * Catcrypt, simple RSA/PKE for C
 * Copyright (C) 2023, Oğuzhan Eroğlu <meowingcate@gmail.com> (https://meowingcat.io)
 * Licensed under GPLv3 License
 * See LICENSE for more info
 */

#include <stdlib.h>
#include <assert.h>

#include "../include/ref.h"
#include "../include/util.h"
#include "../include/string.h"

void catcrypt_ref_counted_init(catcrypt_ref_counted_t* ref_counted, catcrypt_ref_free_f_t free_f) {
    ref_counted->count = 0;
    ref_counted->free_f = free_f;
}

void catcrypt_ref_counted_use(catcrypt_ref_counted_t* ref_counted) {
    ref_counted->count++;
}

void catcrypt_ref_counted_leave(void** obj_vp, catcrypt_ref_counted_t* ref_counted) {
    void* to_free = *obj_vp;
    
    CATCRYPT_UTIL_ASSERT(ref_counted->count > 0);
    
    ref_counted->count--;

    if (ref_counted->count == 0) {
        *obj_vp = NULL;
        ref_counted->free_f(to_free);
    }
}

catcrypt_ref_t* catcrypt_ref_new(void* obj, catcrypt_ref_counted_t* ref_counted) {
    catcrypt_ref_t* ref = malloc(sizeof(catcrypt_ref_t));
    ref->count = 0;
    ref->obj = obj;
    ref->ref_counted = ref_counted;
    return ref;
}

void catcrypt_ref_free(catcrypt_ref_t* ref) {
    free(ref);
}

void catcrypt_ref_use(catcrypt_ref_t* ref) {
    catcrypt_ref_counted_use(ref->ref_counted);
    ref->count++;
}

void catcrypt_ref_leave(catcrypt_ref_t** p_ref) {
    catcrypt_ref_t* ref = *p_ref;
    CATCRYPT_UTIL_ASSERT(ref);
    if (!ref) {
        return;
    }
    
    catcrypt_ref_counted_leave(&ref->obj, ref->ref_counted);
    ref->count--;
    CATCRYPT_UTIL_ASSERT(ref->count >= 0);
    if (ref->count == 0) {
        catcrypt_ref_free(ref);
    }
}

void catcrypt_ref_assign(catcrypt_ref_t** p_dst, catcrypt_ref_t** p_src) {
    catcrypt_ref_t* dst = *p_dst;
    catcrypt_ref_t* src = *p_src;
    
    dst->ref_counted->count -= dst->count;
    src->ref_counted->count += dst->count;
    CATCRYPT_UTIL_ASSERT(dst->ref_counted->count >= 0);
    if (dst->ref_counted->count == 0) {
        dst->ref_counted->free_f(dst->obj);
    }

    src->count = dst->count;
    *p_dst = src;

    free(dst);
}

void catcrypt_ref_set(catcrypt_ref_t* ref, void* obj) {
    int offset = ((uint64_t) (ref->ref_counted)) - ((uint64_t) (ref->obj));
    catcrypt_ref_counted_t ref_counted = *ref->ref_counted;
    void* to_free = ref->obj;
    ref->obj = obj;
    ref->ref_counted = ref->obj + offset;
    *(ref->ref_counted) = ref_counted;
    ref->ref_counted->free_f(to_free);
}